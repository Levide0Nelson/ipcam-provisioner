"""Caméra virtuelle (Phase 1) : écoute les protocoles de découverte en UDP et imite
les APIs HTTP des 4 familles de vendors (ISAPI Hikvision, CGI Dahua, JSON Tiandy,
SOAP ONVIF) pour le fingerprinting, l'activation et l'attribution.
"""

from __future__ import annotations

import asyncio
import json
import re
import socket
from collections.abc import Callable
from dataclasses import dataclass

from ..auth import (
    auth_header_value,
    verify_basic_authorization,
    verify_digest_authorization,
    verify_onvif_username_token,
)
from ..models import DiscoveryMethod
from .fake_server import FakeHttpserver, HttpRequest, HttpResponse

_USERNAME = "admin"

#: Adresses/ports de découverte réels par méthode (mode répétition Phase 2) :
#: (genre, adresse cible, port) — multicast pour WS-Discovery, broadcast pour les autres.
REHEARSAL_BINDS: dict[DiscoveryMethod, tuple[str, str, int]] = {
    DiscoveryMethod.ONVIF_WS_DISCOVERY: ("multicast", "239.255.255.250", 3702),
    DiscoveryMethod.SADP: ("broadcast", "255.255.255.255", 37020),
    DiscoveryMethod.DAHUA_DISCOVERY: ("broadcast", "255.255.255.255", 37810),
    DiscoveryMethod.TIANDY_DISCOVERY: ("broadcast", "255.255.255.255", 9999),
}

FACTORY_IP = {
    "hikvision": "192.0.0.64",
    "dahua": "192.0.0.64",
    "tiandy": "10.1.1.64",
    "onvif": "169.254.20.64",
}
FACTORY_MODEL = {
    "hikvision": "DS-2CD2042WD-I",
    "dahua": "IPC-HFW2431S-S",
    "tiandy": "TC-C52WP-2MP",
    "onvif": "GenericONVIF-IPC",
}


@dataclass
class CameraSpec:
    """Description d'une caméra simulée à démarrer."""

    vendor: str
    mac: str
    ip: str | None = None
    model: str | None = None
    serial: str | None = None
    firmware: str | None = None
    active: bool = False
    password: str | None = None
    rehearse: bool = False

    def effective(self) -> CameraSpec:
        default_ip = FACTORY_IP.get(self.vendor, "192.0.0.64")
        default_model = FACTORY_MODEL.get(self.vendor, "IPCamera")
        return CameraSpec(
            vendor=self.vendor,
            mac=self.mac or _default_mac(self.vendor),
            ip=self.ip or default_ip,
            model=self.model or default_model,
            serial=self.serial or f"{self.vendor.upper()}-{self.mac.replace(':', '')[:8]}",
            firmware=self.firmware or "V1.0 (Phase1)",
            active=self.active,
            password=self.password,
            rehearse=self.rehearse,
        )


def _default_mac(vendor: str) -> str:
    prefixes = {"hikvision": "ac:cc:8e", "dahua": "e0:50:8b", "tiandy": "00:cc:2f", "onvif": "aa:bb:cc"}
    return f"{prefixes[vendor]}:11:22:33"


class VirtualCamera:
    """Caméra simulée : protocoles de découverte UDP + serveur HTTP par vendor."""

    def __init__(self, spec: CameraSpec, on_ip_changed: Callable[[str, str, str], None] | None = None):
        resolved = spec.effective()
        self.vendor = resolved.vendor
        self.mac_address = resolved.mac
        self.serial_number = resolved.serial
        self.model = resolved.model
        self.firmware_version = resolved.firmware
        self.logical_ip = resolved.ip
        self._active = resolved.active
        self._password = resolved.password
        self._rehearse = resolved.rehearse
        self._on_ip_changed = on_ip_changed
        self.http_port = 0
        self._udp_ports: dict[DiscoveryMethod, int] = {}
        self._udp_transports: list[asyncio.DatagramTransport] = []
        self._http_server: FakeHttpserver | None = None

    # --- cycle de vie -------------------------------------------------------

    def supported_methods(self) -> list[DiscoveryMethod]:
        table = {
            "hikvision": DiscoveryMethod.SADP,
            "dahua": DiscoveryMethod.DAHUA_DISCOVERY,
            "tiandy": DiscoveryMethod.TIANDY_DISCOVERY,
            "onvif": DiscoveryMethod.ONVIF_WS_DISCOVERY,
        }
        return [table[self.vendor]]

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        for method in self.supported_methods():
            factory = lambda m=method: _UdpService(  # noqa: E731 - callback asyncio
                lambda data, m=m: self._discovery_reply(m, data)
            )
            rehearsal = REHEARSAL_BINDS.get(method) if self._rehearse else None
            if rehearsal is not None:
                kind, address, port = rehearsal
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if kind == "multicast":
                    mreq = socket.inet_aton(address) + socket.inet_aton("0.0.0.0")
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                sock.bind(("0.0.0.0", port))
                transport, _ = await loop.create_datagram_endpoint(factory, sock=sock)
            else:
                transport, _ = await loop.create_datagram_endpoint(
                    factory, local_addr=("127.0.0.1", 0)
                )
            self._udp_transports.append(transport)
            self._udp_ports[method] = transport.get_extra_info("sockname")[1]
        self._http_server = FakeHttpserver(self._http_dispatch)
        self.http_port = await self._http_server.start()

    async def stop(self) -> None:
        for transport in self._udp_transports:
            transport.close()
        if self._http_server is not None:
            await self._http_server.stop()

    def probe_port(self, method: DiscoveryMethod) -> int:
        return self._udp_ports[method]

    def is_active(self) -> bool:
        return self._active

    # --- changement d'état --------------------------------------------------

    def activate(self, new_password: str) -> None:
        self._active = True
        self._password = new_password

    def change_ip(self, new_ip: str) -> None:
        old_ip = self.logical_ip
        if new_ip == old_ip:
            return
        self.logical_ip = new_ip
        if self._on_ip_changed is not None:
            self._on_ip_changed(old_ip, new_ip, self.mac_address)

    # --- découverte ---------------------------------------------------------

    def _discovery_reply(self, method: DiscoveryMethod, data: bytes) -> bytes | None:
        if method is DiscoveryMethod.SADP:
            if data.strip() != b"SADP:DeviceDiscovery":
                return None
            return self._sadp_reply().encode("utf-8")
        if method is DiscoveryMethod.DAHUA_DISCOVERY:
            if data.strip() != b"Dahua:Discovery":
                return None
            return self._dahua_reply().encode("utf-8")
        if method is DiscoveryMethod.TIANDY_DISCOVERY:
            if data.strip() != b"TIANDY:DISCOVER":
                return None
            return self._tiandy_reply().encode("utf-8")
        if method is DiscoveryMethod.ONVIF_WS_DISCOVERY:
            if b"<d:Probe" not in data and b"Probe" not in data:
                return None
            return self._onvif_probe_match().encode("utf-8")
        return None

    def _sadp_reply(self) -> str:
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<ProbeMatch>
  <DeviceType>IPCamera</DeviceType>
  <MACAddress>{self.mac_address}</MACAddress>
  <SerialNumber>{self.serial_number}</SerialNumber>
  <IPv4Address>{self.logical_ip}</IPv4Address>
  <IPv4SubnetMask>255.255.255.0</IPv4SubnetMask>
  <IPv4Gateway>192.0.0.1</IPv4Gateway>
  <HttpPort>{self.http_port}</HttpPort>
  <FirmwareVersion>{self.firmware_version}</FirmwareVersion>
  <Model>{self.model}</Model>
  <Activated>{str(self._active).lower()}</Activated>
</ProbeMatch>"""

    def _dahua_reply(self) -> str:
        return (
            "DeviceType=IPCamera\n"
            f"DeviceMacAddress={self.mac_address}\n"
            f"SerialNumber={self.serial_number}\n"
            f"HardwareVersion=0x100\n"
            f"NetworkInterface.IPv4Address={self.logical_ip}\n"
            f"NetworkInterface.IPv4SubnetMask=255.255.255.0\n"
            f"NetworkInterface.IPv4Gateway=10.1.1.1\n"
        )

    def _tiandy_reply(self) -> str:
        return (
            "vendor=tiandy\n"
            f"mac={self.mac_address}\n"
            f"ip={self.logical_ip}\n"
            f"serial={self.serial_number}\n"
            f"mode={self.model}\n"
        )

    def _onvif_probe_match(self) -> str:
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
 xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
 xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
 <e:Header><w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatch</w:Action></e:Header>
 <e:Body>
  <d:ProbeMatch>
   <d:EndpointReference><w:Address>urn:uuid:{self.mac_address}</w:Address></d:EndpointReference>
   <d:Types>dn:NetworkVideoTransmitter</d:Types>
   <d:Scopes>onvif://www.onvif.org/name/{self.model}</d:Scopes>
   <d:XAddrs>http://{self.logical_ip}:{self.http_port}/onvif/device_service</d:XAddrs>
  </d:ProbeMatch>
 </e:Body>
</e:Envelope>"""

    # --- HTTP ---------------------------------------------------------------

    async def _http_dispatch(self, request: HttpRequest) -> HttpResponse:
        handler = {
            "hikvision": self._hik_http,
            "dahua": self._dahua_http,
            "tiandy": self._tiandy_http,
            "onvif": self._onvif_http,
        }[self.vendor]
        return await handler(request)

    # -- Hikvision (ISAPI) ---------------------------------------------------

    async def _hik_http(self, req: HttpRequest) -> HttpResponse:
        if req.path == "/ISAPI/System/deviceInfo" and req.method == "GET":
            return self._hik_device_info(req)
        if req.path == "/ISAPI/System/activate" and req.method == "POST":
            return self._hik_activate(req)
        if req.path.startswith("/ISAPI/System/Network/interfaces") and req.method == "PUT":
            return self._hik_set_network(req)
        return HttpResponse(status=404, body=b"Not Found")

    def _hik_device_info(self, req: HttpRequest) -> HttpResponse:
        if not self._active:
            return HttpResponse.unauthorized_digest()
        if not self._digest_ok(req, "GET", "/ISAPI/System/deviceInfo"):
            return HttpResponse.unauthorized_digest()
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<DeviceInfo xmlns="http://www.hikvision.com/ver10/XMLSchema">
  <deviceName>IPCamera</deviceName>
  <model>{self.model}</model>
  <serialNumber>{self.serial_number}</serialNumber>
  <macAddress>{self.mac_address}</macAddress>
  <firmwareVersion>{self.firmware_version}</firmwareVersion>
</DeviceInfo>"""
        return HttpResponse.text(200, xml, **{"Content-Type": "application/xml"})

    def _hik_activate(self, req: HttpRequest) -> HttpResponse:
        if self._active:
            return HttpResponse.text(400, "<ResponseStatus><statusCode>4</statusCode></ResponseStatus>")
        password = _xml_tag(req.body, "password")
        if not password:
            return HttpResponse.text(400, "<ResponseStatus><statusCode>8</statusCode></ResponseStatus>")
        self.activate(password)
        return HttpResponse.text(200, "<ResponseStatus><statusCode>1</statusCode></ResponseStatus>")

    def _hik_set_network(self, req: HttpRequest) -> HttpResponse:
        if not self._active or not self._digest_ok(req, "PUT", req.path):
            return HttpResponse.unauthorized_digest()
        new_ip = _xml_tag(req.body, "IPv4Address")
        if new_ip:
            self.change_ip(new_ip)
        return HttpResponse.text(200, "<ResponseStatus><statusCode>1</statusCode></ResponseStatus>")

    # -- Dahua (CGI) ---------------------------------------------------------

    async def _dahua_http(self, req: HttpRequest) -> HttpResponse:
        action = (req.query.get("action") or [""])[0]
        if req.path == "/cgi-bin/magicBox.cgi" and action == "getSystemInfo":
            return self._dahua_device_info(req)
        if req.path == "/cgi-bin/account.cgi" and action == "activate":
            return self._dahua_activate(req)
        if req.path == "/cgi-bin/configManager.cgi" and action == "setConfig":
            return self._dahua_set_network(req)
        return HttpResponse(status=404, body=b"Not Found")

    def _dahua_device_info(self, req: HttpRequest) -> HttpResponse:
        if not self._active:
            return HttpResponse.unauthorized_basic()
        if not self._basic_ok(req):
            return HttpResponse.unauthorized_basic()
        text = (
            f"model={self.model},\n"
            f"serialNumber={self.serial_number},\n"
            f"firmwareVersion={self.firmware_version},\n"
        )
        return HttpResponse.text(200, text, **{"Content-Type": "text/plain"})

    def _dahua_activate(self, req: HttpRequest) -> HttpResponse:
        if self._active:
            return HttpResponse.text(403, "result=error\n")
        password = _urlencoded_field(req.body, "password")
        if not password:
            return HttpResponse.text(400, "result=error\n")
        self.activate(password)
        return HttpResponse.text(200, "result=ok\n")

    def _dahua_set_network(self, req: HttpRequest) -> HttpResponse:
        if self._active and not self._basic_ok(req):
            return HttpResponse.unauthorized_basic()
        new_ip = (req.query.get("Network.eth0.address") or [""])[0]
        if new_ip:
            self.change_ip(new_ip)
        return HttpResponse.text(200, "result=ok\n")

    # -- Tiandy (JSON) -------------------------------------------------------

    async def _tiandy_http(self, req: HttpRequest) -> HttpResponse:
        if req.path == "/device/info.json" and req.method == "GET":
            if not self._active:
                return HttpResponse.unauthorized_basic()
            if not self._basic_ok(req):
                return HttpResponse.unauthorized_basic()
            info = {
                "model": self.model,
                "serial": self.serial_number,
                "firmware": self.firmware_version,
                "activated": True,
            }
            return HttpResponse.text(200, json.dumps(info), **{"Content-Type": "application/json"})
        if req.path == "/device/activate" and req.method == "POST":
            return self._tiandy_activate(req)
        if req.path == "/device/network" and req.method == "PUT":
            return self._tiandy_set_network(req)
        return HttpResponse(status=404, body=b"Not Found")

    def _tiandy_activate(self, req: HttpRequest) -> HttpResponse:
        if self._active:
            return HttpResponse.text(403, json.dumps({"result": "error"}), **{"Content-Type": "application/json"})
        try:
            password = json.loads(req.body or b"{}").get("password")
        except json.JSONDecodeError:
            password = None
        if not password:
            return HttpResponse.text(400, json.dumps({"result": "error"}), **{"Content-Type": "application/json"})
        self.activate(password)
        return HttpResponse.text(200, json.dumps({"result": "ok"}), **{"Content-Type": "application/json"})

    def _tiandy_set_network(self, req: HttpRequest) -> HttpResponse:
        if self._active and not self._basic_ok(req):
            return HttpResponse.unauthorized_basic()
        try:
            new_ip = json.loads(req.body or b"{}").get("ip")
        except json.JSONDecodeError:
            new_ip = None
        if new_ip:
            self.change_ip(new_ip)
        return HttpResponse.text(200, json.dumps({"result": "ok"}), **{"Content-Type": "application/json"})

    # -- ONVIF (SOAP) --------------------------------------------------------

    async def _onvif_http(self, req: HttpRequest) -> HttpResponse:
        if req.path == "/onvif/device_service" and req.method == "POST":
            return self._onvif_soap(req)
        return HttpResponse(status=404, body=b"Not Found")

    def _onvif_soap(self, req: HttpRequest) -> HttpResponse:
        body = req.body.decode("utf-8", errors="replace")
        if "CreateUsers" in body:
            return self._onvif_create_users(body)
        if not self._active:
            # Config usine : aucune opération autorisée avant l'activation.
            return HttpResponse.text(401, _onvif_fault(401))
        security = _security_block(body)
        if not security or not verify_onvif_username_token(
            security, self._password or "", expected_username=_USERNAME
        ):
            return HttpResponse.text(401, _onvif_fault(401))
        if "GetDeviceInformation" in body:
            xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope">
 <env:Body>
  <GetDeviceInformationResponse>
   <Manufacturer>{self.vendor.title()}</Manufacturer>
   <Model>{self.model}</Model>
   <FirmwareVersion>{self.firmware_version}</FirmwareVersion>
   <SerialNumber>{self.serial_number}</SerialNumber>
   <HardwareId>{self.mac_address}</HardwareId>
  </GetDeviceInformationResponse>
 </env:Body>
</env:Envelope>"""
            return HttpResponse.text(200, xml)
        if "GetNetworkInterfaces" in body:
            xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope">
 <env:Body>
  <GetNetworkInterfacesResponse>
   <NetworkInterfaces>
    <NetworkInterface>
     <InterfaceToken>NetworkInterface</InterfaceToken>
     <Info><Name>eth0</Name><MacAddress>{self.mac_address}</MacAddress></Info>
     <IPv4><Manual><Address>{self.logical_ip}</Address><PrefixLength>24</PrefixLength></Manual></IPv4>
    </NetworkInterface>
   </NetworkInterfaces>
  </GetNetworkInterfacesResponse>
 </env:Body>
</env:Envelope>"""
            return HttpResponse.text(200, xml)
        if "SetNetworkInterfaces" in body:
            new_ip = _soap_value(body, "Address") or _soap_value(body, "IPv4Address")
            if new_ip:
                self.change_ip(new_ip)
            xml = """<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope">
 <env:Body><SetNetworkInterfacesResponse/></env:Body>
</env:Envelope>"""
            return HttpResponse.text(200, xml)
        return HttpResponse.text(404, _onvif_fault(404))

    def _onvif_create_users(self, body: str) -> HttpResponse:
        """Création du premier compte (activation) sur appareil en config usine."""
        if self._active:
            # Déjà activée : CreateUsers est refusé proprement (fault receiver).
            return HttpResponse.text(400, _onvif_fault(400))
        username = _soap_value(body, "Username")
        password = _soap_value(body, "Password")
        if not username or not password:
            return HttpResponse.text(400, _onvif_fault(400))
        self.activate(password)
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope">
 <env:Body><CreateUsersResponse/></env:Body>
</env:Envelope>"""
        return HttpResponse.text(200, xml)

    # -- auth helpers --------------------------------------------------------

    def _digest_ok(self, req: HttpRequest, method: str, uri: str) -> bool:
        header = auth_header_value(req.headers, "Authorization") or ""
        if not header:
            return False
        return verify_digest_authorization(
            header, real_password=self._password or "", method=method, expected_uri=uri
        )

    def _basic_ok(self, req: HttpRequest) -> bool:
        header = auth_header_value(req.headers, "Authorization") or ""
        if not header:
            return False
        return verify_basic_authorization(
            header, expected_username=_USERNAME, expected_password=self._password or ""
        )


class _UdpService(asyncio.DatagramProtocol):
    def __init__(self, handler) -> None:
        self._handler = handler
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr) -> None:
        try:
            reply = self._handler(data)
        except Exception:  # noqa: BLE001 - jamais d'exception hors du simulateur
            reply = None
        if reply and self._transport is not None:
            self._transport.sendto(reply, addr)


def _xml_tag(payload: bytes, tag: str) -> str | None:
    text = payload.decode("utf-8", errors="replace")
    match = re.search(rf"<{tag}(?:\s[^>]*)?>([^<]+)</{tag}>", text)
    return match.group(1).strip() if match and match.group(1) else None


def _urlencoded_field(payload: bytes, key: str) -> str | None:
    from urllib.parse import parse_qs

    return (parse_qs(payload.decode("utf-8", errors="replace")) or {}).get(key, [None])[0]


def _security_block(soap_text: str) -> str | None:
    match = re.search(r"<(?:\w+:)?Security[^>]*>.*?</(?:\w+:)?Security>", soap_text, re.DOTALL)
    return match.group(0) if match else None


def _soap_value(soap_text: str, tag: str) -> str | None:
    match = re.search(rf"<(?:\w+:)?{tag}[^>]*>([^<]+)</(?:\w+:)?{tag}>", soap_text)
    return match.group(1).strip() if match and match.group(1) else None


def _onvif_fault(code: int) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope">
 <env:Body><env:Fault><env:Code><env:Value>env:Receiver</env:Value></env:Code>
 <env:Reason><env:Text xml:lang="en">{code}</env:Text></env:Reason></env:Fault></env:Body>
</env:Envelope>"""


__all__ = ["CameraSpec", "VirtualCamera", "FACTORY_IP", "FACTORY_MODEL"]
