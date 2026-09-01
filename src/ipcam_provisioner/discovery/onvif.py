"""Adaptateur de découverte générique ONVIF via WS-Discovery (multicast 239.255.255.250:3702).

Le WS-Discovery ne transporte pas le MAC : `mac_address` reste vide ici et sera rempli
par le fingerprinting ONVIF (GetNetworkInterfaces) ou par le fallback ARP.
"""

from __future__ import annotations

import logging
import uuid
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlsplit

from ..models import Camera, DiscoveryMethod
from .base import DiscoveryAdapter, DiscoveryContext
from .sadp import _decode, _safe_parse

logger = logging.getLogger("ipcam_provisioner.discovery.onvif")

_WS = "http://schemas.xmlsoap.org/ws/2005/04/discovery"
_ADDRESSING = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
_SOAP_ENV = "http://www.w3.org/2003/05/soap-envelope"
_ONVIF_NET = "http://www.onvif.org/ver10/network/wsdl"


def build_probe() -> bytes:
    message_id = f"uuid:{uuid.uuid4()}"
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="{_SOAP_ENV}" xmlns:w="{_ADDRESSING}"
 xmlns:d="{_WS}" xmlns:dn="{_ONVIF_NET}">
 <e:Header>
  <w:MessageID>{message_id}</w:MessageID>
  <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
  <w:Action>{_WS}/Probe</w:Action>
 </e:Header>
 <e:Body>
  <d:Probe>
   <d:Types>dn:NetworkVideoTransmitter</d:Types>
  </d:Probe>
 </e:Body>
</e:Envelope>"""
    return xml.encode("utf-8")


class OnvifWsDiscoveryAdapter(DiscoveryAdapter):
    method = DiscoveryMethod.ONVIF_WS_DISCOVERY

    async def discover(self, ctx: DiscoveryContext) -> list[Camera]:
        replies = await ctx.probe(self.method, build_probe())
        cameras: list[Camera] = []
        seen: set[str] = set()
        for reply in replies:
            camera = _parse_reply(reply)
            if camera is None:
                continue
            key = (camera.ip_address, str(reply.payload[:64]))
            if key in seen:
                continue
            seen.add(key)
            cameras.append(camera)
        return cameras


def _parse_reply(reply) -> Camera | None:
    envelope = _safe_parse(_decode(reply.payload))
    if envelope is None:
        return None
    xaddrs_text = _first(envelope, f"{{{_WS}}}XAddrs")
    if not xaddrs_text:
        return None
    first_url = xaddrs_text.split()[0]
    hostname = urlsplit(first_url).hostname
    if not hostname:
        return None
    types_text = _first(envelope, f"{{{_WS}}}Types") or ""
    raw: dict[str, Any] = {
        "source": reply.source,
        "payload_type": "ws_discovery_probe_match",
        "xaddrs": xaddrs_text,
        "types": types_text,
        "scopes": _first(envelope, f"{{{_WS}}}Scopes") or "",
    }
    return Camera(
        mac_address="",
        ip_address=hostname,
        discovery_method=DiscoveryMethod.ONVIF_WS_DISCOVERY,
        raw_discovery_payload=raw,
        vendor=None,
        vendor_confirmed=False,
    )


def _first(root: ET.Element, tag: str) -> str | None:
    node = root.find(f".//{tag}")
    if node is None or node.text is None:
        return None
    return node.text.strip()
