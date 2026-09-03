"""Tests du protocole DVRIP et des adaptateurs xmsecu (fingerprinter + assigneur).

Le canal DVRIP est un TCP binaire : les tests ne passent pas par le réseau simulé HTTP
mais par un petit serveur DVRIP factice sur 127.0.0.1 (thread + socket).
"""

from __future__ import annotations

import contextlib
import json
import socket
import struct
import threading

import pytest

from ipcam_provisioner import dvrip
from ipcam_provisioner.assignment.base import AssignmentError
from ipcam_provisioner.assignment.xmsecu import assign_xmsecu
from ipcam_provisioner.config import build_config
from ipcam_provisioner.fingerprinting.base import FingerprintContext
from ipcam_provisioner.fingerprinting.xmsecu import XmsecuFingerprinter
from ipcam_provisioner.models import ActivationStatus, Camera, DiscoveryMethod

# ---------------------------------------------------------------------------
# Serveur DVRIP factice
# ---------------------------------------------------------------------------

_HEADER = struct.Struct("BB2xII2xHI")
PASSWORD = "plok"


def _pack(code: int, session: int, seq: int, data: dict) -> bytes:
    payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
    return _HEADER.pack(255, 0, session, seq, code, len(payload) + 2) + payload + b"\x0a\x00"


class _FakeDvripServer:
    """Répond login + ConfigGet/ConfigSet NetCommon et NetDHCP."""

    def __init__(
        self, *, password: str = PASSWORD, net_common: dict | None = None, binary_lock: bool = False
    ) -> None:
        self._password = password
        self._binary_lock = binary_lock
        self._net_common = dict(net_common or {})
        self._net_common.setdefault("MAC", "00:12:17:c3:4c:7a")
        self._net_common.setdefault("HostIP", dvrip.ip_to_hex("192.168.9.183"))
        self._net_common.setdefault("Submask", dvrip.ip_to_hex("255.255.255.0"))
        self._net_common.setdefault("GateWay", dvrip.ip_to_hex("192.168.9.254"))
        self._auth_fail = False
        self._session = 0
        self._written: dict | None = None
        self._server = None
        self.port = 0

    def start(self) -> None:
        sock = _server_for_test()
        self._server = sock
        self.port = sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        with contextlib.suppress(OSError):
            self._server.shutdown(socket.SHUT_RDWR)
        self._server.close()

    @property
    def last_net_common(self) -> dict | None:
        return dict(self._written) if self._written is not None else None

    def _serve(self) -> None:
        try:
            conn, _ = self._server.accept()
        except OSError:
            return
        with conn:
            while True:
                header = self._recv_exact(conn, 20)
                if header is None:
                    return
                _h, _v, session, seq, code, length = _HEADER.unpack(header)
                body = self._recv_exact(conn, length)
                if body is None:
                    return
                data = json.loads(body[:-2].decode("utf-8", errors="replace"))
                if code == dvrip.MSG_LOGIN:
                    self._session = session
                    if self._binary_lock:
                        body = struct.pack("<IIIIII", 0, 0, 205, 0, session, 72)
                        header = struct.pack("BB2xII2xHI", 255, 1, session, seq, 1001, len(body))
                        conn.sendall(header + body)
                        continue
                    if self._auth_fail:
                        self._auth_fail = False
                        reply = {"EncryptType": "MD5", "LoginType": "DVRIP-Web", "Ret": 106}
                        conn.sendall(_pack(1000, session, seq, reply))
                        continue
                    if data.get("PassWord") != dvrip.sofia_hash(self._password):
                        reply = {"Ret": 203}
                    else:
                        self._session = session + 1
                        reply = {
                            "Ret": 100,
                            "SessionID": f"0x{self._session:08X}",
                            "AliveInterval": 20,
                            "ChannelNum": 1,
                            "DeviceType ": "IPC",
                        }
                    conn.sendall(_pack(1000, session, seq, reply))
                elif code == dvrip.MSG_CONFIG_GET:
                    name = data.get("Name")
                    if name == "NetWork.NetCommon":
                        reply = {"Name": name, "SessionID": data["SessionID"],
                                 "NetWork.NetCommon": self._net_common}
                    elif name == "NetWork.NetDHCP":
                        reply = {"Name": name, "SessionID": data["SessionID"],
                                 "NetWork.NetDHCP": [{"Enable": True, "Interface": "eth0"}]}
                    else:
                        reply = {"Name": name, "SessionID": data["SessionID"]}
                    conn.sendall(_pack(1042, self._session, seq, reply))
                elif code == dvrip.MSG_CONFIG_SET:
                    value = data.get("NetWork.NetCommon")
                    if value is not None:
                        self._written = value
                    reply = {"Name": data["Name"], "SessionID": data["SessionID"], "Ret": 100}
                    conn.sendall(_pack(1040, self._session, seq, reply))
                else:
                    reply = {"Ret": 100}
                    conn.sendall(_pack(code, self._session, seq, reply))

    @staticmethod
    def _recv_exact(conn, length: int) -> bytes | None:
        buf = bytearray()
        while len(buf) < length:
            chunk = conn.recv(length - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)


def _server_for_test():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    return sock


def _config(**overrides) -> object:
    raw = {
        "site_name": "test",
        "ip_range": {"start": "192.168.1.2", "end": "192.168.1.254"},
        "subnet_mask": "255.255.255.0",
        "gateway": "192.168.1.1",
        "vendors": {},  # xmsecu mot de passe par défaut vide
    }
    raw.update(overrides)
    return build_config(raw)


def _camera(ip: str = "192.168.9.183", target: str = "192.168.1.50", *, dvrip_port: int | None = None):
    payload = {}
    if dvrip_port is not None:
        payload["dvrip_port"] = dvrip_port
    return Camera(
        ip_address=ip,
        target_ip=target,
        mac_address="00:12:17:c3:4c:7a",
        vendor="xmsecu",
        discovery_method=DiscoveryMethod.ARP_OUI_FALLBACK,
        raw_discovery_payload=payload,
    )


# ---------------------------------------------------------------------------
# Protocole
# ---------------------------------------------------------------------------


def test_sofia_hash():
    # Valeur de contrôle stable : caractères bien base62, longueur 8.
    h = dvrip.sofia_hash("plok")
    assert len(h) == 8
    assert set(h) <= set(
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    )


def test_ip_roundtrip():
    for ip in ("192.168.9.183", "255.255.255.0", "192.168.1.1", "0.0.0.0", "10.0.0.7"):
        assert dvrip.hex_to_ip(dvrip.ip_to_hex(ip)) == ip


def test_ip_known_encoding():
    assert dvrip.ip_to_hex("192.168.9.183") == "0xB709A8C0"
    assert dvrip.ip_to_hex("255.255.255.0") == "0x00FFFFFF"
    assert dvrip.ip_to_hex("192.168.9.254") == "0xFE09A8C0"


def test_login_ok_and_config_get():
    server = _FakeDvripServer()
    server.start()
    try:
        client = dvrip.DvripClient("127.0.0.1", port=server.port)
        client.connect()
        try:
            client.login("admin", PASSWORD)
            reply = client.get_config("NetWork.NetCommon")
            net = reply["NetWork.NetCommon"]
            assert net["MAC"] == "00:12:17:c3:4c:7a"
            assert dvrip.hex_to_ip(net["HostIP"]) == "192.168.9.183"
        finally:
            client.close()
    finally:
        server.stop()


def test_login_bad_password():
    server = _FakeDvripServer()
    server.start()
    try:
        client = dvrip.DvripClient("127.0.0.1", port=server.port)
        client.connect()
        try:
            with pytest.raises(dvrip.DvripError) as exc:
                client.login("admin", "nope")
            assert dvrip.is_auth_error(exc.value)
        finally:
            client.close()
    finally:
        server.stop()


def test_login_binary_ip_lock():
    """Un firmware plus ancien répond par un corps binaire (version 1) : le code en
    position 8 (205) doit être traduit en une erreur d'authentification « IP verrouillée »."""
    server = _FakeDvripServer(binary_lock=True)
    server.start()
    try:
        client = dvrip.DvripClient("127.0.0.1", port=server.port)
        client.connect()
        try:
            with pytest.raises(dvrip.DvripError) as exc:
                client.login("admin", "")
            assert "205" in str(exc.value)
            assert dvrip.is_auth_error(exc.value)
        finally:
            client.close()
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# Fingerprinter
# ---------------------------------------------------------------------------


async def test_fingerprint_xmsecu_factory(semaphore):
    server = _FakeDvripServer(password="")
    server.start()
    try:
        camera = _camera("127.0.0.1", dvrip_port=server.port)
        fingerprinter = XmsecuFingerprinter()
        fingerprint_context = FingerprintContext(
            talker=None, config=_config(), semaphore=semaphore
        )
        out = await fingerprinter.identify(camera, fingerprint_context)
        assert out.activation_status is ActivationStatus.ACTIVE
        assert out.vendor == "xmsecu"
        assert out.vendor_confirmed
        assert out.mac_address == "00:12:17:c3:4c:7a"
    finally:
        server.stop()


async def test_fingerprint_xmsecu_requires_default_login(semaphore):
    # Le fingerprinter utilise le mot de passe par défaut (vide) ; la caméra étant
    # protégée, le login échoue mais la caméra est bien détectée ACTIVE.
    server = _FakeDvripServer(password="secret")
    server.start()
    try:
        camera = _camera("127.0.0.1", dvrip_port=server.port)
        fingerprinter = XmsecuFingerprinter()
        fingerprint_context = FingerprintContext(
            talker=None, config=_config(), semaphore=semaphore
        )
        out = await fingerprinter.identify(camera, fingerprint_context)
        assert out.activation_status is ActivationStatus.ACTIVE
        assert out.vendor == "xmsecu"
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# Assigneur
# ---------------------------------------------------------------------------


async def test_assign_xmsecu_writes_net_common(semaphore):
    server = _FakeDvripServer(password="")
    server.start()
    try:
        config = _config()
        camera = _camera("127.0.0.1", dvrip_port=server.port)

        def password_for(_vendor):
            return ""

        await assign_xmsecu(camera, talker=None, config=config, password_for=password_for)

        net = server.last_net_common
        assert net is not None
        assert net["HostIP"] == dvrip.ip_to_hex("192.168.1.50")
        assert net["Submask"] == dvrip.ip_to_hex("255.255.255.0")
        assert net["GateWay"] == dvrip.ip_to_hex("192.168.1.1")
    finally:
        server.stop()


async def test_assign_xmsecu_bad_password_raises(semaphore):
    server = _FakeDvripServer(password="secret")
    server.start()
    try:
        config = _config()
        camera = _camera("127.0.0.1", dvrip_port=server.port)

        def password_for(_vendor):
            return ""

        with pytest.raises(AssignmentError):
            await assign_xmsecu(camera, talker=None, config=config, password_for=password_for)
    finally:
        server.stop()
