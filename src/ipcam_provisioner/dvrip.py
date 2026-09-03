"""Protocole DVRIP / « Sofia » (NetSurveillance / Xiongmai / xmsecu).

Implémentation indépendante (clean-room, stdlib uniquement) du protocole binaire
TCP utilisé par les caméras génériques serveur `uc-httpd` sur le port 34567. Il
permet de lire et de modifier la configuration réseau (NetWork.NetCommon) — c'est
le canal utilisé par l'outil XMeye / l'interface web pour changer l'IP de ce type
de caméra, là où l'activation/attribution ISAPI/ONVIF/Dahua/Tiandy est inconnue.

Format du paquet (entête 20 octets, `struct.pack("BB2xII2xHI", ...)`) :
    FF | version(0) | pad2 | session(I LE) | séquence(I LE) | pad2 | code(H LE)
    | taille(I LE) | données JSON + b"\\x0a\\x00"

Codes de message : 1000=login, 1006=KeepAlive, 1040=ConfigSet, 1042=ConfigGet.

Tout le code est bloquant (sockets) : il est appelé via `asyncio.to_thread` depuis
les adaptateurs asyncio du pipeline.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
import struct

DEFAULT_PORT = 34567
MSG_LOGIN = 1000
MSG_KEEPALIVE = 1006
MSG_CONFIG_SET = 1040
MSG_CONFIG_GET = 1042

_OK_CODES = (100, 515)

#: Charset base62 du hash Sofia (ordre = table du firmware).
_BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

#: Erreurs d'authentification (code Ret) → identifiants inconnus/refusés.
_AUTH_ERRORS = {104, 106, 203, 205, 206, 207}

#: Libellés courts des codes d'authentification (affichage).
_AUTH_TIPS = {
    104: "(verrouillé)",
    106: "(identifiants incorrects)",
    203: "(mot de passe incorrect)",
    205: "(IP verrouillée / utilisateur inexistant)",
    206: "(mot de passe incorrect)",
    207: "(identifiants incorrects)",
}


class DvripError(RuntimeError):
    """Erreur protocole DVRIP (connexion, réponse ou authentification)."""


def sofia_hash(password: str) -> str:
    """Hash Sofia du mot de passe : MD5 -> 8 caractères base62 (paires d'octets)."""
    digest = hashlib.md5(password.encode("utf-8")).digest()
    return "".join(
        _BASE62[sum(pair) % 62] for pair in zip(digest[::2], digest[1::2], strict=True)
    )


def ip_to_hex(ip: str) -> str:
    """Encode une IPv4 en hexadécimal « renversé » utilisé par NetWork.NetCommon."""
    raw = ipaddress.IPv4Address(ip).packed
    return f"0x{int.from_bytes(raw[::-1], 'big'):08X}"

def hex_to_ip(value: str | int) -> str:
    """Décode la valeur hexadécimale renversée d'une IPv4 (NetCommon)."""
    integer = int(str(value), 0) if isinstance(value, str) else int(value)
    raw = integer.to_bytes(4, "big")[::-1]
    return str(ipaddress.IPv4Address(raw))


class DvripClient:
    """Client minimal du protocole DVRIP pour lire/écrire la config réseau."""

    def __init__(self, host: str, port: int = DEFAULT_PORT, timeout: float = 6.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self._socket: socket.socket | None = None
        self._sequence = 0
        self.session = 0

    # --- cycle de vie -------------------------------------------------------

    def connect(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((self.host, self.port))
        except OSError as exc:
            sock.close()
            raise DvripError(f"connexion DVRIP impossible ({self.host}:{self.port}) : {exc}") from exc
        self._socket = sock

    def close(self) -> None:
        if self._socket is not None:
            try:
                self._socket.close()
            finally:
                self._socket = None

    # --- envoi / réception --------------------------------------------------

    def _send_message(self, code: int, data: dict) -> dict:
        if self._socket is None:
            raise DvripError("client DVRIP non connecté")
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        header = struct.pack(
            "BB2xII2xHI",
            255,
            0,
            self.session,
            self._sequence,
            code,
            len(payload) + 2,
        )
        self._socket.sendall(header + payload + b"\x0a\x00")
        self._sequence += 1

        header_resp = self._recv_exact(20)
        if header_resp is None or len(header_resp) < 20:
            raise DvripError("réponse DVRIP tronquée (entête)")
        (
            _head,
            _version,
            self.session,
            _sequence,
            _code,
            body_len,
        ) = struct.unpack("BB2xII2xHI", header_resp)
        body = self._recv_exact(body_len)
        if body is None:
            raise DvripError("réponse DVRIP tronquée (corps)")
        if not body.endswith(b"\x0a\x00") or b"{" not in body:
            # Réponse binaire (pas de JSON), fréquente sur les firmwares anciens/verrouillés.
            # Pour un login refusé, le 3e mot de 4 octets porte le code d'erreur (ex. 205).
            self._raise_binary(_code, body)
        text = body[:-2].decode("utf-8", errors="replace")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            raise DvripError("réponse DVRIP non-JSON") from None

    def _raise_binary(self, code: int, body: bytes) -> None:
        if len(body) >= 12:
            ret = struct.unpack("<I", body[8:12])[0]
            if ret in _AUTH_ERRORS:
                tip = _AUTH_TIPS.get(ret, "")
                raise DvripError(
                    f"authentification DVRIP refusée (code {ret}) sur {self.host} {tip}".strip()
                )
        raise DvripError(f"réponse DVRIP binaire inattendue (code msg {code})") from None

    def _recv_exact(self, length: int) -> bytes | None:
        if self._socket is None:
            return None
        buf = bytearray()
        while len(buf) < length:
            chunk = self._socket.recv(length - len(buf))
            if not chunk:
                return None if not buf else None
            buf.extend(chunk)
        return bytes(buf)

    # --- commandes ----------------------------------------------------------

    def login(self, username: str, password: str) -> dict:
        """Connexion DVRIP. Retourne la réponse ; lève DvripError si refusée."""
        auth = sofia_hash(password)
        reply = self._send_message(
            MSG_LOGIN,
            {
                "EncryptType": "MD5",
                "LoginType": "DVRIP-Web",
                "PassWord": auth,
                "UserName": username,
            },
        )
        ret = reply.get("Ret")
        if ret not in _OK_CODES:
            self._raise_auth(ret, reply)
        session = reply.get("SessionID")
        if session:
            self.session = int(str(session), 0)
        return reply

    def get_config(self, name: str) -> dict:
        return self._send_message(
            MSG_CONFIG_GET, {"Name": name, "SessionID": f"0x{self.session:08X}"}
        )

    def set_config(self, name: str, value) -> dict:
        return self._send_message(
            MSG_CONFIG_SET,
            {"Name": name, "SessionID": f"0x{self.session:08X}", name: value},
        )

    def keepalive(self) -> dict:
        return self._send_message(
            MSG_KEEPALIVE, {"Name": "KeepAlive", "SessionID": f"0x{self.session:08X}"}
        )

    def _raise_auth(self, ret, reply: dict) -> None:
        detail = reply.get("Tip") or ""
        raise DvripError(
            f"authentification DVRIP refusée (code {ret}) sur {self.host} {detail}".strip()
        )


def is_auth_error(exc: DvripError) -> bool:
    """Vrai si l'exception provient d'un refus d'identifiants (pas d'un réseau coupé)."""
    msg = str(exc)
    return "authentification" in msg


__all__ = [
    "DEFAULT_PORT",
    "DvripClient",
    "DvripError",
    "hex_to_ip",
    "ip_to_hex",
    "is_auth_error",
    "sofia_hash",
]
