"""Calcul/parsing du challenge Digest (RFC 2617) et de l'auth Basic.

Servent d'une part aux simulateurs de caméras (vérification des credentials) et
d'autre part au client ONVIF (UsernameToken digeste du SOAP). Le calcul du digest est
fidèle au RFC — utile pour un futur passage sur matériel réel.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from collections.abc import Mapping
from datetime import UTC


def md5_hex(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def parse_auth_header(header: str) -> dict[str, str]:
    """Parse une valeur d'en-tête WWW-Authenticate ou Authorization de type auth string.

    Gère `Digest realm="a", nonce="b", qop="auth"` ainsi que les clés sans guillemets.
    """
    fields: dict[str, str] = {}
    scheme, _, rest = header.partition(" ")
    fields["scheme"] = scheme
    for part in _split_commas(rest):
        key, eq, value = part.partition("=")
        key = key.strip()
        value = value.strip()
        if value.startswith('"') and value.endswith('"') and len(value) >= 2:
            value = value[1:-1]
        if eq:
            fields[key] = value
    return fields


def _split_commas(text: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    in_quote = False
    for char in text:
        if char == '"':
            in_quote = not in_quote
        if char == "," and not in_quote:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    if current:
        parts.append("".join(current))
    return parts


def compute_digest_response(
    username: str,
    password: str,
    realm: str,
    nonce: str,
    method: str,
    uri: str,
    qop: str | None = None,
    nc: str = "00000001",
    cnonce: str = "",
) -> str:
    """digest-response du RFC 2617 (algorithme MD5, qop=auth ou sans qop)."""
    ha1 = md5_hex(f"{username}:{realm}:{password}")
    ha2 = md5_hex(f"{method}:{uri}")
    if qop:
        return md5_hex(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
    return md5_hex(f"{ha1}:{nonce}:{ha2}")


def build_www_authenticate_digest(realm: str, nonce: str | None = None) -> str:
    return (
        f'Digest realm="{realm}", nonce="{nonce or secrets.token_hex(16)}", '
        'qop="auth", algorithm=MD5, stale=false'
    )


def build_authorization_digest(
    username: str,
    real_password: str,
    www_authenticate: str,
    method: str,
    uri: str,
) -> str:
    """Construit une Authorization Digest valide pour le challenge fourni."""
    fields = parse_auth_header(www_authenticate)
    realm = fields.get("realm", "")
    nonce = fields.get("nonce", "")
    qop_value = fields.get("qop") or ""
    cnonce = secrets.token_hex(8)
    nc = "00000001"
    response = compute_digest_response(
        username,
        real_password,
        realm,
        nonce,
        method,
        uri,
        qop=qop_value or None,
        nc=nc,
        cnonce=cnonce,
    )
    fields = [
        f'username="{username}"',
        f'realm="{realm}"',
        f'nonce="{nonce}"',
        f'uri="{uri}"',
        f'response="{response}"',
    ]
    if qop_value:
        fields.extend([f"qop={qop_value}", f"nc={nc}", f'cnonce="{cnonce}"'])
    return "Digest " + ", ".join(fields)


def verify_digest_authorization(
    authz: str,
    *,
    real_password: str,
    method: str,
    expected_uri: str,
) -> bool:
    """Vérifie une Authorization Digest reçue par le simulateur."""
    fields = parse_auth_header(authz)
    replay = fields.get("response", "")
    if not replay:
        return False
    qop = fields.get("qop")
    nc = fields.get("nc", "00000001")
    cnonce = fields.get("cnonce", "")
    expected = compute_digest_response(
        fields.get("username", ""),
        real_password,
        fields.get("realm", ""),
        fields.get("nonce", ""),
        method,
        fields.get("uri", expected_uri),
        qop=qop,
        nc=nc,
        cnonce=cnonce,
    )
    return secrets.compare_digest(replay, expected)


def build_basic_authorization(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    return f"Basic {token}"


def verify_basic_authorization(
    authz: str, *, expected_username: str, expected_password: str
) -> bool:
    try:
        scheme, _, token = authz.partition(" ")
        if scheme.lower() != "basic":
            return False
        decoded = base64.b64decode(token).decode("utf-8")
        username, sep, password = decoded.partition(":")
        if not sep:
            return False
        return username == expected_username and secrets.compare_digest(
            password, expected_password
        )
    except (ValueError, UnicodeDecodeError):
        return False


def auth_header_value(headers: Mapping[str, str], key: str) -> str | None:
    for name, value in headers.items():
        if name.lower() == key.lower():
            return value
    return None


# ---------------------------------------------------------------------------
# ONVIF WS-Security (UsernameToken) — PasswordDigest = Base64(SHA1(Nonce+Created+Pwd))
# ---------------------------------------------------------------------------

ONVIF_PWD_ALG = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"


def build_onvif_username_token(username: str, password: str) -> dict[str, str]:
    """Construit les champs du UsernameToken SOAP pour la phase client."""
    nonce_raw = secrets.token_bytes(16)
    from datetime import datetime

    created = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    digest = hashlib.sha1(nonce_raw + created.encode("ascii") + password.encode("utf-8"))
    return {
        "username": username,
        "nonce": base64.b64encode(nonce_raw).decode("ascii"),
        "created": created,
        "digest": base64.b64encode(digest.digest()).decode("ascii"),
        "algorithm": ONVIF_PWD_ALG,
    }


def verify_onvif_username_token(
    security_xml: str,
    real_password: str,
    expected_username: str = "admin",
) -> bool:
    """Vérifie un UsernameToken ONVIF depuis le fragment <Security> reçu.

    La norme encode le digest dans <Password Type="...#PasswordDigest">, on extrait
    donc le contenu du tag <Password> (le `Type` distingue Digest/Plain/None).
    """
    nonce = _extract_tag(security_xml, "Nonce")
    created = _extract_tag(security_xml, "Created")
    digest_sent = _extract_tag(security_xml, "Password")
    passed_user = _extract_tag(security_xml, "Username")
    if not all([nonce, created, digest_sent, passed_user]) or digest_sent is None:
        return False
    try:
        nonce_raw = base64.b64decode(nonce)
    except Exception:  # noqa: BLE001
        return False
    expected = base64.b64encode(
        hashlib.sha1(
            nonce_raw + created.encode("ascii") + real_password.encode("utf-8")
        ).digest()
    ).decode("ascii")
    return passed_user == expected_username and secrets.compare_digest(digest_sent, expected)


def _extract_tag(xml_fragment: str, tag: str) -> str | None:
    import re

    match = re.search(
        rf"<(?:\w+:)?{tag}[^>]*>([^<]+)</(?:\w+:)?{tag}>", xml_fragment
    )
    return match.group(1).strip() if match and match.group(1) else None
