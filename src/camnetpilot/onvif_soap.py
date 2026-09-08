"""Construction de requêtes SOAP ONVIF (device_service) avec UsernameToken WS-Security."""

from __future__ import annotations

from .auth import build_onvif_username_token

_SOAP_ENV = "http://www.w3.org/2003/05/soap-envelope"
_SECEXT = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
_UT_PROFILE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
_BASE64 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
_WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
_TDS = "http://www.onvif.org/ver10/device/wsdl"


def build_device_request(
    operation: str,
    body_fragment: str | None = None,
    *,
    username: str = "admin",
    password: str = "",
) -> bytes:
    """SOAP POST /onvif/device_service pour `operation`, avec UsernameToken si password."""
    token = build_onvif_username_token(username, password) if password else None
    security = ""
    if token is not None:
        security = (
            '<Security s:mustUnderstand="1">'
            "<o:UsernameToken>"
            f"<o:Username>{token['username']}</o:Username>"
            f'<o:Password Type="{_UT_PROFILE}">{token["digest"]}</o:Password>'
            f'<o:Nonce EncodingType="{_BASE64}">{token["nonce"]}</o:Nonce>'
            f"<wsu:Created>{token['created']}</wsu:Created>"
            "</o:UsernameToken>"
            "</Security>"
        )
    body = body_fragment if body_fragment is not None else f"<tds:{operation}/>"
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<s:Envelope xmlns:s="{_SOAP_ENV}" xmlns:o="{_SECEXT}" '
        f'xmlns:wsu="{_WSU}" xmlns:tds="{_TDS}">'
        f"<s:Header>{security}</s:Header>"
        f"<s:Body>{body}</s:Body>"
        "</s:Envelope>"
    )
    return xml.encode("utf-8")


def build_set_network_request(
    ip: str,
    mask: str,
    gateway: str,
    *,
    username: str = "admin",
    password: str = "",
) -> bytes:
    body = (
        "<tds:SetNetworkInterfaces>"
        "<tds:InterfaceToken>NetworkInterface</tds:InterfaceToken>"
        "<tds:NetworkInterface><s:IPv4><s:Enabled>true</s:Enabled><s:Manual>"
        f"<s:Address>{ip}</s:Address><s:PrefixLength>24</s:PrefixLength>"
        "</s:Manual></s:IPv4></tds:NetworkInterface>"
        "</tds:SetNetworkInterfaces>"
    )
    return build_device_request("SetNetworkInterfaces", body, username=username, password=password)


def build_info_request(operation: str, *, username: str, password: str) -> bytes:
    return build_device_request(operation, username=username, password=password)


def build_create_users_request(
    new_username: str,
    new_password: str,
    *,
    user_level: str = "Administrator",
) -> bytes:
    """SOAP CreateUsers (activation par création du premier compte).

    Tenté sans authentification préalable : les appareils ONVIF en config usine
    l'exposent parfois sans credentials. Signé seulement si le token est fourni.
    """
    body = (
        "<tds:CreateUsers>"
        "<tds:User>"
        f"<tds:Username>{new_username}</tds:Username>"
        f"<tds:Password>{new_password}</tds:Password>"
        f"<tds:UserLevel>{user_level}</tds:UserLevel>"
        "</tds:User>"
        "</tds:CreateUsers>"
    )
    return build_device_request("CreateUsers", body)
