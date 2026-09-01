"""Tests de la couche auth : Digest RFC 2617, Basic, UsernameToken ONVIF."""

from __future__ import annotations

import secrets

from ipcam_provisioner.auth import (
    build_authorization_digest,
    build_basic_authorization,
    build_onvif_username_token,
    build_www_authenticate_digest,
    verify_basic_authorization,
    verify_digest_authorization,
    verify_onvif_username_token,
)


def test_digest_roundtrip():
    challenge = build_www_authenticate_digest("cam-test", nonce=secrets.token_hex(16))
    authz = build_authorization_digest("admin", "secret", challenge, "GET", "/ISAPI/System/deviceInfo")
    assert verify_digest_authorization(
        authz,
        real_password="secret",
        method="GET",
        expected_uri="/ISAPI/System/deviceInfo",
    )


def test_digest_wrong_password_is_rejected():
    challenge = build_www_authenticate_digest("cam-test", nonce="fixednonce")
    authz = build_authorization_digest("admin", "secret", challenge, "GET", "/p")
    assert not verify_digest_authorization(
        authz, real_password="autre", method="GET", expected_uri="/p"
    )


def test_basic_roundtrip():
    authz = build_basic_authorization("admin", "monmotdepasse")
    assert verify_basic_authorization(
        authz, expected_username="admin", expected_password="monmotdepasse"
    )
    assert not verify_basic_authorization(
        authz, expected_username="admin", expected_password="mauvais"
    )


def test_onvif_username_token_roundtrip():
    token = build_onvif_username_token("admin", "REPLACE_ME")
    security = (
        '<Security s:mustUnderstand="1"><o:UsernameToken>'
        f"<o:Username>{token['username']}</o:Username>"
        f'<o:Password Type="http://...#PasswordDigest">{token["digest"]}</o:Password>'
        f'<o:Nonce EncodingType="http://...#Base64Binary">{token["nonce"]}</o:Nonce>'
        f"<wsu:Created>{token['created']}</wsu:Created>"
        "</o:UsernameToken></Security>"
    )
    assert verify_onvif_username_token(security, "REPLACE_ME", expected_username="admin")


def test_onvif_username_token_wrong_password_is_rejected():
    token = build_onvif_username_token("admin", "REPLACE_ME")
    security = (
        '<Security><o:UsernameToken>'
        f"<o:Username>{token['username']}</o:Username>"
        f'<o:Password Type="x">{token["digest"]}</o:Password>'
        f'<o:Nonce Type="x">{token["nonce"]}</o:Nonce>'
        f"<wsu:Created>{token['created']}</wsu:Created>"
        "</o:UsernameToken></Security>"
    )
    assert not verify_onvif_username_token(security, "WRONG", expected_username="admin")
