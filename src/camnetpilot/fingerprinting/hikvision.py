"""Fingerprinter Hikvision : GET /ISAPI/System/deviceInfo (handshake Digest)."""

from __future__ import annotations

from ..auth import build_authorization_digest
from ..models import ActivationStatus, Camera
from .base import FingerprintContext, Fingerprinter, local_find, parse_xml

USERNAME = "admin"
DEVICE_INFO_PATH = "/ISAPI/System/deviceInfo"


class HikvisionFingerprinter(Fingerprinter):
    vendor = "hikvision"

    async def identify(self, camera: Camera, ctx: FingerprintContext) -> Camera:
        response = await _device_info(ctx, camera.ip_address, "")
        if response.status_code == 401:
            challenge = response.headers.get("www-authenticate") or ""
            if "Digest" in challenge:
                authz = build_authorization_digest(
                    USERNAME,
                    _password(ctx, camera),
                    challenge,
                    "GET",
                    DEVICE_INFO_PATH,
                )
                response = await _device_info(
                    ctx, camera.ip_address, authz
                )
        if response.status_code == 200:
            camera.activation_status = ActivationStatus.ACTIVE
            camera.vendor = "hikvision"
            camera.vendor_confirmed = True
            _apply_info(camera, response.content)
            return camera
        if response.status_code == 401:
            # Caméra inactive (config usine) ou mot de passe inconnu : l'activation
            # tentée ensuite tentera de trancher.
            camera.activation_status = ActivationStatus.INACTIVE
            return camera
        if response.status_code == 403:
            # Hikvision en config usine : ISAPI désactivé jusqu'à activation.
            # Le body XML contient souvent <subStatusCode>notActivated</subStatusCode>.
            camera.activation_status = ActivationStatus.INACTIVE
            return camera
        raise RuntimeError(
            f"fingerprint Hikvision HTTP {response.status_code} sur {camera.ip_address}"
        )


def _password(ctx: FingerprintContext, camera: Camera) -> str:
    return ctx.config.default_password_for("hikvision")


async def _device_info(ctx: FingerprintContext, ip: str, authorization: str) -> object:
    headers = {"Authorization": authorization} if authorization else None
    return await ctx.talker.request("GET", ip, DEVICE_INFO_PATH, headers=headers)


def _apply_info(camera: Camera, content: bytes) -> None:
    root = parse_xml(content)
    if root is None:
        return
    model = local_find(root, "model")
    serial = local_find(root, "serialNumber")
    mac = local_find(root, "macAddress")
    firmware = local_find(root, "firmwareVersion")
    if model:
        camera.model = model
    if serial:
        camera.serial_number = serial
    if mac:
        camera.mac_address = mac
    if firmware:
        camera.firmware_version = firmware
