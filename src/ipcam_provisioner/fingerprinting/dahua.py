"""Fingerprinter Dahua : GET /cgi-bin/magicBox.cgi?action=getSystemInfo (auth Basic)."""

from __future__ import annotations

from ..auth import build_basic_authorization
from ..models import ActivationStatus, Camera
from .base import FingerprintContext, Fingerprinter

USERNAME = "admin"
INFO_PATH = "/cgi-bin/magicBox.cgi"


class DahuaFingerprinter(Fingerprinter):
    vendor = "dahua"

    async def identify(self, camera: Camera, ctx: FingerprintContext) -> Camera:
        params = {"action": "getSystemInfo"}
        password = ctx.config.default_password_for("dahua")
        response = await ctx.talker.request("GET", camera.ip_address, INFO_PATH, params=params)
        if response.status_code == 401:
            authz = build_basic_authorization(USERNAME, password)
            response = await ctx.talker.request(
                "GET",
                camera.ip_address,
                INFO_PATH,
                params=params,
                headers={"Authorization": authz},
            )
        if response.status_code == 200:
            camera.activation_status = ActivationStatus.ACTIVE
            camera.vendor = "dahua"
            camera.vendor_confirmed = True
            _apply_info(camera, response.content)
            return camera
        if response.status_code == 401:
            camera.activation_status = ActivationStatus.INACTIVE
            return camera
        raise RuntimeError(
            f"fingerprint Dahua HTTP {response.status_code} sur {camera.ip_address}"
        )


def _apply_info(camera: Camera, content: bytes) -> None:
    fields: dict[str, str] = {}
    for line in content.decode("utf-8", errors="replace").splitlines():
        key, sep, value = line.partition("=")
        if sep:
            fields[key.strip()] = value.rstrip(",").strip()
    if fields.get("model"):
        camera.model = fields["model"]
    if fields.get("serialNumber"):
        camera.serial_number = fields["serialNumber"]
    if fields.get("firmwareVersion"):
        camera.firmware_version = fields["firmwareVersion"]
