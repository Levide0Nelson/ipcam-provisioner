"""Fingerprinter Tiandy : GET /device/info.json (auth Basic).

L'API Tiandy exacte est à confirmer en Phase 2 ; le contrat ici est documenté et
reflété par le simulateur de caméra Tiandy.
"""

from __future__ import annotations

import json

from ..auth import build_basic_authorization
from ..models import ActivationStatus, Camera
from .base import FingerprintContext, Fingerprinter

USERNAME = "admin"
INFO_PATH = "/device/info.json"


class TiandyFingerprinter(Fingerprinter):
    vendor = "tiandy"

    async def identify(self, camera: Camera, ctx: FingerprintContext) -> Camera:
        password = ctx.config.default_password_for("tiandy")
        response = await ctx.talker.request("GET", camera.ip_address, INFO_PATH)
        if response.status_code == 401:
            authz = build_basic_authorization(USERNAME, password)
            response = await ctx.talker.request(
                "GET", camera.ip_address, INFO_PATH, headers={"Authorization": authz}
            )
        if response.status_code == 200:
            camera.activation_status = ActivationStatus.ACTIVE
            camera.vendor = "tiandy"
            camera.vendor_confirmed = True
            _apply_info(camera, response.content)
            return camera
        if response.status_code == 401:
            camera.activation_status = ActivationStatus.INACTIVE
            return camera
        raise RuntimeError(
            f"fingerprint Tiandy HTTP {response.status_code} sur {camera.ip_address}"
        )


def _apply_info(camera: Camera, content: bytes) -> None:
    try:
        info = json.loads(content.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return
    if info.get("model"):
        camera.model = info["model"]
    if info.get("serial"):
        camera.serial_number = info["serial"]
    if info.get("firmware"):
        camera.firmware_version = info["firmware"]
