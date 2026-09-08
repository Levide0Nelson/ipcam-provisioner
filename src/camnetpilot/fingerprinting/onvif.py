"""Fingerprinter ONVIF générique : GetDeviceInformation puis GetNetworkInterfaces.

Le MAC n'étant pas porté par WS-Discovery, un second appel récupère l'adresse MAC si
elle est encore vide. Si l'authentification échoue, l'état reste UNKNOWN : l'ONVIF
n'est pas couvert par le flux d'activation usine (Phase 1).
"""

from __future__ import annotations

import logging

from ..models import ActivationStatus, Camera, DiscoveryMethod
from ..onvif_soap import build_device_request
from .base import FingerprintContext, Fingerprinter, local_find, parse_xml

logger = logging.getLogger("ipcam_provisioner.fingerprinting.onvif")

DEVICE_SERVICE_PATH = "/onvif/device_service"


class OnvifFingerprinter(Fingerprinter):
    vendor = "onvif"

    async def identify(self, camera: Camera, ctx: FingerprintContext) -> Camera:
        password = ctx.config.default_password_for("onvif")
        username = camera.raw_discovery_payload.get("username") or "admin"
        response = await ctx.talker.request(
            "POST",
            camera.ip_address,
            DEVICE_SERVICE_PATH,
            content=build_device_request("GetDeviceInformation", username=username, password=password),
            headers={"Content-Type": "application/soap+xml; charset=utf-8"},
        )
        if response.status_code == 200:
            camera.activation_status = ActivationStatus.ACTIVE
            camera.vendor_confirmed = True
            _apply_info(camera, response.content)
            if not camera.mac_address:
                await _apply_mac(camera, ctx, username, password)
            return camera
        if response.status_code == 401:
            logger.warning(
                "authentification ONVIF refusée pour %s (%s)",
                camera.ip_address,
                camera.mac_address or "MAC inconnu",
            )
            camera.activation_status = ActivationStatus.UNKNOWN
            return camera
        raise RuntimeError(
            f"fingerprint ONVIF HTTP {response.status_code} sur {camera.ip_address}"
        )


async def _apply_mac(camera: Camera, ctx: FingerprintContext, username: str, password: str) -> None:
    try:
        response = await ctx.talker.request(
            "POST",
            camera.ip_address,
            DEVICE_SERVICE_PATH,
            content=build_device_request(
                "GetNetworkInterfaces", username=username, password=password
            ),
            headers={"Content-Type": "application/soap+xml; charset=utf-8"},
        )
    except Exception:  # noqa: BLE001 - un appel secondaire ne doit pas faire échouer l'étape
        return
    if response.status_code == 200 and (root := parse_xml(response.content)) is not None:
        mac = local_find(root, "MacAddress")
        if mac is None and root is not None:
            # GetNetworkInterfaces renvoie parfois le MAC via l'attribut d'un nœud
            for element in root.iter():
                if element.tag.endswith("MacAddress") and element.text:
                    mac = element.text
                    break
        if mac:
            camera.mac_address = mac.lower()


def _apply_info(camera: Camera, content: bytes) -> None:
    root = parse_xml(content)
    if root is None:
        return
    manufacturer = local_find(root, "Manufacturer")
    model = local_find(root, "Model")
    serial = local_find(root, "SerialNumber")
    firmware = local_find(root, "FirmwareVersion")
    if manufacturer:
        alias = _vendor_alias(manufacturer)
        camera.vendor = alias or "generic"
        if (
            camera.discovery_method is DiscoveryMethod.ONVIF_WS_DISCOVERY
            and camera.vendor != "generic"
        ):
            camera.vendor_confirmed = True
    if model:
        camera.model = model
    if serial:
        camera.serial_number = serial
    if firmware:
        camera.firmware_version = firmware


def _vendor_alias(manufacturer: str) -> str | None:
    lowered = manufacturer.lower()
    for vendor in ("hikvision", "dahua", "tiandy", "generic"):
        if vendor in lowered:
            return vendor
    return None


__all__ = ["OnvifFingerprinter"]
