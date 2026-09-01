"""Activation des caméras inactives avec le mot de passe par défaut (section 5).

Stratégie par branche :
- Hikvision / Dahua / Tiandy : API du fabricant (ISAPI / CGI / JSON) avec le mot de
  passe par défaut configuré par l'utilisateur.
- ONVIF générique : tentative `CreateUsers` sur un appareil en config usine (comportement
  non garanti selon les fabricants) — sinon la caméra est marquée `manual_required`.
- Vendor inconnu : `manual_required`, aucune tentative automatique.

Un échec d'activation marque `activation_result=FAILED` + `last_error` mais ne fait
jamais planter le pipeline ; une caméra `manual_required` est simplement listée à la fin
pour être traitée manuellement par l'utilisateur.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable

from ..models import (
    ActivationResult,
    ActivationStatus,
    Camera,
)
from ..net import HttpTalker
from ..onvif_soap import build_create_users_request
from ..retry import call_with_retry

logger = logging.getLogger("ipcam_provisioner.activation")

Activator = Callable[[Camera, HttpTalker, str], Awaitable[Camera]]

HIK_ACTIVATE_PATH = "/ISAPI/System/activate"
DAHUA_ACTIVATE_PATH = "/cgi-bin/account.cgi"
TIANDY_ACTIVATE_PATH = "/device/activate"
ONVIF_DEVICE_PATH = "/onvif/device_service"
USERNAME = "admin"


class ActivationEngine:
    def __init__(self, talker: HttpTalker, config) -> None:
        self._talker = talker
        self._config = config

    async def activate(self, camera: Camera) -> Camera:
        if camera.activation_status is ActivationStatus.ACTIVE:
            return camera
        vendor = camera.vendor or "unknown"
        if vendor not in ACTIVATORS:
            camera.activation_result = ActivationResult.MANUAL_REQUIRED
            logger.info(
                "activation manuelle requise pour MAC %s (vendor=%s)",
                camera.mac_address,
                vendor,
            )
            return camera
        password = self._config.default_password_for(vendor)
        if not password:
            camera.activation_result = ActivationResult.MANUAL_REQUIRED
            logger.warning(
                "mot de passe par défaut manquant pour vendor=%s (MAC %s)",
                vendor,
                camera.mac_address,
            )
            return camera
        activator = ACTIVATORS[vendor]

        async def attempt() -> Camera:
            return await activator(camera, self._talker, password)

        try:
            return await call_with_retry(
                attempt, context=f"activation {camera.mac_address or camera.ip_address}", logger_=logger
            )
        except Exception as exc:  # noqa: BLE001 - isolation par caméra
            camera.activation_result = ActivationResult.FAILED
            camera.mark_error(f"activation : {exc}")
            logger.error("échec activation MAC %s : %s", camera.mac_address, exc)
            return camera


def _confirm_activated(camera: Camera) -> Camera:
    camera.activation_status = ActivationStatus.ACTIVE
    camera.activation_result = ActivationResult.SUCCESS
    return camera


def _confirm_unreachable(camera: Camera, response) -> Camera:
    """Réponse non-200 après la tentative : mot de passe refusé ou device injoignable."""
    camera.activation_result = ActivationResult.FAILED
    camera.mark_error(f"activation refusée (HTTP {response.status_code})")
    return camera


async def _activate_hikvision(camera: Camera, talker: HttpTalker, password: str) -> Camera:
    body = (
        "<ActivateInfo>"
        f"<password>{password}</password>"
        "</ActivateInfo>"
    ).encode()
    response = await talker.request(
        "POST",
        camera.ip_address,
        HIK_ACTIVATE_PATH,
        content=body,
        headers={"Content-Type": "application/xml"},
    )
    if response.status_code == 200:
        camera.vendor = "hikvision"
        camera.vendor_confirmed = True
        return _confirm_activated(camera)
    return _confirm_unreachable(camera, response)


async def _activate_dahua(camera: Camera, talker: HttpTalker, password: str) -> Camera:
    body = f"password={_urlencode(password)}".encode()
    response = await talker.request(
        "POST",
        camera.ip_address,
        DAHUA_ACTIVATE_PATH,
        params={"action": "activate"},
        content=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if response.status_code == 200:
        camera.vendor = "dahua"
        camera.vendor_confirmed = True
        return _confirm_activated(camera)
    return _confirm_unreachable(camera, response)


async def _activate_tiandy(camera: Camera, talker: HttpTalker, password: str) -> Camera:
    body = json.dumps({"password": password}).encode("utf-8")
    response = await talker.request(
        "POST",
        camera.ip_address,
        TIANDY_ACTIVATE_PATH,
        content=body,
        headers={"Content-Type": "application/json"},
    )
    if response.status_code == 200:
        camera.vendor = "tiandy"
        camera.vendor_confirmed = True
        return _confirm_activated(camera)
    return _confirm_unreachable(camera, response)


async def _activate_onvif(camera: Camera, talker: HttpTalker, password: str) -> Camera:
    body = build_create_users_request(USERNAME, password)
    response = await talker.request(
        "POST",
        camera.ip_address,
        ONVIF_DEVICE_PATH,
        content=body,
        headers={"Content-Type": "application/soap+xml; charset=utf-8"},
    )
    if response.status_code == 200:
        return _confirm_activated(camera)
    camera.activation_result = ActivationResult.MANUAL_REQUIRED
    logger.warning(
        "CreateUsers non accepté (HTTP %s) pour %s — activation manuelle requise",
        response.status_code,
        camera.mac_address or camera.ip_address,
    )
    return camera


ACTIVATORS: dict[str, Activator] = {
    "hikvision": _activate_hikvision,
    "dahua": _activate_dahua,
    "tiandy": _activate_tiandy,
    "onvif": _activate_onvif,
    "generic": _activate_onvif,
}


def _urlencode(value: str) -> str:
    from urllib.parse import quote

    return quote(value, safe="")


__all__ = ["ActivationEngine"]
