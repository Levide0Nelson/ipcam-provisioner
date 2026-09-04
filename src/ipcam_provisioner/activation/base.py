"""Activation des caméras inactives avec le mot de passe par défaut (section 5).

Stratégie par branche :
- Hikvision / Dahua / Tiandy : API du fabricant (ISAPI / CGI / JSON) avec le mot de
  passe par défaut configuré par l'utilisateur, ou essais des mots de passe usine connus.
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

from ..config import DEFAULT_FACTORY_PASSWORDS, MAX_DEFAULT_PASSWORD_ATTEMPTS
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
    def __init__(
        self,
        talker: HttpTalker,
        config,
        password_for: Callable[[str], str] | None = None,
    ) -> None:
        self._talker = talker
        self._config = config
        self._password_for = password_for or config.default_password_for

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
        
        # Get user-provided password (or empty string)
        user_password = self._password_for(vendor)
        
        # Build list of passwords to try: user password first, then factory defaults
        passwords_to_try = []
        if user_password:
            passwords_to_try.append(user_password)
        
        # Add factory defaults for this vendor
        factory_passwords = DEFAULT_FACTORY_PASSWORDS.get(vendor.lower(), [])
        for pwd in factory_passwords:
            if pwd not in passwords_to_try:
                passwords_to_try.append(pwd)
        
        # Limit attempts
        passwords_to_try = passwords_to_try[:MAX_DEFAULT_PASSWORD_ATTEMPTS]
        
        if not passwords_to_try:
            camera.activation_result = ActivationResult.MANUAL_REQUIRED
            logger.warning(
                "aucun mot de passe à essayer pour vendor=%s (MAC %s)",
                vendor,
                camera.mac_address,
            )
            return camera
        
        activator = ACTIVATORS[vendor]

        async def attempt_with_password(pwd: str) -> Camera:
            return await activator(camera, self._talker, pwd)

        # Try each password until one works
        last_error = None
        for pwd in passwords_to_try:
            try:
                result = await call_with_retry(
                    lambda: attempt_with_password(pwd),
                    context=f"activation {camera.mac_address or camera.ip_address} (pwd attempt)",
                    logger_=logger
                )
                if result.activation_result == ActivationResult.SUCCESS:
                    logger.info("Activation réussie pour %s avec mot de passe", camera.mac_address)
                    return result
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                logger.debug("Échec activation %s avec mot de passe: %s", camera.mac_address, exc)
                continue
        
        # All passwords failed
        camera.activation_result = ActivationResult.FAILED
        camera.mark_error(f"activation : tous les mots de passe ont échoué (dernier: {last_error})")
        logger.error("échec activation MAC %s : tous les mots de passe ont échoué", camera.mac_address)
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
