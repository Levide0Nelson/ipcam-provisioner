"""Attribution ordonnée des adresses IP dans la plage configurée (section 5)."""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable

from ..auth import build_authorization_digest, build_basic_authorization
from ..models import ActivationResult, ActivationStatus, AssignmentStatus, Camera
from ..net import HttpTalker
from ..onvif_soap import build_set_network_request
from ..retry import call_with_retry
from .errors import AssignmentError
from .xmsecu import assign_xmsecu

logger = logging.getLogger("ipcam_provisioner.assignment")

USERNAME = "admin"
HIK_NET_PATH = "/ISAPI/System/Network/interfaces/1"
DAHUA_NET_PATH = "/cgi-bin/configManager.cgi"
TIANDY_NET_PATH = "/device/network"
ONVIF_NET_PATH = "/onvif/device_service"

Assigner = Callable[[Camera, HttpTalker, object, Callable[[str], str]], Awaitable[None]]


class AssignmentEngine:
    def __init__(
        self,
        talker: HttpTalker,
        config,
        password_for: Callable[[str], str] | None = None,
    ) -> None:
        self._talker = talker
        self._config = config
        self._password_for = password_for or config.default_password_for

    async def assign(self, camera: Camera) -> Camera:
        if camera.last_error is not None:
            return camera
        if camera.activation_result is ActivationResult.MANUAL_REQUIRED:
            # Caméra laissée à l'utilisateur : listée en fin de pipeline, pas un échec.
            return camera
        if camera.target_ip is None:
            camera.mark_error("attribution : pas d'adresse cible planifiée")
            return camera
        if camera.assignment_status is AssignmentStatus.SUCCESS:
            return camera
        if camera.activation_status is not ActivationStatus.ACTIVE:
            camera.mark_error("attribution : caméra non active (activation requise)")
            return camera
        if camera.ip_address == camera.target_ip:
            # Déjà à la bonne adresse (ex. vainqueur de conflit ou IP déjà dans la plage).
            camera.assignment_status = AssignmentStatus.SUCCESS
            return camera
        if camera.vendor not in ASSIGNERS:
            camera.mark_error(f"attribution : assigner inconnu pour vendor={camera.vendor}")
            return camera

        camera.assignment_status = AssignmentStatus.IN_PROGRESS
        assigner = ASSIGNERS[camera.vendor]

        async def attempt() -> None:
            await assigner(camera, self._talker, self._config, self._password_for)

        try:
            await call_with_retry(
                attempt,
                context=f"assign {camera.mac_address or camera.ip_address}",
                logger_=logger,
            )
        except Exception as exc:  # noqa: BLE001 - isolation par caméra
            camera.mark_error(f"attribution : {exc}")
            logger.error("échec attribution MAC %s : %s", camera.mac_address, exc)
            return camera

        camera.ip_address = camera.target_ip
        camera.assignment_status = AssignmentStatus.SUCCESS
        return camera


# ---------------------------------------------------------------------------
# Attribueurs par vendor
# ---------------------------------------------------------------------------


async def _assign_hikvision(camera: Camera, talker: HttpTalker, config, password_for: Callable[[str], str]) -> None:
    password = password_for("hikvision")
    body = (
        '<NetworkInterface xmlns="http://www.hikvision.com/ver10/XMLSchema">'
        "<id>1</id>"
        f"<IPv4Address>{camera.target_ip}</IPv4Address>"
        f"<IPv4SubnetMask>{config.subnet_mask}</IPv4SubnetMask>"
        f"<IPv4Gateway>{config.gateway}</IPv4Gateway>"
        "</NetworkInterface>"
    ).encode()
    headers = {"Content-Type": "application/xml"}
    response = await talker.request("PUT", camera.ip_address, HIK_NET_PATH, content=body, headers=headers)
    if response.status_code == 401:
        challenge = response.headers.get("www-authenticate") or ""
        if "Digest" in challenge:
            authz = build_authorization_digest(USERNAME, password, challenge, "PUT", HIK_NET_PATH)
            response = await talker.request(
                "PUT", camera.ip_address, HIK_NET_PATH, content=body, headers={**headers, "Authorization": authz}
            )
    if response.status_code != 200:
        raise AssignmentError(f"Hikvision refuse la configuration réseau (HTTP {response.status_code})")


async def _assign_dahua(camera: Camera, talker: HttpTalker, config, password_for: Callable[[str], str]) -> None:
    password = password_for("dahua")
    params = {
        "action": "setConfig",
        "Network.eth0.address": camera.target_ip or "",
        "Network.eth0.Netmask": str(config.subnet_mask),
        "Network.eth0.Gateway": str(config.gateway),
    }
    response = await talker.request("POST", camera.ip_address, DAHUA_NET_PATH, params=params)
    if response.status_code == 401:
        authz = build_basic_authorization(USERNAME, password)
        response = await talker.request(
            "POST", camera.ip_address, DAHUA_NET_PATH, params=params, headers={"Authorization": authz}
        )
    if response.status_code != 200:
        raise AssignmentError(f"Dahua refuse la configuration réseau (HTTP {response.status_code})")


async def _assign_tiandy(camera: Camera, talker: HttpTalker, config, password_for: Callable[[str], str]) -> None:
    password = password_for("tiandy")
    body = json.dumps(
        {"ip": camera.target_ip, "mask": str(config.subnet_mask), "gateway": str(config.gateway)}
    ).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    response = await talker.request("PUT", camera.ip_address, TIANDY_NET_PATH, content=body, headers=headers)
    if response.status_code == 401:
        authz = build_basic_authorization(USERNAME, password)
        response = await talker.request(
            "PUT", camera.ip_address, TIANDY_NET_PATH, content=body, headers={**headers, "Authorization": authz}
        )
    if response.status_code != 200:
        raise AssignmentError(f"Tiandy refuse la configuration réseau (HTTP {response.status_code})")


async def _assign_onvif(camera: Camera, talker: HttpTalker, config, password_for: Callable[[str], str]) -> None:
    password = password_for("onvif")
    username = camera.raw_discovery_payload.get("username") or "admin"
    body = build_set_network_request(
        camera.target_ip or "",
        str(config.subnet_mask),
        str(config.gateway),
        username=username,
        password=password,
    )
    response = await talker.request(
        "POST",
        camera.ip_address,
        ONVIF_NET_PATH,
        content=body,
        headers={"Content-Type": "application/soap+xml; charset=utf-8"},
    )
    if response.status_code != 200:
        raise AssignmentError(f"ONVIF refuse la configuration réseau (HTTP {response.status_code})")


ASSIGNERS: dict[str, Assigner] = {
    "hikvision": _assign_hikvision,
    "dahua": _assign_dahua,
    "tiandy": _assign_tiandy,
    "onvif": _assign_onvif,
    "generic": _assign_onvif,
    "xmsecu": assign_xmsecu,
}
