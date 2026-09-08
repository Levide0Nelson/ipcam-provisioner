"""Fingerprinting : identification vendor/modèle/firmware (section 5).

engine.identify(camera) exécute UN appel HTTP/ONVIF par appareil (plus un appel
GetNetworkInterfaces si le MAC est encore inconnu — cas ONVIF), sous retry pour les
erreurs réseau transitoires. Un échec d'authentification (401) est un *résultat*
(inactive / mot de passe inconnu), pas une exception.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod

from ..config import SiteConfig
from ..models import ActivationStatus, Camera, DiscoveryMethod
from ..net import HttpTalker
from ..retry import call_with_retry

logger = logging.getLogger("ipcam_provisioner.fingerprinting")


class FingerprintContext:
    def __init__(self, talker: HttpTalker, config: SiteConfig, semaphore) -> None:
        self.talker = talker
        self.config = config
        self.semaphore = semaphore


class Fingerprinter(ABC):
    vendor: str
    login: str = "admin"

    @abstractmethod
    async def identify(self, camera: Camera, ctx: FingerprintContext) -> Camera: ...


class FingerprintEngine:
    """Sélectionne puis exécute le fingerprinter adapté à la caméra."""

    def __init__(self, ctx: FingerprintContext, registry: dict[str, Fingerprinter]) -> None:
        self._ctx = ctx
        self._registry = registry

    async def identify(self, camera: Camera) -> Camera:
        fingerprinter = self._select(camera)
        if fingerprinter is None:
            logger.info(
                "pas de fingerprinter pour vendor=%s method=%s",
                camera.vendor,
                camera.discovery_method.value,
            )
            return camera

        async def attempt() -> Camera:
            return await fingerprinter.identify(camera, self._ctx)

        return await call_with_retry(
            attempt,
            context=f"fingerprint {camera.mac_address or camera.ip_address}",
            logger_=logger,
        )

    def _select(self, camera: Camera) -> Fingerprinter | None:
        if camera.vendor in self._registry:
            return self._registry[camera.vendor]
        if camera.discovery_method is DiscoveryMethod.ONVIF_WS_DISCOVERY:
            return self._registry.get("onvif")
        return None


def unauthorized_or_inactive(camera: Camera, response) -> Camera:
    """Un 401 après tentative d'identification : caméra inactive (vendor propriétaire,
    découverte certaine) ou mot de passe inconnu → la tentative d'activation tranchera."""
    camera.activation_status = ActivationStatus.INACTIVE
    return camera


# ---------------------------------------------------------------------------
# Helpers XML (tags sans préfixe de namespace)
# ---------------------------------------------------------------------------


def local_find(root: ET.Element, name: str) -> str | None:
    if root is None:
        return None
    for elem in root.iter():
        tag = elem.tag.split("}")[-1]
        if tag == name and elem.text is not None and elem.text.strip():
            return elem.text.strip()
    return None


def parse_xml(content: bytes) -> ET.Element | None:
    try:
        return ET.fromstring(content.decode("utf-8", errors="replace"))
    except ET.ParseError:
        return None
