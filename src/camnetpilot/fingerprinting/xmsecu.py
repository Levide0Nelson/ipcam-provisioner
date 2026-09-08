"""Fingerprinter XM / xmsecu (NetSurveillance, protocole DVRIP/Sofia sur TCP 34567).

Les caméras génériques serveur `uc-httpd` (Xiongmai / NetSurveillance) n'exposent ni
ISAPI ni ONVIF ni CGI utilisable et sont mal identifiées par la palpe HTTP. Leur canal
fiable est le protocole binaire DVRIP sur TCP 34567 : une connexion réussie (ou un refus
d'authentification) confirme à la fois le vendeur et l'état de la caméra.

Contrairement aux fabricants classiques, ces caméras n'ont pas d'« activation usine » :
elles acceptent toujours un login (souvent admin/mot de passe vide en sortie d'usine).
Aussi le fingerprinter les marque directement ACTIVE ; la récupération des identifiants
se joue à l'étape d'attribution si le mot de passe par défaut est refusé.
"""

from __future__ import annotations

import asyncio
import logging

from .. import dvrip
from ..models import ActivationStatus, Camera
from .base import FingerprintContext, Fingerprinter

logger = logging.getLogger("ipcam_provisioner.fingerprinting.xmsecu")

USERNAME = "admin"


class XmsecuFingerprinter(Fingerprinter):
    vendor = "xmsecu"

    async def identify(self, camera: Camera, ctx: FingerprintContext) -> Camera:
        password = ctx.config.default_password_for("xmsecu")
        port = int(camera.raw_discovery_payload.get("dvrip_port") or dvrip.DEFAULT_PORT)

        async def attempt() -> Camera:
            return await asyncio.to_thread(
                self._identify_blocking, camera, ctx, password, port
            )

        # DVRIP est en TCP : pas de gestion de retry HTTP; on laisse passer les résultats.
        return await attempt()

    def _identify_blocking(
        self, camera: Camera, ctx: FingerprintContext, password: str, port: int
    ) -> Camera:
        client = dvrip.DvripClient(
            camera.ip_address, port=port, timeout=ctx.config.discovery.timeout_seconds
        )
        try:
            client.connect()
        except dvrip.DvripError as exc:
            logger.warning("DVRIP injoignable pour %s : %s", camera.ip_address, exc)
            camera.activation_status = ActivationStatus.UNKNOWN
            return camera
        try:
            try:
                client.login(USERNAME, password)
            except dvrip.DvripError as exc:
                camera.vendor = "xmsecu"
                camera.vendor_confirmed = True
                if dvrip.is_auth_error(exc):
                    # Caméra activée mais mot de passe par défaut non valable :
                    # on la garde ACTIVE — l'attribution demandera les identifiants.
                    logger.warning(
                        "xmsecu %s signale identifiants refusés (mot de passe défaut invalide)",
                        camera.ip_address,
                    )
                camera.activation_status = ActivationStatus.ACTIVE
                return camera
            self._apply_info(camera, client)
            return camera
        finally:
            client.close()

    def _apply_info(self, camera: Camera, client: dvrip.DvripClient) -> None:
        camera.vendor = "xmsecu"
        camera.vendor_confirmed = True
        camera.activation_status = ActivationStatus.ACTIVE
        try:
            reply = client.get_config("NetWork.NetCommon")
        except dvrip.DvripError as exc:
            logger.info("NetCommon non lisible pour %s : %s", camera.ip_address, exc)
            return
        net = reply.get("NetWork.NetCommon") or {}
        mac = str(net.get("MAC", ""))
        if mac and ":" in mac:
            camera.mac_address = mac.lower()
        host = str(net.get("HostName", ""))
        if host and not camera.model:
            camera.firmware_version = camera.firmware_version or host


__all__ = ["XmsecuFingerprinter"]
