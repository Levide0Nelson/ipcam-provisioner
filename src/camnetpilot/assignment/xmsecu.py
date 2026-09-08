"""Attribueur XM / xmsecu : configuration réseau via DVRIP (NetWork.NetCommon).

La configuration réseau d'une caméra NetSurveillance se fait par un `ConfigSet` des
champs `HostIP`/`Submask`/`GateWay` (encodés en hexadécimal renversé). On force aussi
`NetWork.NetDHCP[0].Enable=False` pour garantir une adresse statique.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

from .. import dvrip
from .errors import AssignmentError

logger = logging.getLogger("ipcam_provisioner.assignment.xmsecu")

USERNAME = "admin"


async def assign_xmsecu(camera, talker, config, password_for) -> None:
    """Assigner pour le vendeur xmsecu (DVRIP). `talker` est inutilisé : canal TCP."""
    password = password_for("xmsecu")
    port = int(camera.raw_discovery_payload.get("dvrip_port") or dvrip.DEFAULT_PORT)
    await asyncio.to_thread(
        _assign_blocking,
        camera,
        password,
        config.subnet_mask,
        config.gateway,
        port,
    )


def _assign_blocking(camera, password: str, subnet_mask, gateway, port: int) -> None:
    client = dvrip.DvripClient(camera.ip_address, port=port)
    try:
        try:
            client.connect()
        except dvrip.DvripError as exc:
            raise AssignmentError(f"DVRIP injoignable pour {camera.ip_address} : {exc}") from exc
        try:
            client.login(USERNAME, password)
        except dvrip.DvripError as exc:
            raise AssignmentError(
                f"xmsecu refuse les identifiants (mot de passe par défaut invalide ?) : {exc}"
            ) from exc
        try:
            reply = client.get_config("NetWork.NetCommon")
        except dvrip.DvripError as exc:
            raise AssignmentError(f"impossible de lire la config réseau : {exc}") from exc
        net = dict(reply.get("NetWork.NetCommon") or {})
        net["HostIP"] = dvrip.ip_to_hex(camera.target_ip)
        net["Submask"] = dvrip.ip_to_hex(str(subnet_mask))
        net["GateWay"] = dvrip.ip_to_hex(str(gateway))
        try:
            client.set_config("NetWork.NetCommon", net)
        except dvrip.DvripError as exc:
            raise AssignmentError(f"échec du ConfigSet réseau : {exc}") from exc
        _disable_dhcp(client)
    finally:
        client.close()


def _disable_dhcp(client: dvrip.DvripClient) -> None:
    try:
        reply = client.get_config("NetWork.NetDHCP")
    except dvrip.DvripError:
        # Tous les firmwares n'exposent pas NetDHCP : on considère que le NetCommon
        # statique suffit.
        return
    table = reply.get("NetWork.NetDHCP")
    if isinstance(table, list):
        for entry in table:
            if isinstance(entry, dict):
                entry["Enable"] = False
        with contextlib.suppress(dvrip.DvripError):
            client.set_config("NetWork.NetDHCP", table)


__all__ = ["assign_xmsecu"]
