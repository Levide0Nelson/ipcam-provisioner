"""Résolution de conflit au niveau 2 : adressage MAC-ciblé + IP temporaire (section 5).

L'insight central du projet : quand deux caméras partagent une IP, on ne peut plus les
distinguer par IP. La résolution passe par l'adresse MAC (comme SADP) : chaque caméra
d'un groupe de conflit reçoit une **IP temporaire unique et individuellement joignable**
via un canal d'adressage MAC-ciblé (broadcast simulé en Phase 1, raw L2 en Phase 4).

Cette IP temporaire ne vise PAS l'adresse finale utilisateur : elle lève uniquement
l'ambiguïté. L'attribution définitive est déléguée au module Attribution, qui dispose
alors de caméras adressables en unicast.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Protocol

from ..models import Camera, Conflict, ResolutionStatus

logger = logging.getLogger("ipcam_provisioner.conflicts")


class Layer2Announcer(Protocol):
    """Canal L2 : émet une annonce L2 et reconfigurable une IP ciblée par MAC."""

    def announce(self, ip: str, mac: str, method: str = "gratuitous_arp") -> None: ...

    def arp_lookup(self, ip: str) -> str | None: ...

    def set_ip_by_mac(self, mac: str, new_ip: str) -> bool: ...


def resolve_conflict(
    conflict: Conflict,
    cameras_by_mac: dict[str, Camera],
    announcer: Layer2Announcer,
    *,
    subnet_mask: str,
    reserved_ips: set[str],
) -> Conflict:
    """Résout un conflit en donnant une IP temporaire unique à chaque caméra présente.

    Les IP temporaires sont choisies dans le sous-réseau de l'IP en conflit en évitant
    toutes les adresses déjà occupées (`reserved_ips`, muté pour éviter les collisions
    entre groupes de conflit). L'ordre d'allocation est déterministe (tri par MAC).
    """
    conflict.resolution_status = ResolutionStatus.RESOLVING
    present: list[str] = sorted(mac for mac in conflict.camera_macs if mac in cameras_by_mac)
    if not present:
        conflict.resolution_status = ResolutionStatus.FAILED
        conflict.resolution_detail = "aucune caméra résolvable par MAC"
        return conflict

    assignments = _temp_ip_assignments(
        conflict.conflicting_ip, present, subnet_mask, reserved_ips
    )
    if assignments is None:
        conflict.resolution_status = ResolutionStatus.FAILED
        conflict.resolution_detail = "pool d'IP temporaires insuffisant"
        return conflict

    conflict.resolution_method = "mac_addressed_broadcast"
    conflict.winner_mac = present[0]
    failures: list[str] = []
    for mac, temp_ip in assignments.items():
        if not announcer.set_ip_by_mac(mac, temp_ip):
            failures.append(mac)
            continue
        camera = cameras_by_mac[mac]
        camera.ip_address = temp_ip
        camera.temp_ip = temp_ip
        reserved_ips.add(temp_ip)

    if failures:
        conflict.resolution_status = ResolutionStatus.FAILED
        conflict.resolution_detail = f"caméras injoignables par MAC : {', '.join(failures)}"
        for mac in failures:
            if mac in cameras_by_mac:
                cameras_by_mac[mac].mark_error("résolution : caméra injoignable par MAC")
        return conflict

    conflict.resolution_status = ResolutionStatus.RESOLVED
    conflict.resolution_detail = (
        f"{len(present)} IP en conflit dédoublonnées sur des IP temporaires "
        f"(canal MAC-adressé), dans {ipaddress.IPv4Network(f'{conflict.conflicting_ip}/{subnet_mask}', strict=False)}"
    )
    logger.warning(
        "conflit résolu pour %s : IP temporaires %s",
        conflict.conflicting_ip,
        {mac: assignments[mac] for mac in present},
    )
    return conflict


def _temp_ip_assignments(
    conflicting_ip: str,
    macs: list[str],
    subnet_mask: str,
    reserved_ips: set[str],
) -> dict[str, str] | None:
    """Alloue une IP temporaire distincte par MAC, dans le sous-réseau de l'IP en conflit."""
    try:
        network = ipaddress.IPv4Network(f"{conflicting_ip}/{subnet_mask}", strict=False)
        pool = [
            str(address)
            for address in network.hosts()
            if str(address) not in reserved_ips and str(address) != conflicting_ip
        ]
    except ValueError:
        return None
    if len(pool) < len(macs):
        return None
    return {mac: pool[index] for index, mac in enumerate(macs)}


__all__ = ["Layer2Announcer", "resolve_conflict"]
