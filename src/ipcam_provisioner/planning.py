"""Planification des adresses cibles dans la plage du site (attribution ordonnée)."""

from __future__ import annotations

from .config import SiteConfig
from .models import Camera, Conflict


class PlanningError(RuntimeError):
    """Impossible de planifier les adresses cibles (plage saturée, etc.)."""


def plan_target_ips(
    cameras: list[Camera],
    config: SiteConfig,
    conflicts: list[Conflict],
) -> None:
    """Assigne `target_ip` à chaque caméra, de façon déterministe (tri par MAC).

    - Les caméras déjà dans la plage et hors conflit gardent leur adresse (aucun appel
      réseau nécessaire).
    - Toute autre caméra (adresse usine hors plage, IP temporaire de résolution) reçoit
      la prochaine adresse libre de la plage, dans l'ordre.
    """
    reserved = {str(config.gateway)}

    for camera in cameras:
        in_range = config.ip_range.contains(camera.ip_address)
        keeps = (camera.has_conflict is False) and in_range
        if keeps:
            camera.target_ip = camera.ip_address
            reserved.add(camera.ip_address)

    available = (
        str(address)
        for address in config.ip_range.iter_addresses()
        if str(address) not in reserved
    )

    ordered = sorted(cameras, key=lambda c: (c.mac_address or c.ip_address))
    for camera in ordered:
        if camera.target_ip is not None:
            continue
        try:
            camera.target_ip = next(available)
        except StopIteration:
            raise PlanningError(
                f"plage d'adresses saturée pour le site {config.site_name!r} "
                f"({config.ip_range.size()} adresses)"
            ) from None
