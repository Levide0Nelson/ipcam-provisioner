"""Détection des conflits d'adresses IP entre caméras découvertes (section 5)."""

from __future__ import annotations

from collections import defaultdict

from ..models import Camera, Conflict


def detect_conflicts(cameras: list[Camera]) -> list[Conflict]:
    """Regroupe les caméras partageant la même adresse IP en conflits."""
    by_ip: dict[str, list[Camera]] = defaultdict(list)
    for camera in cameras:
        if camera.ip_address:
            by_ip[camera.ip_address].append(camera)

    conflicts: list[Conflict] = []
    for ip_address, group in by_ip.items():
        if len(group) < 2:
            continue
        for camera in group:
            camera.has_conflict = True
        conflicts.append(
            Conflict(
                conflicting_ip=ip_address,
                camera_macs=[c.mac_address or c.ip_address for c in group],
            )
        )
    return conflicts
