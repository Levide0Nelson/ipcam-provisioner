"""Adaptateur de découverte Dahua (UDP broadcast 37810).

Réponse textuelle key=value (format représentatif Phase 1, à confirmer en Phase 2).
"""

from __future__ import annotations

import logging
from typing import Any

from ..models import Camera, DiscoveryMethod
from .base import DiscoveryAdapter, DiscoveryContext

logger = logging.getLogger("ipcam_provisioner.discovery.dahua")

PROBE_PAYLOAD = b"Dahua:Discovery\n"


class DahuaDiscoveryAdapter(DiscoveryAdapter):
    method = DiscoveryMethod.DAHUA_DISCOVERY

    async def discover(self, ctx: DiscoveryContext) -> list[Camera]:
        replies = await ctx.probe(self.method, PROBE_PAYLOAD)
        cameras: list[Camera] = []
        for reply in replies:
            camera = _parse_reply(reply)
            if camera is not None:
                cameras.append(camera)
            elif reply.payload:
                logger.debug("réponse Dahua non parseable", extra={
                    "extra_fields": {"source": reply.source, "payload": reply.payload[:120]},
                })
        return cameras


def _parse_reply(reply) -> Camera | None:
    text = reply.payload.decode("utf-8", errors="replace")
    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, eq, value = line.partition("=")
        if eq:
            fields[key.strip()] = value.strip()
    mac = fields.get("DeviceMacAddress")
    ip = fields.get("NetworkInterface.IPv4Address")
    if not mac or not ip:
        return None
    raw: dict[str, Any] = {
        "source": reply.source,
        "payload_type": "dahua_probe_match",
        "payload": text,
        "fields": fields,
    }
    return Camera(
        mac_address=mac.lower(),
        ip_address=ip,
        discovery_method=DiscoveryMethod.DAHUA_DISCOVERY,
        raw_discovery_payload=raw,
        vendor="dahua",
        vendor_confirmed=True,
    )
