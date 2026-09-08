"""Adaptateur de découverte Tiandy (UDP broadcast 9999).

La réponse est modélisée en key=value (Phase 1, format réel à confirmer Phase 2).
"""

from __future__ import annotations

import logging
from typing import Any

from ..models import Camera, DiscoveryMethod
from .base import DiscoveryAdapter, DiscoveryContext

logger = logging.getLogger("ipcam_provisioner.discovery.tiandy")

PROBE_PAYLOAD = b"TIANDY:DISCOVER\n"


class TiandyDiscoveryAdapter(DiscoveryAdapter):
    method = DiscoveryMethod.TIANDY_DISCOVERY

    async def discover(self, ctx: DiscoveryContext) -> list[Camera]:
        replies = await ctx.probe(self.method, PROBE_PAYLOAD)
        cameras: list[Camera] = []
        for reply in replies:
            camera = _parse_reply(reply)
            if camera is not None:
                cameras.append(camera)
            elif reply.payload:
                logger.debug("réponse Tiandy non parseable", extra={
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
    mac = fields.get("mac")
    ip = fields.get("ip")
    if not mac or not ip:
        return None
    raw: dict[str, Any] = {
        "source": reply.source,
        "payload_type": "tiandy_probe_match",
        "payload": text,
        "fields": fields,
    }
    return Camera(
        mac_address=mac.lower(),
        ip_address=ip,
        discovery_method=DiscoveryMethod.TIANDY_DISCOVERY,
        raw_discovery_payload=raw,
        vendor="tiandy",
        vendor_confirmed=True,
    )
