"""Adaptateur de découverte Hikvision via SADP (UDP broadcast 37020).

Format représentatif simplifié (Phase 1) : on sonde avec une requête texte, la réponse
est un ProbeMatch XML dont on extrait MAC/série/IP. Le format binaire exact du
protocole SADP sera confirmé en Phase 2 sur matériel.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import Any

from ..models import Camera, DiscoveryMethod
from .base import DiscoveryAdapter, DiscoveryContext

logger = logging.getLogger("ipcam_provisioner.discovery.sadp")

PROBE_PAYLOAD = b"SADP:DeviceDiscovery\n"


class SadpAdapter(DiscoveryAdapter):
    method = DiscoveryMethod.SADP

    async def discover(self, ctx: DiscoveryContext) -> list[Camera]:
        replies = await ctx.probe(self.method, PROBE_PAYLOAD)
        cameras: list[Camera] = []
        for reply in replies:
            camera = _parse_reply(reply)
            if camera is not None:
                cameras.append(camera)
            elif reply.payload:
                logger.debug("réponse SADP non parseable", extra={
                    "extra_fields": {"source": reply.source, "payload": reply.payload[:120]},
                })
        return cameras


def _parse_reply(reply) -> Camera | None:
    text = _decode(reply.payload)
    root = _safe_parse(text)
    if root is None:
        return None
    mac = _elem(root, "MACAddress")
    ip = _elem(root, "IPv4Address")
    if not mac or not ip:
        return None
    raw: dict[str, Any] = {
        "source": reply.source,
        "payload_type": "sadp_probe_match",
        "payload": text,
    }
    return Camera(
        mac_address=mac.lower(),
        ip_address=ip,
        discovery_method=DiscoveryMethod.SADP,
        raw_discovery_payload=raw,
        vendor="hikvision",
        vendor_confirmed=True,
    )


def _decode(payload: bytes) -> str:
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return payload.decode(encoding)
        except UnicodeDecodeError:
            continue
    return payload.decode("latin-1", errors="replace")


def _safe_parse(text: str) -> ET.Element | None:
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        return None


def _elem(root: ET.Element, tag: str) -> str | None:
    node = root.find(f".//{tag}")
    if node is None or node.text is None:
        return None
    return node.text.strip()
