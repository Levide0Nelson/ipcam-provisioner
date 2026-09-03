"""Découverte ARP + devinette vendor par OUI (fallback générique).

Le rôle principal : compléter le MAC des caméras découvertes par WS-Discovery (qui ne
transportent pas d'adresse MAC) et attraper les caméras silencieuses aux protocoles pro.

- Mode simulé : on lit la table ARP du réseau simulé (Phase 1).
- Mode réel (Phase 2) : on lit la table ARP du système — `/proc/net/arp` sous Linux,
  `arp -a` en secours — et on ne garde que les entrées dont l'OUI correspond à un
  vendor caméra connu, pour limiter les faux positifs.
"""

from __future__ import annotations

import asyncio
import logging
import re
import subprocess
from pathlib import Path

from ..models import Camera, DiscoveryMethod
from .base import DiscoveryAdapter, DiscoveryContext

logger = logging.getLogger("ipcam_provisioner.discovery.arp")

#: Table OUI caméras (Phase 1 → enrichie en Phase 2 avec les OUIs observés sur
#: matériel réel, ex. `c0:51:7e` : Hikvision DS-2CD1043G0E-I du site réel).
OUI_TABLE: dict[str, str] = {
    # Hikvision
    "ac:cc:8e": "hikvision",
    "44:19:b6": "hikvision",
    "c0:51:7e": "hikvision",
    "10:12:fb": "hikvision",
    "c0:56:e3": "hikvision",
    "bc:ad:28": "hikvision",
    "c4:2f:90": "hikvision",
    "18:68:cb": "hikvision",
    "28:57:be": "hikvision",
    "4c:bd:8f": "hikvision",
    "54:c4:15": "hikvision",
    "64:db:8b": "hikvision",
    "94:e1:ac": "hikvision",
    "a4:14:37": "hikvision",
    "b4:a3:82": "hikvision",
    # Dahua / Zhejiang Dahua
    "e0:50:8b": "dahua",
    "3c:ef:8c": "dahua",
    "4c:11:bf": "dahua",
    "90:02:a9": "dahua",
    "bc:32:5f": "dahua",
    "14:a7:8b": "dahua",
    # Tiandy / Tianjin Tiandy
    "00:cc:2f": "tiandy",
    "3c:da:6d": "tiandy",
    # Generic / divers
    "aa:bb:cc": "generic",
    "08:3a:f2": "generic",
    # Parc réel (site 192.168.x) : clones génériques serveur `uc-httpd` (xmsecu / DVRIP 34567)
    "00:12:31": "xmsecu",
    "00:12:17": "xmsecu",
    "f4:5b:73": "xmsecu",
}

_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")


def oui_vendor(mac_address: str) -> str | None:
    """Devine un vendor depuis les 3 premiers octets du MAC."""
    oui = mac_address.lower().strip().replace("-", ":").split(":")[:3]
    prefix = ":".join(oui)
    return OUI_TABLE.get(prefix)


def read_system_arp_entries() -> list[tuple[str, str]]:
    """Table ARP du système : liste de couples (ip, mac). Linux `/proc/net/arp` d'abord."""
    try:
        text = Path("/proc/net/arp").read_text(encoding="utf-8", errors="replace")
        entries = _parse_proc_arp(text)
        if entries:
            return entries
    except OSError:
        pass
    return _parse_arp_a(_run_arp_a())


def _parse_proc_arp(text: str) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        ip, mac = parts[0], parts[3]
        if mac == "00:00:00:00:00:00":
            continue
        entries.append((ip, mac.lower()))
    return entries


def _parse_arp_a(text: str) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for line in text.splitlines():
        ip_match = _IPV4_RE.search(line)
        mac_match = _MAC_RE.search(line)
        if ip_match and mac_match:
            entries.append((ip_match.group(0), mac_match.group(0).replace("-", ":").lower()))
    return entries


def _run_arp_a() -> str:
    try:
        proc = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, check=False, timeout=10
        )
        return proc.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


class ArpOuiFallbackAdapter(DiscoveryAdapter):
    method = DiscoveryMethod.ARP_OUI_FALLBACK

    async def discover(self, ctx: DiscoveryContext) -> list[Camera]:
        if ctx.sim_network is not None:
            return self._from_entries(list(ctx.sim_network.arp_entries()), "l2_arp")
        entries = await asyncio.to_thread(read_system_arp_entries)
        kept = [(ip, mac) for ip, mac in entries if oui_vendor(mac) is not None]
        cameras = self._from_entries(kept, "system_arp_table")
        if not cameras:
            logger.warning("table ARP système vide ou sans OUI caméra connu")
        return cameras

    def _from_entries(
        self, entries: list[tuple[str, str]], source: str
    ) -> list[Camera]:
        cameras: list[Camera] = []
        for ip_address, mac_address in entries:
            cameras.append(
                Camera(
                    mac_address=mac_address.lower(),
                    ip_address=ip_address,
                    discovery_method=DiscoveryMethod.ARP_OUI_FALLBACK,
                    raw_discovery_payload={"source": source, "via": "l2_arp"},
                    vendor=oui_vendor(mac_address),
                    vendor_confirmed=False,
                )
            )
        return cameras
