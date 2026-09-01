"""Orchestration des méthodes de découverte + dédup par MAC (section 5)."""

from __future__ import annotations

import asyncio

from ..models import Camera, DiscoveryMethod
from .arp import ArpOuiFallbackAdapter
from .base import DiscoveryAdapter, DiscoveryContext
from .dahua import DahuaDiscoveryAdapter
from .onvif import OnvifWsDiscoveryAdapter
from .sadp import SadpAdapter
from .tiandy import TiandyDiscoveryAdapter

ADAPTERS: dict[DiscoveryMethod, DiscoveryAdapter] = {
    DiscoveryMethod.SADP: SadpAdapter(),
    DiscoveryMethod.DAHUA_DISCOVERY: DahuaDiscoveryAdapter(),
    DiscoveryMethod.TIANDY_DISCOVERY: TiandyDiscoveryAdapter(),
    DiscoveryMethod.ONVIF_WS_DISCOVERY: OnvifWsDiscoveryAdapter(),
    DiscoveryMethod.ARP_OUI_FALLBACK: ArpOuiFallbackAdapter(),
}


async def discover_all(config, sim_network=None) -> list[Camera]:
    """Découvre les caméras avec toutes les méthodes configurées, en parallèle.

    La dédup se fait par MAC — la première méthode (dans l'ordre de priorité de la
    config) qui rapporte un MAC donné l'emporte. Les caméras découvertes par
    WS-Discovery sans MAC sont fusionnées avec l'entrée ARP correspondante.
    """
    ctx = DiscoveryContext(config, sim_network)
    methods = config.discovery.methods
    adapters = [ADAPTERS[m] for m in methods if m in ADAPTERS]

    by_method: dict[DiscoveryMethod, list[Camera]] = {}
    results = await asyncio.gather(
        *(adapter.discover(ctx) for adapter in adapters), return_exceptions=True
    )
    for adapter, outcome in zip(adapters, results, strict=True):
        if isinstance(outcome, Exception):
            # Un échec d'une méthode ne fait pas échouer la découverte des autres.
            continue
        by_method[adapter.method] = outcome

    ordered: list[Camera] = []
    for method in methods:
        ordered.extend(by_method.get(method, []))

    return _deduplicate(ordered)


def _deduplicate(cameras: list[Camera]) -> list[Camera]:
    """Dédup par MAC ; les caméras WS-Discovery sans MAC sont fusionnées avec
    l'entrée ARP de même IP (référence riche conservée, MAC complétée)."""
    by_mac: dict[str, Camera] = {}
    mac_by_ip: dict[str, str] = {}
    by_ip_no_mac: dict[str, Camera] = {}

    final: list[Camera] = []
    for camera in cameras:
        mac = camera.mac_address.lower()
        if mac:
            if mac not in by_mac:
                by_mac[mac] = camera
                final.append(camera)
            if camera.ip_address:
                mac_by_ip.setdefault(camera.ip_address, mac)
        elif camera.ip_address:
            by_ip_no_mac.setdefault(camera.ip_address, camera)

    for ip, camera in by_ip_no_mac.items():
        arp_mac = mac_by_ip.get(ip)
        if arp_mac:
            camera.mac_address = arp_mac
            if camera.vendor is None:
                from .arp import oui_vendor

                camera.vendor = oui_vendor(arp_mac)
            existing = by_mac.get(arp_mac)
            if existing is not None and existing is not camera:
                if existing in final:
                    final.remove(existing)
                final.append(camera)
                by_mac[arp_mac] = camera
        else:
            final.append(camera)

    return final
