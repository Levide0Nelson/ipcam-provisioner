"""Interface commune du module découverte + contexte d'exécution (section 5)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..config import SiteConfig
from ..models import Camera, DiscoveryMethod
from ..net import ProbeEndpoint, ProbeKind, udp_probe

#: Ports de découverte réels (documentés Phase 1, à confirmer Phase 2).
_REAL_PROBE_PORTS: dict[DiscoveryMethod, int] = {
    DiscoveryMethod.SADP: 37020,
    DiscoveryMethod.DAHUA_DISCOVERY: 37810,
    DiscoveryMethod.TIANDY_DISCOVERY: 9999,
    DiscoveryMethod.ONVIF_WS_DISCOVERY: 3702,
}


class DiscoveryContext:
    """Fournit la configuration + accès réseau aux adaptateurs de découverte.

    En phase simulée, les sondes sont unicast vers chaque simulateur ; en phase réelle,
    broadcast (SADP/Dahua/Tiandy) ou multicast (WS-Discovery).
    """

    def __init__(self, config: SiteConfig, sim_network=None) -> None:
        self.config = config
        self.sim_network = sim_network

    @property
    def timeout(self) -> float:
        return self.config.discovery.timeout_seconds

    async def probe(self, method: DiscoveryMethod, request: bytes) -> list:
        """Envoie `request` selon la méthode et retourne les datagrammes reçus."""
        if self.sim_network is not None:
            endpoints = self.sim_network.endpoints_for(method)
            if not endpoints:
                return []
            return await udp_probe(request, endpoints, self.timeout, kind=ProbeKind.UNICAST)
        if method is DiscoveryMethod.ONVIF_WS_DISCOVERY:
            group = [ProbeEndpoint("239.255.255.250", _REAL_PROBE_PORTS[method])]
            return await udp_probe(
                request,
                group,
                self.timeout,
                kind=ProbeKind.MULTICAST,
                multicast_group="239.255.255.250",
            )
        if method not in _REAL_PROBE_PORTS:
            return []
        endpoints = [ProbeEndpoint("255.255.255.255", _REAL_PROBE_PORTS[method])]
        return await udp_probe(request, endpoints, self.timeout, kind=ProbeKind.BROADCAST)


class DiscoveryAdapter(ABC):
    """Un adaptateur par protocole de découverte."""

    method: DiscoveryMethod

    @abstractmethod
    async def discover(self, ctx: DiscoveryContext) -> list[Camera]: ...
