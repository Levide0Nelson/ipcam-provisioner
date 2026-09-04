"""Active subnet scanner : sondage TCP parallèle des ports caméras courants.

Remplace/augmente la découverte passive (ARP, multicast) par un balayage actif
du/des sous-réseaux locaux. Garantit la détection même si ARP/multicast échouent.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import sys
from dataclasses import dataclass, field
from typing import Any

from ..models import Camera, DiscoveryMethod
from .base import DiscoveryAdapter, DiscoveryContext

logger = logging.getLogger("ipcam_provisioner.discovery.active_scan")

# Ports caméras courants (ordre = priorité) - réduit aux plus critiques pour vitesse
CAMERA_PORTS = [80, 554, 8000, 8080, 37020]

# Concurrence max pour le scan TCP (ajustable via config)
DEFAULT_MAX_CONCURRENT = 100


@dataclass
class ActiveScanConfig:
    ports: list[int] = field(default_factory=lambda: CAMERA_PORTS)
    timeout: float = 0.5
    max_concurrent: int = DEFAULT_MAX_CONCURRENT
    scan_timeout: float = 20.0
    target_subnets: list[str] = field(default_factory=list)  # sous-réseaux cibles (ex: ["192.168.1.0/24"])


class ActiveSubnetScanner(DiscoveryAdapter):
    """Découverte par balayage TCP actif des sous-réseaux locaux."""

    method = DiscoveryMethod.ACTIVE_SUBNET_SCAN

    def __init__(self, config: ActiveScanConfig | None = None):
        self.config = config or ActiveScanConfig()

    def _get_subnets_from_sim(self, sim_network) -> list[ipaddress.IPv4Network]:
        """Extrait les sous-réseaux du réseau simulé."""
        subnets: list[ipaddress.IPv4Network] = []
        try:
            for camera in sim_network.cameras:
                ip = camera.logical_ip
                net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                if net not in subnets:
                    subnets.append(net)
        except Exception as e:
            logger.warning("Impossible d'extraire les sous-reseaux du simulateur: %s", e)
        return subnets

    def _get_local_subnets(self, sim_network=None) -> list[ipaddress.IPv4Network]:
        """Détermine les sous-réseaux à scanner.
        
        Priorité :
        1. target_subnets explicite dans la config
        2. Réseau simulé (si sim_network fourni)
        3. Auto-détection interfaces UP (réel)
        """
        subnets: list[ipaddress.IPv4Network] = []
        
        # 1. Sous-réseaux cibles explicites (priorité)
        if self.config.target_subnets:
            for subnet_str in self.config.target_subnets:
                try:
                    net = ipaddress.IPv4Network(subnet_str, strict=False)
                    if net not in subnets:
                        subnets.append(net)
                except Exception as e:
                    logger.warning("Sous-reseau cible invalide %s: %s", subnet_str, e)
            return subnets
        
        # 2. Réseau simulé (si dispo)
        if sim_network is not None:
            return self._get_subnets_from_sim(sim_network)
        
        # 3. Auto-détection interfaces UP (réel)
        try:
            import subprocess
            if sys.platform == "win32":
                proc = subprocess.run(["ipconfig"], capture_output=True, check=False)
                out = proc.stdout.decode("cp1252", errors="replace")
                current_iface = None
                current_media_state = None
                current_ip = None
                current_mask = None
                cidr = 24
                
                for line in out.splitlines():
                    line_stripped = line.strip()
                    if line and not line.startswith(" ") and ":" in line:
                        if current_ip and current_mask and current_media_state != "Media disconnected":
                            net = ipaddress.IPv4Network(f"{current_ip}/{cidr}", strict=False)
                            if net not in subnets:
                                subnets.append(net)
                        current_iface = line_stripped.rstrip(":")
                        current_media_state = None
                        current_ip = None
                        current_mask = None
                    if "Media" in line_stripped and ("disconnect" in line_stripped.lower() or "déconnect" in line_stripped.lower()):
                        current_media_state = "Media disconnected"
                    if "IPv4" in line_stripped and "." in line_stripped:
                        current_ip = line_stripped.split(":")[-1].strip()
                    if ("Masque" in line_stripped or "Subnet" in line_stripped) and "." in line_stripped:
                        current_mask = line_stripped.split(":")[-1].strip()
                        if current_mask and current_mask != "255.255.255.0":
                            try:
                                mask_ip = ipaddress.IPv4Address(current_mask)
                                cidr = sum(bin(int(mask_ip)).count('1'))
                            except Exception:
                                cidr = 24
                        else:
                            cidr = 24
                
                if current_ip and current_mask and current_media_state != "Media disconnected":
                    net = ipaddress.IPv4Network(f"{current_ip}/{cidr}", strict=False)
                    if net not in subnets:
                        subnets.append(net)
            else:
                proc = subprocess.run(
                    ["ip", "-br", "addr"], capture_output=True, text=True, check=False
                )
                for line in proc.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] == "UP":
                        for cidr_ip in parts[2:]:
                            if "/" in cidr_ip and "." in cidr_ip:
                                net = ipaddress.IPv4Network(cidr_ip, strict=False)
                                if net not in subnets:
                                    subnets.append(net)
        except Exception as e:
            logger.warning("Impossible de determiner les sous-reseaux locaux: %s", e)
        return subnets

    async def _tcp_probe(self, ip: str, port: int, timeout: float) -> bool:
        """Test de connexion TCP rapide."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def _scan_subnet(
        self, network: ipaddress.IPv4Network, sem: asyncio.Semaphore
    ) -> list[tuple[str, int]]:
        """Balaye un sous-réseau : retourne liste (ip, port) répondant."""
        ips = [str(ip) for ip in network.hosts()]
        found: list[tuple[str, int]] = []

        async def probe_ip_port(ip: str, port: int) -> tuple[str, int] | None:
            async with sem:
                if await self._tcp_probe(ip, port, self.config.timeout):
                    return (ip, port)
                return None

        tasks = [probe_ip_port(ip, port) for ip in ips for port in self.config.ports]
        results = await asyncio.gather(*tasks)
        for r in results:
            if r is not None:
                found.append(r)
        return found

    async def discover(self, ctx: DiscoveryContext) -> list[Camera]:
        sim_net = ctx.sim_network
        subnets = self._get_local_subnets(sim_net)
        if not subnets:
            logger.warning("Aucun sous-reseau local detecte pour le scan actif")
            return []

        logger.info(
            "Demarrage scan actif sur %d sous-reseau(x) : %s",
            len(subnets),
            [str(n) for n in subnets],
        )

        sem = asyncio.Semaphore(self.config.max_concurrent)
        all_found: list[tuple[str, int]] = []

        for network in subnets:
            try:
                found = await asyncio.wait_for(
                    self._scan_subnet(network, sem), timeout=self.config.scan_timeout
                )
                all_found.extend(found)
                logger.info(
                    "Sous-reseau %s : %d hote(s) detecte(s)", network, len(found)
                )
            except asyncio.TimeoutError:
                logger.warning("Timeout scan sur %s", network)
            except Exception as e:
                logger.error("Erreur scan %s: %s", network, e)

        # Dédup par IP (garder le premier port trouvé)
        seen_ips = set()
        unique_found = []
        for ip, port in all_found:
            if ip not in seen_ips:
                seen_ips.add(ip)
                unique_found.append((ip, port))

        logger.info("Scan actif termine : %d IP uniques detectees", len(unique_found))

        cameras: list[Camera] = []
        for ip, port in unique_found:
            mac = ""
            try:
                from .arp import read_system_arp_entries
                for arp_ip, arp_mac in read_system_arp_entries():
                    if arp_ip == ip:
                        mac = arp_mac
                        break
            except Exception:
                pass

            cameras.append(
                Camera(
                    mac_address=mac.lower() if mac else "",
                    ip_address=ip,
                    discovery_method=DiscoveryMethod.ACTIVE_SUBNET_SCAN,
                    raw_discovery_payload={
                        "source": "active_tcp_scan",
                        "port": port,
                        "ports_tried": self.config.ports,
                    },
                    vendor=None,
                    vendor_confirmed=False,
                )
            )

        return cameras


__all__ = ["ActiveSubnetScanner", "ActiveScanConfig"]