"""Réseau simulé (Phase 1) : table ARP, résolution d'endpoint HTTP, ports de sondes.

Représente le segment L2 sur lequel vivent les caméras virtuelles : il connaît leur
MAC/IP et le port de leur serveur HTTP localhost, expose la table ARP (qui détermine
quel MAC "possède" une IP — la notion centrale de la résolution de conflit L2), et
fournit une résolution d'endpoint à la couche HTTP.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..net import ProbeEndpoint, ResolvedEndpoint
from .camera import CameraSpec, VirtualCamera


class SimulatedNetwork:
    def __init__(self) -> None:
        self.cameras: list[VirtualCamera] = []
        self._by_mac: dict[str, VirtualCamera] = {}
        self._by_ip: dict[str, VirtualCamera] = {}
        self._arp: dict[str, str] = {}
        self.l2_announcements: list[tuple[str, str, str]] = []

    async def start_camera(self, spec: CameraSpec) -> VirtualCamera:
        cam = VirtualCamera(
            spec,
            on_ip_changed=self._on_ip_changed,
        )
        await cam.start()
        self.cameras.append(cam)
        self._by_mac[cam.mac_address] = cam
        self._by_ip[cam.logical_ip] = cam
        if cam.logical_ip not in self._arp:
            self._arp[cam.logical_ip] = cam.mac_address
        return cam

    def _on_ip_changed(self, old_ip: str, new_ip: str, mac: str) -> None:
        cam = self._by_mac[mac]
        if self._by_ip.get(old_ip) is cam:
            del self._by_ip[old_ip]
        if self._arp.get(old_ip) == mac:
            del self._arp[old_ip]
        self._by_ip[new_ip] = cam
        if new_ip not in self._arp:
            self._arp[new_ip] = mac

    async def stop(self) -> None:
        for cam in self.cameras:
            await cam.stop()

    # --- endpoints / découverte ---------------------------------------------

    def resolve(self, ip: str) -> ResolvedEndpoint:
        """Endpoint localhost joignable pour `ip` (celui du MAC propriétaire)."""
        mac = self._arp.get(ip)
        cam = self._by_mac.get(mac) if mac else None
        if cam is None:
            cam = self._by_ip.get(ip)
        if cam is None:
            raise KeyError(f"aucune caméra simulée à l'adresse {ip}")
        return ResolvedEndpoint(host="127.0.0.1", port=cam.http_port)

    def endpoints_for(self, method) -> list[ProbeEndpoint]:
        out = []
        for cam in self.cameras:
            if method in cam.supported_methods():
                out.append(ProbeEndpoint(host="127.0.0.1", port=cam.probe_port(method)))
        return out

    # --- couche L2 (ARP / annonces) ------------------------------------------

    def arp_entries(self) -> Iterable[tuple[str, str]]:
        return list(self._arp.items())

    def arp_lookup(self, ip: str) -> str | None:
        return self._arp.get(ip)

    def announce(self, ip: str, mac: str, method: str = "gratuitous_arp") -> None:
        """Attache (au niveau L2) l'IP au MAC indiqué — cœur de la résolution de conflit."""
        self._arp[ip] = mac
        self.l2_announcements.append((ip, mac, method))

    def set_ip_by_mac(self, mac: str, new_ip: str) -> bool:
        """Canal d'adressage MAC-ciblé (façon SADP) : reconfigurer l'IP d'une caméra
        indépendamment de son adresse actuelle, même si elle est en conflit.

        C'est ce mécanisme que le module Résolution utilise pour dédoublonner les IP.
        """
        cam = self._by_mac.get(mac.lower())
        if cam is None:
            return False
        cam.change_ip(new_ip)
        return True

    # --- introspection -------------------------------------------------------

    def camera_by_mac(self, mac: str) -> VirtualCamera | None:
        return self._by_mac.get(mac.lower())

    def camera_by_ip(self, ip: str) -> VirtualCamera | None:
        return self._by_ip.get(ip)
