"""Tests de la détection et de la résolution L2 des conflits d'adresses."""

from __future__ import annotations

import ipaddress

from ipcam_provisioner.config import build_config
from ipcam_provisioner.conflicts import detect_conflicts, resolve_conflict
from ipcam_provisioner.models import Camera, DiscoveryMethod, ResolutionStatus
from ipcam_provisioner.planning import plan_target_ips


def _camera(mac: str, ip: str) -> Camera:
    return Camera(mac_address=mac, ip_address=ip, discovery_method=DiscoveryMethod.ARP_OUI_FALLBACK)


class _Announcer:
    """Annonceur L2 simulé : table ARP + reconfiguration d'IP indexée par MAC."""

    def __init__(self) -> None:
        self.arp = {}
        self.mac_ip = {}
        self.rejects: set[str] = set()
        self.calls = []

    def announce(self, ip, mac, method="gratuitous_arp") -> None:
        self.arp[ip] = mac
        self.calls.append((ip, mac, method))

    def arp_lookup(self, ip) -> str | None:
        return self.arp.get(ip)

    def set_ip_by_mac(self, mac, new_ip) -> bool:
        if mac in self.rejects:
            return False
        old_ip = self.mac_ip.get(mac)
        if old_ip:
            self.arp.pop(old_ip, None)
        self.mac_ip[mac] = new_ip
        self.arp[new_ip] = mac
        self.calls.append((new_ip, mac, "set_ip_by_mac"))
        return True


def test_detect_conflicts():
    cameras = [
        _camera("ac:cc:8e:00:00:01", "192.0.0.64"),
        _camera("e0:50:8b:00:00:01", "192.0.0.64"),
        _camera("e0:50:8b:00:00:02", "192.168.5.22"),
    ]
    conflicts = detect_conflicts(cameras)
    assert len(conflicts) == 1
    conflict = conflicts[0]
    assert conflict.conflicting_ip == "192.0.0.64"
    assert set(conflict.camera_macs) == {"ac:cc:8e:00:00:01", "e0:50:8b:00:00:01"}
    assert cameras[0].has_conflict and cameras[1].has_conflict
    assert not cameras[2].has_conflict


def test_resolve_conflict_assigns_unique_temp_ips():
    announcer = _Announcer()
    conflict, cameras_by_mac = _build_conflict(["ac:cc:8e:00:00:01", "e0:50:8b:00:00:01"])
    result = resolve_conflict(
        conflict, cameras_by_mac, announcer, subnet_mask="255.255.255.0", reserved_ips={"192.0.0.64"}
    )
    assert result.resolution_status is ResolutionStatus.RESOLVED
    assert result.winner_mac == "ac:cc:8e:00:00:01"
    assert result.resolution_method == "mac_addressed_broadcast"

    hik, dahua = cameras_by_mac["ac:cc:8e:00:00:01"], cameras_by_mac["e0:50:8b:00:00:01"]
    assert hik.temp_ip is not None and dahua.temp_ip is not None
    assert hik.temp_ip != dahua.temp_ip
    assert hik.temp_ip != "192.0.0.64" and dahua.temp_ip != "192.0.0.64"
    assert hik.ip_address == hik.temp_ip and dahua.ip_address == dahua.temp_ip
    network = ipaddress.IPv4Network("192.0.0.64/255.255.255.0", strict=False)
    assert hik.temp_ip in {str(a) for a in network.hosts()}
    # la table L2 reflète les reconfigurations
    assert announcer.arp[hik.temp_ip] == hik.mac_address
    assert announcer.arp[dahua.temp_ip] == dahua.mac_address


def test_resolve_conflict_respects_reserved_ips():
    announcer = _Announcer()
    conflict, cameras_by_mac = _build_conflict(["ac:cc:8e:00:00:01", "e0:50:8b:00:00:01"])
    reserved = {"192.0.0.64", "192.0.0.1", "192.0.0.2", "192.0.0.3"}
    reserved_before = set(reserved)
    result = resolve_conflict(conflict, cameras_by_mac, announcer, subnet_mask="255.255.255.0", reserved_ips=reserved)
    assert result.resolution_status is ResolutionStatus.RESOLVED
    ips = {c.ip_address for c in cameras_by_mac.values()}
    assert not ips & reserved_before
    assert len(ips) == 2


def test_resolve_conflict_fails_without_cameras():
    announcer = _Announcer()
    conflict, _cameras_by_mac = _build_conflict(["ac:cc:8e:00:00:01", "e0:50:8b:00:00:01"])
    result = resolve_conflict(
        conflict, {}, announcer, subnet_mask="255.255.255.0", reserved_ips=set()
    )
    assert result.resolution_status is ResolutionStatus.FAILED


def test_resolve_conflict_fails_when_mac_unreachable():
    announcer = _Announcer()
    announcer.rejects.add("e0:50:8b:00:00:01")
    conflict, cameras_by_mac = _build_conflict(["ac:cc:8e:00:00:01", "e0:50:8b:00:00:01"])
    result = resolve_conflict(
        conflict, cameras_by_mac, announcer, subnet_mask="255.255.255.0", reserved_ips={"192.0.0.64"}
    )
    assert result.resolution_status is ResolutionStatus.FAILED
    assert "e0:50:8b:00:00:01" in (result.resolution_detail or "")
    # la caméra injoignable est marquée en erreur, l'autre est quand même dédoublonnée
    assert cameras_by_mac["e0:50:8b:00:00:01"].last_error is not None
    assert cameras_by_mac["ac:cc:8e:00:00:01"].last_error is None
    assert cameras_by_mac["ac:cc:8e:00:00:01"].temp_ip is not None


def _build_conflict(macs: list[str]):
    cameras = [_camera(mac, "192.0.0.64") for mac in macs]
    conflict = detect_conflicts(cameras)[0]
    return conflict, {c.mac_address: c for c in cameras}


def test_planning_after_resolution_assigns_pool_ips():
    announcer = _Announcer()
    conflict, cameras_by_mac = _build_conflict(["ac:cc:8e:00:00:01", "e0:50:8b:00:00:01"])
    resolve_conflict(
        conflict, cameras_by_mac, announcer, subnet_mask="255.255.255.0", reserved_ips={"192.0.0.64"}
    )

    config = build_config(
        {
            "site_name": "Test",
            "ip_range": {"start": "192.0.0.64", "end": "192.0.0.80"},
            "subnet_mask": "255.255.255.0",
            "gateway": "192.0.0.1",
        }
    )
    cameras = list(cameras_by_mac.values())
    plan_target_ips(cameras, config, [conflict])
    targets = {c.target_ip for c in cameras}
    assert len(targets) == 2
    # résolution = IP temporaires hors plage → pas de « vainqueur » qui garde son IP
    assert all(not config.ip_range.contains(c.ip_address) for c in cameras)
    # les deux caméras reçoivent une cible finale distincte dans la plage
    assert all(config.ip_range.contains(ip) for ip in targets)
