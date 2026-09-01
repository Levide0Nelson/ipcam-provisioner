"""Tests de la planification des adresses cibles (attribution ordonnée)."""

from __future__ import annotations

from ipcam_provisioner.config import SiteConfig
from ipcam_provisioner.models import Camera, Conflict, DiscoveryMethod
from ipcam_provisioner.planning import PlanningError, plan_target_ips


def _config() -> SiteConfig:
    from ipcam_provisioner.config import build_config

    return build_config(
        {
            "site_name": "Test",
            "ip_range": {"start": "192.168.10.100", "end": "192.168.10.102"},
            "subnet_mask": "255.255.255.0",
            "gateway": "192.168.10.1",
        }
    )


def _camera(mac: str, ip: str, has_conflict: bool = False) -> Camera:
    return Camera(
        mac_address=mac,
        ip_address=ip,
        discovery_method=DiscoveryMethod.ARP_OUI_FALLBACK,
        has_conflict=has_conflict,
    )


def test_keeps_ip_already_in_range_and_not_conflicting():
    config = _config()
    cameras = [_camera("aa:bb:cc:00:00:01", "192.168.10.100")]
    camera = cameras[0]
    plan_target_ips(cameras, config, [])
    assert camera.target_ip == "192.168.10.100"


def test_assigns_next_free_for_factory_ip():
    config = _config()
    camera = _camera("aa:bb:cc:00:00:01", "192.0.0.64")
    plan_target_ips([camera], config, [])
    assert camera.target_ip == "192.168.10.100"


def test_conflict_cameras_get_next_free_addresses():
    config = _config()
    winner = _camera("ac:cc:8e:00:00:01", "192.0.0.9", has_conflict=True)
    loser = _camera("e0:50:8b:00:00:01", "192.0.0.9", has_conflict=True)
    conflict = Conflict(
        conflicting_ip="192.0.0.9",
        camera_macs=["ac:cc:8e:00:00:01", "e0:50:8b:00:00:01"],
        winner_mac="ac:cc:8e:00:00:01",
    )
    plan_target_ips([winner, loser], config, [conflict])
    assert winner.target_ip == "192.168.10.100"
    assert loser.target_ip == "192.168.10.101"


def test_conflict_loser_gets_free_address():
    config = _config()
    camera = _camera("e0:50:8b:00:00:01", "192.0.0.9", has_conflict=True)
    plan_target_ips([camera], config, [])
    assert camera.target_ip == "192.168.10.100"


def test_planning_deterministic_by_mac():
    config = _config()
    cameras = [
        _camera("b:e0:50:8b:00:00:02", "10.0.0.2"),
        _camera("c:ac:cc:8e:00:00:01", "10.0.0.1"),
    ]
    plan_target_ips(cameras, config, [])
    assert cameras[0].target_ip == "192.168.10.100"
    assert cameras[1].target_ip == "192.168.10.101"


def test_exhausted_range_raises():
    config = _config()
    cameras = [_camera(f"aa:bb:cc:00:00:{i:02x}", "10.0.0.1") for i in range(1, 6)]
    cameras.append(_camera("af:bb:cc:00:00:66", "10.0.0.1"))
    try:
        plan_target_ips(cameras, config, [])
    except PlanningError:
        return
    raise AssertionError("PlanningError non levée sur plage saturée")
