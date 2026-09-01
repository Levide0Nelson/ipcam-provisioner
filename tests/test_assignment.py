"""Tests de l'attribution : changement d'IP effectif + cas d'échec."""

from __future__ import annotations

from ipcam_provisioner.assignment import AssignmentEngine
from ipcam_provisioner.discovery import discover_all
from ipcam_provisioner.fingerprinting import build_engine
from ipcam_provisioner.fingerprinting.base import FingerprintContext
from ipcam_provisioner.models import ActivationStatus, AssignmentStatus


async def _active_dahua(cfg, network, talker, semaphore):
    cameras = await discover_all(cfg, network)
    camera = next(c for c in cameras if c.mac_address == "e0:50:8b:00:00:02")
    network.announce(camera.ip_address, camera.mac_address, method="l2_steer")
    engine = build_engine(FingerprintContext(talker, cfg, semaphore))
    out = await engine.identify(camera)
    assert out.activation_status is ActivationStatus.ACTIVE
    return out


async def test_assign_active_camera_changes_ip(config, network, talker, semaphore):
    camera = await _active_dahua(config, network, talker, semaphore)
    camera.target_ip = "192.168.5.200"
    await AssignmentEngine(talker, config).assign(camera)
    assert camera.assignment_status is AssignmentStatus.SUCCESS
    assert camera.last_error is None
    assert camera.ip_address == "192.168.5.200"
    assert network.arp_lookup("192.168.5.200") == "e0:50:8b:00:00:02"


async def test_assign_already_in_range_is_noop(config, network, talker, semaphore):
    camera = await _active_dahua(config, network, talker, semaphore)
    camera.ip_address = "192.168.5.77"
    camera.target_ip = "192.168.5.77"
    await AssignmentEngine(talker, config).assign(camera)
    assert camera.assignment_status is AssignmentStatus.SUCCESS


async def test_assign_inactive_fails(config, network, talker, semaphore):
    cameras = await discover_all(config, network)
    camera = next(c for c in cameras if c.mac_address == "e0:50:8b:00:00:01")
    camera.activation_status = ActivationStatus.INACTIVE
    camera.target_ip = "192.168.5.200"
    await AssignmentEngine(talker, config).assign(camera)
    assert camera.assignment_status is AssignmentStatus.FAILED
    assert "non active" in camera.last_error


async def test_assign_missing_target_fails(config, network, talker, semaphore):
    camera = await _active_dahua(config, network, talker, semaphore)
    camera.target_ip = None
    await AssignmentEngine(talker, config).assign(camera)
    assert camera.last_error is not None
    assert "adresse cible" in camera.last_error
