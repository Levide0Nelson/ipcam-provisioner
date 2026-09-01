"""Tests de l'activation des caméras inactives (config usine)."""

from __future__ import annotations

from ipcam_provisioner.activation import ActivationEngine
from ipcam_provisioner.discovery import discover_all
from ipcam_provisioner.fingerprinting import build_engine
from ipcam_provisioner.fingerprinting.base import FingerprintContext
from ipcam_provisioner.models import ActivationResult, ActivationStatus
from ipcam_provisioner.net import HttpTalker
from ipcam_provisioner.simulation.camera import CameraSpec
from ipcam_provisioner.simulation.network import SimulatedNetwork


async def _make_inactive_hik(cfg, network, talker, semaphore):
    cameras = await discover_all(cfg, network)
    camera = next(c for c in cameras if c.mac_address == "ac:cc:8e:00:00:02")
    network.announce(camera.ip_address, camera.mac_address, method="l2_steer")
    engine = build_engine(FingerprintContext(talker, cfg, semaphore))
    out = await engine.identify(camera)
    assert out.activation_status is ActivationStatus.INACTIVE
    return out


async def test_activates_inactive_hikvision(config, network, talker, semaphore):
    camera = await _make_inactive_hik(config, network, talker, semaphore)
    activators = ActivationEngine(talker, config)
    out = await activators.activate(camera)
    assert out.activation_status is ActivationStatus.ACTIVE
    assert out.vendor_confirmed
    assert out.last_error is None
    assert out.activation_result is ActivationResult.SUCCESS


async def test_activation_is_idempotent_for_active(config, network, talker, semaphore):
    cameras = await discover_all(config, network)
    camera = next(c for c in cameras if c.mac_address == "e0:50:8b:00:00:02")
    camera.activation_status = ActivationStatus.ACTIVE
    await ActivationEngine(talker, config).activate(camera)
    assert camera.activation_status is ActivationStatus.ACTIVE
    assert camera.activation_result is None


async def test_missing_default_password_requires_manual(config, network, talker, semaphore):
    cameras = await discover_all(config, network)
    camera = next(c for c in cameras if c.mac_address == "ac:cc:8e:00:00:02")
    camera.activation_status = ActivationStatus.INACTIVE
    config.vendors["hikvision"].default_password = ""
    await ActivationEngine(talker, config).activate(camera)
    assert camera.activation_status is ActivationStatus.INACTIVE
    assert camera.last_error is None
    assert camera.activation_result is ActivationResult.MANUAL_REQUIRED


async def test_activates_inactive_onvif_via_create_users(config, semaphore):
    net = SimulatedNetwork()
    await net.start_camera(
        CameraSpec(vendor="onvif", mac="aa:bb:cc:00:00:02", ip="169.254.20.65", active=False)
    )
    try:
        talker = HttpTalker(net, timeout=1.0)
        cameras = await discover_all(config, net)
        camera = next(c for c in cameras if c.mac_address == "aa:bb:cc:00:00:02")
        camera = await build_engine(FingerprintContext(talker, config, semaphore)).identify(camera)
        assert camera.activation_status is not ActivationStatus.ACTIVE
        out = await ActivationEngine(talker, config).activate(camera)
        assert out.activation_status is ActivationStatus.ACTIVE
        assert out.activation_result is ActivationResult.SUCCESS
        assert out.last_error is None
    finally:
        await net.stop()
