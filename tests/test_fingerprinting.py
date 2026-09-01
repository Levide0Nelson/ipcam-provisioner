"""Tests du fingerprinting : identification vendor + état d'activation."""

from __future__ import annotations

from ipcam_provisioner.discovery import discover_all
from ipcam_provisioner.fingerprinting import build_engine
from ipcam_provisioner.fingerprinting.base import FingerprintContext
from ipcam_provisioner.models import ActivationStatus, DiscoveryMethod


def _camera_by_mac(cameras, mac: str):
    return next(c for c in cameras if c.mac_address == mac)


async def _steer_and_identify(network, talker, config, semaphore, camera):
    network.announce(camera.ip_address, camera.mac_address, method="l2_steer")
    engine = build_engine(FingerprintContext(talker, config, semaphore))
    return await engine.identify(camera)


async def test_fingerprint_hikvision_inactive(config, network, talker, semaphore):
    cameras = await discover_all(config, network)
    camera = _camera_by_mac(cameras, "ac:cc:8e:00:00:02")
    out = await _steer_and_identify(network, talker, config, semaphore, camera)
    assert out.activation_status is ActivationStatus.INACTIVE
    assert out.vendor == "hikvision"
    assert out.vendor_confirmed


async def test_fingerprint_dahua_active(config, network, talker, semaphore):
    cameras = await discover_all(config, network)
    camera = _camera_by_mac(cameras, "e0:50:8b:00:00:02")
    out = await _steer_and_identify(network, talker, config, semaphore, camera)
    assert out.activation_status is ActivationStatus.ACTIVE
    assert out.vendor == "dahua"
    assert out.model == "IPC-HFW2431S-S"


async def test_fingerprint_tiandy_inactive(config, network, talker, semaphore):
    cameras = await discover_all(config, network)
    camera = _camera_by_mac(cameras, "00:cc:2f:00:00:01")
    out = await _steer_and_identify(network, talker, config, semaphore, camera)
    assert out.activation_status is ActivationStatus.INACTIVE
    assert out.vendor == "tiandy"


async def test_fingerprint_onvif_active_and_mac(config, network, talker, semaphore):
    cameras = await discover_all(config, network)
    camera = next(c for c in cameras if c.discovery_method is DiscoveryMethod.ONVIF_WS_DISCOVERY)
    out = await _steer_and_identify(network, talker, config, semaphore, camera)
    assert out.activation_status is ActivationStatus.ACTIVE
    assert out.vendor == "generic"
    assert out.mac_address == "aa:bb:cc:00:00:01"
    assert out.serial_number == "ONVIF-aabbcc00"
