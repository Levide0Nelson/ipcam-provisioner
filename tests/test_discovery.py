"""Tests de la découverte : simulateurs UDP, dédup par MAC, fusion ARP/WS-Discovery."""

from __future__ import annotations

from collections import Counter

import pytest

from ipcam_provisioner.discovery import discover_all
from ipcam_provisioner.discovery.arp import (
    _parse_arp_a,
    _parse_proc_arp,
    oui_vendor,
)
from ipcam_provisioner.models import DiscoveryMethod


def test_oui_vendor():
    assert oui_vendor("AC-CC-8E-11-22-33") == "hikvision"
    assert oui_vendor("e0:50:8b:ff:00:01") == "dahua"
    assert oui_vendor("00:cc:2f:00:00:01") == "tiandy"
    assert oui_vendor("aa:bb:cc:00:00:01") == "generic"
    assert oui_vendor("de:ad:be:ef:00:01") is None


def test_oui_vendor_real_hikvision_c0517e():
    # OUI observé sur matériel réel : caméra Hikvision DS-2CD1043G0E-I (site réel).
    assert oui_vendor("c0:51:7e:c9:2e:6e") == "hikvision"
    assert oui_vendor("C0:51:7E:C9:2E:6E") == "hikvision"


def test_oui_vendor_real_hikvision_1012fb():
    # OUI observé sur matériel réel : caméra Hikvision DS-2CD1153G0-I (site réel).
    assert oui_vendor("10:12:fb:db:df:b6") == "hikvision"


async def test_discover_all_demo(config, network):
    cameras = await discover_all(config, network)
    # En mode simulation, le scan actif ne trouve pas de caméras supplémentaires
    # car les caméras simulées écoutent sur 127.0.0.1, pas sur leurs IPs logiques.
    # Le test vérifie que les 8 caméras du demo sont bien découvertes.
    assert len(cameras) == 8
    macs = [c.mac_address for c in cameras]
    assert len(set(macs)) == len(macs)
    ips = [c.ip_address for c in cameras]
    assert len(set(ips)) < len(ips)  # 2 IP en conflit
    methods = Counter(c.discovery_method for c in cameras)
    assert methods[DiscoveryMethod.SADP] == 3
    assert methods[DiscoveryMethod.DAHUA_DISCOVERY] == 3
    assert methods[DiscoveryMethod.TIANDY_DISCOVERY] == 1
    # La caméra ONVIF (sans MAC au WS-Discovery) est fusionnée avec l'ARP.
    assert methods[DiscoveryMethod.ONVIF_WS_DISCOVERY] == 1


async def test_discover_sadp_hikvision(config, network):
    cameras = await discover_all(config, network)
    hik = [c for c in cameras if c.vendor == "hikvision"]
    assert len(hik) == 3
    for camera in hik:
        assert camera.vendor_confirmed
        assert camera.discovery_method is DiscoveryMethod.SADP
        assert camera.mac_address.startswith("ac:cc:8e")


async def test_discover_dahua(config, network):
    cameras = await discover_all(config, network)
    dahua = [c for c in cameras if c.vendor == "dahua"]
    assert len(dahua) == 3
    assert all(c.mac_address.startswith("e0:50:8b") for c in dahua)


async def test_discover_onvif_merged_with_arp(config, network):
    cameras = await discover_all(config, network)
    onvif = [c for c in cameras if c.discovery_method is DiscoveryMethod.ONVIF_WS_DISCOVERY]
    assert len(onvif) == 1
    camera = onvif[0]
    assert camera.ip_address == "169.254.20.64"
    assert camera.mac_address == "aa:bb:cc:00:00:01"
    assert camera.discovery_method is DiscoveryMethod.ONVIF_WS_DISCOVERY
    assert "xaddrs" in camera.raw_discovery_payload


async def test_discover_no_duplicate_ip_for_onvif(config, network):
    """La fusion ne laisse qu'une caméra par IP : pas d'entrée ARP résiduelle."""
    cameras = await discover_all(config, network)
    ips = [c.ip_address for c in cameras]
    count = ips.count("169.254.20.64")
    assert count == 1


async def test_discovery_methods_only_selected(config, network):
    from ipcam_provisioner.config import build_config

    raw = {
        "site_name": "Test",
        "ip_range": {"start": "192.168.1.100", "end": "192.168.1.120"},
        "subnet_mask": "255.255.255.0",
        "gateway": "192.168.1.1",
        "discovery": {"methods": ["sadp"]},
    }
    restricted = build_config(raw)
    restricted.discovery.timeout_seconds = 0.3
    cameras = await discover_all(restricted, network)
    assert all(c.discovery_method is DiscoveryMethod.SADP for c in cameras)


async def test_real_multicast_ws_discovery_finds_rehearsal_camera():
    """Phase 2 — chemin réel (aucun réseau simulé) : la sonde part en multicast
    239.255.255.250:3702 et une caméra virtuelle inscrite sur le groupe répond.
    Valide le transport multicast réel sur la machine, sans matériel."""
    from ipcam_provisioner.simulation import demo
    from ipcam_provisioner.simulation.camera import CameraSpec
    from ipcam_provisioner.simulation.network import SimulatedNetwork

    cfg = demo.demo_config()
    cfg.discovery.methods = [DiscoveryMethod.ONVIF_WS_DISCOVERY]
    cfg.discovery.timeout_seconds = 1.0

    net = SimulatedNetwork()
    await net.start_camera(
        CameraSpec(
            vendor="onvif",
            mac="aa:bb:cc:00:00:02",
            ip="169.254.20.65",
            active=True,
            password="REPLACE_ME",
            rehearse=True,
        )
    )
    try:
        cameras = await discover_all(cfg)
    finally:
        await net.stop()

    assert len(cameras) >= 1
    rehearsal = [c for c in cameras if c.ip_address == "169.254.20.65"]
    assert len(rehearsal) == 1
    camera = rehearsal[0]
    assert camera.discovery_method is DiscoveryMethod.ONVIF_WS_DISCOVERY
    assert camera.ip_address == "169.254.20.65"


@pytest.mark.parametrize(
    ("method", "vendor", "mac", "ip"),
    [
        (DiscoveryMethod.SADP, "hikvision", "ac:cc:8e:00:00:02", "192.0.0.65"),
        (DiscoveryMethod.DAHUA_DISCOVERY, "dahua", "e0:50:8b:00:00:02", "192.0.0.65"),
        (DiscoveryMethod.TIANDY_DISCOVERY, "tiandy", "00:cc:2f:00:00:02", "10.1.1.21"),
    ],
)
async def test_real_broadcast_protocol_finds_rehearsal_camera(method, vendor, mac, ip):
    """Phase 2 — chemin réel en broadcast (255.255.255.255) sur le port du protocole :
    la caméra virtuelle inscrite sur le port répond à la sonde réelle."""
    from ipcam_provisioner.simulation import demo
    from ipcam_provisioner.simulation.camera import CameraSpec
    from ipcam_provisioner.simulation.network import SimulatedNetwork

    cfg = demo.demo_config()
    cfg.discovery.methods = [method]
    cfg.discovery.timeout_seconds = 1.0

    net = SimulatedNetwork()
    await net.start_camera(
        CameraSpec(vendor=vendor, mac=mac, ip=ip, active=True, password="REPLACE_ME", rehearse=True)
    )
    try:
        cameras = await discover_all(cfg)
    finally:
        await net.stop()

    assert len(cameras) == 1
    camera = cameras[0]
    assert camera.discovery_method is method
    assert camera.ip_address == ip
    assert camera.mac_address == mac


def test_parse_proc_arp_linux():
    text = (
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.64     0x1         0x2         ac:cc:8e:00:00:01     *        eth0\n"
        "10.0.0.2         0x1         0x2         00:00:00:00:00:00     *        eth0\n"
    )
    assert _parse_proc_arp(text) == [("192.168.1.64", "ac:cc:8e:00:00:01")]


def test_parse_arp_a_windows():
    text = (
        "Interface: 192.168.1.10 --- 0x11\n"
        "  Internet Address      Physical Address      Type\n"
        "  192.168.1.1           ac-cc-8e-11-22-33     dynamic\n"
        "  192.168.1.64          e0-50-8b-44-55-66     static\n"
    )
    assert ("192.168.1.1", "ac:cc:8e:11:22:33") in _parse_arp_a(text)
    assert ("192.168.1.64", "e0:50:8b:44:55:66") in _parse_arp_a(text)
