"""Tests de la couche configuration (validation, attributs par défaut)."""

from __future__ import annotations

import ipaddress

import pytest

from ipcam_provisioner.config import ConfigError, IpRange, build_config, load_config
from ipcam_provisioner.models import DiscoveryMethod


def _valid_raw() -> dict:
    return {
        "site_name": "Test",
        "ip_range": {"start": "192.168.1.100", "end": "192.168.1.150"},
        "subnet_mask": "255.255.255.0",
        "gateway": "192.168.1.1",
        "vendors": {"hikvision": {"default_password": "X"} },
        "concurrency": {"max_parallel_requests": 10},
        "discovery": {"methods": ["sadp"], "timeout_seconds": 1.5},
    }


def test_build_config_defaults():
    cfg = build_config(_valid_raw())
    assert cfg.site_name == "Test"
    assert cfg.ip_range.size() == 51
    assert isinstance(cfg.subnet_mask, ipaddress.IPv4Address)
    assert cfg.default_password_for("hikvision") == "X"
    assert cfg.default_password_for("dahua") == ""
    assert cfg.concurrency.max_parallel_requests == 10
    assert cfg.discovery.methods == [DiscoveryMethod.SADP]
    assert cfg.discovery.timeout_seconds == 1.5


def test_build_config_default_methods_when_absent():
    raw = _valid_raw()
    raw.pop("discovery")
    cfg = build_config(raw)
    assert cfg.discovery.methods == list(DiscoveryMethod)


def test_ip_range():
    rng = IpRange(
        start=ipaddress.IPv4Address("192.168.1.100"),
        end=ipaddress.IPv4Address("192.168.1.150"),
    )
    assert rng.contains("192.168.1.100")
    assert rng.contains("192.168.1.125")
    assert not rng.contains("192.168.1.151")
    assert not rng.contains("10.0.0.1")
    assert list(rng.iter_addresses())[0] == ipaddress.IPv4Address("192.168.1.100")


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda r: r.update(site_name="   "), "site_name"),
        (lambda r: r.update(ip_range={"start": "300.0.0.1", "end": "192.168.1.150"}), "ip_range.start"),
        (lambda r: r.update(ip_range={"start": "192.168.1.150", "end": "192.168.1.100"}), "ip_range.start"),
        (lambda r: r.update(subnet_mask="bad"), "subnet_mask"),
        (lambda r: r.update(discovery={"methods": ["foobar"]}), "Méthode"),
        (lambda r: r.update(concurrency={"max_parallel_requests": 0}), "entier"),
    ],
)
def test_build_config_invalid(mutate, message):
    raw = _valid_raw()
    mutate(raw)
    with pytest.raises(ConfigError, match=message):
        build_config(raw)


def test_load_config_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="introuvable"):
        load_config(tmp_path / "nope.yaml")


def test_load_config_invalid_yaml(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("foo: [1, 2\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="YAML invalide"):
        load_config(path)
