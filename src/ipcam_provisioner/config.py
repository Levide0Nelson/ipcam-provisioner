"""Chargement et validation de la configuration YAML par site (section 6)."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .models import DiscoveryMethod

DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_PARALLEL = 50
DEFAULT_METHODS = [
    DiscoveryMethod.SADP,
    DiscoveryMethod.DAHUA_DISCOVERY,
    DiscoveryMethod.TIANDY_DISCOVERY,
    DiscoveryMethod.ONVIF_WS_DISCOVERY,
    DiscoveryMethod.ARP_OUI_FALLBACK,
]

_METHOD_NAME_TO_ENUM = {m.value: m for m in DiscoveryMethod}
_VALID_VENDORS = ("hikvision", "dahua", "tiandy", "onvif")


class ConfigError(ValueError):
    """Erreur de configuration utilisateur (message affichable)."""


def _parse_methods(raw: list[str] | None) -> list[DiscoveryMethod]:
    if raw is None:
        return list(DEFAULT_METHODS)
    methods: list[DiscoveryMethod] = []
    for name in raw:
        try:
            methods.append(_METHOD_NAME_TO_ENUM[name])
        except KeyError:
            raise ConfigError(
                f"Méthode de découverte inconnue : {name!r} "
                f"(valides : {', '.join(sorted(_METHOD_NAME_TO_ENUM))})"
            ) from None
    if not methods:
        raise ConfigError("discovery.methods ne doit pas être vide")
    return methods


def _parse_ip(value: str, label: str) -> ipaddress.IPv4Address:
    try:
        return ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise ConfigError(f"{label} invalide : {value!r}") from None


@dataclass
class VendorConfig:
    default_password: str


_EMPTY_VENDOR = VendorConfig(default_password="")


@dataclass
class IpRange:
    start: ipaddress.IPv4Address
    end: ipaddress.IPv4Address

    def iter_addresses(self):
        """Itère toutes les adresses de la plage, bornes incluses."""
        current = int(self.start)
        last = int(self.end)
        while current <= last:
            yield ipaddress.IPv4Address(current)
            current += 1

    def size(self) -> int:
        return int(self.end) - int(self.start) + 1

    def contains(self, ip: str | ipaddress.IPv4Address) -> bool:
        addr = ip if isinstance(ip, ipaddress.IPv4Address) else _parse_ip(ip, "ip")
        return int(self.start) <= int(addr) <= int(self.end)


@dataclass
class ConcurrencyConfig:
    max_parallel_requests: int = DEFAULT_MAX_PARALLEL


@dataclass
class DiscoveryConfig:
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    methods: list[DiscoveryMethod] = field(default_factory=lambda: list(DEFAULT_METHODS))


@dataclass
class SiteConfig:
    site_name: str
    ip_range: IpRange
    subnet_mask: ipaddress.IPv4Address
    gateway: ipaddress.IPv4Address
    vendors: dict[str, VendorConfig]
    concurrency: ConcurrencyConfig = field(default_factory=ConcurrencyConfig)
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)

    def default_password_for(self, vendor: str) -> str:
        if vendor == "generic":
            vendor = "onvif"
        return self.vendors.get(vendor, _EMPTY_VENDOR).default_password


def load_config(path: str | Path) -> SiteConfig:
    """Charge et valide une configuration YAML de site."""
    cfg_path = Path(path)
    if not cfg_path.exists():
        raise ConfigError(f"Fichier de configuration introuvable : {cfg_path}")
    try:
        raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"YAML invalide dans {cfg_path} : {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("La configuration doit être un mapping YAML")
    return build_config(raw)


def build_config(raw: dict) -> SiteConfig:
    """Construit une SiteConfig depuis un dict YAML, avec validation."""
    site_name = raw.get("site_name")
    if not isinstance(site_name, str) or not site_name.strip():
        raise ConfigError("site_name manquant ou vide")

    ip_range_raw = raw.get("ip_range") or {}
    start = _parse_ip(str(ip_range_raw.get("start", "")), "ip_range.start")
    end = _parse_ip(str(ip_range_raw.get("end", "")), "ip_range.end")
    if int(start) > int(end):
        raise ConfigError("ip_range.start doit être <= ip_range.end")
    ip_range = IpRange(start=start, end=end)

    subnet_mask = _parse_ip(str(raw.get("subnet_mask", "")), "subnet_mask")
    gateway = _parse_ip(str(raw.get("gateway", "")), "gateway")

    vendors_raw = raw.get("vendors") or {}
    if not isinstance(vendors_raw, dict):
        raise ConfigError("vendors doit être un mapping")
    vendors: dict[str, VendorConfig] = {}
    unknown = [name for name in vendors_raw if name not in _VALID_VENDORS]
    if unknown:
        raise ConfigError(
            f"vendor(s) inconnu(s) : {', '.join(sorted(unknown))} "
            f"(valides : {', '.join(_VALID_VENDORS)})"
        )
    for name, block in vendors_raw.items():
        block = block or {}
        pwd = str(block.get("default_password", ""))
        vendors[name] = VendorConfig(default_password=pwd)

    concurrency_raw = raw.get("concurrency") or {}
    max_parallel = concurrency_raw.get("max_parallel_requests", DEFAULT_MAX_PARALLEL)
    if not isinstance(max_parallel, int) or max_parallel < 1:
        raise ConfigError(
            "concurrency.max_parallel_requests doit être un entier >= 1"
        )

    disc_raw = raw.get("discovery") or {}
    timeout = float(disc_raw.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS))
    if timeout <= 0:
        raise ConfigError("discovery.timeout_seconds doit être > 0")
    methods = _parse_methods(disc_raw.get("methods"))

    return SiteConfig(
        site_name=site_name,
        ip_range=ip_range,
        subnet_mask=subnet_mask,
        gateway=gateway,
        vendors=vendors,
        concurrency=ConcurrencyConfig(max_parallel_requests=max_parallel),
        discovery=DiscoveryConfig(timeout_seconds=timeout, methods=methods),
    )


def broadcast_address_for(network_ip: str, mask: ipaddress.IPv4Address) -> str:
    """Adresse de broadcast du sous-réseau contenant network_ip."""
    addr = _parse_ip(network_ip, "ip")
    net = ipaddress.IPv4Network(f"{addr}/{mask}", strict=False)
    return str(net.broadcast_address)
