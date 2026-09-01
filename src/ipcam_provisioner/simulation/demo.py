"""Site de démonstration en simulation (Phase 1).

Construit un mélange représentatif de caméras virtuelles (Hikvision, Dahua, Tiandy,
ONVIF), incluant des caméras inactives (config usine) et une paire en conflit d'IP,
ainsi qu'une SiteConfig dont la plage d'attribution couvre de nouvelles adresses.
"""

from __future__ import annotations

from ..config import SiteConfig, build_config
from .camera import CameraSpec
from .network import SimulatedNetwork

DEFAULT_PASSWORD = "REPLACE_ME"


def demo_specs() -> list[CameraSpec]:
    return [
        CameraSpec(vendor="hikvision", mac="ac:cc:8e:00:00:01", ip="192.0.0.64", active=False),
        CameraSpec(vendor="hikvision", mac="ac:cc:8e:00:00:02", ip="192.0.0.65", active=False),
        CameraSpec(vendor="dahua", mac="e0:50:8b:00:00:01", ip="192.0.0.64", active=False),
        CameraSpec(
            vendor="dahua",
            mac="e0:50:8b:00:00:02",
            ip="192.168.5.22",
            active=True,
            password=DEFAULT_PASSWORD,
        ),
        CameraSpec(vendor="tiandy", mac="00:cc:2f:00:00:01", ip="10.1.1.20", active=False),
        CameraSpec(
            vendor="onvif",
            mac="aa:bb:cc:00:00:01",
            ip="169.254.20.64",
            active=True,
            password=DEFAULT_PASSWORD,
        ),
        # Paire en conflit : deux caméras (Dahua + Hikvision) sur la même adresse.
        CameraSpec(
            vendor="dahua",
            mac="e0:50:8b:00:00:03",
            ip="192.168.5.23",
            active=True,
            password=DEFAULT_PASSWORD,
        ),
        CameraSpec(vendor="hikvision", mac="ac:cc:8e:00:00:03", ip="192.168.5.23", active=False),
    ]


def demo_config() -> SiteConfig:
    return build_config(
        {
            "site_name": "Démo simulation Phase 1",
            "ip_range": {"start": "192.168.5.100", "end": "192.168.5.250"},
            "subnet_mask": "255.255.255.0",
            "gateway": "192.168.5.1",
            "vendors": {
                "hikvision": {"default_password": DEFAULT_PASSWORD},
                "dahua": {"default_password": DEFAULT_PASSWORD},
                "tiandy": {"default_password": DEFAULT_PASSWORD},
                "onvif": {"default_password": DEFAULT_PASSWORD},
            },
            "concurrency": {"max_parallel_requests": 50},
        }
    )


async def build_demo_site(config: SiteConfig | None = None) -> SimulatedNetwork:
    network = SimulatedNetwork()
    for spec in demo_specs():
        await network.start_camera(spec)
    return network


def demo_target_capacity(config: SiteConfig) -> int:
    return config.ip_range.size()
