"""Caméras virtuelles et réseau simulé pour la Phase 1 (sans matériel réel)."""

from .camera import CameraSpec, VirtualCamera
from .demo import build_demo_site, demo_config, demo_specs
from .network import SimulatedNetwork

__all__ = [
    "CameraSpec",
    "SimulatedNetwork",
    "VirtualCamera",
    "build_demo_site",
    "demo_config",
    "demo_specs",
]
