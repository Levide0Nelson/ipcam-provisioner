"""Fingerprinting : identify(camera) -> Camera (un appel HTTP/ONVIF par appareil)."""

from .base import FingerprintContext, FingerprintEngine, Fingerprinter
from .dahua import DahuaFingerprinter
from .hikvision import HikvisionFingerprinter
from .onvif import OnvifFingerprinter
from .tiandy import TiandyFingerprinter

REGISTRY: dict[str, Fingerprinter] = {
    "hikvision": HikvisionFingerprinter(),
    "dahua": DahuaFingerprinter(),
    "tiandy": TiandyFingerprinter(),
    "onvif": OnvifFingerprinter(),
    "generic": OnvifFingerprinter(),
}


def build_engine(ctx: FingerprintContext) -> FingerprintEngine:
    return FingerprintEngine(ctx, REGISTRY)


__all__ = [
    "FingerprintContext",
    "FingerprintEngine",
    "REGISTRY",
    "build_engine",
]
