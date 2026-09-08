"""Transports réseau de l'outil (HTTP/TCP + UDP)."""

from .http import (
    HttpEndpointResolver,
    HttpTalker,
    NetworkResolver,
    ResolvedEndpoint,
    basic_auth,
    digest_auth,
)
from .udp import DatagramReply, ProbeEndpoint, ProbeKind, udp_probe

__all__ = [
    "DatagramReply",
    "HttpEndpointResolver",
    "HttpTalker",
    "NetworkResolver",
    "ProbeEndpoint",
    "ProbeKind",
    "ResolvedEndpoint",
    "basic_auth",
    "digest_auth",
    "udp_probe",
]
