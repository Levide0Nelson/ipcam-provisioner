"""Modèle de données de l'outil (section 3 de la spécification).

Chaque attribut est rempli progressivement par une étape du pipeline ; une valeur par
défaut signifie « étape pas encore atteinte », pas « erreur ».
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


class RunMode(enum.Enum):
    """Modes de fonctionnement du pipeline (modules de clarification)."""

    DISCOVER = "discover"
    ASSIGN = "assign"
    ACTIVATE_ASSIGN = "activate_assign"


class DiscoveryMethod(enum.Enum):
    SADP = "sadp"
    DAHUA_DISCOVERY = "dahua_discovery"
    TIANDY_DISCOVERY = "tiandy_discovery"
    ONVIF_WS_DISCOVERY = "onvif_ws_discovery"
    ARP_OUI_FALLBACK = "arp_oui_fallback"
    ACTIVE_SUBNET_SCAN = "active_subnet_scan"


class ActivationStatus(enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"


class ActivationResult(enum.Enum):
    """Résultat de la tentative d'activation, pour le rapport final (section 5)."""

    SUCCESS = "success"
    FAILED = "failed"
    MANUAL_REQUIRED = "manual_required"


class AssignmentStatus(enum.Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"


class ResolutionStatus(enum.Enum):
    UNRESOLVED = "unresolved"
    RESOLVING = "resolving"
    RESOLVED = "resolved"
    FAILED = "failed"


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


@dataclass
class Camera:
    """État courant d'une caméra découverte sur le site."""

    mac_address: str
    ip_address: str
    discovery_method: DiscoveryMethod
    discovered_at: datetime = field(default_factory=datetime.now)
    raw_discovery_payload: dict[str, Any] = field(default_factory=dict)

    vendor: str | None = None
    vendor_confirmed: bool = False

    model: str | None = None
    serial_number: str | None = None
    firmware_version: str | None = None
    activation_status: ActivationStatus = ActivationStatus.UNKNOWN
    activation_result: ActivationResult | None = None

    has_conflict: bool = False
    temp_ip: str | None = None
    target_ip: str | None = None
    assignment_status: AssignmentStatus = AssignmentStatus.PENDING
    last_error: str | None = None

    def mark_error(self, message: str) -> None:
        self.last_error = message
        if self.assignment_status == AssignmentStatus.PENDING:
            self.assignment_status = AssignmentStatus.FAILED


@dataclass
class Conflict:
    """Conflit d'adresse IP entre deux caméras ou plus, identifiées par MAC."""

    conflicting_ip: str
    camera_macs: list[str]
    detected_at: datetime = field(default_factory=datetime.now)
    resolution_status: ResolutionStatus = ResolutionStatus.UNRESOLVED
    resolution_method: str | None = None
    resolution_detail: str | None = None
    winner_mac: str | None = None


@dataclass
class AssignmentResult:
    """Rapport de synthèse d'un run orchestration."""

    site_name: str
    started_at: datetime = field(default_factory=datetime.now)
    finished_at: datetime | None = None
    run_mode: str = "discover"
    total_discovered: int = 0
    total_assigned: int = 0
    total_failed: int = 0
    total_manual_required: int = 0
    total_conflicts_detected: int = 0
    total_conflicts_resolved: int = 0
    cameras: list[Camera] = field(default_factory=list)
    conflicts: list[Conflict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        return {
            "discovered": self.total_discovered,
            "assigned": self.total_assigned,
            "failed": self.total_failed,
            "manual_required": self.total_manual_required,
            "conflicts_detected": self.total_conflicts_detected,
            "conflicts_resolved": self.total_conflicts_resolved,
        }


def capture_timestamp() -> str:
    """Horodatage court et stable pour les logs (tout en ASCII)."""
    return _now()


__all__ = [
    "ActivationResult",
    "ActivationStatus",
    "AssignmentResult",
    "AssignmentStatus",
    "Camera",
    "Conflict",
    "DiscoveryMethod",
    "ResolutionStatus",
    "RunMode",
    "capture_timestamp",
]
