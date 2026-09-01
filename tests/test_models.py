"""Tests du modèle de données : transitions d'état, cumuls de rapport."""

from __future__ import annotations

from datetime import datetime

from ipcam_provisioner.models import (
    ActivationStatus,
    AssignmentResult,
    AssignmentStatus,
    Camera,
    Conflict,
    DiscoveryMethod,
    ResolutionStatus,
)


def make_camera(**kwargs) -> Camera:
    defaults = dict(
        mac_address="aa:bb:cc:00:00:01",
        ip_address="192.168.1.64",
        discovery_method=DiscoveryMethod.ARP_OUI_FALLBACK,
    )
    defaults.update(kwargs)
    return Camera(**defaults)


def test_mark_error_passes_pending_to_failed():
    camera = make_camera()
    assert camera.assignment_status is AssignmentStatus.PENDING
    camera.mark_error("boom")
    assert camera.assignment_status is AssignmentStatus.FAILED
    assert camera.last_error == "boom"
    assert camera.assignment_status is not AssignmentStatus.SUCCESS


def test_mark_error_does_not_overwrite_in_progress():
    camera = make_camera()
    camera.assignment_status = AssignmentStatus.IN_PROGRESS
    camera.mark_error("boom")
    assert camera.assignment_status is AssignmentStatus.IN_PROGRESS


def test_activation_status_default_is_unknown():
    assert make_camera().activation_status is ActivationStatus.UNKNOWN


def test_activation_result_and_temp_ip_are_none_by_default():
    camera = make_camera()
    assert camera.activation_result is None
    assert camera.temp_ip is None


def test_conflict_defaults():
    conflict = Conflict(conflicting_ip="10.0.0.1", camera_macs=["a", "b"])
    assert conflict.resolution_status is ResolutionStatus.UNRESOLVED
    assert conflict.winner_mac is None


def test_assignment_result_summary():
    result = AssignmentResult(site_name="Site", started_at=datetime.now())
    result.total_discovered = 5
    result.total_assigned = 3
    result.total_failed = 1
    result.total_manual_required = 1
    result.total_conflicts_detected = 2
    result.total_conflicts_resolved = 2
    assert result.summary() == {
        "discovered": 5,
        "assigned": 3,
        "failed": 1,
        "manual_required": 1,
        "conflicts_detected": 2,
        "conflicts_resolved": 2,
    }
