"""Tests de bout en bout : le pipeline complet en simulation (Phase 1)."""

from __future__ import annotations

import pytest

from ipcam_provisioner.models import (
    ActivationResult,
    ActivationStatus,
    AssignmentStatus,
    RunMode,
)
from ipcam_provisioner.orchestrator import run


async def test_full_pipeline_demo(config, network):
    result = await run(config, sim_network=network)
    assert result.errors == []
    assert result.summary() == {
        "discovered": 8,
        "assigned": 8,
        "failed": 0,
        "manual_required": 0,
        "conflicts_detected": 2,
        "conflicts_resolved": 2,
    }
    assert all(
        c.assignment_status is AssignmentStatus.SUCCESS for c in result.cameras
    )


async def test_activation_happens_before_resolution(config, network):
    """Chaque caméra inactive d'usine est activée puis les conflits sont levés sur IP
    temporaires : les conflits concernent des caméras actives."""
    result = await run(config, sim_network=network)
    activated = [
        c for c in result.cameras if c.activation_result is ActivationResult.SUCCESS
    ]
    assert len(activated) == 5
    # toute caméra ayant porté un conflit est active (détection post-activation)
    conflicted = [c for c in result.cameras if c.has_conflict]
    assert len(conflicted) == 4
    assert all(c.activation_status is ActivationStatus.ACTIVE for c in conflicted)


async def test_conflicts_use_unique_mac_addressed_temp_ips(config, network):
    result = await run(config, sim_network=network)
    conflicted = [c for c in result.cameras if c.has_conflict]
    factory = {"192.0.0.64", "192.168.5.23"}
    for camera in conflicted:
        assert camera.temp_ip is not None
        assert camera.temp_ip not in factory
        assert camera.temp_ip != camera.target_ip
        assert camera.ip_address == camera.target_ip
    temps = [c.temp_ip for c in conflicted]
    assert len(temps) == len(set(temps))


async def test_all_targets_within_range_and_unique(config, network):
    result = await run(config, sim_network=network)
    targets = [c.target_ip for c in result.cameras]
    assert len(targets) == len(set(targets))
    for ip in targets:
        assert config.ip_range.contains(ip)


async def test_no_camera_left_at_factory_ip(config, network):
    result = await run(config, sim_network=network)
    for camera in result.cameras:
        assert camera.ip_address not in {"192.0.0.64", "192.0.0.65", "10.1.1.20", "169.254.20.64"}


async def test_target_allocation_is_deterministic(config, network):
    """Tri par MAC : la première caméra libre reçoit la plus petite adresse disponible."""
    result = await run(config, sim_network=network)
    by_mac = {c.mac_address: c for c in result.cameras}
    assert by_mac["00:cc:2f:00:00:01"].target_ip == "192.168.5.100"
    assert by_mac["aa:bb:cc:00:00:01"].target_ip == "192.168.5.101"
    assert by_mac["ac:cc:8e:00:00:01"].target_ip == "192.168.5.102"


@pytest.mark.parametrize("mac", ["E0:50:8b:00:00:01", "aa:bb:cc:00:00:01"])
async def test_conflict_cameras_both_assigned(config, network, mac):
    result = await run(config, sim_network=network)
    camera = next(c for c in result.cameras if c.mac_address == mac.lower())
    assert camera.assignment_status is AssignmentStatus.SUCCESS
    assert camera.last_error is None


async def test_re_fingerprint_populates_model_after_activation(config, network):
    """Les caméras inactives d'usine sont re-fingerprintées après activation : le rapport
    expose leur modèle/série/firmware au lieu de laisser la colonne vide."""
    result = await run(config, sim_network=network)
    activated = [
        c
        for c in result.cameras
        if c.activation_result is ActivationResult.SUCCESS
        and c.last_error is None
    ]
    assert activated
    for camera in activated:
        assert camera.model is not None, camera.mac_address
        assert camera.serial_number is not None, camera.mac_address
        assert camera.firmware_version is not None, camera.mac_address


async def test_confirm_write_false_skips_all_writes(config, network):
    """`confirm_write` refusant tout : aucune caméra n'est attribuée (le pipeline
    garde tout en lecture seule) et aucune n'est modifiée sur le réseau simulé."""
    result = await run(config, sim_network=network, confirm_write=lambda camera: False)
    # aucune attribution réussie
    assert result.total_assigned == 0
    # les caméras restent sur leur IP découverte (IP usine non réassignée)
    for camera in result.cameras:
        assert camera.assignment_status is not AssignmentStatus.SUCCESS
        assert camera.target_ip != camera.ip_address


async def test_confirm_write_false_marks_manual_required(config, network):
    """Le rejet d'écriture est visible dans le rapport : les caméras non attribuées
    sont marquées comme nécessitant une action manuelle (pas un silence)."""
    result = await run(config, sim_network=network, confirm_write=lambda camera: False)
    assert result.total_manual_required == 8
    assert all(
        c.activation_result is ActivationResult.MANUAL_REQUIRED for c in result.cameras
    )


async def test_discover_mode_is_read_only(config, network):
    """Mode DISCOVER : aucune écriture réseau — aucune attribution, masque ni
    modification d'IP. Les caméras restent identifiées mais non planifiées."""
    result = await run(config, sim_network=network, mode=RunMode.DISCOVER)
    assert result.run_mode == "discover"
    assert result.total_assigned == 0
    assert result.summary()["assigned"] == 0
    for camera in result.cameras:
        assert camera.assignment_status is not AssignmentStatus.SUCCESS
        assert camera.target_ip is None
        assert camera.temp_ip is None
        assert camera.activation_status is ActivationStatus.ACTIVE or camera.activation_result is None


async def test_discover_mode_still_identifies_cameras(config, network):
    """Mode DISCOVER ne modifie rien mais découvre et identifie tout le parc."""
    result = await run(config, sim_network=network, mode=RunMode.DISCOVER)
    assert result.total_discovered == 8
    assert all(c.vendor is not None for c in result.cameras)


async def test_assign_mode_skips_activation_but_assigns_active(config, network):
    """Mode ASSIGN : pas d'activation (les inactives sont laissées en manuel) mais les
    caméras déjà actives sont bien attribuées."""
    result = await run(config, sim_network=network, mode=RunMode.ASSIGN)
    assert result.run_mode == "assign"
    # aucune caméra activée par le pipeline (une inactive le reste / devient manuel)
    assert not any(c.activation_result is ActivationResult.SUCCESS for c in result.cameras)
    # les 3 caméras déjà actives sont attribuées
    active = [
        c
        for c in result.cameras
        if c.activation_status is ActivationStatus.ACTIVE and c.last_error is None
    ]
    assert len(active) == 3
    assert all(c.assignment_status is AssignmentStatus.SUCCESS for c in active)
    # les 5 inactives passent en activation manuelle requise
    inactive = [c for c in result.cameras if c.activation_status is not ActivationStatus.ACTIVE]
    assert len(inactive) == 5
    assert all(c.activation_result is ActivationResult.MANUAL_REQUIRED for c in inactive)
