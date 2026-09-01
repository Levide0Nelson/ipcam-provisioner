"""Tests de la CLI : parser, codes de retour, mode simulation."""

from __future__ import annotations

import json

from ipcam_provisioner import cli
from ipcam_provisioner.models import AssignmentResult


def test_build_parser_defaults():
    parser = cli.build_parser()
    args = parser.parse_args([])
    assert args.config == "config/example_site.yaml"
    assert args.simulate is False
    assert args.log_level == "INFO"


def test_render_outputs_summary(capsys):
    result = AssignmentResult(site_name="Démo")
    result.total_discovered = 8
    result.total_assigned = 8
    result.total_conflicts_detected = 2
    result.total_conflicts_resolved = 2
    cli.render(result)
    captured = capsys.readouterr()
    assert "Démo" in captured.out
    assert "Caméras découvertes" in captured.out
    assert "attribuées" in captured.out


def test_render_lists_last_error(capsys):
    from ipcam_provisioner.models import Camera, DiscoveryMethod

    result = AssignmentResult(site_name="Démo")
    camera = Camera(
        mac_address="aa:bb:cc:00:00:01",
        ip_address="10.0.0.2",
        discovery_method=DiscoveryMethod.ARP_OUI_FALLBACK,
    )
    camera.mark_error("attribution : erreur réseau")
    result.cameras = [camera]
    cli.render(result)
    assert "erreur réseau" in capsys.readouterr().out


def test_render_manual_required_block_when_present(capsys):
    from ipcam_provisioner.models import (
        ActivationResult,
        ActivationStatus,
        Camera,
        DiscoveryMethod,
    )

    result = AssignmentResult(site_name="Démo")
    camera = Camera(
        mac_address="aa:bb:cc:00:00:01",
        ip_address="10.0.0.2",
        discovery_method=DiscoveryMethod.ARP_OUI_FALLBACK,
        activation_status=ActivationStatus.INACTIVE,
        activation_result=ActivationResult.MANUAL_REQUIRED,
    )
    result.cameras = [camera]
    result.total_manual_required = 1
    cli.render(result)
    out = capsys.readouterr().out
    assert "Activation manuelle requise :   1" in out
    assert "Caméras nécessitant une activation manuelle" in out
    assert "aa:bb:cc:00:00:01" in out
    assert "10.0.0.2" in out


def test_render_omits_manual_required_block_when_none(capsys):
    from ipcam_provisioner.models import (
        ActivationResult,
        ActivationStatus,
        Camera,
        DiscoveryMethod,
    )

    result = AssignmentResult(site_name="Démo")
    camera = Camera(
        mac_address="aa:bb:cc:00:00:01",
        ip_address="10.0.0.2",
        discovery_method=DiscoveryMethod.ARP_OUI_FALLBACK,
        activation_status=ActivationStatus.ACTIVE,
        activation_result=ActivationResult.SUCCESS,
    )
    result.cameras = [camera]
    cli.render(result)
    out = capsys.readouterr().out
    assert "activation manuelle" not in out


def test_render_table_shows_columns_and_state_notes(capsys):
    from ipcam_provisioner.models import (
        ActivationResult,
        ActivationStatus,
        AssignmentStatus,
        Camera,
        DiscoveryMethod,
    )

    result = AssignmentResult(site_name="Démo")
    result.cameras = [
        Camera(
            mac_address="ac:cc:8e:00:00:01",
            ip_address="192.168.5.102",
            discovery_method=DiscoveryMethod.SADP,
            vendor="hikvision",
            model="IPC-X",
            activation_status=ActivationStatus.ACTIVE,
            activation_result=ActivationResult.SUCCESS,
            has_conflict=True,
            temp_ip="192.0.0.1",
            target_ip="192.168.5.102",
            assignment_status=AssignmentStatus.SUCCESS,
        ),
        Camera(
            mac_address="e0:50:8b:00:00:01",
            ip_address="192.168.5.105",
            discovery_method=DiscoveryMethod.DAHUA_DISCOVERY,
            vendor="dahua",
            activation_status=ActivationStatus.ACTIVE,
            activation_result=ActivationResult.SUCCESS,
            target_ip="192.168.5.105",
            assignment_status=AssignmentStatus.SUCCESS,
        ),
    ]
    cli.render(result)
    out = capsys.readouterr().out
    assert "MAC" in out
    assert "Vendor" in out
    assert "Modèle" in out
    assert "État" in out
    # notes enrichies : conflit + IP temporaire
    assert "conflit" in out
    assert "temp 192.0.0.1" in out
    assert "IPC-X" in out
    # chaque colonne alignée sur une ligne du tableau
    assert "ac:cc:8e:00:00:01" in out
    assert "e0:50:8b:00:00:01" in out


def test_render_empty_camera_list(capsys):
    result = AssignmentResult(site_name="Démo")
    cli.render(result)
    assert "aucune caméra découverte" in capsys.readouterr().out


def test_render_vendor_totals(capsys):
    from ipcam_provisioner.models import Camera, DiscoveryMethod

    result = AssignmentResult(site_name="Démo")
    result.cameras = [
        Camera(
            mac_address=f"ac:cc:8e:00:00:{i:02d}",
            ip_address=f"192.168.5.{100+i}",
            discovery_method=DiscoveryMethod.SADP,
            vendor="hikvision",
        )
        for i in range(3)
    ] + [
        Camera(
            mac_address=f"e0:50:8b:00:00:{i:02d}",
            ip_address=f"192.168.5.{110+i}",
            discovery_method=DiscoveryMethod.DAHUA_DISCOVERY,
            vendor="dahua",
        )
        for i in range(2)
    ]
    cli.render(result)
    out = capsys.readouterr().out
    assert "Répartition par fabricant" in out
    assert "hikvision" in out
    assert "dahua" in out
    assert "3" in out
    assert "2" in out
    # le fabricant majoritaire apparaît en premier (tri décroissant)
    assert out.index("hikvision") < out.index("dahua")


def test_render_vendor_totals_omitted_when_none(capsys):
    from ipcam_provisioner.models import Camera, DiscoveryMethod

    result = AssignmentResult(site_name="Démo")
    result.cameras = [
        Camera(
            mac_address="aa:bb:cc:00:00:01",
            ip_address="10.0.0.2",
            discovery_method=DiscoveryMethod.ARP_OUI_FALLBACK,
        )
    ]
    cli.render(result)
    assert "Répartition par fabricant" not in capsys.readouterr().out


def test_main_missing_config_returns_two(capsys):
    rc = cli.main(["--config", "does-not-exist.yaml"])
    assert rc == 2
    assert "introuvable" in capsys.readouterr().err


def test_main_simulate_runs_end_to_end(capsys, monkeypatch):
    from ipcam_provisioner.simulation import demo

    original = demo.demo_config

    def short_demo_config():
        cfg = original()
        cfg.discovery.timeout_seconds = 0.3
        return cfg

    monkeypatch.setattr(demo, "demo_config", short_demo_config)
    rc = cli.main(["--simulate", "--log-level", "WARNING"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "attribuées" in out
    assert "8" in out


def test_main_init_writes_valid_yaml(tmp_path, capsys):
    dest = tmp_path / "site.yaml"
    rc = cli.main(["--init", str(dest)])
    assert rc == 0
    assert dest.exists()
    assert "Configuration de départ écrite" in capsys.readouterr().out
    from ipcam_provisioner.config import load_config

    cfg = load_config(dest)
    assert cfg.site_name == "Site A"
    assert "hikvision" in cfg.vendors


def test_main_init_refuses_existing_file(tmp_path, capsys):
    dest = tmp_path / "site.yaml"
    dest.write_text("site_name: old\n", encoding="utf-8")
    rc = cli.main(["--init", str(dest)])
    assert rc == 2
    assert "existe déjà" in capsys.readouterr().err


def test_main_wizard_writes_provided_answers(tmp_path, capsys, monkeypatch):
    from ipcam_provisioner import wizard

    dest = tmp_path / "wiz.yaml"
    replies = iter(["Usine B", "10.0.0.10", "10.0.0.200", "255.255.255.0", "10.0.0.1", "2"])
    original = wizard.collect_answers

    def fake_collect_answers(**kwargs):
        answers = original(
            ask=lambda _l, _d: next(replies),
            ask_password=lambda _l: "letmein",
            say=lambda *_: None,
        )
        return answers

    monkeypatch.setattr(wizard, "collect_answers", fake_collect_answers)
    rc = cli.main(["--wizard", "--config", str(dest)])
    assert rc == 0
    assert dest.exists()
    from ipcam_provisioner.config import load_config

    cfg = load_config(dest)
    assert cfg.site_name == "Usine B"
    assert set(cfg.vendors) == {"dahua"}
    assert cfg.ip_range.contains("10.0.0.100")
    assert cfg.vendors["dahua"].default_password == "letmein"


def test_menu_quits_on_zero(capsys):
    rc = cli._run_menu("config/does-not-exist.yaml", ask=lambda _: "0")
    assert rc == 0
    assert "Quitter" in capsys.readouterr().out


def test_menu_rejects_invalid_then_quits(capsys):
    answers = iter(["X", "0"])

    def ask(_label):
        return next(answers)

    rc = cli._run_menu("config/does-not-exist.yaml", ask=ask)
    assert rc == 0
    out = capsys.readouterr().out
    assert "choix invalide" in out


def test_menu_simulate_action_dispatches(capsys, monkeypatch):
    answers = iter(["2", "0"])
    monkeypatch.setattr(cli, "_run_simulated", lambda json_path=None: 0)
    rc = cli._run_menu("config/does-not-exist.yaml", ask=lambda _: next(answers))
    assert rc == 0


def test_menu_dispatches_config_wizard(capsys, tmp_path, monkeypatch):
    dest = tmp_path / "menu_wiz.yaml"
    # option 3 (gestion config) → 2 (modifier) → 0 (retour) → 0 (quitter)
    answers = iter(["3", "2", "0", "0"])
    calls = []

    def fake_edit(path, ask, say):
        calls.append(("edit", path))

    monkeypatch.setattr(cli, "_run_config_edit", fake_edit)
    rc = cli._run_menu(str(dest), ask=lambda _: next(answers))
    assert rc == 0
    assert calls == [("edit", str(dest))]


def test_config_menu_creates_edit_deletes_inits(capsys, monkeypatch, tmp_path):
    dest = tmp_path / "menu_cfg.yaml"
    # sous-menu : 1 (créer) → 4 (init) → 3 (supprimer) → 0 (retour)
    answers = iter(["1", "4", "3", "0"])
    seen = []

    monkeypatch.setattr(cli, "_run_wizard", lambda path: seen.append(("wizard", path)))
    monkeypatch.setattr(cli, "_run_init", lambda dest, src: seen.append(("init", dest)))
    monkeypatch.setattr(cli, "_run_config_delete", lambda *a, **k: seen.append(("delete",)))

    cli._run_config_menu(str(dest), ask=lambda _: next(answers), say=lambda *_: None)
    assert [s[0] for s in seen] == ["wizard", "init", "delete"]
    assert seen[0][1] == str(dest)


def test_pick_rehearse_method_by_number():
    from ipcam_provisioner.models import DiscoveryMethod

    # 2 = SADP (2e entrée du sous-menu)
    method = cli._pick_rehearse_method(ask=lambda _: "2", say=lambda *_: None)
    assert method is DiscoveryMethod.SADP


def test_pick_rehearse_method_zero_returns_none():
    method = cli._pick_rehearse_method(ask=lambda _: "0", say=lambda *_: None)
    assert method is None


def test_menu_rehearse_uses_submenu_then_loops(capsys, monkeypatch):
    from ipcam_provisioner.models import DiscoveryMethod

    # option 5, puis méthode 1 (ONVIF), puis quitter
    calls = {"rehearsed": None}
    answers = iter(["5", "1", "0"])

    def fake_rehearse(method):
        calls["rehearsed"] = method

    monkeypatch.setattr(cli, "_rehearse_discovery", fake_rehearse)
    rc = cli._run_menu("config/x.yaml", ask=lambda _: next(answers))
    assert rc == 0
    assert calls["rehearsed"] is DiscoveryMethod.ONVIF_WS_DISCOVERY


def test_render_conflicts_resolved_block(capsys):
    from ipcam_provisioner.models import Conflict, ResolutionStatus

    result = AssignmentResult(site_name="Démo")
    result.conflicts = [
        Conflict(
            conflicting_ip="192.0.0.64",
            camera_macs=["ac:cc:8e:00:00:01", "e0:50:8b:00:00:01"],
            resolution_status=ResolutionStatus.RESOLVED,
            resolution_method="mac_addressed_broadcast",
            winner_mac="ac:cc:8e:00:00:01",
        )
    ]
    cli.render(result)
    out = capsys.readouterr().out
    assert "Conflits d'adresse résolus" in out
    assert "192.0.0.64" in out
    assert "ac:cc:8e:00:00:01" in out
    assert "e0:50:8b:00:00:01" in out
    assert "vainqueur" in out


def test_render_conflicts_block_omitted_when_none(capsys):
    cli.render(AssignmentResult(site_name="Démo"))
    assert "Conflits d'adresse résolus" not in capsys.readouterr().out


def test_json_export_writes_serialized_report(tmp_path, capsys):
    from ipcam_provisioner.models import Camera, Conflict, DiscoveryMethod, ResolutionStatus

    result = AssignmentResult(site_name="Démo")
    result.total_discovered = 1
    result.total_assigned = 1
    result.cameras = [
        Camera(
            mac_address="ac:cc:8e:00:00:01",
            ip_address="192.168.5.102",
            discovery_method=DiscoveryMethod.SADP,
            vendor="hikvision",
            model="DS-2CD2042WD-I",
        )
    ]
    result.conflicts = [
        Conflict(
            conflicting_ip="192.0.0.64",
            camera_macs=["ac:cc:8e:00:00:01"],
            resolution_status=ResolutionStatus.RESOLVED,
            winner_mac="ac:cc:8e:00:00:01",
        )
    ]
    dest = tmp_path / "rapport.json"
    rc = cli._emit_report(result, str(dest))
    assert rc == 0
    assert dest.exists()
    assert "Rapport JSON écrit" in capsys.readouterr().out

    data = json.loads(dest.read_text(encoding="utf-8"))
    assert data["site_name"] == "Démo"
    assert data["summary"]["discovered"] == 1
    assert data["cameras"][0]["model"] == "DS-2CD2042WD-I"
    assert data["conflicts"][0]["conflicting_ip"] == "192.0.0.64"
    assert data["errors"] == []


def test_config_delete_removes_file(tmp_path, capsys):
    dest = tmp_path / "site.yaml"
    dest.write_text("site_name: A\n", encoding="utf-8")
    rc = cli._run_config_delete(str(dest), ask=lambda _l: "o")
    assert rc == 0
    assert not dest.exists()
    assert "Configuration supprimée" in capsys.readouterr().out


def test_config_delete_aborts_without_confirmation(tmp_path, capsys):
    dest = tmp_path / "site.yaml"
    dest.write_text("site_name: A\n", encoding="utf-8")
    rc = cli._run_config_delete(str(dest), ask=lambda _l: "N")
    assert rc == 0
    assert dest.exists()
    assert "Suppression annulée" in capsys.readouterr().out


def test_config_delete_missing_file_returns_two(tmp_path, capsys):
    rc = cli._run_config_delete(str(tmp_path / "absent.yaml"), ask=lambda _l: "o")
    assert rc == 2
    assert "n'existe pas" in capsys.readouterr().err


def test_config_edit_updates_existing_values(tmp_path, capsys):
    from ipcam_provisioner.config import load_config
    from ipcam_provisioner.wizard import WizardAnswers, starter_yaml

    initial = WizardAnswers(
        site_name="Site A",
        ip_range_start="192.168.1.10",
        ip_range_end="192.168.1.250",
        subnet_mask="255.255.255.0",
        gateway="192.168.1.1",
        vendor_types=["hikvision", "dahua"],
    )
    dest = tmp_path / "site.yaml"
    dest.write_text(starter_yaml(initial), encoding="utf-8")

    # Édition : on change le nom du site et la passerelle, on garde le reste par Entrée.
    replies = iter(["Site Renomme", "", "", "", "10.0.0.1", ""])
    rc = cli._run_config_edit(
        str(dest),
        ask=lambda _l, _d: next(replies),
        ask_password=lambda _l: "",
        say=lambda *_: None,
    )
    assert rc == 0
    cfg = load_config(dest)
    assert cfg.site_name == "Site Renomme"
    assert str(cfg.gateway) == "10.0.0.1"
    assert set(cfg.vendors) == {"hikvision", "dahua"}
    assert "Configuration modifiée" in capsys.readouterr().out


def test_config_edit_without_say_uses_print(tmp_path, capsys):
    """Régression : `--config-edit` doit fonctionner quand `say` n'est pas injecté
    (appel réel depuis main()), faute de quoi TypeError: 'NoneType' object is not callable."""
    from ipcam_provisioner.wizard import WizardAnswers, starter_yaml

    initial = WizardAnswers(
        site_name="Site A",
        ip_range_start="192.168.1.10",
        ip_range_end="192.168.1.250",
        subnet_mask="255.255.255.0",
        gateway="192.168.1.1",
        vendor_types=["hikvision"],
    )
    dest = tmp_path / "site.yaml"
    dest.write_text(starter_yaml(initial), encoding="utf-8")

    # `say` n'est volontairement pas fourni → défaut à print (aucun crash).
    # Tous les champs gardés par Entrée ("").
    replies = iter(["", "", "", "", "", ""])
    rc = cli._run_config_edit(
        str(dest),
        ask=lambda _l, _d: next(replies),
        ask_password=lambda _l: "",
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "Édition de la configuration" in out
    assert "Configuration modifiée" in out
