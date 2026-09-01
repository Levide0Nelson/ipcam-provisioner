"""Tests de l'assistant de configuration interactive (Phase 5)."""

from __future__ import annotations

from ipcam_provisioner.config import ConfigError
from ipcam_provisioner.wizard import (
    WizardAnswers,
    answers_to_config,
    collect_answers,
    starter_yaml,
)


def _dialogue(*answers_with_defaults, default="", pwd=None):
    """Crée des inputs factices : `answers_with_defaults` pour les champs visibles
    ("" → valeur par défaut) et `pwd` une liste pour `ask_password` (saisies masquées).
    `pwd` est consommée dans l'ordre ; par défaut retourne "" (pas de mot de passe)."""
    iterator = iter(answers_with_defaults)
    pwd_iter = iter(pwd) if pwd is not None else None

    def ask(label, _dflt):
        return next(iterator, default)

    def ask_password(label):
        if pwd_iter is None:
            return ""
        return next(pwd_iter, "")

    return ask, ask_password


def test_collect_answers_defaults():
    ask, ask_password = _dialogue()
    answers = collect_answers(ask=ask, ask_password=ask_password, say=lambda *_: None)
    assert answers.site_name == "Site A"
    assert answers.ip_range_start == "192.168.1.10"
    assert answers.vendor_types == ["hikvision", "dahua", "tiandy", "onvif"]
    assert answers.default_password == ""


def test_collect_answers_custom():
    ask, ask_password = _dialogue(
        "Usine A",
        "10.0.0.100",
        "10.0.0.200",
        "255.255.0.0",
        "10.0.0.1",
        "1,3",
        pwd=["admin1234", "admin1234"],
    )
    answers = collect_answers(ask=ask, ask_password=ask_password, say=lambda *_: None)
    assert answers.site_name == "Usine A"
    assert answers.ip_range_start == "10.0.0.100"
    assert answers.ip_range_end == "10.0.0.200"
    assert answers.subnet_mask == "255.255.0.0"
    assert answers.gateway == "10.0.0.1"
    assert answers.vendor_types == ["hikvision", "tiandy"]
    assert answers.default_password == "admin1234"


def test_password_confirmation_retries_on_mismatch():
    """Deux saisies différentes sont refusées : l'assistant re-demande le mot de passe."""
    ask, ask_password = _dialogue(
        "Site",
        "192.168.1.10",
        "192.168.1.200",
        "255.255.255.0",
        "192.168.1.1",
        "1",
        # mauvaise confirmation d'abord, puis paire correcte
        pwd=["secret1", "secret2", "secret1", "secret1"],
    )
    messages = []
    answers = collect_answers(ask=ask, ask_password=ask_password, say=messages.append)
    assert answers.default_password == "secret1"
    assert any("correspondent pas" in m for m in messages)


def test_password_blank_allowed():
    """Laisser le mot de passe vide est autorisé (aucune activation auto)."""
    ask, ask_password = _dialogue(
        "Site",
        "192.168.1.10",
        "192.168.1.200",
        "255.255.255.0",
        "192.168.1.1",
        "1",
        pwd=["", "", ""],
    )
    answers = collect_answers(ask=ask, ask_password=ask_password, say=lambda *_: None)
    assert answers.default_password == ""


def test_collect_answers_edit_keeps_values_on_enter():
    """En mode édition (`initial`), saisir Entrée conserve les valeurs existantes,
    y compris un mot de passe déjà défini (conservé à l'identique)."""
    existing = WizardAnswers(
        site_name="Site A",
        ip_range_start="10.1.1.10",
        ip_range_end="10.1.1.200",
        subnet_mask="255.255.255.0",
        gateway="10.1.1.1",
        vendor_types=["hikvision", "dahua", "tiandy"],
        default_password="oldpass",
    )
    # tout Entrée → on conserve chaque valeur, y compris le mot de passe existant
    ask, ask_password = _dialogue(pwd=["", ""])
    answers = collect_answers(
        ask=ask, ask_password=ask_password, say=lambda *_: None, initial=existing
    )
    assert answers.site_name == "Site A"
    assert answers.ip_range_start == "10.1.1.10"
    assert answers.ip_range_end == "10.1.1.200"
    assert answers.gateway == "10.1.1.1"
    # les types pré-remplis sont conservés
    assert answers.vendor_types == ["hikvision", "dahua", "tiandy"]
    # mot de passe conservé sans retaper
    assert answers.default_password == "oldpass"


def test_collect_answers_edit_replaces_password():
    """En mode édition, un nouveau mot de passe saisi (et confirmé) remplace l'ancien."""
    existing = WizardAnswers(
        site_name="Site A",
        ip_range_start="10.1.1.10",
        ip_range_end="10.1.1.200",
        subnet_mask="255.255.255.0",
        gateway="10.1.1.1",
        vendor_types=["hikvision"],
        default_password="oldpass",
    )
    ask, ask_password = _dialogue(pwd=["newpass", "newpass"])
    answers = collect_answers(
        ask=ask, ask_password=ask_password, say=lambda *_: None, initial=existing
    )
    assert answers.default_password == "newpass"


def test_parse_types_rejects_bad_numbers():
    from ipcam_provisioner.wizard import _parse_types

    assert _parse_types("2") == ["dahua"]
    try:
        _parse_types("5")
    except ConfigError as exc:
        assert "hors plage" in str(exc)
    else:
        raise AssertionError("ConfigError attendue")
    try:
        _parse_types("abc")
    except ConfigError:
        pass
    else:
        raise AssertionError("ConfigError attendue")


def test_answers_to_config_is_valid():
    answers = WizardAnswers(
        site_name="Site",
        ip_range_start="192.168.10.10",
        ip_range_end="192.168.10.200",
        subnet_mask="255.255.255.0",
        gateway="192.168.10.1",
        vendor_types=["hikvision", "onvif"],
    )
    cfg = answers_to_config(answers)
    assert cfg.site_name == "Site"
    assert cfg.ip_range.contains("192.168.10.100")
    assert set(cfg.vendors) == {"hikvision", "onvif"}
    assert cfg.vendors["hikvision"].default_password == ""


def test_answers_to_config_rejects_bad_range():
    from ipcam_provisioner.config import ConfigError

    answers = WizardAnswers(
        site_name="Site",
        ip_range_start="999.1.1.1",
        ip_range_end="192.168.10.200",
        subnet_mask="255.255.255.0",
        gateway="192.168.10.1",
    )
    try:
        answers_to_config(answers)
    except ConfigError:
        pass
    else:
        raise AssertionError("ConfigError attendue")


def test_starter_yaml_roundtrips_through_load_config(tmp_path):
    from ipcam_provisioner.config import load_config

    answers = WizardAnswers(
        site_name="Usine",
        ip_range_start="10.0.0.50",
        ip_range_end="10.0.0.150",
        subnet_mask="255.255.255.0",
        gateway="10.0.0.1",
        vendor_types=["hikvision", "dahua"],
        default_password="admin1234",
    )
    path = tmp_path / "site.yaml"
    path.write_text(starter_yaml(answers), encoding="utf-8")
    cfg = load_config(path)
    assert cfg.site_name == "Usine"
    assert cfg.ip_range.contains("10.0.0.100")
    assert cfg.vendors["hikvision"].default_password == "admin1234"
    assert cfg.vendors["dahua"].default_password == "admin1234"


def test_collect_answers_corrects_ivan_and_zero_ip():
    """Une adresse incomplète (195.154.3, acceptée à tort par IPv4Address) ou non
    routeable (0.0.0.0) est refusée : la question est re-posée jusqu'à une saisie valide."""
    answers_input = iter([
        "Site X",
        "195.154.3",       # invalide (IVAN) → re-posé
        "192.168.1.10",    # correct
        "0.0.0.0",         # invalide (non routeable) → re-posé
        "192.168.1.200",   # correct
        "",
        "",
        "1,2",
        "",
    ])

    def ask(label, _dflt):
        return next(answers_input)

    messages = []
    answers = collect_answers(ask=ask, ask_password=lambda _label: "", say=messages.append)
    assert answers.ip_range_start == "192.168.1.10"
    assert answers.ip_range_end == "192.168.1.200"
    assert any("erreur" in m for m in messages)


def test_collect_answers_corrects_reversed_range():
    """Si la fin précède le début, l'assistant re-pose les deux adresses."""
    answers_input = iter([
        "Site",
        "192.168.1.200",
        "192.168.1.10",
        "",
        "",
        "192.168.1.10",
        "192.168.1.200",
        "",
        "",
    ])

    def ask(label, _dflt):
        return next(answers_input)

    messages = []
    answers = collect_answers(ask=ask, ask_password=lambda _label: "", say=messages.append)
    assert answers.ip_range_start == "192.168.1.10"
    assert answers.ip_range_end == "192.168.1.200"
    assert any("erreur" in m for m in messages)


def test_collect_answers_corrects_bad_subnet():
    """Un masque non contigu (255.255.0.255) est refusé."""
    answers_input = iter([
        "Site",
        "192.168.1.10",
        "192.168.1.200",
        "255.255.0.255",   # non contigu → re-posé
        "255.255.255.0",
        "",
        "",
        "",
    ])

    def ask(label, _dflt):
        return next(answers_input)

    messages = []
    answers = collect_answers(ask=ask, ask_password=lambda _label: "", say=messages.append)
    assert answers.subnet_mask == "255.255.255.0"
    assert any("erreur" in m for m in messages)


def test_is_ip_rejects_ivan_and_zero():
    from ipcam_provisioner.wizard import _is_ip

    assert not _is_ip("195.154.3")
    assert not _is_ip("195.154.3.")
    assert not _is_ip("0.0.0.0")
    assert not _is_ip("192.168.1")
    assert not _is_ip("192.168.1.256")
    assert _is_ip("192.168.1.10")
    assert _is_ip("255.255.255.0")
