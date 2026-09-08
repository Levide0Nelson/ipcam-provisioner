# -*- coding: utf-8 -*-
"""Interface CLI : formatage/affichage uniquement, jamais de logique metier (section 5).

`render(result)` est le seul point de presentation : synthese + detail par camera vers
stdout, les logs structures (JSON-lines) vont sur stderr.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import logging
import sys
from pathlib import Path

import yaml

from .config import ConfigError, build_config, load_config
from .logging_conf import setup_logging
from .models import ActivationResult, AssignmentResult, DiscoveryMethod, ResolutionStatus, RunMode

IS_SIMULATION_DOC = (
    "Phase 1 — sans materiel : le pipeline tourne sur des cameras simulees "
    "(mocks UDP/HTTP Hikvision/Dahua/Tiandy/ONVIF + ARP)."
)


def _get_active_interface_ips() -> list[tuple[str, str, str]]:
    """Retourne la liste des (interface_name, ipv4, cidr) pour les interfaces UP
    avec une IPv4 non loopback/link-local. Utilise `ipconfig`/`ifconfig` via stdlib."""
    ips: list[tuple[str, str, str]] = []
    try:
        import subprocess
        if sys.platform == "win32":
            # `ipconfig` : parse les blocs par adaptateur (sortie CP1252 sur Windows FR)
            proc = subprocess.run(["ipconfig"], capture_output=True, check=False)
            out = proc.stdout.decode("cp1252", errors="replace")
            current_iface = None
            for line in out.splitlines():
                line_stripped = line.strip()
                # Interface header line (doesn't start with space, has colon)
                if line and not line.startswith(" ") and ":" in line:
                    current_iface = line_stripped.rstrip(":")
                    # Sanitize interface name for safe terminal display
                    # Replace common CP1252 mojibake chars with ASCII equivalents
                    sanitized = current_iface
                    replacements = {
                        "\u201a": "e",  # ‚
                        "\u00e9": "e",  # é
                        "\u00ea": "e",  # ê
                        "\u00e8": "e",  # è
                        "\u00f4": "o",  # ô
                        "\u00fb": "u",  # û
                        "\u00ee": "i",  # î
                        "\u00e0": "a",  # à
                        "\u00e7": "c",  # ç
                    }
                    for k, v in replacements.items():
                        sanitized = sanitized.replace(k, v)
                    # Also handle the mojibake from CP1252 misdecoding
                    # "réseau" -> "r�seau" -> replace � with e
                    sanitized = sanitized.replace("\ufffd", "e")
                    current_iface = sanitized
                # IPv4 line (starts with spaces, contains "IPv4" and ".")
                if "IPv4" in line_stripped and "." in line_stripped:
                    # IPv4 Address. . . . . . . . . . . : 192.168.1.100
                    ip = line_stripped.split(":")[-1].strip()
                    if not ip.startswith("127.") and not ip.startswith("169.254."):
                        # Trouver le masque via la ligne suivante si possible
                        cidr = "24"  # defaut
                        # Garder le nom d'interface tel quel (UTF-8)
                        iface_clean = current_iface or "?"
                        ips.append((iface_clean, ip, cidr))
        else:
            # Linux/macOS : `ip -br addr` ou `ifconfig`
            out = subprocess.run(["ip", "-br", "addr"], capture_output=True, text=True, check=False).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "UP":
                    iface = parts[0]
                    for cidr_ip in parts[2:]:
                        if "/" in cidr_ip and "." in cidr_ip:
                            ip, cidr = cidr_ip.split("/")
                            if not ip.startswith("127.") and not ip.startswith("169.254."):
                                ips.append((iface, ip, cidr))
    except Exception:
        pass
    return ips


def _format_network_info() -> str:
    """Formate une ligne resumant les interfaces actives pour l'affichage menu."""
    entries = _get_active_interface_ips()
    if not entries:
        return "  Réseau : aucune interface active détectée (vérifiez la connexion caméras)"
    lines = ["  Réseau local détecté :"]
    for iface, ip, cidr in entries:
        lines.append(f"    {iface} : {ip}/{cidr}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="camnetpilot",
        description="Decouverte, identification et attribution d'adresses IP pour cameras CCTV.",
    )
    parser.add_argument(
        "--config",
        default="config/example_site.yaml",
        help="fichier de configuration YAML du site",
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="executer le pipeline sur le site de demonstration simule (Phase 1)",
    )
    parser.add_argument(
        "--mode",
        choices=[m.value for m in RunMode],
        default="discover",
        help="mode de fonctionnement du pipeline : "
        "discover (lecture seule, defaut), "
        "assign (decouverte + attribution IP), "
        "activate_assign (decouverte + activation + attribution)",
    )
    parser.add_argument(
        "--rehearse",
        metavar="METHOD",
        choices=[m.value for m in DiscoveryMethod],
        help="repetition locale d'une methode de decouverte réelle (multicast/broadcast) "
        "sur son vrai groupe/port, contre une camera virtuelle — sans materiel (Phase 2)",
    )
    parser.add_argument(
        "--method",
        action="append",
        choices=[m.value for m in DiscoveryMethod],
        help="restreindre la decouverte aux methodes listees (repetable)",
    )
    parser.add_argument(
        "--init",
        metavar="PATH",
        help="creer un fichier de configuration YAML de depart (ex. config/site.yaml) "
        "en reutilisant la configuration par défaut ou celle passee via --config",
    )
    parser.add_argument(
        "--wizard",
        action="store_true",
        help="assistant interactif : construire une configuration en repondant a des "
        "questions (menu type de cameras, plage, passerelle…) puis l'ecrire",
    )
    parser.add_argument(
        "--menu",
        action="store_true",
        help="ouvrir le menu interactif principal (selection d'une action : simuler, "
        "lancer le pipeline, repetition, config…)",
    )
    parser.add_argument(
        "--json",
        metavar="PATH",
        help="exporter le rapport au format JSON dans le fichier indique (en complement "
        "de l'affichage console)",
    )
    parser.add_argument(
        "--config-edit",
        metavar="PATH",
        help="modifier interactivement un fichier de configuration YAML existant "
        "(valeurs pre-remplies, Entrée pour conserver)",
    )
    parser.add_argument(
        "--config-delete",
        metavar="PATH",
        help="supprimer un fichier de configuration YAML existant (avec confirmation)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="niveau de detail des logs JSON-lines (stderr)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    # Force UTF-8 encoding on Windows
    if sys.platform == "win32":
        import subprocess
        subprocess.run(["cmd", "/c", "chcp", "65001"], capture_output=True, check=False)
        # Reconfigure stdout/stderr for UTF-8 (Python 3.7+)
        if hasattr(sys.stdout, "reconfigure"):
            try:
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
                sys.stderr.reconfigure(encoding="utf-8", errors="replace")
            except OSError:
                # Fallback: wrap with TextIOWrapper if reconfigure fails
                import io
                sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
                sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
        else:
            # Fallback for older Python: wrap with TextIOWrapper
            import io
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

    args = build_parser().parse_args(argv)
    setup_logging(getattr(logging, args.log_level))

    if args.simulate:
        return _run_simulated(json_path=args.json)

    if args.rehearse is not None:
        return _rehearse_discovery(DiscoveryMethod(args.rehearse))

    if args.wizard:
        return _run_wizard(args.config)

    if args.init is not None:
        return _run_init(args.init, args.config)

    if args.config_edit is not None:
        return _run_config_edit(args.config_edit)

    if args.config_delete is not None:
        return _run_config_delete(args.config_delete)

    if args.menu:
        return _run_menu(args.config, json_path=args.json)

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"erreur de configuration : {exc}", file=sys.stderr)
        return 2

    if args.method:
        config.discovery.methods = [DiscoveryMethod(name) for name in args.method]

    from .orchestrator import run

    mode = RunMode(args.mode)
    try:
        result = asyncio.run(run(config, confirm_write=_ask_write_confirmation, mode=mode))
    except Exception as exc:  # noqa: BLE001 - echec pipeline
        print(f"echec du run : {exc}", file=sys.stderr)
        return 1
    return _emit_report(result, args.json)


def _run_init(dest: str, source_config: str) -> int:
    """Phase 5 — --init : reutilise la configuration existante (ou les valeurs par
    defaut) et ecrit un fichier YAML de depart exploitable."""
    from .config import build_config
    from .wizard import WizardAnswers, starter_yaml

    path = Path(dest)
    if path.exists():
        print(f"le fichier existe deja : {path}", file=sys.stderr)
        return 2

    answers = WizardAnswers()
    try:
        if Path(source_config).exists():
            cfg = load_config(source_config)
            answers.site_name = cfg.site_name
            answers.ip_range_start = str(cfg.ip_range.start)
            answers.ip_range_end = str(cfg.ip_range.end)
            answers.subnet_mask = str(cfg.subnet_mask)
            answers.gateway = str(cfg.gateway)
            answers.vendor_types = list(cfg.vendors)
            first_pwd = next(
                (v.default_password for v in cfg.vendors.values() if v.default_password), ""
            )
            answers.default_password = first_pwd
        yaml_text = starter_yaml(answers)
        # valide le YAML genere avant ecriture
        build_config(yaml.safe_load(yaml_text))
    except ConfigError as exc:
        print(f"configuration de depart invalide : {exc}", file=sys.stderr)
        return 2

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml_text, encoding="utf-8")
    except OSError as exc:
        print(f"impossible d'ecrire {path} : {exc}", file=sys.stderr)
        return 2

    print(f"Configuration de depart ecrite : {path}")
    print("Modifiez le mot de passe par défaut (REPLACE_ME) puis chargez le fichier avec --config.")
    return 0


def _run_wizard(dest: str, ask=None, ask_password=None, say=None) -> int:
    """Phase 5 — --wizard : assistant interactif de configuration."""
    from .config import ConfigError as CfgErr
    from .wizard import answers_to_config, collect_answers, starter_yaml

    if say is None:
        say = print
    try:
        answers = collect_answers(ask=ask, ask_password=ask_password, say=say)
        cfg = answers_to_config(answers)  # valide avant ecriture
    except CfgErr as exc:
        print(f"\nerreur : {exc}", file=sys.stderr)
        return 2

    path = Path(dest)
    if path.exists():
        print(f"le fichier existe deja : {path}", file=sys.stderr)
        return 2
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(starter_yaml(answers), encoding="utf-8")
    except OSError as exc:
        print(f"impossible d'ecrire {path} : {exc}", file=sys.stderr)
        return 2

    say()
    say(f"Configuration écrite : {path}")
    say(f"  Site        : {cfg.site_name}")
    say(f"  Plage       : {cfg.ip_range.start} - {cfg.ip_range.end}")
    say(f"  Masque      : {cfg.subnet_mask}")
    say(f"  Passerelle  : {cfg.gateway}")
    say(f"  Vendors     : {', '.join(cfg.vendors)}")
    return 0


def _run_config_edit(path_str: str, ask=None, ask_password=None, say=None) -> int:
    """Phase 5 — --config-edit : modifie un fichier YAML existant via le wizard,
    valeurs pre-remplies (Entrée = conserver)."""
    from .config import ConfigError as CfgErr
    from .wizard import (
        answers_to_config,
        collect_answers,
        starter_yaml,
        wizard_answers_from_config,
    )

    if say is None:
        say = print

    path = Path(path_str)
    if not path.exists():
        print(f"le fichier n'existe pas : {path}", file=sys.stderr)
        return 2
    try:
        cfg = load_config(path_str)
    except ConfigError as exc:
        print(f"erreur de configuration : {exc}", file=sys.stderr)
        return 2

    say("\nÉdition de la configuration existante (touches Entrée pour conserver la valeur)")
    try:
        initial = wizard_answers_from_config(cfg)
        answers = collect_answers(ask=ask, ask_password=ask_password, say=say, initial=initial)
        new_cfg = answers_to_config(answers)
        path.write_text(starter_yaml(answers), encoding="utf-8")
    except CfgErr as exc:
        print(f"\nerreur : {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"impossible d'ecrire {path} : {exc}", file=sys.stderr)
        return 2

    print()
    print(f"Configuration modifiée : {path}")
    print(f"  Site        : {new_cfg.site_name}")
    print(f"  Plage       : {new_cfg.ip_range.start} - {new_cfg.ip_range.end}")
    print(f"  Masque      : {new_cfg.subnet_mask}")
    print(f"  Passerelle  : {new_cfg.gateway}")
    print(f"  Vendors     : {', '.join(new_cfg.vendors)}")
    return 0


def _run_config_delete(path_str: str, ask=None, say=None) -> int:
    """Phase 5 — --config-delete : supprime un fichier YAML existant, avec confirmation."""
    path = Path(path_str)
    if not path.exists():
        print(f"le fichier n'existe pas : {path}", file=sys.stderr)
        return 2
    if ask is None:
        ask = lambda label: input(label)  # noqa: E731
    if say is None:
        say = print
    reply = (ask(f"Supprimer définitivement {path} ? (o/N) : ") or "").strip().lower()
    if reply not in ("o", "oui", "y", "yes"):
        say("Suppression annulée.")
        return 0
    try:
        path.unlink()
    except OSError as exc:
        print(f"impossible de supprimer {path} : {exc}", file=sys.stderr)
        return 1
    say(f"Configuration supprimée : {path}")
    return 0


MENU_ITEMS = [
    ("1", "Lancer le pipeline réel (découverte seule — lecture)"),
    ("2", "Lancer le pipeline avec modification IP (attribution)"),
    ("3", "Lancer le pipeline complet (activation + attribution)"),
    ("4", "Gerer les fichiers de configuration (creer / modifier / supprimer / generer)"),
    ("5", "Répétition locale d'une methode de decouverte (Phase 2)"),
    ("6", "Changer le fichier de configuration actif"),
    ("0", "Quitter"),
]

#: Methodes de decouverte repetables depuis le menu (ARP exclu : pas de repetition L2).
_REHEARSAL_MENU_METHODS = [
    DiscoveryMethod.ONVIF_WS_DISCOVERY,
    DiscoveryMethod.SADP,
    DiscoveryMethod.DAHUA_DISCOVERY,
    DiscoveryMethod.TIANDY_DISCOVERY,
]

_REHEARSAL_LABELS = {
    DiscoveryMethod.ONVIF_WS_DISCOVERY: "ONVIF WS-Discovery (multicast 239.255.255.250:3702)",
    DiscoveryMethod.SADP: "Hikvision SADP (UDP broadcast 37020)",
    DiscoveryMethod.DAHUA_DISCOVERY: "Dahua (UDP broadcast 37810)",
    DiscoveryMethod.TIANDY_DISCOVERY: "Tiandy (UDP broadcast 9999)",
}


def _pick_rehearse_method(ask, say) -> DiscoveryMethod | None:
    """Sous-menu de selection d'une methode de decouverte. Retourne la methode choisie
    ou None si l'utilisateur abandonne (croix/Entrée)."""
    while True:
        say("\n  Méthode de découverte à répéter :")
        for index, method in enumerate(_REHEARSAL_MENU_METHODS, start=1):
            say(f"    {index}. {_REHEARSAL_LABELS[method]}")
        say("    0. Retour au menu principal")
        raw = (ask("  Votre choix : ") or "").strip()
        if raw == "0" or raw == "":
            return None
        try:
            index = int(raw)
        except ValueError:
            say(f"    choix invalide : {raw!r}")
            continue
        if 1 <= index <= len(_REHEARSAL_MENU_METHODS):
            return _REHEARSAL_MENU_METHODS[index - 1]
        say(f"    numero hors plage : {index}")


_CONFIG_MENU_ITEMS = [
    ("1", "Créer un nouveau site (--wizard)"),
    ("2", "Modifier une configuration existante (--config-edit)"),
    ("3", "Supprimer une configuration existante (--config-delete)"),
    ("4", "Générer un fichier de config de depart (--init)"),
    ("0", "Retour au menu principal"),
]


def _ask_path(ask, label: str, default: str = "") -> str:
    """Demande un chemin de fichier via `ask(label_nu, default)`. Taper Entrée retourne
    `default` (si non vide). Le prompt (avec `[defaut] :`) est formate par le callable."""
    raw = (ask(label, default) or "").strip()
    return raw or default


def _run_config_menu(config_path: str, ask=None, ask_password=None, say=None) -> None:
    """Sous-menu de gestion des fichiers de configuration (option 3 du menu principal).

    `ask(label, default)` a 2 arguments lit les saisies visibles (il formate lui-meme
    le prompt `label [defaut] :`), `ask_password(label)` les saisies masquees, `say`
    affiche. Chaque action demande le chemin du fichier concerne : l'utilisateur choisit
    donc librement le fichier a creer / modifier / supprimer.
    """
    if ask is None:
        ask = lambda label, default: input(f"{label} [{default}] : " if default else f"{label} : ")  # noqa: E731
    if ask_password is None:
        import getpass

        ask_password = lambda label: getpass.getpass(f"{label} (saisie masquee) : ")  # noqa: E731
    if say is None:
        say = print
    ask_delete = lambda label: ask(label, "")  # noqa: E731
    while True:
        say("\n  Gestion de la configuration :")
        for code, label in _CONFIG_MENU_ITEMS:
            say(f"    {code}. {label}")
        choice = (ask("  Votre choix", "") or "").strip()
        if choice == "0" or choice == "":
            say("  Retour au menu principal.")
            return
        if choice == "1":
            dest = _ask_path(ask, "  Chemin du nouveau fichier", "config/siteB.yaml")
            if not dest:
                say("  chemin requis : aucune modification effectuée.")
                continue
            _run_wizard(dest, ask=ask, ask_password=ask_password, say=say)
        elif choice == "2":
            dest = _ask_path(ask, "  Fichier à modifier", config_path)
            _run_config_edit(dest, ask=ask, ask_password=ask_password, say=say)
        elif choice == "3":
            dest = _ask_path(ask, "  Fichier à supprimer", config_path)
            _run_config_delete(dest, ask=ask_delete, say=say)
        elif choice == "4":
            dest = _ask_path(ask, "  Fichier à générer", "config/example_site.yaml")
            if not dest:
                say("  chemin requis : aucune modification effectuée.")
                continue
            _run_init(dest, config_path)
        else:
            say(f"  choix invalide : {choice!r}")


def _run_interactive_assign(config_path: str, ask=None, ask_password=None, say=None, json_path: str | None = None) -> int:
    """Flux interactif pour l'attribution IP (option 2) : demande plage + credentials,
    construit une config en memoire, lance le pipeline ASSIGN. Pas de fichier requis."""
    if ask is None:
        ask = lambda label: input(label)  # noqa: E731
    if ask_password is None:
        import getpass
        ask_password = lambda label: getpass.getpass(f"{label} (saisie masquee) : ")  # noqa: E731
    if say is None:
        say = print

    say("\n--- Attribution IP interactive (sans fichier de config) ---")
    say(_format_network_info())

    # 1. Plage d'adresses
    say("\n  Plage d'adresses a attribuer (ex: 192.168.5.10 - 192.168.5.20) :")
    ip_start = (ask("    IP de debut : ") or "").strip()
    ip_end = (ask("    IP de fin   : ") or "").strip()
    if not ip_start or not ip_end:
        say("  Plage requise : annule.")
        return 0
    try:
        ipaddress.IPv4Address(ip_start)
        ipaddress.IPv4Address(ip_end)
    except ValueError:
        say("  Adresses IPv4 invalides : annule.")
        return 0

    # 2. Masque / Passerelle (déduction auto depuis la 1re IP + /24 par défaut)
    say("\n  Reseau (masque / passerelle) :")
    mask = (ask("    Masque [255.255.255.0] : ") or "255.255.255.0").strip()
    gateway = (ask(f"    Passerelle [{ip_start.rsplit('.', 1)[0]}.1] : ") or f"{ip_start.rsplit('.', 1)[0]}.1").strip()

    # 3. Credentials : par défaut (usine) OU actuels (si déjà activées)
    say("\n  Identifiants :")
    say("    Les caméras en config usine utilisent le mot de passe par défaut (étiquette).")
    say("    Les caméras déjà activées utilisent leurs identifiants actuels.")
    say("    Tous les mots de passe doivent être confirmés (saisie double).")
    
    def ask_password_confirmed(prompt: str) -> str:
        """Demande un mot de passe avec confirmation."""
        while True:
            pwd1 = (ask_password(f"{prompt} : ") or "").strip()
            pwd2 = (ask_password(f"Confirmez {prompt.lower()} : ") or "").strip()
            if pwd1 == pwd2:
                return pwd1
            say("  Les mots de passe ne correspondent pas. Réessayez.")
    
    default_pwd = ask_password_confirmed("    Mot de passe par défaut (usine)") or ""
    current_pwd = ask_password_confirmed("    Mot de passe actuel (si déjà activées, Entrée = identique)") or default_pwd
    username = (ask("    Nom d'utilisateur [admin] : ") or "admin").strip()

    # 4. Vendors attendus (optionnel, pour pre-filtrer)
    say("\n  Types de caméras attendus (optionnel, Entrée = tous) :")
    say("    Ex: hikvision,dahua,tiandy,onvif,xmsecu")
    vendors_input = (ask("    Vendors : ") or "").strip()
    vendors = [v.strip().lower() for v in vendors_input.split(",") if v.strip()] if vendors_input else []

    # 5. Construire la config en memoire
    try:
        config = build_config({
            "site_name": "Interactive",
            "ip_range": {"start": ip_start, "end": ip_end},
            "subnet_mask": mask,
            "gateway": gateway,
            "vendors": {v: {"default_password": default_pwd or current_pwd} for v in vendors} if vendors else {
                "hikvision": {"default_password": default_pwd or current_pwd},
                "dahua": {"default_password": default_pwd or current_pwd},
                "tiandy": {"default_password": default_pwd or current_pwd},
                "onvif": {"default_password": default_pwd or current_pwd},
                "xmsecu": {"default_password": default_pwd or current_pwd},
            },
            "discovery": {"methods": ["onvif_ws_discovery", "sadp", "dahua_discovery", "tiandy_discovery", "arp_oui_fallback"]},
        })
    except ConfigError as exc:
        say(f"  Erreur de configuration : {exc}")
        return 1

    # 6. Lancer le pipeline ASSIGN avec callback de credentials dynamique
    def ask_credentials(vendor: str):
        # Pour les cameras inactives (usine) : default_pwd
        # Pour les cameras actives : current_pwd
        return (username, current_pwd or default_pwd)

    try:
        from .orchestrator import run
        result = asyncio.run(run(
            config,
            confirm_write=lambda c: True,  # deja confirme par le flux interactif
            mode=RunMode.ASSIGN,
            ask_credentials=ask_credentials,
        ))
    except Exception as exc:
        say(f"echec du run : {exc}")
        return 1

    return _emit_report(result, json_path)


# ASCII Banner for CamNetPilot
BANNER = r"""
________  ________  _____ ______   ________   _______  _________  ________  ___  ___       ________  _________   
|\   ____\|\   __  \|\   _ \  _   \|\   ___  \|\  ___ \|\___   ___\\   __  \|\  \|\  \     |\   __  \|\___   ___\ 
\ \  \___|\ \  \|\  \ \  \\\__\ \  \ \  \\ \  \ \   __/\|___ \  \_\ \  \|\  \ \  \ \  \    \ \  \|\  \|___ \  \_| 
 \ \  \    \ \   __  \ \  \\|__| \  \ \  \\ \  \ \  \_|/__  \ \  \ \ \   ____\ \  \ \  \    \ \  \\\  \   \ \  \  
  \ \  \____\ \  \ \  \ \  \    \ \  \ \  \\ \  \ \  \_|\ \  \ \  \ \ \  \___|\ \  \ \  \____\ \  \\\  \   \ \  \ 
   \ \_______\ \__\ \__\ \__\    \ \__\ \__\\ \__\ \_______\  \ \__\ \ \__\    \ \__\ \_______\ \_______\   \ \__\
    \|_______|\|__|\|__|\|__|     \|__|\|__| \|__|\|_______|   \|__|  \|__|     \|__|\|_______|\|_______|    \|__| 
"""

def _print_banner(say):
    """Print the application banner."""
    for line in BANNER.strip('\n').split('\n'):
        say(line)
    say("Camera Network Pilot — Automated IP Provisioning")
    say("")


def _run_menu(config_path: str, ask=None, ask_password=None, say=None, json_path: str | None = None) -> int:
    """Phase 5 — menu interactif principal : selectionne et execute une action."""
    if ask is None:
        ask = lambda label: input(label)  # noqa: E731
    if ask_password is None:
        import getpass
        ask_password = lambda label: getpass.getpass(f"{label} (saisie masquee) : ")  # noqa: E731
    if say is None:
        say = print

    _print_banner(say)

    current_config_path = config_path

    while True:
        say("\n===== CamNetPilot Provisioner Tool =====")
        say(_format_network_info())
        say(f"  Config active : {current_config_path}")
        say("")
        for code, label in MENU_ITEMS:
            say(f"  {code}. {label}")
        choice = (ask("Votre choix : ") or "").strip()
        if choice == "0" or choice.lower() in ("q", "quit", "quitter"):
            say("Au revoir.")
            return 0
        if choice == "1":
            try:
                config = load_config(current_config_path)
            except ConfigError as exc:
                say(f"erreur de configuration : {exc}")
                continue
            _run_pipeline(config, mode=RunMode.DISCOVER, json_path=json_path)
        elif choice == "2":
            return _run_interactive_assign(current_config_path, ask=ask, ask_password=ask_password, say=say, json_path=json_path)
        elif choice == "3":
            try:
                config = load_config(current_config_path)
            except ConfigError as exc:
                say(f"erreur de configuration : {exc}")
                continue
            _run_pipeline(config, mode=RunMode.ACTIVATE_ASSIGN, json_path=json_path)
        elif choice == "4":
            import getpass
            _run_config_menu(
                current_config_path,
                ask=lambda label, default: ask(  # noqa: E731
                    f"{label} [{default}] : " if default else f"{label} : "
                ),
                ask_password=lambda label: getpass.getpass(f"{label} (saisie masquee) : "),
                say=say,
            )
        elif choice == "5":
            method = _pick_rehearse_method(ask, say)
            if method is None:
                say("  Retour au menu principal.")
                continue
            _rehearse_discovery(method)
        elif choice == "6":
            new_path = (ask(f"  Nouveau fichier de config [{current_config_path}] : ") or "").strip()
            if new_path:
                try:
                    load_config(new_path)  # valide
                    current_config_path = new_path
                    say(f"  Config active changee : {current_config_path}")
                except ConfigError as exc:
                    say(f"  Fichier invalide : {exc}")
            else:
                say("  Inchange.")
        else:
            say(f"choix invalide : {choice!r}")


def _run_simulated(json_path: str | None = None) -> int:
    from .orchestrator import run
    from .simulation.demo import build_demo_site, demo_config

    config = demo_config()
    print(IS_SIMULATION_DOC, file=sys.stderr)

    async def _run_simulated() -> AssignmentResult:
        network = await build_demo_site(config)
        try:
            return await run(config, sim_network=network)
        finally:
            await network.stop()

    try:
        result = asyncio.run(_run_simulated())
    except Exception as exc:  # noqa: BLE001 - echec pipeline (niveau CRITICAL)
        print(f"echec du run : {exc}", file=sys.stderr)
        return 1
    return _emit_report(result, json_path)


def _ask_write_confirmation(camera) -> bool:
    """Demande a l'utilisateur s'il autorise une *ecriture* reseau sur cette camera.

    En non-interactif (stdin non terminal), on refuse par défaut : un script ne
    modifie jamais le reseau sans confirmation explicite. `--config` reste donc sur
    en CI / dans un pipe.
    """
    if not sys.stdin.isatty():
        print(
            f"[lecture seule] pas de terminal — ecriture refusee pour "
            f"{camera.mac_address or camera.ip_address}",
            file=sys.stderr,
        )
        return False
    label = (
        f"{camera.mac_address or camera.ip_address} ({camera.vendor or '?'}, "
        f"{camera.model or 'modele inconnu'})"
    )
    answer = input(f"[ecriture] Autoriser l'ecriture reseau sur {label} ? [y/N] ")
    return answer.strip().lower() in ("y", "yes", "o", "oui")


def _run_pipeline(config, mode: RunMode = RunMode.DISCOVER, json_path: str | None = None) -> int:
    from .orchestrator import run

    try:
        result = asyncio.run(run(config, confirm_write=_ask_write_confirmation, mode=mode))
    except Exception as exc:  # noqa: BLE001 - echec pipeline
        print(f"echec du run : {exc}", file=sys.stderr)
        return 1
    return _emit_report(result, json_path)


def _emit_report(result: AssignmentResult, json_path: str | None = None) -> int:
    """Affiche le rapport puis exporte eventuellement le JSON (aucune logique metier)."""
    render(result)
    if json_path is not None:
        try:
            _write_json(result, json_path)
        except OSError as exc:
            print(f"impossible d'ecrire le rapport JSON {json_path} : {exc}", file=sys.stderr)
            return 1
        print(f"Rapport JSON ecrit : {json_path}")
    return 0


_REHEARSAL_CAMERA: dict[DiscoveryMethod, tuple[str, str, str]] = {
    DiscoveryMethod.ONVIF_WS_DISCOVERY: ("onvif", "aa:bb:cc:00:00:02", "169.254.20.65"),
    DiscoveryMethod.SADP: ("hikvision", "ac:cc:8e:00:00:02", "192.0.0.65"),
    DiscoveryMethod.DAHUA_DISCOVERY: ("dahua", "e0:50:8b:00:00:02", "192.0.0.65"),
    DiscoveryMethod.TIANDY_DISCOVERY: ("tiandy", "00:cc:2f:00:00:02", "10.1.1.21"),
}


def _rehearse_discovery(method: DiscoveryMethod) -> int:
    """Phase 2 : valide le chemin réel (multicast/broadcast) d'une methode de decouverte,
    sur la machine et sans materiel — une camera virtuelle est inscrite sur le vrai
    port/groupe de diffusion du protocole."""
    from .discovery import discover_all
    from .simulation.camera import CameraSpec
    from .simulation.demo import DEFAULT_PASSWORD, demo_config
    from .simulation.network import SimulatedNetwork

    if method is DiscoveryMethod.ARP_OUI_FALLBACK:
        print(
            "ARP : pas de repetition locale — ce fallback lit la table ARP du systeme "
            "(voir README, section tests sur cameras réelles).",
            file=sys.stderr,
        )
        return 0

    spec = _REHEARSAL_CAMERA[method]
    print(
        f"Répétition {method.value} réel (adresse/port du protocole contre une camera virtuelle)…",
        file=sys.stderr,
    )

    async def _run() -> int:
        cfg = demo_config()
        cfg.discovery.methods = [method]
        cfg.discovery.timeout_seconds = 1.0
        network = SimulatedNetwork()
        vendor, mac, ip = spec
        await network.start_camera(
            CameraSpec(
                vendor=vendor,
                mac=mac,
                ip=ip,
                active=True,
                password=DEFAULT_PASSWORD,
                rehearse=True,
            )
        )
        try:
            cameras = await discover_all(cfg)
        finally:
            await network.stop()
        if not cameras:
            print(
                "Aucune réponse reçue — le groupe/port de diffusion est inaccessible.",
                file=sys.stderr,
            )
            return 1
        for camera in cameras:
            print(
                f"  {camera.ip_address:<15} {camera.mac_address or '?'} "
                f"({camera.discovery_method.value})"
            )
        print(f"Répétition {method.value} OK : {len(cameras)} caméra(s) détectée(s).")
        return 0

    try:
        return asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001 - echec de repetition (niveau ERROR)
        print(f"échec de la répétition : {exc}", file=sys.stderr)
        return 1


def render(result: AssignmentResult) -> None:
    """Affiche le rapport de synthese final (aucune logique metier ici)."""
    _render_summary(result)
    _render_cameras(result.cameras)
    _render_vendor_totals(result.cameras)
    _render_conflicts(result.conflicts)
    _render_manual_required(result.cameras)
    if result.errors:
        print("\nErreurs :")
        for error in result.errors:
            print(f"  - {error}")


def _render_summary(result: AssignmentResult) -> None:
    summary = result.summary()
    mode_label = {
        "discover": "Découverte seule (lecture)",
        "assign": "Découverte + Attribution IP",
        "activate_assign": "Découverte + Activation + Attribution",
    }.get(result.run_mode, result.run_mode)
    print()
    print("=" * 62)
    print(f"  Rapport de synthèse — {result.site_name}")
    print(f"  Mode : {mode_label}")
    print("=" * 62)
    print(
        f"  Caméras découvertes : {summary['discovered']:>3}"
        f"   attribuées : {summary['assigned']:>3}"
        f"   en échec : {summary['failed']:>3}"
    )
    print(
        f"  Conflits détectés : {summary['conflicts_detected']:>3}"
        f"   résolus : {summary['conflicts_resolved']:>3}"
    )
    if summary["manual_required"]:
        print(f"  Activation manuelle requise : {summary['manual_required']:>3}")
    started = result.started_at.strftime("%H:%M:%S") if result.started_at else "?"
    finished = result.finished_at.strftime("%H:%M:%S") if result.finished_at else "?"
    print(f"  Debut : {started}   Fin : {finished}")


def _render_cameras(cameras) -> None:
    print()
    print("  Caméras :")
    if not cameras:
        print("    (aucune caméra découverte)")
        return
    rows: list[list[str]] = []
    for camera in cameras:
        mac = camera.mac_address or "??"
        vendor = camera.vendor or "?"
        model = camera.model or "-"
        activation = camera.activation_status.value
        target = camera.target_ip if camera.target_ip is not None else "-"
        state = camera.assignment_status.value if camera.last_error is None else "failed"

        notes = []
        if camera.has_conflict:
            notes.append("conflit")
        if camera.temp_ip is not None:
            notes.append(f"temp {camera.temp_ip}")
        if camera.activation_result is ActivationResult.MANUAL_REQUIRED:
            notes.append("activation manuelle requise")
        note = "  " + ", ".join(notes) if notes else ""

        rows.append(
            [mac, camera.ip_address, vendor, model, activation, target, state]
            + [note]
        )

    headers = ["MAC", "IP", "Vendor", "Modèle", "Activation", "Cible", "État"]
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row[:7]):
            if len(cell) > widths[i]:
                widths[i] = len(cell)

    def fmt(row: list[str]) -> str:
        cols = [row[i].ljust(widths[i]) for i in range(7)]
        note = row[7] if len(row) > 7 else ""
        return "    " + "  ".join(cols) + note

    print(fmt(headers))
    print("    " + "  ".join("-" * w for w in widths))
    for row in rows:
        print(fmt(row))

    errors = [c for c in cameras if c.last_error]
    if errors:
        print()
        for camera in errors:
            print(f"      * {camera.mac_address or '?'} : {camera.last_error}")


def _render_vendor_totals(cameras) -> None:
    """Repartition du parc par fabricant, a partir des cameras identifiees."""
    totals: dict[str, int] = {}
    for camera in cameras:
        if camera.vendor:
            totals[camera.vendor] = totals.get(camera.vendor, 0) + 1
    if not totals:
        return
    print()
    print("  Répartition par fabricant :")
    for vendor, count in sorted(totals.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"    {vendor:<10} {count:>3}")


def _render_conflicts(conflicts) -> None:
    """Bloc dedie : detail des conflits d'adresse résolus (par groupe de MAC)."""
    resolved = [c for c in conflicts if c.resolution_status is ResolutionStatus.RESOLVED]
    if not resolved:
        return
    print()
    print("  Conflits d'adresse résolus :")
    rows: list[list[str]] = []
    for conflict in resolved:
        for mac in conflict.camera_macs:
            tag = "  (vainqueur)" if mac == conflict.winner_mac else ""
            rows.append([conflict.conflicting_ip, mac, conflict.winner_mac or "-"] + [tag])
    headers = ["IP en conflit", "Caméras (MAC)", "Adresse gagnante"]
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row[:3]):
            if len(cell) > widths[i]:
                widths[i] = len(cell)
    print("    " + "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)))
    print("    " + "  ".join("-" * w for w in widths))
    for row in rows:
        cols = [row[i].ljust(widths[i]) for i in range(3)]
        print("    " + "  ".join(cols) + row[3])


def _render_manual_required(cameras) -> None:
    """Bloc dedie : cameras laissees a l'operateur (activation manuelle requise)."""
    pending = [c for c in cameras if c.activation_result is ActivationResult.MANUAL_REQUIRED]
    if not pending:
        return
    print()
    print("  Caméras nécessitant une activation manuelle :")
    for camera in pending:
        mac = camera.mac_address or "??"
        print(
            f"    {mac:<18} {camera.ip_address:<15} {camera.vendor or '?':<9}"
            "  — pas de mot de passe par défaut ni d'activation auto reconnue"
        )


def _camera_to_dict(camera) -> dict:
    return {
        "mac_address": camera.mac_address,
        "ip_address": camera.ip_address,
        "discovery_method": camera.discovery_method.value,
        "discovered_at": camera.discovered_at.isoformat(),
        "vendor": camera.vendor,
        "vendor_confirmed": camera.vendor_confirmed,
        "model": camera.model,
        "serial_number": camera.serial_number,
        "firmware_version": camera.firmware_version,
        "activation_status": camera.activation_status.value,
        "activation_result": camera.activation_result.value if camera.activation_result else None,
        "has_conflict": camera.has_conflict,
        "temp_ip": camera.temp_ip,
        "target_ip": camera.target_ip,
        "assignment_status": camera.assignment_status.value,
        "last_error": camera.last_error,
    }


def _conflict_to_dict(conflict) -> dict:
    return {
        "conflicting_ip": conflict.conflicting_ip,
        "camera_macs": list(conflict.camera_macs),
        "detected_at": conflict.detected_at.isoformat(),
        "resolution_status": conflict.resolution_status.value,
        "resolution_method": conflict.resolution_method,
        "resolution_detail": conflict.resolution_detail,
        "winner_mac": conflict.winner_mac,
    }


def _result_to_dict(result: AssignmentResult) -> dict:
    return {
        "site_name": result.site_name,
        "run_mode": result.run_mode,
        "summary": result.summary(),
        "started_at": result.started_at.isoformat(),
        "finished_at": result.finished_at.isoformat() if result.finished_at else None,
        "cameras": [_camera_to_dict(c) for c in result.cameras],
        "conflicts": [_conflict_to_dict(c) for c in result.conflicts],
        "errors": list(result.errors),
    }


def _write_json(result: AssignmentResult, path: str) -> None:
    """Serialise le rapport en JSON (aucune logique metier ici)."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(_result_to_dict(result), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
