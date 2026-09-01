"""Assistant de configuration interactive (Phase 5).

Construit une `SiteConfig` (ou un fichier YAML de départ) à partir d'un dialogue avec
l'utilisateur : menu de sélection du type de caméras, plage d'attribution, passerelle,
mot de passe par défaut.

Les fonctions de collecte (`_ask`) acceptent des callables injectables (`input`/`print`)
pour rester testables ; les fonctions de construction sont pures.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass, field
from getpass import getpass

from .config import ConfigError, SiteConfig, build_config
from .models import DiscoveryMethod

_VENDORS = ("hikvision", "dahua", "tiandy", "onvif")

_VENDOR_LABELS = {
    "hikvision": "Hikvision (SADP / ISAPI)",
    "dahua": "Dahua (broadcast / CGI)",
    "tiandy": "Tiandy (broadcast / JSON)",
    "onvif": "ONVIF générique (WS-Discovery)",
}


@dataclass
class WizardAnswers:
    site_name: str = "Site A"
    ip_range_start: str = "192.168.1.10"
    ip_range_end: str = "192.168.1.250"
    subnet_mask: str = "255.255.255.0"
    gateway: str = "192.168.1.1"
    vendor_types: list[str] = field(default_factory=lambda: list(_VENDORS))
    default_password: str = ""


def wizard_answers_from_config(cfg: SiteConfig) -> WizardAnswers:
    """Pré-remplit une structure de dialogue à partir d'une configuration existante
    (utilisé par l'édition d'un fichier YAML)."""
    first_pwd = next(
        (v.default_password for v in cfg.vendors.values() if v.default_password), ""
    )
    return WizardAnswers(
        site_name=cfg.site_name,
        ip_range_start=str(cfg.ip_range.start),
        ip_range_end=str(cfg.ip_range.end),
        subnet_mask=str(cfg.subnet_mask),
        gateway=str(cfg.gateway),
        vendor_types=list(cfg.vendors),
        default_password=first_pwd,
    )


def _prefill_type_defaults(answers: WizardAnswers) -> str:
    """Chaîne (ex. '1,3') des numéros de vendors actuellement retenus, pour servir de
    valeur par défaut au prompt d'édition."""
    selected = [name for name in _VENDORS if name in answers.vendor_types]
    return ",".join(str(i) for i, name in enumerate(_VENDORS, 1) if name in selected)


def collect_answers(
    *,
    ask=None,
    ask_password=None,
    say=None,
    initial: WizardAnswers | None = None,
) -> WizardAnswers:
    """Dialogue pas à pas. `ask(label, default)` retourne la saisie visible,
    `ask_password(label)` la saisie **masquée** (mot de passe), `say(text)` affiche
    une ligne. Testable via des callables injectés.

    Taper simplement **Entrée** conserve la valeur par défaut (**ne pas retaper**).
    Une valeur incorrecte est refusée séance tenante : la question est re-posée
    jusqu'à obtenir une saisie valide (hors défaut, toujours accepté).

    Le mot de passe est saisi **à l'aveugle** (pas d'écho) puis **confirmé** : il doit
    être tapé deux fois à l'identique, sinon la saisie est relancée.

    Si `initial` est fourni (édition), ses valeurs servent de défaut : saisir
    **Entrée** conserve la valeur existante, et le prompt des vendors est pré-rempli
    avec les types déjà retenus.
    """
    if ask is None:
        ask = lambda label, default: input(f"{label} [{default}] : ")  # noqa: E731
    if ask_password is None:
        ask_password = lambda label: getpass(f"{label} (saisie masquée) : ")  # noqa: E731
    if say is None:
        say = print
    answers = WizardAnswers()
    if initial is not None:
        fields = {
            "site_name": initial.site_name,
            "ip_range_start": initial.ip_range_start,
            "ip_range_end": initial.ip_range_end,
            "subnet_mask": initial.subnet_mask,
            "gateway": initial.gateway,
            "vendor_types": list(initial.vendor_types),
            "default_password": initial.default_password,
        }
        answers = WizardAnswers(**fields)

    def prompt(label: str, default: str, valid: Callable[[str], bool] | None = None) -> str:
        while True:
            line = (ask(label, default) or "").strip()
            if not line:
                return default
            if valid is None or valid(line):
                return line
            say(f"  erreur : valeur invalide ({line!r}), réessayez.")

    editing = initial is not None
    previous_password = initial.default_password if editing else ""

    def prompt_password(label: str) -> str:
        while True:
            first = (ask_password(label) or "").strip()
            if not first:
                if previous_password:
                    say("  mot de passe inchangé (conservé).")
                    return previous_password
                say("  mot de passe vide : aucune activation automatique.")
                return ""
            second = (ask_password("  Confirmez le mot de passe") or "").strip()
            if first == second:
                return first
            say("  erreur : les deux saisies ne correspondent pas, réessayez.")

    say("Configuration du site (touches Entrée pour accepter la valeur par défaut)")
    answers.site_name = prompt("Nom du site", answers.site_name)

    answers.ip_range_start = prompt(
        "Première adresse de la plage",
        answers.ip_range_start,
        valid=_is_ip,
    )
    answers.ip_range_end = prompt(
        "Dernière adresse de la plage",
        answers.ip_range_end,
        valid=_is_ip,
    )
    answers.subnet_mask = prompt(
        "Masque de sous-réseau",
        answers.subnet_mask,
        valid=_is_subnet_mask,
    )
    answers.gateway = prompt("Passerelle", answers.gateway, valid=_is_ip)

    # Cohérence globale de la plage : départ <= arrivée (re-posé si besoin)
    while True:
        try:
            _validate_range(answers.ip_range_start, answers.ip_range_end)
            break
        except ConfigError as exc:
            say(f"  erreur : {exc}")
            answers.ip_range_start = prompt(
                "Première adresse de la plage",
                answers.ip_range_start,
                valid=_is_ip,
            )
            answers.ip_range_end = prompt(
                "Dernière adresse de la plage",
                answers.ip_range_end,
                valid=_is_ip,
            )

    say("")
    say(_format_menu())

    def valid_types(text: str) -> bool:
        try:
            _parse_types(text)
            return True
        except ConfigError:
            return False

    raw_types = prompt(
        "Types de caméras (numéros séparés par des virgules)",
        _prefill_type_defaults(answers),
        valid=valid_types,
    )
    answers.vendor_types = _parse_types(raw_types)
    answers.default_password = prompt_password(
        "Mot de passe par défaut (laisser vide si aucune activation auto)"
    )
    return answers


def _format_menu() -> str:
    lines = ["Types de caméras disponibles :"]
    for index, name in enumerate(_VENDORS, start=1):
        lines.append(f"  {index}. {_VENDOR_LABELS[name]}")
    return "\n".join(lines)


def _parse_types(text: str) -> list[str]:
    """Convertit la saisie (ex. '1,3') en liste de vendors, avec validation."""
    if not text.strip():
        raise ConfigError("Aucun type de caméras sélectionné.")
    selected: list[str] = []
    for token in text.split(","):
        token = token.strip()
        try:
            index = int(token)
        except ValueError:
            raise ConfigError(f"Choix invalide (doit être un nombre) : {token!r}") from None
        if not 1 <= index <= len(_VENDORS):
            raise ConfigError(
                f"Numéro hors plage : {index} (valides : 1-{len(_VENDORS)})"
            )
        name = _VENDORS[index - 1]
        if name not in selected:
            selected.append(name)
    return selected


def answers_to_config(answers: WizardAnswers) -> SiteConfig:
    """Construit une SiteConfig validée depuis les réponses de l'assistant."""
    if not answers.vendor_types:
        raise ConfigError("Aucun type de caméras sélectionné.")
    raw: dict = {
        "site_name": answers.site_name,
        "ip_range": {
            "start": answers.ip_range_start,
            "end": answers.ip_range_end,
        },
        "subnet_mask": answers.subnet_mask,
        "gateway": answers.gateway,
    }
    _validate_range(answers.ip_range_start, answers.ip_range_end)
    if not _is_subnet_mask(answers.subnet_mask):
        raise ConfigError("Masque de sous-réseau invalide.")
    if not _is_ip(answers.gateway):
        raise ConfigError("Passerelle invalide.")
    raw["vendors"] = {
        name: {"default_password": answers.default_password} for name in answers.vendor_types
    }
    return build_config(raw)


def _is_subnet_mask(value: str) -> bool:
    """Vrai si `value` est un masque de sous-réseau contigu (ex. 255.255.255.0)."""
    if not _is_ip(value):
        return False
    bits = "".join(f"{octet:08b}" for octet in ipaddress.IPv4Address(value).packed)
    return "01" not in bits


def _is_ip(value: str) -> bool:
    """Vrai si `value` est une adresse IPv4 valide à 4 octets explicites, non nulle
    et non broadcast (`0.0.0.0`, `255.255.255.255`).

    `ipaddress.IPv4Address` accepte à tort des IVAN (`195.154.3` → 195.154.0.3) ; on
    exige donc exactement 4 champs numériques.
    """
    parts = value.split(".")
    if len(parts) != 4 or any(not part or not part.isdigit() for part in parts):
        return False
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return False
    return address != ipaddress.IPv4Address("0.0.0.0") and address != ipaddress.IPv4Address(
        "255.255.255.255"
    )


def _validate_range(start: str, end: str) -> None:
    """Vérifie que la plage est cohérente (début <= fin, même réseau raisonnable)."""
    if not _is_ip(start) or not _is_ip(end):
        raise ConfigError("Adresses de plage invalides.")
    first = ipaddress.IPv4Address(start)
    last = ipaddress.IPv4Address(end)
    if last < first:
        raise ConfigError("La première adresse doit précéder la dernière.")

#: Ordre canonique des méthodes de découverte (défaut du fichier init).
_INIT_METHODS = [m.value for m in DiscoveryMethod]


def starter_yaml(answers: WizardAnswers) -> str:
    """Produit un YAML de configuration exploitable directement par l'outil."""
    vendors_lines = []
    for name in answers.vendor_types:
        pwd = answers.default_password or "REPLACE_ME"
        vendors_lines.append(f"  {name}:\n    default_password: \"{pwd}\"")
    methods = ", ".join(_INIT_METHODS)
    return (
        f"site_name: \"{answers.site_name}\"\n"
        f"ip_range:\n"
        f"  start: {answers.ip_range_start}\n"
        f"  end: {answers.ip_range_end}\n"
        f"subnet_mask: {answers.subnet_mask}\n"
        f"gateway: {answers.gateway}\n"
        f"vendors:\n" + "\n".join(vendors_lines) + "\n"
        f"concurrency:\n"
        f"  max_parallel_requests: 50\n"
        f"discovery:\n"
        f"  timeout_seconds: 5\n"
        f"  methods: [{methods}]\n"
    )


__all__ = ["answers_to_config", "collect_answers", "starter_yaml"]
