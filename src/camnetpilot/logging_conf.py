"""Configuration du logging structuré (section 7 de la spécification).

Les logs sont émis en JSON-lines (parsables à l'échelle) vers stderr ; l'interface
CLI réserve stdout pour son rendu humain. Niveaux : DEBUG=payloads bruts,
INFO=progression, WARNING=conflit détecté/retry, ERROR=échec caméra,
CRITICAL=échec pipeline (ex. impossible de binder l'interface réseau).
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

import httpx


class JsonLineFormatter(logging.Formatter):
    """Formatter qui émet un objet JSON par ligne."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": record.created,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # "extra_fields" est posé par le module lui-même (jamais d'input utilisateur).
        extra = getattr(record, "extra_fields", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info is not None:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def setup_logging(level: int = logging.INFO) -> None:
    """Configure le logger racine avec un handler JSON-lines vers stderr."""
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonLineFormatter())
    root.addHandler(handler)


def camera_log(
    logger: logging.Logger,
    level: int,
    camera,
    message: str,
    **fields: Any,
) -> None:
    """Log attaché à l'identité (MAC/IP/vendor) d'une caméra."""
    extra: dict[str, Any] = {"mac": camera.mac_address, "ip": camera.ip_address}
    if camera.vendor is not None:
        extra["vendor"] = camera.vendor
    extra.update(fields)
    logger.log(level, message, extra={"extra_fields": extra})


def is_transient_error(exc: BaseException) -> bool:
    """Une erreur est transitoire si elle ne dépend pas de la configuration fournie
    (timeout, connexion refusée, reset). Une 401/4xx liée au contenu ne doit pas être
    retentée."""
    if isinstance(exc, (TimeoutError, ConnectionResetError, BrokenPipeError)):
        return True
    if isinstance(exc, httpx.TransportError):
        return True
    return isinstance(exc, OSError)
