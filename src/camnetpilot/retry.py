"""Retry pour erreurs réseau transitoires (section 7).

« 2 tentatives max » est interprété comme **2 retries** (3 tentatives au total), avec
un backoff exponentiel (0.5s, 1.5s), conformément au chiffre de la spécification.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

from .logging_conf import is_transient_error

logger = logging.getLogger("ipcam_provisioner.retry")

DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_RETRY_DELAYS = (0.5, 1.5)


async def call_with_retry(
    factory: Callable[[], Awaitable],
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    retry_delays: tuple[float, ...] = DEFAULT_RETRY_DELAYS,
    context: str = "",
    logger_: logging.Logger | None = None,
):
    """Exécute `factory()` jusqu'à `max_attempts` fois si les échecs sont transitoires.

    Une exception non-transitoire est toujours propagée immédiatement. Une exception
    transitoire épuisée est relancée (l'appelant décidera de marquer la caméra en FAILED).
    """
    log = logger_ or logger
    attempt = 1
    while True:
        try:
            return await factory()
        except Exception as exc:  # noqa: BLE001 - panne réseau attendue
            if not is_transient_error(exc) or attempt >= max_attempts:
                raise
            delay = retry_delays[min(attempt - 1, len(retry_delays) - 1)]
            log.warning(
                "retry %s tentative %d/%d dans %.1fs : %s",
                context,
                attempt,
                max_attempts,
                delay,
                exc,
            )
            attempt += 1
            await asyncio.sleep(delay)


def retries_left(exception: Exception, attempt: int, max_attempts: int) -> bool:
    return attempt < max_attempts
