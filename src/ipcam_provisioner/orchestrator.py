"""Orchestrateur : pipeline complet, seul module autorisé à tout appeler (section 5).

Ordre des étapes (conforme à `pipeline_attribution_ip.md`) :
découverte → fingerprinting → activation → détection des conflits → résolution
(IP temporaires via canal MAC-adressé) → planification → attribution finale.

Toute opération réseau par appareil est bornée par la sémaphore de concurrence ;
un échec sur une caméra pose `last_error` + `assignment_status=FAILED` et ne sort
jamais de la boucle (isolation par caméra).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import datetime

from .activation import ActivationEngine
from .assignment import AssignmentEngine
from .config import SiteConfig
from .conflicts import Layer2Announcer, detect_conflicts, resolve_conflict
from .discovery import discover_all
from .fingerprinting import FingerprintContext, build_engine
from .models import (
    ActivationResult,
    ActivationStatus,
    AssignmentResult,
    AssignmentStatus,
    Camera,
    Conflict,
    ResolutionStatus,
)
from .net import HttpTalker, NetworkResolver
from .planning import PlanningError, plan_target_ips

logger = logging.getLogger("ipcam_provisioner.orchestrator")


class _NullAnnouncer:
    """Annonceur L2 vide : utilisé en mode réel tant que la couche L2 (Phase 2) n'existe pas."""

    def announce(self, ip: str, mac: str, method: str = "gratuitous_arp") -> None:
        logger.warning("annonce L2 non disponible en Phase 1 (ip=%s mac=%s)", ip, mac)

    def arp_lookup(self, ip: str) -> str | None:
        return None

    def set_ip_by_mac(self, mac: str, new_ip: str) -> bool:
        logger.warning("canal MAC-adressé non disponible en Phase 1 (mac=%s)", mac)
        return False


async def run(
    config: SiteConfig,
    *,
    sim_network=None,
    talker: HttpTalker | None = None,
    confirm_write: Callable[[Camera], bool] | None = None,
) -> AssignmentResult:
    """Exécute le pipeline complet pour un site et retourne le rapport de synthèse.

    `confirm_write` est un callback appelé avant chaque opération réseau qui *écrit*
    (activation d'une caméra inactive, attribution d'une nouvelle IP). S'il renvoie
    False, la caméra est sautée : activation -> `manual_required`, attribution ->
    laissée en l'état (non modifiée). `None` = tout autoriser (comportement par défaut).
    """
    result = AssignmentResult(site_name=config.site_name)
    own_talker = talker is None
    if talker is None:
        resolver = sim_network if sim_network is not None else NetworkResolver()
        talker = HttpTalker(resolver, timeout=config.discovery.timeout_seconds)
    announcer: Layer2Announcer = sim_network if sim_network is not None else _NullAnnouncer()
    sem = asyncio.Semaphore(config.concurrency.max_parallel_requests)

    async def writes_approved(camera: Camera) -> bool:
        if confirm_write is None:
            return True
        return confirm_write(camera)

    async def run_with_steer(camera: Camera, operation) -> None:
        """Annonce l'IP/MAC au niveau L2 (pour joindre le bon appareil) puis opère."""
        if camera.mac_address:
            announcer.announce(camera.ip_address, camera.mac_address, method="l2_steer")
        try:
            await operation(camera)
        except Exception as exc:  # noqa: BLE001 - isolation par caméra
            camera.mark_error(str(exc))
            logger.error(
                "échec %s : %s", camera.mac_address or camera.ip_address, exc
            )

    async def bounded(cameras: list[Camera], operation) -> None:
        """Exécute l'opération sur toutes les caméras.

        La table L2 (une entrée par IP) est une ressource partagée : si plusieurs
        caméras portent encore la même IP (avant résolution), elles sont traitées
        séquentiellement (l'annonce L2 cible une MAC à la fois). Les caméras d'IP
        différentes sont traitées en parallèle, bornées par la sémaphore.
        """
        groups: dict[str, list[Camera]] = {}
        for camera in cameras:
            key = camera.ip_address
            groups.setdefault(key, []).append(camera)

        async def process_group(group: list[Camera]) -> None:
            for camera in group:
                async with sem:
                    await run_with_steer(camera, operation)

        await asyncio.gather(*(process_group(g) for g in groups.values()))

    try:
        # --- 1. Découverte ---------------------------------------------------
        cameras = await discover_all(config, sim_network)
        result.cameras = cameras
        result.total_discovered = len(cameras)
        logger.info("découverte terminée : %d caméra(s)", len(cameras))

        # --- 2. Fingerprinting (concurrent) ---------------------------------
        fingerprinting = build_engine(FingerprintContext(talker, config, sem))
        await bounded(sorted(cameras, key=lambda c: c.ip_address), fingerprinting.identify)
        logger.info(
            "fingerprinting terminé : %d active(s), %d inactive(s), %d à l'état inconnu",
            sum(1 for c in cameras if c.activation_status.value == "active"),
            sum(1 for c in cameras if c.activation_status.value == "inactive"),
            sum(1 for c in cameras if c.activation_status.value == "unknown"),
        )

        # --- 3. Activation des caméras inactives / en config usine ----------
        activation_pending = [c for c in cameras if c.last_error is None]
        to_activate: list[Camera] = []
        for camera in activation_pending:
            if await writes_approved(camera):
                to_activate.append(camera)
            elif camera.activation_status is not ActivationStatus.ACTIVE:
                camera.activation_result = ActivationResult.MANUAL_REQUIRED
        activation = ActivationEngine(talker, config)
        await bounded(
            to_activate,
            activation.activate,
        )

        # --- 3bis. Re-fingerprint : récupérer modèle/série/firmware après
        # activation. Les caméras inactives (config usine) refusaient le
        # fingerprinting (401) pendant la découverte ; une fois activées, on
        # relit leur identité pour enrichir le rapport. Best-effort : un échec
        # d'enrichissement ne fait pas échouer la caméra. --------------------
        to_enrich = [
            c
            for c in cameras
            if c.last_error is None
            and c.activation_status is ActivationStatus.ACTIVE
            and c.model is None
        ]
        if to_enrich:
            await bounded(to_enrich, fingerprinting.identify)
            logger.info(
                "re-fingerprint : %d caméra(s) enrichie(s) après activation",
                sum(1 for c in to_enrich if c.model is not None),
            )

        # --- 4. Détection des conflits (caméras actives) --------------------
        addressable = [
            c
            for c in cameras
            if c.activation_status is ActivationStatus.ACTIVE and c.last_error is None
        ]
        conflicts: list[Conflict] = detect_conflicts(addressable)
        result.total_conflicts_detected = len(conflicts)
        if not conflicts:
            logger.info("aucun conflit d'adresse détecté")
        else:
            logger.warning(
                "%d conflit(s) d'adresse détecté(s) : %s",
                len(conflicts),
                [c.conflicting_ip for c in conflicts],
            )

        # --- 5. Résolution : IP temporaire unique par canal MAC-adressé -----
        if conflicts:
            cameras_by_mac = {c.mac_address: c for c in cameras if c.mac_address}
            reserved: set[str] = {str(config.gateway)}
            reserved.update(
                c.ip_address for c in cameras if c.ip_address and c.last_error is None
            )
            for conflict in conflicts:
                resolved = resolve_conflict(
                    conflict,
                    cameras_by_mac,
                    announcer,
                    subnet_mask=str(config.subnet_mask),
                    reserved_ips=reserved,
                )
                if resolved.resolution_status is ResolutionStatus.RESOLVED:
                    result.total_conflicts_resolved += 1
                else:
                    result.errors.append(
                        f"conflit {conflict.conflicting_ip} non résolu : {conflict.resolution_detail}"
                    )
                result.conflicts.append(resolved)

        # --- 6. Planification des adresses cibles ---------------------------
        try:
            plan_target_ips(cameras, config, conflicts)
        except PlanningError as exc:
            result.errors.append(str(exc))
            logger.critical("%s", exc)
            return _finish(result)

        # --- 7. Attribution finale (unicast, IP désormais uniques) ----------
        assignment = AssignmentEngine(talker, config)
        assignment_candidates: list[Camera] = []
        for camera in cameras:
            if camera.last_error is not None:
                continue
            if await writes_approved(camera):
                assignment_candidates.append(camera)
            elif camera.assignment_status is not AssignmentStatus.SUCCESS:
                # Non confirmée par l'utilisateur : pas d'écriture réseau. Elle reste
                # à traiter manuellement (visible dans le rapport), non modifiée.
                camera.activation_result = ActivationResult.MANUAL_REQUIRED
        await bounded(assignment_candidates, assignment.assign)

    except Exception as exc:  # noqa: BLE001 - erreur au niveau pipeline
        result.errors.append(f"échec pipeline : {exc}")
        logger.critical("échec pipeline : %s", exc, exc_info=True)

    finally:
        if own_talker:
            await talker.aclose()

    return _finish(result)


def _finish(result: AssignmentResult) -> AssignmentResult:
    for camera in result.cameras:
        if camera.assignment_status.value == "success":
            result.total_assigned += 1
        elif camera.activation_result is ActivationResult.MANUAL_REQUIRED:
            result.total_manual_required += 1
        elif camera.last_error is not None:
            result.total_failed += 1
    result.finished_at = datetime.now()
    return result
