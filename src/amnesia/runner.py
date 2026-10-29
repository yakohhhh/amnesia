"""Moteur d'audit : exécute les checks sur une cible et agrège leurs résultats.

Pour chaque check, dans l'ordre reçu :

1. collecte de ses faits requis (``requires_facts``) par un ``CachingCollector``
   propre à l'audit : un fait demandé par plusieurs checks n'est collecté qu'une
   fois ;
2. ``resolve()`` traduit un fait requis indisponible en résultat (error, skipped
   ou not_applicable) ; le check n'est alors pas évalué ;
3. sinon, ``evaluate()`` rend le résultat.

Un check qui plante ne fait jamais tomber les autres :

=======================================  =======================================
Le check (ou la collecte de ses faits)   Résultat
=======================================  =======================================
lève ``CheckSkipped``                    ``skipped``, motif de l'exception
lève ``NotApplicable``                   ``not_applicable``
lève ``NotImplementedError``             ``skipped`` / ``not_implemented``
lève une autre exception                 ``error`` / ``internal_error`` : type
                                         et message caviardé ; la trace
                                         seulement avec ``debug=True``
rend autre chose que son propre          ``error`` / ``internal_error``
résultat sur cette cible
dépasse le délai                         ``error`` / ``timeout``
lève ``KeyboardInterrupt``               arrêt : ``AuditResult`` partiel,
                                         ``interrupted=True``
=======================================  =======================================

Délai
-----
Chaque check s'exécute dans un thread de travail (``concurrent.futures``), attendu
au plus ``timeout`` secondes (120 par défaut). Après un dépassement, l'exécuteur
est abandonné par ``shutdown(wait=False, cancel_futures=True)`` et le check
suivant part sur un thread neuf : un bloc ``with ThreadPoolExecutor()``
attendrait la fin du check bloqué.

Un thread Python ne peut pas être tué : le check bloqué continue en arrière-plan
(l'interpréteur l'attend à la sortie) et garde le verrou du ``CachingCollector``
s'il est bloqué dans une collecte. Les collecteurs bornent donc eux-mêmes leurs
appels (``subprocess.run(timeout=...)``, timeouts WinRM) avec le ``timeout``
qu'ils reçoivent.

Temps
-----
Durées mesurées par ``time.monotonic()`` ; ``started_at`` et ``finished_at``
viennent d'une horloge injectable (``clock``), en UTC ISO 8601.
"""

from __future__ import annotations

import dataclasses
import functools
import getpass
import logging
import math
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any

from . import __version__
from .checks.base import (
    Check,
    CheckResult,
    CheckSkipped,
    NotApplicable,
    Reason,
    Status,
)
from .checks.context import Context
from .checks.registry import SEVERITES
from .facts import CachingCollector, Collector, resolve
from .log import check_logger
from .target import Target

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 120.0
"""Délai par défaut d'un check, collecte de ses faits comprise (secondes)."""

OPERATEUR_INCONNU = "inconnu"

# rang des resultats sans Gap : apres toutes les severites, connues ou non
_RANG_SANS_GAP = len(SEVERITES) + 1


def _maintenant() -> datetime:
    return datetime.now(UTC)


def _horodatage(instant: datetime) -> str:
    """Horodatage ISO 8601 ramené en UTC ; un instant sans fuseau est refusé."""
    if not isinstance(instant, datetime) or instant.utcoffset() is None:
        raise ValueError(f"horloge : instant UTC avec fuseau attendu, reçu {instant!r}")
    return instant.astimezone(UTC).isoformat()


def _operateur() -> str:
    """Compte local qui exécute amnesia, ou « inconnu »."""
    try:
        return getpass.getuser()
    except Exception:  # ni variable d'environnement ni entree pwd
        return OPERATEUR_INCONNU


def _verifier_timeout(timeout: float) -> None:
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, int | float)
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError(f"timeout invalide : {timeout!r} (secondes > 0 attendues)")


def _rang(resultat: CheckResult) -> int:
    """Rang de la sévérité maximale des Gaps du résultat (0 : critical)."""
    rangs = [
        SEVERITES.index(g.severity) if g.severity in SEVERITES else len(SEVERITES)
        for g in resultat.gaps
    ]
    return min(rangs, default=_RANG_SANS_GAP)


def _cle_de_tri(resultat: CheckResult) -> tuple[int, str]:
    # severite maximale decroissante, puis check_id : ordre independant de
    # l'ordre d'execution
    return _rang(resultat), resultat.check_id


@dataclass(frozen=True, kw_only=True)
class AuditSummary:
    """Comptes d'un audit : résultats par statut, Gaps par sévérité.

    ``by_status`` porte tous les statuts, ``by_severity`` toutes les sévérités
    connues (``critical`` à ``info``), à zéro s'il le faut. ``excluded`` et
    ``not_evaluated`` reprennent les propriétés de ``CheckResult``.
    """

    total: int
    by_status: Mapping[str, int]
    by_severity: Mapping[str, int]
    gaps: int
    excluded: int
    not_evaluated: int

    @classmethod
    def from_results(cls, results: Iterable[CheckResult]) -> AuditSummary:
        resultats = list(results)
        par_statut = {s.value: 0 for s in Status}
        par_severite = dict.fromkeys(SEVERITES, 0)
        for r in resultats:
            par_statut[r.status.value] += 1
            for gap in r.gaps:
                cle = str(gap.severity)
                par_severite[cle] = par_severite.get(cle, 0) + 1
        return cls(
            total=len(resultats),
            by_status=MappingProxyType(par_statut),
            by_severity=MappingProxyType(par_severite),
            gaps=sum(len(r.gaps) for r in resultats),
            excluded=sum(r.excluded for r in resultats),
            not_evaluated=sum(r.not_evaluated for r in resultats),
        )


def _nouvel_id() -> str:
    return str(uuid.uuid4())


@dataclass(frozen=True, kw_only=True)
class AuditResult:
    """Résultat agrégé d'un audit sur une cible.

    ``results`` est trié à la construction par sévérité maximale décroissante
    puis par ``check_id`` : deux exécutions donnent le même ordre. ``summary``
    et ``complete`` en sont dérivés. ``complete`` est faux dès qu'un check est
    en ``error`` ou en ``skipped`` hors ``user_excluded``, ou si l'audit a été
    interrompu (``interrupted``, résultats partiels).

    ``operator`` est le compte local qui a lancé amnesia (surchargeable) ;
    ``started_at`` et ``finished_at`` sont en UTC ISO 8601.
    """

    amnesia_version: str = __version__
    run_id: str = field(default_factory=_nouvel_id)
    started_at: str
    finished_at: str
    duration_s: float
    target: Target
    operator: str
    results: tuple[CheckResult, ...]
    interrupted: bool = False

    def __post_init__(self) -> None:
        resultats = tuple(self.results)
        for resultat in resultats:
            if not isinstance(resultat, CheckResult):
                raise TypeError(f"results : CheckResult attendu, reçu {resultat!r}")
        object.__setattr__(self, "results", tuple(sorted(resultats, key=_cle_de_tri)))

    @property
    def summary(self) -> AuditSummary:
        """Comptes par statut et par sévérité."""
        return AuditSummary.from_results(self.results)

    @property
    def complete(self) -> bool:
        """Vrai si chaque check a été évalué ou exclu par l'utilisateur."""
        return not self.interrupted and not any(r.not_evaluated for r in self.results)


class _Executeur:
    """Thread de travail réutilisé d'un check à l'autre, abandonné s'il bloque."""

    def __init__(self) -> None:
        self._pool: ThreadPoolExecutor | None = None

    def soumettre(self, tache: Callable[[], CheckResult]) -> Future[CheckResult]:
        if self._pool is None:
            self._pool = ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="amnesia-check"
            )
        return self._pool.submit(tache)

    def abandonner(self) -> None:
        """Libère l'exécuteur sans attendre le check en cours."""
        if self._pool is not None:
            # wait=True (ou un bloc with) attendrait la fin du check bloque
            self._pool.shutdown(wait=False, cancel_futures=True)
            self._pool = None


def _verifier_resultat(resultat: object, check_id: str, cible: str) -> CheckResult:
    if not isinstance(resultat, CheckResult):
        raise TypeError(
            f"evaluate() doit rendre un CheckResult, reçu {type(resultat).__name__}"
        )
    if (resultat.check_id, resultat.target) != (check_id, cible):
        raise ValueError(
            f"evaluate() a rendu le résultat de {resultat.check_id!r} "
            f"sur {resultat.target!r}"
        )
    return resultat


def _evaluer(
    check: Check,
    collecteur: CachingCollector,
    contexte: Context,
    *,
    timeout: float,
    debug: bool,
) -> CheckResult:
    """Collecte, résolution puis évaluation d'un check (thread de travail).

    Ne lève que ``KeyboardInterrupt`` : toute autre exception devient un résultat.
    """
    cible = contexte.target
    try:
        faits = collecteur.collect(cible, check.requires_facts, timeout=timeout)
        impose = resolve(check.id, cible.id, check.requires_facts, faits)
        if impose is not None:
            return impose
        return _verifier_resultat(check.evaluate(faits, contexte), check.id, cible.id)
    except KeyboardInterrupt:
        raise
    except CheckSkipped as exc:
        return CheckResult.skipped(check.id, cible.id, exc.reason, exc.message)
    except NotApplicable as exc:
        return CheckResult.not_applicable(check.id, cible.id, exc.message)
    except NotImplementedError:
        return CheckResult.skipped(
            check.id, cible.id, Reason.NOT_IMPLEMENTED, "check non implémenté"
        )
    except BaseException as exc:
        # SystemExit compris : un check ne fait jamais tomber l'audit
        contexte.logger.debug(
            "exception %s", type(exc).__name__, exc_info=exc, extra={"target": cible.id}
        )
        return CheckResult.failed(
            check.id, cible.id, Reason.INTERNAL_ERROR, exc, with_traceback=debug
        )


def _depassement(check_id: str, cible: str, timeout: float) -> CheckResult:
    message = f"délai dépassé après {timeout:g} s"
    return CheckResult.failed(
        check_id, cible, Reason.TIMEOUT, TimeoutError(message), message=message
    )


def _executer(
    check: Check,
    target: Target,
    collecteur: CachingCollector,
    executeur: _Executeur,
    *,
    config: Mapping[str, Any] | None,
    clock: Callable[[], datetime],
    timeout: float,
    debug: bool,
) -> CheckResult:
    """Exécute un check avec son délai ; journalise début, fin, statut et durée."""
    journal = check_logger(check.id)
    journal.debug("début", extra={"target": target.id})
    contexte = Context.for_check(check.id, target, config=config, clock=clock)
    tache = functools.partial(
        _evaluer, check, collecteur, contexte, timeout=timeout, debug=debug
    )
    debut = time.monotonic()
    future = executeur.soumettre(tache)
    try:
        resultat = future.result(timeout=timeout)
    except TimeoutError:
        # _evaluer ne leve jamais TimeoutError : c'est l'attente qui a expire
        executeur.abandonner()
        resultat = _depassement(check.id, target.id, timeout)
    except KeyboardInterrupt:
        executeur.abandonner()
        journal.warning("interrompu", extra={"target": target.id})
        raise
    duree = time.monotonic() - debut
    resultat = dataclasses.replace(resultat, duration_s=duree)
    statut = resultat.status.value
    if resultat.reason is not None:
        statut = f"{statut}/{resultat.reason.value}"
    journal.log(
        logging.WARNING if resultat.status is Status.ERROR else logging.INFO,
        "fin : %s en %.3f s",
        statut,
        duree,
        extra={"target": target.id, "duration_ms": round(duree * 1000)},
    )
    return resultat


def _notifier(
    on_result: Callable[[CheckResult], object], resultat: CheckResult
) -> None:
    try:
        on_result(resultat)
    except Exception as exc:
        # un affichage de progression defaillant n'arrete pas l'audit
        logger.warning(
            "on_result a levé %s pour %s", type(exc).__name__, resultat.check_id
        )


def run_audit(
    checks: Iterable[Check | type[Check]],
    target: Target,
    collector: Collector,
    *,
    config: Mapping[str, Any] | None = None,
    clock: Callable[[], datetime] | None = None,
    debug: bool = False,
    on_result: Callable[[CheckResult], object] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    operator: str | None = None,
) -> AuditResult:
    """Exécute ``checks`` sur ``target`` et agrège leurs résultats.

    ``checks`` : classes (instanciées ici, neuves à chaque audit) ou instances
    neuves, par ex. ``REGISTRY.classes()``. ``collector`` est enveloppé dans un
    ``CachingCollector`` propre à cet audit. ``config`` est transmis en lecture
    seule aux checks (``Context``). ``clock`` (UTC) date l'audit et sert aux
    checks ; ``timeout`` borne chaque check, collecte comprise. ``debug=True``
    garde la trace des exceptions dans les résultats. ``on_result`` est appelé
    après chaque check, dans l'ordre d'exécution (progression ; branchement
    dans la CLI : #24). Un ``KeyboardInterrupt`` arrête l'audit : le résultat
    partiel est rendu avec ``interrupted=True``.

    Lève ``ValueError`` si ``timeout`` n'est pas un nombre de secondes > 0 ou si
    l'horloge rend un instant sans fuseau.
    """
    _verifier_timeout(timeout)
    horloge = _maintenant if clock is None else clock
    operateur = _operateur() if operator is None else operator
    # instances neuves : aucun etat ne passe d'un audit a l'autre (#17)
    instances = [c() if isinstance(c, type) else c for c in checks]
    collecteur = CachingCollector(collector)
    executeur = _Executeur()
    started_at = _horodatage(horloge())
    debut = time.monotonic()
    logger.info(
        "audit de %s : %d check(s)",
        target.id,
        len(instances),
        extra={"target": target.id},
    )
    resultats: list[CheckResult] = []
    interrompu = False
    try:
        for check in instances:
            resultat = _executer(
                check,
                target,
                collecteur,
                executeur,
                config=config,
                clock=horloge,
                timeout=timeout,
                debug=debug,
            )
            resultats.append(resultat)
            if on_result is not None:
                _notifier(on_result, resultat)
    except KeyboardInterrupt:
        interrompu = True
        logger.warning(
            "audit de %s interrompu après %d check(s) sur %d",
            target.id,
            len(resultats),
            len(instances),
            extra={"target": target.id},
        )
    finally:
        executeur.abandonner()
    duree = time.monotonic() - debut
    audit = AuditResult(
        started_at=started_at,
        finished_at=_horodatage(horloge()),
        duration_s=duree,
        target=target,
        operator=operateur,
        results=tuple(resultats),
        interrupted=interrompu,
    )
    logger.info(
        "audit de %s terminé en %.3f s : %s",
        target.id,
        duree,
        ", ".join(f"{n} {s}" for s, n in audit.summary.by_status.items() if n),
        extra={"target": target.id, "duration_ms": round(duree * 1000)},
    )
    return audit
