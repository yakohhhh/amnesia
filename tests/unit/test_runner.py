"""Moteur d'audit : isolation des erreurs, délai, interruption, agrégation (#21)."""

from __future__ import annotations

import getpass
import logging
import subprocess
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

import amnesia
from amnesia import AuditResult, run_audit, runner
from amnesia.checks import REGISTRY, Check, Gap
from amnesia.checks.base import (
    CheckResult,
    CheckSkipped,
    Confidence,
    Evidence,
    NotApplicable,
    Reason,
    Severity,
    Status,
)
from amnesia.checks.context import Context
from amnesia.facts import Fact, FactSet, UnavailableReason
from amnesia.runner import DEFAULT_TIMEOUT, OPERATEUR_INCONNU, AuditSummary
from amnesia.target import Target

CIBLE = Target.parse("winrm://dc01")
INSTANT = datetime(2026, 10, 21, 9, 30, tzinfo=UTC)

# --- collecteurs et checks factices ------------------------------------------


class CollecteurFactice:
    """Rend chaque fait demandé, observé ou indisponible ; compte ses appels."""

    def __init__(self, indisponibles: dict[str, UnavailableReason] | None = None):
        self.indisponibles = dict(indisponibles or {})
        self.appels: Counter[str] = Counter()

    def collect(
        self, target: Target, names: Iterable[str], *, timeout: float
    ) -> FactSet:
        faits = []
        for nom in names:
            self.appels[nom] += 1
            raison = self.indisponibles.get(nom)
            if raison is None:
                faits.append(Fact.ok(nom, True, source="test", collected_at=INSTANT))
            else:
                faits.append(
                    Fact.unavailable(nom, raison, source="test", collected_at=INSTANT)
                )
        return FactSet(faits)


class Factice(Check):
    """Check factice : le comportement est une fonction des faits et du contexte."""

    def __init__(
        self,
        id: str,
        comportement: Callable[[Factice, FactSet, Context], CheckResult],
        requires_facts: tuple[str, ...] = (),
    ) -> None:
        self.id = id
        self.requires_facts = requires_facts
        self.comportement = comportement
        self.appels = 0

    def evaluate(self, facts: FactSet, ctx: Context) -> CheckResult:
        self.appels += 1
        return self.comportement(self, facts, ctx)


def conforme(check: Factice, facts: FactSet, ctx: Context) -> CheckResult:
    return CheckResult.passed(check.id, ctx.target.id)


def un_gap(
    check_id: str, cible: str, severite: str, ressource: str = "Security"
) -> Gap:
    return Gap(
        check_id=check_id,
        target=cible,
        resource=ressource,
        question="Qui s'est connecté ?",
        reason="journal écrasé",
        severity=Severity.parse(severite),
        evidence=Evidence(
            observed=4,
            expected=90,
            unit="days",
            confidence=Confidence.MEASURED,
            source="test",
        ),
        remediation="agrandir le journal",
    )


def gap(severite: str) -> Callable[[Factice, FactSet, Context], CheckResult]:
    def comportement(check: Factice, facts: FactSet, ctx: Context) -> CheckResult:
        return CheckResult.with_gaps(
            check.id, ctx.target.id, [un_gap(check.id, ctx.target.id, severite)]
        )

    return comportement


def leve(exc: BaseException) -> Callable[[Factice, FactSet, Context], CheckResult]:
    def comportement(check: Factice, facts: FactSet, ctx: Context) -> CheckResult:
        raise exc

    return comportement


@pytest.fixture
def liberation() -> Iterator[threading.Event]:
    """Événement qui réveille les checks « endormis » à la fin du test."""
    evenement = threading.Event()
    yield evenement
    evenement.set()


def dort(
    evenement: threading.Event, secondes: float = 5.0
) -> Callable[[Factice, FactSet, Context], CheckResult]:
    # dort 5 s, ou jusqu'a la fin du test : aucun thread ne survit a la suite
    def comportement(check: Factice, facts: FactSet, ctx: Context) -> CheckResult:
        evenement.wait(secondes)
        return CheckResult.passed(check.id, ctx.target.id)

    return comportement


def auditer(checks: Iterable[Check | type[Check]], **options: Any) -> AuditResult:
    collecteur = options.pop("collector", CollecteurFactice())
    options.setdefault("operator", "auditeur")
    return run_audit(checks, CIBLE, collecteur, **options)


def par_id(audit: AuditResult) -> dict[str, CheckResult]:
    return {r.check_id: r for r in audit.results}


# --- critères d'acceptation ---------------------------------------------------


def test_cinq_checks_factices_et_poursuite_apres_erreur(
    liberation: threading.Event,
) -> None:
    executes: list[str] = []
    checks = [
        Factice("test.pass", conforme),
        Factice("test.gap", gap("high")),
        Factice("test.erreur", leve(RuntimeError("sortie inattendue"))),
        Factice("test.lent", dort(liberation)),
        Factice("test.sans_objet", leve(NotApplicable("serveur de fichiers"))),
    ]
    audit = auditer(
        checks, timeout=0.2, on_result=lambda r: executes.append(r.check_id)
    )
    resultats = par_id(audit)
    assert len(audit.results) == 5
    assert resultats["test.pass"].status is Status.PASS
    assert resultats["test.gap"].status is Status.GAP
    erreur = resultats["test.erreur"]
    assert (erreur.status, erreur.reason) == (Status.ERROR, Reason.INTERNAL_ERROR)
    assert erreur.error is not None
    assert (erreur.error.type, erreur.error.message) == (
        "RuntimeError",
        "sortie inattendue",
    )
    lent = resultats["test.lent"]
    assert (lent.status, lent.reason) == (Status.ERROR, Reason.TIMEOUT)
    assert lent.message == "délai dépassé après 0.2 s"
    assert lent.error is not None and lent.error.type == "TimeoutError"
    sans_objet = resultats["test.sans_objet"]
    assert sans_objet.status is Status.NOT_APPLICABLE
    assert sans_objet.message == "serveur de fichiers"
    # l'execution continue apres l'erreur et apres le depassement
    assert executes == [c.id for c in checks]
    assert all(c.appels == 1 for c in checks)


def test_timeout_court_rend_la_main_vite(liberation: threading.Event) -> None:
    debut = time.monotonic()
    audit = auditer(
        [Factice("test.lent", dort(liberation)), Factice("test.suivant", conforme)],
        timeout=0.2,
    )
    assert time.monotonic() - debut < 2
    resultats = par_id(audit)
    assert resultats["test.lent"].reason is Reason.TIMEOUT
    # le check suivant part sur un thread neuf, sans attendre le check bloque
    assert resultats["test.suivant"].status is Status.PASS
    duree = resultats["test.lent"].duration_s
    # sous Windows, l'attente de Future.result() peut rendre la main une
    # fraction de milliseconde avant que time.monotonic() n'ait avance de
    # 0.2 s (granularite des horloges) : marge de 50 ms sur la borne basse
    assert duree is not None and 0.15 <= duree < 2


def test_keyboard_interrupt_rend_un_audit_partiel() -> None:
    apres = Factice("test.c_apres", conforme)
    audit = auditer(
        [
            Factice("test.a_avant", conforme),
            Factice("test.b_interruption", leve(KeyboardInterrupt())),
            apres,
        ]
    )
    assert audit.interrupted is True
    assert [r.check_id for r in audit.results] == ["test.a_avant"]
    assert audit.results[0].status is Status.PASS
    assert apres.appels == 0
    assert audit.complete is False


def test_summary_et_complete() -> None:
    audit = auditer(
        [
            Factice("test.pass", conforme),
            Factice("test.gap_high", gap("high")),
            Factice("test.gap_low", gap("low")),
            Factice("test.erreur", leve(ValueError("format imprévu"))),
            Factice(
                "test.exclu",
                leve(CheckSkipped(Reason.USER_EXCLUDED, "retiré du périmètre")),
            ),
        ]
    )
    resume = audit.summary
    assert isinstance(resume, AuditSummary)
    assert resume.total == 5
    assert dict(resume.by_status) == {
        "pass": 1,
        "gap": 2,
        "error": 1,
        "skipped": 1,
        "not_applicable": 0,
    }
    assert dict(resume.by_severity) == {
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 1,
        "info": 0,
    }
    assert (resume.gaps, resume.excluded, resume.not_evaluated) == (2, 1, 1)
    # une erreur suffit a rendre l'audit incomplet
    assert audit.complete is False


def test_complete_vrai_sans_erreur_ni_saut() -> None:
    audit = auditer(
        [
            Factice("test.pass", conforme),
            Factice("test.gap", gap("medium")),
            Factice("test.sans_objet", leve(NotApplicable("hors périmètre"))),
            Factice(
                "test.exclu",
                leve(CheckSkipped(Reason.USER_EXCLUDED, "retiré du périmètre")),
            ),
        ]
    )
    assert audit.complete is True
    assert audit.interrupted is False


@pytest.mark.parametrize(
    ("comportement", "complet"),
    [
        (leve(CheckSkipped(Reason.NOT_COLLECTED, "bundle partiel")), False),
        (leve(CheckSkipped(Reason.MISSING_PRIVILEGE, "SeSecurityPrivilege")), False),
        (leve(NotImplementedError()), False),
        (leve(CheckSkipped(Reason.USER_EXCLUDED, "exclu")), True),
    ],
)
def test_complete_selon_le_motif_de_saut(
    comportement: Callable[[Factice, FactSet, Context], CheckResult], complet: bool
) -> None:
    audit = auditer([Factice("test.pass", conforme), Factice("test.x", comportement)])
    assert audit.complete is complet


def test_ordre_deterministe() -> None:
    def checks() -> list[Check]:
        return [
            Factice("test.c_pass", conforme),
            Factice("test.b_low", gap("low")),
            Factice("test.a_high", gap("high")),
            Factice("test.d_critical", gap("critical")),
            Factice("test.a_erreur", leve(RuntimeError("x"))),
            Factice("test.e_high", gap("high")),
        ]

    premier = auditer(checks())
    second = auditer(checks())
    melange = checks()[::-1]
    troisieme = auditer(melange)
    ordre = [r.check_id for r in premier.results]
    assert ordre == [r.check_id for r in second.results]
    assert ordre == [r.check_id for r in troisieme.results]
    # severite maximale decroissante, puis check_id ; sans Gap a la fin
    assert ordre == [
        "test.d_critical",
        "test.a_high",
        "test.e_high",
        "test.b_low",
        "test.a_erreur",
        "test.c_pass",
    ]


def test_severite_maximale_d_un_resultat() -> None:
    def plusieurs(check: Factice, facts: FactSet, ctx: Context) -> CheckResult:
        gaps = [
            un_gap(check.id, ctx.target.id, "low", "System"),
            un_gap(check.id, ctx.target.id, "critical", "Security"),
        ]
        return CheckResult.with_gaps(check.id, ctx.target.id, gaps)

    audit = auditer([Factice("test.a_high", gap("high")), Factice("test.z", plusieurs)])
    assert [r.check_id for r in audit.results] == ["test.z", "test.a_high"]


def test_traceback_absent_par_defaut_present_en_debug() -> None:
    def checks() -> list[Check]:
        return [Factice("test.erreur", leve(KeyError("EventID")))]

    sans = auditer(checks()).results[0]
    assert sans.error is not None and sans.error.traceback is None
    assert sans.to_dict()["error"]["traceback"] is None
    avec = auditer(checks(), debug=True).results[0]
    assert avec.error is not None and avec.error.traceback is not None
    assert avec.error.traceback.startswith("Traceback (most recent call last):")
    assert "comportement" in avec.error.traceback


def test_horloge_figee_horodatages_utc(
    horloge_figee: Callable[[], datetime],
) -> None:
    audit = auditer([Factice("test.pass", conforme)], clock=horloge_figee)
    assert audit.started_at == "2026-10-21T09:30:00+00:00"
    assert audit.finished_at == "2026-10-21T09:30:00+00:00"
    assert datetime.fromisoformat(audit.started_at).utcoffset() == timedelta(0)


def test_horloge_avancante_et_fuseau_ramene_en_utc() -> None:
    paris = timezone(timedelta(hours=2))
    instants = iter(
        [
            datetime(2026, 10, 21, 11, 30, tzinfo=paris),
            datetime(2026, 10, 21, 11, 31, 5, tzinfo=paris),
        ]
    )
    audit = auditer([], clock=lambda: next(instants))
    assert audit.started_at == "2026-10-21T09:30:00+00:00"
    assert audit.finished_at == "2026-10-21T09:31:05+00:00"


def test_horloge_sans_fuseau_refusee() -> None:
    naif = datetime(2026, 10, 21, 9, 30)  # noqa: DTZ001 - cas refuse
    with pytest.raises(ValueError, match="fuseau"):
        auditer([], clock=lambda: naif)


def test_export_public() -> None:
    assert amnesia.run_audit is run_audit
    assert amnesia.AuditResult is AuditResult
    assert {"run_audit", "AuditResult"} <= set(amnesia.__all__)


# --- collecte, résolution, contexte ---------------------------------------------


def test_fait_indisponible_resolu_sans_evaluer() -> None:
    collecteur = CollecteurFactice(
        {"windows.sysmon.service": UnavailableReason.ACCESS_DENIED}
    )
    refuse = Factice("test.refuse", conforme, ("windows.sysmon.service",))
    absent = Factice("test.absent", conforme, ("windows.sysmon.config",))
    audit = auditer([refuse, absent], collector=_SansFait(collecteur))
    resultats = par_id(audit)
    assert (resultats["test.refuse"].status, resultats["test.refuse"].reason) == (
        Status.ERROR,
        Reason.ACCESS_DENIED,
    )
    assert resultats["test.absent"].reason is Reason.NOT_COLLECTED
    assert refuse.appels == absent.appels == 0


class _SansFait:
    """Ne rend pas windows.sysmon.config : fait absent du FactSet."""

    def __init__(self, interne: CollecteurFactice) -> None:
        self.interne = interne

    def collect(
        self, target: Target, names: Iterable[str], *, timeout: float
    ) -> FactSet:
        demandes = [n for n in names if n != "windows.sysmon.config"]
        return self.interne.collect(target, demandes, timeout=timeout)


def test_fait_partage_collecte_une_fois_par_audit() -> None:
    collecteur = CollecteurFactice()
    fait = "windows.auditpol.backup"

    def lit(check: Factice, facts: FactSet, ctx: Context) -> CheckResult:
        assert facts.value(fait) is True
        return CheckResult.passed(check.id, ctx.target.id)

    checks = [Factice("test.a", lit, (fait,)), Factice("test.b", lit, (fait,))]
    auditer(checks, collector=collecteur)
    assert collecteur.appels[fait] == 1
    # cache propre a l'audit : un nouvel audit collecte de nouveau
    auditer(checks, collector=collecteur)
    assert collecteur.appels[fait] == 2


def test_contexte_transmis_au_check(horloge_figee: Callable[[], datetime]) -> None:
    vus: list[Context] = []

    def note(check: Factice, facts: FactSet, ctx: Context) -> CheckResult:
        vus.append(ctx)
        return CheckResult.passed(check.id, ctx.target.id)

    auditer([Factice("test.ctx", note)], config={"seuil": 7}, clock=horloge_figee)
    (contexte,) = vus
    assert contexte.target is CIBLE
    assert contexte.config["seuil"] == 7
    assert contexte.clock() == INSTANT
    assert contexte.logger.name == "amnesia.check.test.ctx"


def test_checks_du_registre_non_implementes() -> None:
    # tous les faits observes : evaluate() est appele et leve NotImplementedError
    audit = auditer(REGISTRY.classes())
    assert len(audit.results) == len(REGISTRY.metas())
    for resultat in audit.results:
        assert (resultat.status, resultat.reason) == (
            Status.SKIPPED,
            Reason.NOT_IMPLEMENTED,
        )
    assert audit.complete is False


class Compteur(Check):
    """Check déclaré par sa classe : le moteur en crée une instance par audit."""

    id = "test.compteur"
    instances: list[Compteur] = []  # noqa: RUF012 - registre de test

    def __init__(self) -> None:
        Compteur.instances.append(self)
        self.evaluations = 0

    def evaluate(self, facts: FactSet, ctx: Context) -> CheckResult:
        self.evaluations += 1
        return CheckResult.passed(self.id, ctx.target.id)


def test_instances_neuves_a_chaque_audit() -> None:
    Compteur.instances.clear()
    auditer([Compteur])
    auditer([Compteur])
    premiere, seconde = Compteur.instances
    assert premiere is not seconde
    assert premiere.evaluations == seconde.evaluations == 1


# --- isolation des erreurs ----------------------------------------------------


@pytest.mark.parametrize(
    ("exc", "statut", "motif"),
    [
        (
            CheckSkipped(Reason.MISSING_PRIVILEGE, "jeton"),
            Status.SKIPPED,
            Reason.MISSING_PRIVILEGE,
        ),
        (NotImplementedError("à écrire"), Status.SKIPPED, Reason.NOT_IMPLEMENTED),
        (SystemExit(3), Status.ERROR, Reason.INTERNAL_ERROR),
        (TimeoutError("WMI"), Status.ERROR, Reason.INTERNAL_ERROR),
    ],
)
def test_exceptions_converties(
    exc: BaseException, statut: Status, motif: Reason
) -> None:
    resultat = auditer([Factice("test.x", leve(exc))]).results[0]
    assert (resultat.status, resultat.reason) == (statut, motif)


# concatene : aucun secret litteral pour gitleaks
MDP = "S3cr3t-" + "Pass!"


def test_message_d_erreur_caviarde() -> None:
    exc = RuntimeError(f"connexion winrm://audit:{MDP}@dc01 refusée")
    resultat = auditer([Factice("test.x", leve(exc))]).results[0]
    assert resultat.error is not None
    assert MDP not in resultat.error.message
    assert MDP not in resultat.message


@pytest.mark.parametrize(
    "rendu",
    [
        None,
        CheckResult.passed("test.autre", CIBLE.id),
        CheckResult.passed("test.x", "winrm://dc02"),
    ],
)
def test_resultat_invalide_devient_erreur_interne(rendu: object) -> None:
    def rend(check: Factice, facts: FactSet, ctx: Context) -> Any:
        return rendu

    resultat = auditer([Factice("test.x", rend)]).results[0]
    assert (resultat.check_id, resultat.status, resultat.reason) == (
        "test.x",
        Status.ERROR,
        Reason.INTERNAL_ERROR,
    )


def test_collecteur_qui_plante() -> None:
    class Defaillant:
        def collect(
            self, target: Target, names: Iterable[str], *, timeout: float
        ) -> FactSet:
            raise OSError("WinRM injoignable")

    check = Factice("test.x", conforme, ("windows.sysmon.service",))
    resultat = auditer([check], collector=Defaillant()).results[0]
    assert (resultat.status, resultat.reason) == (Status.ERROR, Reason.INTERNAL_ERROR)
    assert check.appels == 0


def test_on_result_defaillant_n_arrete_pas_l_audit(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def casse(resultat: CheckResult) -> None:
        raise BrokenPipeError

    caplog.set_level(logging.WARNING, logger="amnesia")
    audit = auditer(
        [Factice("test.a", conforme), Factice("test.b", conforme)], on_result=casse
    )
    assert len(audit.results) == 2
    assert audit.complete is True
    assert "on_result a levé BrokenPipeError" in caplog.text


# --- durées, journaux, métadonnées --------------------------------------------


def test_durees_mesurees() -> None:
    audit = auditer([Factice("test.a", conforme), Factice("test.b", conforme)])
    for resultat in audit.results:
        assert resultat.duration_s is not None and resultat.duration_s >= 0
    assert audit.duration_s >= sum(r.duration_s or 0 for r in audit.results)


def test_journal_par_check(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger="amnesia")
    auditer(
        [Factice("test.pass", conforme), Factice("test.erreur", leve(RuntimeError()))]
    )
    par_logger: dict[str, list[logging.LogRecord]] = {}
    for record in caplog.records:
        par_logger.setdefault(record.name, []).append(record)
    debut, fin = par_logger["amnesia.check.test.pass"]
    assert debut.getMessage() == "début"
    assert fin.getMessage().startswith("fin : pass en ")
    assert fin.levelno == logging.INFO
    assert isinstance(getattr(fin, "duration_ms", None), int)
    assert getattr(fin, "target", None) == CIBLE.id
    fin_erreur = par_logger["amnesia.check.test.erreur"][-1]
    assert fin_erreur.getMessage().startswith("fin : error/internal_error en ")
    assert fin_erreur.levelno == logging.WARNING


def test_metadonnees_d_execution() -> None:
    a = auditer([], operator="ACME\\auditeur")
    b = auditer([])
    assert a.amnesia_version == amnesia.__version__
    assert a.run_id != b.run_id
    assert len(a.run_id) == 36
    assert a.target is CIBLE
    assert a.operator == "ACME\\auditeur"
    assert a.results == ()
    assert a.complete is True


def test_operateur_par_defaut(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(getpass, "getuser", lambda: "analyste")
    assert run_audit([], CIBLE, CollecteurFactice()).operator == "analyste"

    def sans_compte() -> str:
        raise OSError("aucun compte")

    monkeypatch.setattr(getpass, "getuser", sans_compte)
    assert run_audit([], CIBLE, CollecteurFactice()).operator == OPERATEUR_INCONNU


@pytest.mark.parametrize(
    "timeout", [0, -1, float("inf"), float("nan"), True, threading.TIMEOUT_MAX * 2]
)
def test_timeout_invalide(timeout: float) -> None:
    with pytest.raises(ValueError, match="timeout invalide"):
        auditer([], timeout=timeout)


def test_timeout_par_defaut() -> None:
    assert DEFAULT_TIMEOUT == 120


def test_audit_result_trie_a_la_construction() -> None:
    resultats = (
        CheckResult.passed("test.a", CIBLE.id),
        CheckResult.with_gaps("test.b", CIBLE.id, [un_gap("test.b", CIBLE.id, "high")]),
    )
    audit = AuditResult(
        started_at="2026-10-21T09:30:00+00:00",
        finished_at="2026-10-21T09:30:01+00:00",
        duration_s=1.0,
        target=CIBLE,
        operator="auditeur",
        results=resultats,
    )
    assert [r.check_id for r in audit.results] == ["test.b", "test.a"]
    with pytest.raises(TypeError, match="CheckResult attendu"):
        AuditResult(
            started_at="",
            finished_at="",
            duration_s=0.0,
            target=CIBLE,
            operator="",
            results=("pas un résultat",),  # type: ignore[arg-type]
        )


# --- revue adversariale (#21) -------------------------------------------------


@pytest.mark.parametrize(
    "exc",
    [
        NotApplicable(None),  # type: ignore[arg-type]
        CheckSkipped(Reason.NOT_COLLECTED, 42),  # type: ignore[arg-type]
    ],
)
def test_saut_invalide_devient_erreur_interne_sans_arreter_l_audit(
    exc: BaseException,
) -> None:
    suivant = Factice("test.c_suivant", conforme)
    audit = auditer(
        [Factice("test.a_ok", conforme), Factice("test.b_bogue", leve(exc)), suivant]
    )
    resultats = par_id(audit)
    assert resultats["test.a_ok"].status is Status.PASS
    fautif = resultats["test.b_bogue"]
    assert (fautif.status, fautif.reason) == (Status.ERROR, Reason.INTERNAL_ERROR)
    assert resultats["test.c_suivant"].status is Status.PASS
    assert suivant.appels == 1


def test_filet_de_securite_si_l_evaluation_leve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def plante(*args: object, **kwargs: object) -> CheckResult:
        raise RuntimeError("conversion impossible")

    monkeypatch.setattr(runner, "_evaluer", plante)
    audit = auditer([Factice("test.a", conforme), Factice("test.b", conforme)])
    assert [(r.status, r.reason) for r in audit.results] == [
        (Status.ERROR, Reason.INTERNAL_ERROR),
        (Status.ERROR, Reason.INTERNAL_ERROR),
    ]


def _echec_wevtutil() -> subprocess.CalledProcessError:
    commande = ["wevtutil", "qe", "Security", f"/p:{MDP}", "-Password", MDP]
    return subprocess.CalledProcessError(5, commande)


def test_journal_d_erreur_interne_caviarde(caplog: pytest.LogCaptureFixture) -> None:
    # handler hote en DEBUG, sans le filtre d'expurgation d'amnesia
    caplog.set_level(logging.DEBUG, logger="amnesia")

    def implicite(check: Factice, facts: FactSet, ctx: Context) -> CheckResult:
        try:
            raise _echec_wevtutil()
        except subprocess.CalledProcessError:
            raise RuntimeError("collecte wevtutil echouee")  # noqa: B904

    def explicite(check: Factice, facts: FactSet, ctx: Context) -> CheckResult:
        try:
            raise _echec_wevtutil()
        except subprocess.CalledProcessError as exc:
            raise RuntimeError("collecte wevtutil echouee") from exc

    audit = auditer(
        [Factice("test.a", implicite), Factice("test.b", explicite)], debug=True
    )
    assert all(r.reason is Reason.INTERNAL_ERROR for r in audit.results)
    assert all(r.exc_info is None for r in caplog.records)
    assert MDP not in caplog.text
    assert "RuntimeError : collecte wevtutil echouee" in caplog.text


def test_check_sans_fait_non_bloque_par_une_collecte_bloquee(
    liberation: threading.Event,
) -> None:
    class Bloquant:
        def collect(
            self, target: Target, names: Iterable[str], *, timeout: float
        ) -> FactSet:
            liberation.wait(5.0)
            return FactSet()

    debut = time.monotonic()
    audit = auditer(
        [
            Factice("test.a", conforme, ("windows.sysmon.service",)),
            Factice("test.b", conforme),
            Factice("test.c", conforme),
        ],
        collector=Bloquant(),
        timeout=0.3,
    )
    resultats = par_id(audit)
    assert resultats["test.a"].reason is Reason.TIMEOUT
    assert resultats["test.b"].status is Status.PASS
    assert resultats["test.c"].status is Status.PASS
    assert time.monotonic() - debut < 2.0
