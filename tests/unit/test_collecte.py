"""Couche de collecte : collecteurs, memoisation, resolve() et API des checks."""

from __future__ import annotations

import ast
import logging
import re
import sys
from collections import Counter
from collections.abc import Callable, Iterable
from datetime import datetime
from pathlib import Path

import pytest

from amnesia.checks import Check, default_checks
from amnesia.checks.base import CheckResult, Reason, Status
from amnesia.checks.context import Context
from amnesia.facts import (
    CachingCollector,
    Collector,
    Fact,
    FactSet,
    FactUnavailableError,
    FixtureCollector,
    LocalCollector,
    UnavailableReason,
    resolve,
    validate_fact_name,
)
from amnesia.target import Target

RACINE = Path(__file__).resolve().parents[2]
DOC = RACINE / "docs" / "dev" / "faits.md"
INSTANT = datetime.fromisoformat("2026-10-21T09:30:00+00:00")
LOCAL = Target.parse("local")
DC01 = Target.parse("winrm://dc01")

IDS_EXISTANTS = {
    "win.audit_policy",
    "win.event_log_retention",
    "win.powershell_logging",
    "win.sysmon",
    "win.time_sync",
}


class CollecteurCompteur:
    """Collecteur factice : chaque fait vaut son nom ; compte les collectes."""

    def __init__(self, absents: Iterable[str] = ()) -> None:
        self.appels: Counter[tuple[str, str]] = Counter()
        self.lots: list[list[str]] = []
        self.absents = set(absents)

    def collect(
        self, target: Target, names: Iterable[str], *, timeout: float
    ) -> FactSet:
        noms = list(names)
        self.lots.append(noms)
        self.appels.update((target.id, n) for n in noms)
        return FactSet(
            Fact.ok(n, n, source="collecteur factice", collected_at=INSTANT)
            for n in noms
            if n not in self.absents
        )


def _indisponible(nom: str, raison: UnavailableReason) -> Fact:
    return Fact.unavailable(
        nom, raison, source="collecteur factice", collected_at=INSTANT
    )


# --- API des checks ---------------------------------------------------------


def test_run_n_existe_plus() -> None:
    assert not hasattr(Check, "run")
    for check in default_checks():
        assert not hasattr(check, "run"), check.id


def test_les_5_checks_declarent_faits_et_evaluate() -> None:
    checks = {c.id: c for c in default_checks()}
    assert set(checks) >= IDS_EXISTANTS
    for check_id in IDS_EXISTANTS:
        check = checks[check_id]
        assert check.requires_facts, check_id
        assert isinstance(check.requires_facts, tuple), check_id
        assert len(set(check.requires_facts)) == len(check.requires_facts)
        for nom in check.requires_facts:
            assert validate_fact_name(nom).startswith("windows."), nom
        assert callable(check.evaluate)
        # stub : evaluate() herite, non implemente (rendu skipped par #21)
        with pytest.raises(NotImplementedError):
            check.evaluate(FactSet(), Context(LOCAL))


def test_contexte_d_un_check(horloge_figee: Callable[[], datetime]) -> None:
    contexte = Context.for_check(
        "win.sysmon", DC01, config={"seuil": 90}, clock=horloge_figee
    )
    assert contexte.target is DC01
    assert contexte.clock() == horloge_figee()
    assert contexte.logger.name == "amnesia.check.win.sysmon"
    assert contexte.config["seuil"] == 90
    with pytest.raises(TypeError):
        contexte.config["seuil"] = 1  # type: ignore[index]
    defaut = Context(DC01)
    assert dict(defaut.config) == {}
    assert defaut.clock().utcoffset() is not None
    assert defaut.logger is logging.getLogger("amnesia.check")


# --- resolve() --------------------------------------------------------------

REQUIS = ("windows.auditpol.backup", "windows.eventlog.config:Security")


def test_fait_requis_manquant_donne_skipped_not_collected() -> None:
    faits = FactSet([Fact.ok(REQUIS[0], 1, source="s", collected_at=INSTANT)])
    resultat = resolve("win.audit_policy", "local", REQUIS, faits)
    assert resultat is not None
    assert resultat.status is Status.SKIPPED
    assert resultat.reason is Reason.NOT_COLLECTED
    assert resultat.gaps == ()
    assert REQUIS[1] in resultat.message


@pytest.mark.parametrize(
    ("raison", "statut", "motif"),
    [
        (UnavailableReason.ACCESS_DENIED, Status.ERROR, Reason.ACCESS_DENIED),
        (UnavailableReason.TIMEOUT, Status.ERROR, Reason.TIMEOUT),
        (UnavailableReason.UNREACHABLE, Status.ERROR, Reason.UNREACHABLE),
        (UnavailableReason.NOT_COLLECTED, Status.SKIPPED, Reason.NOT_COLLECTED),
        (UnavailableReason.UNSUPPORTED, Status.NOT_APPLICABLE, None),
    ],
    ids=lambda v: str(v),
)
def test_traduction_des_indisponibilites(
    raison: UnavailableReason, statut: Status, motif: Reason | None
) -> None:
    faits = FactSet(
        [
            Fact.ok(REQUIS[0], None, source="s", collected_at=INSTANT),
            _indisponible(REQUIS[1], raison),
        ]
    )
    resultat = resolve("win.audit_policy", "local", REQUIS, faits)
    assert resultat is not None
    assert resultat.status is statut
    assert resultat.reason is motif
    # jamais de Gap pour un fait indisponible, ni de conformite
    assert resultat.status is not Status.GAP
    assert resultat.gaps == ()
    assert not resultat.compliant
    if statut is Status.ERROR:
        assert resultat.error is not None
        assert resultat.error.type.endswith("FactUnavailableError")
        assert REQUIS[1] in resultat.message
        assert raison.value in resultat.message


def test_access_denied_jamais_gap() -> None:
    faits = FactSet([_indisponible(r, UnavailableReason.ACCESS_DENIED) for r in REQUIS])
    resultat = resolve("win.audit_policy", "local", REQUIS, faits)
    assert resultat is not None
    assert (resultat.status, resultat.reason) == (Status.ERROR, Reason.ACCESS_DENIED)


@pytest.mark.parametrize(
    ("raisons", "attendu"),
    [
        # l'erreur l'emporte, quel que soit l'ordre
        (("unsupported", "timeout"), Status.ERROR),
        (("not_collected", "unreachable"), Status.ERROR),
        # « non evalue » l'emporte sur « sans objet » (verifie)
        (("unsupported", "not_collected"), Status.SKIPPED),
        (("unsupported", "unsupported"), Status.NOT_APPLICABLE),
    ],
)
def test_priorite_entre_indisponibilites(
    raisons: tuple[str, str], attendu: Status
) -> None:
    faits = FactSet(
        _indisponible(n, UnavailableReason(r))
        for n, r in zip(REQUIS, raisons, strict=True)
    )
    resultat = resolve("win.audit_policy", "local", REQUIS, faits)
    assert resultat is not None
    assert resultat.status is attendu


def test_faits_tous_observes_rien_a_imposer() -> None:
    # valeur None : observee (cle absente), c'est a evaluate() d'en juger
    faits = FactSet(Fact.ok(n, None, source="s", collected_at=INSTANT) for n in REQUIS)
    assert resolve("win.audit_policy", "local", REQUIS, faits) is None
    assert resolve("win.audit_policy", "local", (), FactSet()) is None


def test_erreur_de_fait_caviardee() -> None:
    fait = Fact.unavailable(
        "windows.auditpol.backup",
        UnavailableReason.ACCESS_DENIED,
        source="winrm://audit:motdepasse@dc01",
        collected_at=INSTANT,
    )
    resultat = resolve("win.audit_policy", "winrm://dc01", [fait.name], FactSet([fait]))
    assert resultat is not None and resultat.error is not None
    assert "motdepasse" not in resultat.message
    assert "motdepasse" not in resultat.error.message
    assert FactUnavailableError(fait).fact is fait


# --- CachingCollector -------------------------------------------------------


def test_fait_partage_collecte_une_seule_fois() -> None:
    interne = CollecteurCompteur()
    collecteur: Collector = CachingCollector(interne)
    # deux checks qui demandent le meme fait, pendant un meme audit
    premier = ("windows.auditpol.backup", "windows.sysmon.service")
    second = ("windows.auditpol.backup", "windows.w32time.config")
    a = collecteur.collect(LOCAL, premier, timeout=30)
    b = collecteur.collect(LOCAL, second, timeout=30)
    assert interne.appels[("local", "windows.auditpol.backup")] == 1
    assert set(interne.appels.values()) == {1}
    assert interne.lots == [list(premier), ["windows.w32time.config"]]
    assert a["windows.auditpol.backup"] is b["windows.auditpol.backup"]
    assert list(b) == list(second)


def test_memoisation_par_cible() -> None:
    interne = CollecteurCompteur()
    collecteur = CachingCollector(interne)
    for cible in (LOCAL, DC01, LOCAL, DC01):
        collecteur.collect(cible, ["windows.sysmon.service"], timeout=30)
    assert interne.appels == {
        ("local", "windows.sysmon.service"): 1,
        ("winrm://dc01", "windows.sysmon.service"): 1,
    }


def test_fait_absent_memorise() -> None:
    interne = CollecteurCompteur(absents={"windows.sysmon.config"})
    collecteur = CachingCollector(interne)
    for _ in range(3):
        faits = collecteur.collect(LOCAL, ["windows.sysmon.config"], timeout=30)
        assert len(faits) == 0
    assert interne.appels[("local", "windows.sysmon.config")] == 1


def test_nouveau_collecteur_nouvel_audit() -> None:
    interne = CollecteurCompteur()
    for _ in range(2):
        CachingCollector(interne).collect(LOCAL, ["windows.sysmon.service"], timeout=1)
    assert interne.appels[("local", "windows.sysmon.service")] == 2


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan"), True])
def test_timeout_explicite_et_valide(timeout: float) -> None:
    collecteurs: list[Collector] = [
        CachingCollector(CollecteurCompteur()),
        LocalCollector(),
        FixtureCollector(RACINE / "tests" / "fixtures" / "facts" / "exemple.json"),
    ]
    for collecteur in collecteurs:
        with pytest.raises(ValueError, match="timeout invalide"):
            collecteur.collect(LOCAL, ["windows.sysmon.service"], timeout=timeout)


def test_noms_demandes_valides() -> None:
    collecteur = CachingCollector(CollecteurCompteur())
    with pytest.raises(TypeError, match="pas une chaîne"):
        collecteur.collect(LOCAL, "windows.sysmon.service", timeout=1)
    with pytest.raises(ValueError, match="nom de fait invalide"):
        collecteur.collect(LOCAL, ["sysmon"], timeout=1)


# --- LocalCollector ---------------------------------------------------------


def _collecte_locale(plateforme: str) -> Callable[[Check], CheckResult | None]:
    collecteur = LocalCollector(platform=plateforme, clock=lambda: INSTANT)

    def resultat(check: Check) -> CheckResult | None:
        faits = collecteur.collect(LOCAL, check.requires_facts, timeout=30)
        return resolve(check.id, LOCAL.id, check.requires_facts, faits)

    return resultat


@pytest.mark.parametrize("plateforme", ["linux", "darwin"])
def test_local_hors_windows_faits_windows_non_supportes(plateforme: str) -> None:
    collecteur = LocalCollector(platform=plateforme, clock=lambda: INSTANT)
    faits = collecteur.collect(
        LOCAL, ["windows.auditpol.backup", "ad.krbtgt.password_last_set"], timeout=30
    )
    windows, ad = faits.values()
    assert windows.unavailable_reason is UnavailableReason.UNSUPPORTED
    assert windows.source == f"collecteur local ({plateforme})"
    assert windows.collected_at == INSTANT
    assert ad.unavailable_reason is UnavailableReason.NOT_COLLECTED
    for check in default_checks():
        resultat = _collecte_locale(plateforme)(check)
        assert resultat is not None, check.id
        assert resultat.status is Status.NOT_APPLICABLE, check.id


def test_local_sous_windows_pas_encore_collecte() -> None:
    # collecte reelle sous Windows : #48 ; d'ici la, non collecte (jamais vérifié)
    for check in default_checks():
        resultat = _collecte_locale("win32")(check)
        assert resultat is not None
        assert (resultat.status, resultat.reason) == (
            Status.SKIPPED,
            Reason.NOT_COLLECTED,
        )


@pytest.mark.skipif(sys.platform == "win32", reason="comportement hors Windows")
def test_local_sur_la_plateforme_courante() -> None:
    # sur la CI ubuntu : faits windows.* unsupported, checks not_applicable
    collecteur = LocalCollector()
    for check in default_checks():
        faits = collecteur.collect(LOCAL, check.requires_facts, timeout=30)
        assert all(
            f.unavailable_reason is UnavailableReason.UNSUPPORTED
            for f in faits.values()
        )
        resultat = resolve(check.id, LOCAL.id, check.requires_facts, faits)
        assert resultat is not None
        assert resultat.status is Status.NOT_APPLICABLE


def test_local_refuse_une_cible_distante() -> None:
    with pytest.raises(ValueError, match="cible locale attendue"):
        LocalCollector().collect(DC01, ["windows.sysmon.service"], timeout=30)


# --- regles des collecteurs et documentation --------------------------------


def test_aucun_shell_true_dans_src() -> None:
    # double les regles ruff S602 et S604 (tests/test_regles_ruff.py)
    for fichier in sorted((RACINE / "src").rglob("*.py")):
        arbre = ast.parse(fichier.read_text(encoding="utf-8"))
        for noeud in ast.walk(arbre):
            if isinstance(noeud, ast.keyword) and noeud.arg == "shell":
                assert not (
                    isinstance(noeud.value, ast.Constant) and noeud.value.value is True
                ), f"{fichier.name}:{noeud.lineno}"


def test_doc_reprend_l_exemple_teste() -> None:
    # l'exemple de docs/dev/faits.md est le contenu exact de fichiers testes
    texte = DOC.read_text(encoding="utf-8")
    blocs = re.findall(r"<!-- exemple : (\S+) -->\n```\w+\n(.*?)```", texte, re.S)
    assert {chemin for chemin, _ in blocs} == {
        "tests/fixtures/facts/exemple.json",
        "tests/unit/test_exemple_faits.py",
    }
    for chemin, contenu in blocs:
        assert (RACINE / chemin).read_text(encoding="utf-8") == contenu, chemin
