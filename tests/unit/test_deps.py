"""Extras optionnels : import paresseux, MissingExtra et « non évalué » (#44)."""

from __future__ import annotations

import copy
import pickle
import sys
from collections.abc import Callable, Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType

import pytest

from amnesia import deps, run_audit
from amnesia.checks import Check, Domain, InvalidCheckError, Registry
from amnesia.checks.base import CheckResult, Reason, Status
from amnesia.checks.context import Context
from amnesia.deps import MissingExtra, Package, install_command, require_extra
from amnesia.facts import Fact, FactSet
from amnesia.render import RenderOptions, render_report
from amnesia.report import build_report
from amnesia.target import Kind, Target

CIBLE = Target.parse("winrm://dc01")
INSTANT = datetime(2026, 10, 21, 9, 30, tzinfo=UTC)

# modules d'essai, crees hors du depot (tmp_path) ; noms propres a ce fichier
PRESENT = "amnesia_essai44_present"
CASSE = "amnesia_essai44_casse"
ABSENT = "amnesia_essai44_absent"
COMMANDE = 'pip install "amnesia-dfr[essai]"'


@pytest.fixture
def sdk_factices(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Un SDK importable, un SDK dont l'import échoue ; aucun n'est importé."""
    dossier = tmp_path / "sdk"
    dossier.mkdir()
    (dossier / f"{PRESENT}.py").write_text("VALEUR = 1\n", encoding="utf-8")
    (dossier / f"{CASSE}.py").write_text(
        "raise ImportError('dependance transitive absente')\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(dossier))
    try:
        yield
    finally:
        for nom in (PRESENT, CASSE, ABSENT):
            sys.modules.pop(nom, None)


@pytest.fixture
def extras_essai(
    sdk_factices: None, monkeypatch: pytest.MonkeyPatch
) -> dict[str, tuple[Package, ...]]:
    """Extras déclarés pour le test : essai (absent), complet et partiel."""
    extras = {
        "essai": (Package("essai-sdk", ABSENT),),
        "complet": (Package("present-sdk", PRESENT),),
        "partiel": (
            Package("present-sdk", PRESENT),
            Package("essai-sdk", ABSENT),
            Package("casse-sdk", CASSE),
        ),
    }
    monkeypatch.setattr(deps, "EXTRAS", MappingProxyType(extras))
    return extras


# --- require_extra et MissingExtra ---------------------------------------------


def test_extras_declares_en_lecture_seule() -> None:
    assert isinstance(deps.EXTRAS, MappingProxyType)
    # chaque extra est ajoute par le ticket de sa premiere dependance
    assert deps.ALL not in deps.EXTRAS


def test_commande_d_installation_exacte() -> None:
    assert install_command("aws") == 'pip install "amnesia-dfr[aws]"'
    assert install_command("cloud-m365") == 'pip install "amnesia-dfr[cloud-m365]"'


def test_extra_absent_leve_missing_extra(
    extras_essai: dict[str, tuple[Package, ...]],
) -> None:
    with pytest.raises(MissingExtra) as exc:
        require_extra("essai")
    assert exc.value.extra == "essai"
    assert exc.value.packages == ("essai-sdk",)
    assert exc.value.command == COMMANDE
    assert str(exc.value) == (
        "extra essai non installé (manquant : essai-sdk) ; "
        f"pour l'installer : {COMMANDE}"
    )


def test_extra_installe_importe_a_la_demande(
    extras_essai: dict[str, tuple[Package, ...]],
) -> None:
    # rien n'est importe avant l'appel : ni par amnesia.deps, ni par le registre
    assert PRESENT not in sys.modules
    require_extra("complet")
    assert sys.modules[PRESENT].VALEUR == 1


def test_seuls_les_paquets_manquants_sont_cites(
    extras_essai: dict[str, tuple[Package, ...]],
) -> None:
    # un SDK dont l'import echoue (installation abimee) compte comme manquant
    with pytest.raises(MissingExtra) as exc:
        require_extra("partiel")
    assert exc.value.packages == ("essai-sdk", "casse-sdk")
    assert "present-sdk" not in str(exc.value)
    assert 'pip install "amnesia-dfr[partiel]"' in str(exc.value)


def test_message_sans_chemin_ni_trace(
    extras_essai: dict[str, tuple[Package, ...]],
) -> None:
    with pytest.raises(MissingExtra) as exc:
        require_extra("partiel")
    message = str(exc.value)
    assert "Traceback" not in message
    assert "dependance transitive absente" not in message
    assert str(Path.cwd()) not in message


@pytest.mark.parametrize("extra", ["inconnu", "all", ""])
def test_extra_non_declare_refuse(
    extras_essai: dict[str, tuple[Package, ...]], extra: str
) -> None:
    # erreur de programmation : aucune installation ne la corrige
    with pytest.raises(ValueError, match=r"extra non déclaré .*complet, essai"):
        require_extra(extra)


def test_extra_non_textuel_refuse() -> None:
    with pytest.raises(TypeError, match="chaîne attendue"):
        require_extra(["aws"])  # type: ignore[arg-type]


def test_aucun_extra_declare_message_explicite() -> None:
    with pytest.raises(ValueError, match=r"déclarés : aucun"):
        require_extra("aws")


def _par_pickle(exc: MissingExtra) -> MissingExtra:
    copie: MissingExtra = pickle.loads(pickle.dumps(exc))  # noqa: S301 - objet du test
    return copie


@pytest.mark.parametrize(
    "dupliquer", [_par_pickle, copy.copy, copy.deepcopy], ids=["pickle", "copy", "deep"]
)
def test_missing_extra_copiable_et_picklable(
    dupliquer: Callable[[MissingExtra], MissingExtra],
) -> None:
    # le moteur peut executer les checks dans d'autres processus
    exc = MissingExtra("aws", ["boto3", "botocore"])
    copie = dupliquer(exc)
    assert isinstance(copie, MissingExtra)
    assert (copie.extra, copie.packages, str(copie)) == (
        "aws",
        ("boto3", "botocore"),
        str(exc),
    )


# --- moteur : un check factice qui requiert un extra absent --------------------


class CheckAvecExtra(Check):
    id = "aws.essai_extra"
    title = "Check qui requiert un extra"
    description = "Lit un fait qu'aucun collecteur ne rend sans le SDK."
    domain = Domain.AWS
    target_kinds = (Kind.AWS_ACCOUNT,)
    version = 1
    default_severity = "high"
    requires_extra: str | None = "essai"
    requires_facts = ("aws.cloudtrail.trails",)

    def evaluate(self, facts: FactSet, ctx: Context) -> CheckResult:
        return CheckResult.passed(self.id, ctx.target.id)


class CheckDuSocle(CheckAvecExtra):
    id = "aws.essai_socle"
    requires_extra = None


class CollecteurEspion:
    """Rend chaque fait demandé ; note les appels."""

    def __init__(self) -> None:
        self.appels: list[str] = []

    def collect(
        self, target: Target, names: Iterable[str], *, timeout: float
    ) -> FactSet:
        noms = list(names)
        self.appels.extend(noms)
        return FactSet(
            Fact.ok(n, True, source="test", collected_at=INSTANT) for n in noms
        )


class CollecteurParesseux(CollecteurEspion):
    """Collecteur dont le SDK s'importe à la demande, comme un futur boto3."""

    def collect(
        self, target: Target, names: Iterable[str], *, timeout: float
    ) -> FactSet:
        require_extra("essai")
        return super().collect(target, names, timeout=timeout)


def _verifier_non_evalue(resultat: CheckResult) -> None:
    assert resultat.status is Status.SKIPPED
    assert resultat.reason is Reason.NOT_COLLECTED
    assert resultat.not_evaluated
    assert not resultat.compliant
    # la commande exacte, sans trace : aucune ErrorInfo
    assert COMMANDE in resultat.message
    assert resultat.error is None
    assert "Traceback" not in resultat.message


@pytest.mark.parametrize("debug", [False, True])
def test_check_qui_requiert_un_extra_absent_non_evalue(
    extras_essai: dict[str, tuple[Package, ...]], debug: bool
) -> None:
    collecteur = CollecteurEspion()
    audit = run_audit(
        [CheckAvecExtra, CheckDuSocle], CIBLE, collecteur, debug=debug, operator="t"
    )
    resultats = {r.check_id: r for r in audit.results}
    _verifier_non_evalue(resultats["aws.essai_extra"])
    # extra verifie avant toute collecte : un seul appel, celui du check du socle
    assert collecteur.appels == ["aws.cloudtrail.trails"]
    assert resultats["aws.essai_socle"].status is Status.PASS
    assert not audit.complete
    assert audit.summary.not_evaluated == 1


def test_check_qui_requiert_un_extra_installe_evalue(
    extras_essai: dict[str, tuple[Package, ...]],
) -> None:
    class CheckComplet(CheckAvecExtra):
        id = "aws.essai_complet"
        requires_extra = "complet"

    (resultat,) = run_audit(
        [CheckComplet], CIBLE, CollecteurEspion(), operator="t"
    ).results
    assert resultat.status is Status.PASS


def test_extra_absent_dans_un_collecteur_non_evalue(
    extras_essai: dict[str, tuple[Package, ...]],
) -> None:
    # extra propre a un transport : le check ne le declare pas, le collecteur
    # l'importe a la demande
    (resultat,) = run_audit(
        [CheckDuSocle], CIBLE, CollecteurParesseux(), operator="t"
    ).results
    _verifier_non_evalue(resultat)


def test_extra_absent_dans_evaluate_non_evalue(
    extras_essai: dict[str, tuple[Package, ...]],
) -> None:
    class CheckParesseux(CheckDuSocle):
        id = "aws.essai_paresseux"

        def evaluate(self, facts: FactSet, ctx: Context) -> CheckResult:
            require_extra("essai")
            return CheckResult.passed(self.id, ctx.target.id)

    (resultat,) = run_audit(
        [CheckParesseux], CIBLE, CollecteurEspion(), operator="t", debug=True
    ).results
    _verifier_non_evalue(resultat)


def test_extra_absent_rendu_avec_la_commande(
    extras_essai: dict[str, tuple[Package, ...]],
) -> None:
    audit = run_audit([CheckAvecExtra], CIBLE, CollecteurEspion(), operator="t")
    rapport = build_report(audit, check_versions={CheckAvecExtra.id: 1})
    (resultat,) = rapport["results"]
    assert (resultat["status"], resultat["reason"]) == ("skipped", "not_collected")
    assert resultat["error"] is None
    texte = render_report(rapport, "text", RenderOptions())
    assert COMMANDE in texte
    assert "Traceback" not in texte


# --- registre : requires_extra validé à l'enregistrement -----------------------


def test_requires_extra_dans_les_metadonnees(
    extras_essai: dict[str, tuple[Package, ...]],
) -> None:
    registre = Registry()
    registre.register(CheckAvecExtra)
    registre.register(CheckDuSocle)
    assert {m.id: m.requires_extra for m in registre.metas()} == {
        "aws.essai_extra": "essai",
        "aws.essai_socle": None,
    }


@pytest.mark.parametrize("extra", ["inconnu", "all", "", 1, ("essai",)])
def test_requires_extra_non_declare_refuse(
    extras_essai: dict[str, tuple[Package, ...]], extra: object
) -> None:
    class CheckInvalide(CheckDuSocle):
        requires_extra = extra  # type: ignore[assignment]

    with pytest.raises(InvalidCheckError, match=r"requires_extra : extra non déclaré"):
        Registry().register(CheckInvalide)
