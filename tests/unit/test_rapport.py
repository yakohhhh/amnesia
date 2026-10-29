"""Rapport JSON v1 : contenu, tri, determinisme, masquage d'argv et JSON Schema."""

from __future__ import annotations

import copy
import dataclasses
import json
import os
import re
from collections import Counter
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jsonschema
import pytest

import amnesia
from amnesia import AuditResult, run_audit
from amnesia import report as module_rapport
from amnesia.checks import REGISTRY, Check
from amnesia.checks.base import (
    CheckResult,
    CheckSkipped,
    Confidence,
    Evidence,
    Gap,
    NotApplicable,
    Reason,
    Reference,
    ReferenceKind,
    Severity,
    Status,
)
from amnesia.checks.context import Context
from amnesia.cli import main
from amnesia.facts import Fact, FactSet
from amnesia.report import (
    MASK,
    SCHEMA_VERSION,
    SENSITIVE_OPTIONS,
    build_report,
    dumps_report,
    load_schema,
    redact_argv,
    schema_text,
)
from amnesia.target import Kind, Target, Transport

RACINE = Path(__file__).resolve().parent.parent.parent
GOLDEN = RACINE / "tests" / "golden" / "report.json"
DOC = RACINE / "docs" / "format-rapport.md"

CIBLE = Target.parse("winrm://srv-file.exemple.invalid")
INSTANT = datetime(2026, 10, 21, 9, 30, tzinfo=UTC)
RUN_ID = "5f0c6b1e-8a3d-4c2b-9e7f-1a2b3c4d5e6f"
RFC3339_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z")
SCHEMA = load_schema()
VALIDATEUR = jsonschema.Draft202012Validator(SCHEMA)


def _strict(schema: Any) -> Any:
    """Copie du schéma où chaque objet décrit refuse les clés non déclarées.

    Le schéma publié les tolère (compatibilité MINEURE) ; les tests vérifient
    qu'amnesia n'écrit aucun champ absent du schéma.
    """
    if isinstance(schema, dict):
        copie = {cle: _strict(v) for cle, v in schema.items()}
        if copie.get("type") == "object" and "properties" in copie:
            copie["additionalProperties"] = False
        return copie
    if isinstance(schema, list):
        return [_strict(v) for v in schema]
    return schema


VALIDATEUR_STRICT = jsonschema.Draft202012Validator(_strict(SCHEMA))


def valider(rapport: Any) -> None:
    VALIDATEUR.validate(rapport)
    VALIDATEUR_STRICT.validate(rapport)


# --- checks et audits factices ----------------------------------------------


def un_gap(
    check_id: str,
    severite: Severity,
    *,
    cible: str = CIBLE.id,
    ressource: str = "Security",
    question: str = "Qui s'est connecté en RDP il y a trois semaines ?",
) -> Gap:
    return Gap(
        check_id=check_id,
        target=cible,
        resource=ressource,
        question=question,
        reason="Le journal a été écrasé.",
        severity=severite,
        evidence=Evidence(
            observed=4,
            expected=90,
            unit="days",
            confidence=Confidence.MEASURED,
            source="test",
        ),
        remediation="Agrandir le journal.",
    )


class Factice(Check):
    """Check factice : rend le résultat que lui dicte ``comportement``."""

    def __init__(
        self, id: str, comportement: Callable[[str, str], CheckResult]
    ) -> None:
        self.id = id
        self.comportement = comportement

    def evaluate(self, facts: FactSet, ctx: Context) -> CheckResult:
        return self.comportement(self.id, ctx.target.id)


def conforme(check_id: str, cible: str) -> CheckResult:
    return CheckResult.passed(check_id, cible)


def avec_gaps(*severites: Severity) -> Callable[[str, str], CheckResult]:
    def comportement(check_id: str, cible: str) -> CheckResult:
        gaps = [
            un_gap(check_id, s, cible=cible, ressource=f"journal-{i}")
            for i, s in enumerate(severites)
        ]
        return CheckResult.with_gaps(check_id, cible, gaps)

    return comportement


def plante(check_id: str, cible: str) -> CheckResult:
    raise RuntimeError("panne factice")


def saute(check_id: str, cible: str) -> CheckResult:
    raise CheckSkipped(Reason.USER_EXCLUDED, "retiré du périmètre")


def sans_objet(check_id: str, cible: str) -> CheckResult:
    raise NotApplicable("la cible n'est pas un contrôleur de domaine")


class CollecteurFactice:
    """Rend chaque fait demandé, observé."""

    def collect(
        self, target: Target, names: Iterable[str], *, timeout: float
    ) -> FactSet:
        return FactSet(
            Fact.ok(nom, True, source="test", collected_at=INSTANT) for nom in names
        )


def auditer(checks: Iterable[Check | type[Check]]) -> AuditResult:
    return run_audit(
        checks,
        CIBLE,
        CollecteurFactice(),
        clock=lambda: INSTANT,
        operator="auditeur-factice",
    )


def audit_de_reference(ordre: int = 1) -> AuditResult:
    """Audit figé du golden : horodatages, durées et run_id fixes."""
    cible = CIBLE.id
    retention = Gap(
        check_id="win.event_log_retention",
        target=cible,
        resource="Security",
        question="Qui s'est connecté en RDP sur SRV-FILE il y a trois semaines ?",
        reason="Le journal Security fait 20 Mo et a été écrasé il y a 4 jours.",
        severity=Severity.HIGH,
        evidence=Evidence(
            observed=4,
            expected=90,
            unit="days",
            observed_window_days=4,
            required_window_days=90,
            confidence=Confidence.MEASURED,
            source="Get-WinEvent -LogName Security -Oldest -MaxEvents 1",
            details={
                "max_size_bytes": 20971520,
                "log_mode": "Circular",
                "oldest_event_utc": datetime(2026, 10, 17, 9, 30, tzinfo=UTC),
            },
        ),
        remediation=(
            "Porter le journal Security à 4 Go au moins par GPO : Configuration "
            "ordinateur > Stratégies > Modèles d'administration > Composants "
            "Windows > Service Journal des événements > Sécurité."
        ),
        references=(
            Reference(
                ReferenceKind.ATTACK,
                "T1021.001",
                url="https://attack.mitre.org/techniques/T1021/001/",
                version="v20",
            ),
        ),
    )
    powershell = Gap(
        check_id="win.powershell_logging",
        target=cible,
        resource="ScriptBlockLogging",
        question="Quelles commandes PowerShell l'attaquant a-t-il exécutées ?",
        reason="La journalisation des blocs de script est désactivée.",
        severity=Severity.MEDIUM,
        evidence=Evidence(
            observed=False,
            expected=True,
            unit="bool",
            confidence=Confidence.MEASURED,
            source="registre HKLM PowerShell ScriptBlockLogging",
        ),
        remediation=(
            "Activer « Activer la journalisation des blocs de scripts PowerShell » "
            "par GPO."
        ),
    )
    resultats = [
        CheckResult.passed("win.audit_policy", cible, duration_s=0.125),
        CheckResult.with_gaps(
            "win.event_log_retention", cible, [retention], duration_s=0.5
        ),
        CheckResult.with_gaps(
            "win.powershell_logging", cible, [powershell], duration_s=0.25
        ),
        CheckResult.failed(
            "win.sysmon",
            cible,
            Reason.ACCESS_DENIED,
            PermissionError("accès refusé à la configuration Sysmon"),
            duration_s=1.5,
        ),
        CheckResult.skipped(
            "win.time_sync", cible, Reason.NOT_IMPLEMENTED, "check non implémenté"
        ),
        CheckResult.not_applicable(
            "ad.exemple_controleur",
            cible,
            "la cible n'est pas un contrôleur de domaine",
            duration_s=0.0,
        ),
    ]
    return AuditResult(
        amnesia_version="0.1.0",
        run_id=RUN_ID,
        started_at="2026-10-21T09:30:00+00:00",
        finished_at="2026-10-21T09:30:04.250000+00:00",
        duration_s=4.25,
        target=CIBLE,
        operator="auditeur-factice",
        results=tuple(resultats[::ordre]),
    )


ARGV_DE_REFERENCE = [
    "audit",
    "--target",
    "winrm://srv-file.exemple.invalid",
    "--token",
    "jeton-factice",
    "--out",
    "rapport-srv-file.json",
]
VERSIONS_DE_REFERENCE = {
    "win.audit_policy": 1,
    "win.event_log_retention": 2,
    "win.powershell_logging": 1,
    "win.sysmon": 1,
    "win.time_sync": 1,
}


def rapport_de_reference(ordre: int = 1) -> dict[str, Any]:
    return build_report(
        audit_de_reference(ordre),
        argv=ARGV_DE_REFERENCE,
        check_versions=VERSIONS_DE_REFERENCE,
    )


# --- criteres d'acceptation --------------------------------------------------


def test_rapport_de_checks_factices_valide_contre_le_schema() -> None:
    checks = [
        Factice("win.conforme", conforme),
        Factice("win.angle_mort", avec_gaps(Severity.HIGH, Severity.LOW)),
        Factice("win.en_panne", plante),
        Factice("win.exclu", saute),
        Factice("ad.sans_objet", sans_objet),
    ]
    rapport = build_report(auditer(checks), check_versions={})
    valider(rapport)
    statuts = {r["check_id"]: r["status"] for r in rapport["results"]}
    assert statuts == {
        "win.conforme": "pass",
        "win.angle_mort": "gap",
        "win.en_panne": "error",
        "win.exclu": "skipped",
        "ad.sans_objet": "not_applicable",
    }
    # le texte serialise se relit et reste conforme
    valider(json.loads(dumps_report(rapport)))


def test_version_horodatages_et_duree() -> None:
    audit = auditer([Factice("win.conforme", conforme)])
    rapport = build_report(audit)
    assert rapport["schema_version"] == SCHEMA_VERSION == "1.0.0"
    assert rapport["tool"] == {
        "name": "amnesia",
        "version": amnesia.__version__,
        "catalog_version": None,
    }
    run = rapport["run"]
    assert run["started_at"] == run["finished_at"] == "2026-10-21T09:30:00Z"
    for champ in ("started_at", "finished_at"):
        assert RFC3339_UTC.fullmatch(run[champ]), run[champ]
    assert isinstance(run["duration_s"], float)
    assert run["duration_s"] >= 0
    assert run["id"] == audit.run_id
    assert (run["complete"], run["interrupted"], run["profile"]) == (True, False, None)


def test_horodatage_avec_fuseau_ramene_en_utc_avec_z() -> None:
    audit = dataclasses.replace(
        audit_de_reference(),
        started_at="2026-10-21T11:30:00.500000+02:00",
    )
    assert build_report(audit)["run"]["started_at"] == "2026-10-21T09:30:00.500000Z"


def test_cinq_checks_du_registre_tous_presents() -> None:
    # evaluate() des 5 checks actuels leve NotImplementedError
    audit = auditer(REGISTRY.classes())
    rapport = build_report(audit)
    valider(rapport)
    metas = REGISTRY.metas()
    assert len(metas) == 5
    assert [r["check_id"] for r in rapport["results"]] == [m.id for m in metas]
    for resultat, meta in zip(rapport["results"], metas, strict=True):
        assert resultat["status"] == "skipped"
        assert resultat["reason"] == "not_implemented"
        assert resultat["check_version"] == meta.version
        assert resultat["target"] == CIBLE.id
    assert rapport["run"]["complete"] is False
    assert rapport["summary"]["not_evaluated"] == 5


def test_gaps_tries_par_severite_domaine_check_et_cible() -> None:
    checks = [
        Factice("win.b", avec_gaps(Severity.LOW, Severity.CRITICAL)),
        Factice("win.a", avec_gaps(Severity.HIGH, Severity.INFO)),
        Factice("ad.z", avec_gaps(Severity.HIGH, Severity.MEDIUM)),
        Factice("aws.y", avec_gaps(Severity.MEDIUM)),
    ]
    rapport = build_report(auditer(checks), check_versions={})
    valider(rapport)
    ordre = [(g["severity"], g["check_id"]) for g in rapport["gaps"]]
    assert ordre == [
        ("critical", "win.b"),
        ("high", "ad.z"),
        ("high", "win.a"),
        ("medium", "ad.z"),
        ("medium", "aws.y"),
        ("low", "win.b"),
        ("info", "win.a"),
    ]


def test_gaps_departages_par_cible() -> None:
    gaps = [
        un_gap("win.a", Severity.HIGH, cible="winrm://srv-b.exemple.invalid"),
        un_gap("win.a", Severity.HIGH, cible="winrm://srv-a.exemple.invalid"),
        un_gap("win.a", Severity.CRITICAL, cible="winrm://srv-c.exemple.invalid"),
    ]
    cibles = [g.target for g in sorted(gaps, key=module_rapport._cle_gap)]
    assert cibles == [
        "winrm://srv-c.exemple.invalid",
        "winrm://srv-a.exemple.invalid",
        "winrm://srv-b.exemple.invalid",
    ]


def test_summary_concorde_avec_results_et_gaps() -> None:
    rapport = rapport_de_reference()
    resume = rapport["summary"]
    statuts = Counter(r["status"] for r in rapport["results"])
    severites = Counter(g["severity"] for g in rapport["gaps"])
    assert resume["by_status"] == {s.value: statuts[s.value] for s in Status}
    assert resume["by_severity"] == {
        s.value: severites[s.value] for s in sorted(Severity, reverse=True)
    }
    assert list(resume["by_severity"]) == ["critical", "high", "medium", "low", "info"]
    assert resume["total"] == len(rapport["results"]) == 6
    assert resume["gaps"] == len(rapport["gaps"]) == 2
    assert resume["not_evaluated"] == 2  # error et skipped/not_implemented
    assert resume["excluded"] == 0


def test_chaque_gap_rattache_a_un_resultat_gap() -> None:
    rapport = rapport_de_reference()
    en_gap = {
        (r["check_id"], r["target"]) for r in rapport["results"] if r["status"] == "gap"
    }
    assert {(g["check_id"], g["target"]) for g in rapport["gaps"]} == en_gap


def test_deux_serialisations_identiques_octet_pour_octet() -> None:
    # ordre d'entree des resultats inverse : meme rapport
    premier = dumps_report(rapport_de_reference()).encode("utf-8")
    second = dumps_report(rapport_de_reference(ordre=-1)).encode("utf-8")
    assert premier == second


def test_golden() -> None:
    texte = dumps_report(rapport_de_reference())
    if os.environ.get("AMNESIA_UPDATE_GOLDEN") == "1":
        GOLDEN.parent.mkdir(exist_ok=True)
        GOLDEN.write_bytes(texte.encode("utf-8"))
    assert GOLDEN.read_bytes() == texte.encode("utf-8"), (
        "golden perime : relancer avec AMNESIA_UPDATE_GOLDEN=1 et relire le diff"
    )
    valider(json.loads(GOLDEN.read_text(encoding="utf-8")))


def test_mise_en_forme_deterministe() -> None:
    texte = dumps_report(rapport_de_reference())
    assert texte.endswith("}\n")
    assert not texte.endswith("\n\n")
    # ensure_ascii=False : accents lisibles ; indentation de 2
    assert "écrasé" in texte
    assert "\\u00e9" not in texte
    assert '\n  "schema_version": "1.0.0",\n' in texte
    assert texte.startswith('{\n  "schema_version"')
    assert list(json.loads(texte)) == [
        "schema_version",
        "tool",
        "run",
        "targets",
        "results",
        "gaps",
        "summary",
    ]


@pytest.mark.parametrize(
    ("argv", "attendu"),
    [
        (["--token", "abc"], ["--token", MASK]),
        (["--token=abc"], [f"--token={MASK}"]),
        (["--password", "p", "--secret=s"], ["--password", MASK, f"--secret={MASK}"]),
        (["--client-secret", "-commence-par-un-tiret"], ["--client-secret", MASK]),
        # abreviations acceptees par argparse
        (["--tok", "abc", "--client=x"], ["--tok", MASK, f"--client={MASK}"]),
        (["--token"], ["--token"]),
        (["--token="], [f"--token={MASK}"]),
        (
            ["audit", "--target", "local", "--out", "r.json"],
            ["audit", "--target", "local", "--out", "r.json"],
        ),
        # filet de securite : identifiants dans une URL, password=...
        (["winrm://audit:mdp@dc01"], [f"winrm://audit:{MASK}@dc01"]),
        (["password=abc"], [f"password={MASK}"]),
    ],
)
def test_argv_masque(argv: list[str], attendu: list[str]) -> None:
    assert redact_argv(argv) == attendu


def test_argv_masque_dans_le_rapport() -> None:
    audit = audit_de_reference()
    rapport = build_report(audit, argv=["--token", "abc", "--token=abc"])
    assert rapport["run"]["argv"] == ["--token", "***", "--token=***"]
    assert "abc" not in dumps_report(rapport)


def test_options_sensibles_couvertes() -> None:
    assert SENSITIVE_OPTIONS == (
        "--password",
        "--token",
        "--secret",
        "--client-secret",
    )
    for option in SENSITIVE_OPTIONS:
        assert redact_argv([option, "v", f"{option}=v"]) == [
            option,
            MASK,
            f"{option}={MASK}",
        ]


def test_argv_non_textuel_refuse() -> None:
    with pytest.raises(TypeError, match="argv"):
        redact_argv([b"--token"])  # type: ignore[list-item]


# --- encodage et donnees hostiles ---------------------------------------------


def test_surrogates_echappes_de_facon_deterministe() -> None:
    # octet non UTF-8 d'argv (surrogateescape), message et chemin de bundle
    octet = b"rapport-\xff.json".decode("utf-8", "surrogateescape")
    assert octet == "rapport-\udcff.json"
    bundle = Target(Kind.WINDOWS_HOST, Transport.BUNDLE, path=Path("bundle-\udcfe"))
    audit = AuditResult(
        run_id=RUN_ID,
        started_at="2026-10-21T09:30:00+00:00",
        finished_at="2026-10-21T09:30:00+00:00",
        duration_s=0.0,
        target=bundle,
        operator="auditeur-factice",
        results=(),
        interrupted=True,
    )
    rapport = build_report(audit, argv=["--out", octet], check_versions={})
    texte = dumps_report(rapport)
    # encodage UTF-8 strict sans erreur : plus aucun surrogate
    donnees = texte.encode("utf-8")
    assert texte == dumps_report(rapport)
    relu = json.loads(donnees.decode("utf-8"))
    assert relu["run"]["argv"] == ["--out", "rapport-\\udcff.json"]
    assert relu["targets"] == [
        {"id": "bundle:bundle-\\udcfe", "kind": "windows_host", "transport": "bundle"}
    ]
    valider(relu)


def test_surrogate_d_un_message_echappe() -> None:
    resultat = CheckResult.skipped(
        "win.exemple", CIBLE.id, Reason.NOT_COLLECTED, "fichier \udcff illisible"
    )
    audit = dataclasses.replace(audit_de_reference(), results=(resultat,))
    texte = dumps_report(build_report(audit, check_versions={}))
    assert json.loads(texte.encode("utf-8"))["results"][0]["message"] == (
        "fichier \\udcff illisible"
    )


def test_dumps_echappe_un_rapport_quelconque() -> None:
    texte = dumps_report({"cl\udcffe": ["v\udcfe"]})
    assert json.loads(texte) == {"cl\\udcffe": ["v\\udcfe"]}


def test_valeurs_de_la_cible_ecrites_telles_quelles() -> None:
    # neutralisation des caracteres C1 et bidi : rendus (#45), pas le rapport
    message = "journal \u202eexe.txt\u202c \x85 fin"
    resultat = CheckResult.not_applicable("win.exemple", CIBLE.id, message)
    audit = dataclasses.replace(audit_de_reference(), results=(resultat,))
    texte = dumps_report(build_report(audit, check_versions={}))
    assert "\u202e" in texte
    assert "\x85" in texte
    assert json.loads(texte)["results"][0]["message"] == message
    # C0 : echappes par JSON
    assert "\x1b" not in dumps_report({"m": "\x1b[31m"})


def test_operateur_absent_du_rapport() -> None:
    texte = dumps_report(rapport_de_reference())
    assert "auditeur-factice" not in texte
    assert "operator" not in texte


# --- erreurs ------------------------------------------------------------------


def test_run_id_invalide_refuse() -> None:
    audit = dataclasses.replace(audit_de_reference(), run_id="pas-un-uuid")
    with pytest.raises(ValueError, match="UUID"):
        build_report(audit)


def test_run_id_normalise_en_minuscules() -> None:
    audit = dataclasses.replace(audit_de_reference(), run_id=RUN_ID.upper())
    assert build_report(audit)["run"]["id"] == RUN_ID


def test_horodatage_sans_fuseau_refuse() -> None:
    audit = dataclasses.replace(audit_de_reference(), finished_at="2026-10-21T09:30")
    with pytest.raises(ValueError, match="sans fuseau"):
        build_report(audit)


@pytest.mark.parametrize("version", [0, -1, True, 1.5, "1"])
def test_version_de_check_invalide_refusee(version: Any) -> None:
    with pytest.raises(ValueError, match="check_versions"):
        build_report(audit_de_reference(), check_versions={"win.sysmon": version})


def test_version_inconnue_vaut_null() -> None:
    rapport = build_report(audit_de_reference(), check_versions={})
    assert {r["check_version"] for r in rapport["results"]} == {None}


def test_flottant_non_fini_refuse() -> None:
    with pytest.raises(ValueError, match="JSON"):
        dumps_report({"duree": float("nan")})


# --- schema ------------------------------------------------------------------


def test_schema_draft_2020_12_valide() -> None:
    assert SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    assert SCHEMA["properties"]["schema_version"]["pattern"]
    assert re.fullmatch(SCHEMA["properties"]["schema_version"]["pattern"], "1.4.0")
    assert not re.search(SCHEMA["properties"]["schema_version"]["pattern"], "2.0.0")


def test_enumerations_du_schema_concordent_avec_le_modele() -> None:
    definitions = SCHEMA["$defs"]
    assert definitions["status"]["enum"] == [s.value for s in Status]
    assert definitions["reason"]["enum"] == [None, *(r.value for r in Reason)]
    assert definitions["severity"]["enum"] == [
        s.value for s in sorted(Severity, reverse=True)
    ]
    cible = definitions["target"]["properties"]
    assert cible["kind"]["enum"] == [k.value for k in Kind]
    assert cible["transport"]["enum"] == [t.value for t in Transport]
    confiance = definitions["evidence"]["properties"]["confidence"]["enum"]
    assert confiance == [c.value for c in Confidence]
    references = definitions["reference"]["properties"]["kind"]["enum"]
    assert references == [k.value for k in ReferenceKind]


def test_cles_du_schema_concordent_avec_les_to_dict() -> None:
    definitions = SCHEMA["$defs"]
    gap = un_gap("win.a", Severity.LOW).to_dict()
    assert list(definitions["gap"]["required"]) == list(gap)
    assert set(definitions["gap"]["properties"]) == set(gap)
    assert set(definitions["evidence"]["required"]) == set(gap["evidence"])
    reference = Reference(ReferenceKind.OTHER, "x").to_dict()
    assert set(definitions["reference"]["required"]) == set(reference)


def test_schema_refuse_un_rapport_incoherent() -> None:
    rapport = rapport_de_reference()
    alterations: list[tuple[tuple[str, ...], str]] = [
        (("run", "started_at"), "2026-10-21T09:30:00+00:00"),
        (("run", "id"), "pas-un-uuid"),
        (("schema_version",), "2.0.0"),
        (("tool", "name"), "autre"),
    ]
    for chemin, valeur in alterations:
        modifie = copy.deepcopy(rapport)
        cible = modifie
        for cle in chemin[:-1]:
            cible = cible[cle]
        cible[chemin[-1]] = valeur
        with pytest.raises(jsonschema.ValidationError):
            VALIDATEUR.validate(modifie)
    # statut error sans motif, statut pass avec motif
    for statut, motif in [("error", None), ("pass", "timeout")]:
        modifie = copy.deepcopy(rapport)
        modifie["results"][0].update(status=statut, reason=motif)
        with pytest.raises(jsonschema.ValidationError):
            VALIDATEUR.validate(modifie)


def test_schema_tolere_un_champ_ajoute() -> None:
    # compatibilite MINEURE : un consommateur v1 ignore les champs inconnus
    rapport = rapport_de_reference()
    rapport["schema_version"] = "1.1.0"
    rapport["run"]["nouveau_champ"] = "valeur"
    VALIDATEUR.validate(rapport)
    with pytest.raises(jsonschema.ValidationError):
        VALIDATEUR_STRICT.validate(rapport)


def test_amnesia_schema_affiche_le_schema(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["schema"]) == 0
    sortie = capsys.readouterr().out
    assert sortie == schema_text()
    schema = json.loads(sortie)
    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema == SCHEMA
    assert sortie.endswith("}\n")


# --- documentation -----------------------------------------------------------


def _texte_doc() -> str:
    return DOC.read_text(encoding="utf-8")


def _exemple_complet() -> Any:
    section = _texte_doc().split("## Exemple complet", 1)[1]
    bloc = re.search(r"```json\n(.*?)\n```", section, re.DOTALL)
    assert bloc is not None
    return json.loads(bloc.group(1))


def test_exemple_de_la_doc_valide_par_le_schema() -> None:
    exemple = _exemple_complet()
    valider(exemple)
    assert exemple["schema_version"] == SCHEMA_VERSION
    statuts = {r["status"] for r in exemple["results"]}
    assert statuts == {s.value for s in Status}


def _proprietes(schema: Any) -> set[str]:
    noms: set[str] = set()
    if isinstance(schema, dict):
        for cle, valeur in schema.items():
            if cle == "properties":
                noms |= set(valeur)
            noms |= _proprietes(valeur)
    elif isinstance(schema, list):
        for valeur in schema:
            noms |= _proprietes(valeur)
    return noms


def test_doc_documente_chaque_champ_et_la_compatibilite() -> None:
    texte = _texte_doc()
    manquants = sorted(n for n in _proprietes(SCHEMA) if f"`{n}`" not in texte)
    assert not manquants
    assert "## Compatibilité" in texte
    for mot in ("MAJEURE", "MINEURE", "ignore"):
        assert mot in texte
