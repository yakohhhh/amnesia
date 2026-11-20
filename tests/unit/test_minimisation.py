# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Minimisation des donnees collectees (#41) : amnesia.privacy et ses branchements.

Seules des configurations et des metadonnees de journaux sortent de la cible.
Le contenu d'un evenement (compte, adresse IP, poste d'un 4624) n'atteint ni un
fait, ni une preuve, ni le rapport, ni le journal, ni les sorties ; une sortie
brute n'est ecrite sur disque que sur demande (--keep-raw).
"""

from __future__ import annotations

import errno
import json
import logging
import shutil
import stat
import subprocess
import sys
import uuid
from collections.abc import Callable, Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from amnesia import cli
from amnesia.checks import REGISTRY, Check
from amnesia.checks.base import (
    CheckResult,
    Confidence,
    Evidence,
    Gap,
    Severity,
)
from amnesia.checks.context import Context
from amnesia.cli import main
from amnesia.exitcodes import FATAL, GAPS, OK
from amnesia.facts import (
    Collector,
    Fact,
    FactSet,
    FactsFormatError,
    FixtureCollector,
    LocalCollector,
    UnavailableReason,
    load_facts,
    run_command,
)
from amnesia.output import RAW_DIR, RawStore, keep_raw
from amnesia.privacy import (
    EVENT_DATA_FIELDS,
    EVENT_METADATA,
    EVENT_PROPERTIES,
    EVIDENCE_FIELDS,
    FACT_SCHEMAS,
    LIST_MAX_LENGTH,
    NUMBER_MAX,
    PERSONAL_FIELDS,
    REPORT_TEXT_FIELDS,
    SETTING_MAX_LENGTH,
    SOURCE_MAX_LENGTH,
    EvidenceField,
    FactField,
    FactSchema,
    Nature,
    TextFormat,
    check_evidence,
    check_evidence_keys,
    check_fact_value,
    check_script_privacy,
    check_source,
    declare_fact_schema,
    event_content_field,
    normalize_key,
    report_text_violations,
)
from amnesia.readonly import check_script_inventory
from amnesia.report import ReportPrivacyError, load_schema
from amnesia.runner import new_run_id, run_audit
from amnesia.target import Target

RACINE = Path(__file__).resolve().parents[2]
EVENEMENT_4624 = RACINE / "tests" / "fixtures" / "facts" / "evenement_4624.json"
DOC = RACINE / "docs" / "DONNEES.md"
README = RACINE / "README.md"
FAIT = "windows.eventlog.oldest:Security"
INSTANT = datetime(2026, 10, 21, 9, 30, tzinfo=UTC)
# valeurs fictives du critere d'acceptation : compte, adresse IP, poste
VALEURS = ("jdupont", "10.1.2.3", "PC-COMPTA")
RUN_ID = "3f2b8c1e-5d4a-4f6b-9a7c-0e1d2c3b4a59"
WEVTUTIL = "C:\\Windows\\System32\\wevtutil.exe"

posix = pytest.mark.skipif(sys.platform == "win32", reason="droits POSIX")


def _preuve(**champs: Any) -> Evidence:
    valeurs: dict[str, Any] = {
        "observed": 4,
        "expected": 90,
        "unit": "days",
        "confidence": Confidence.MEASURED,
        "source": "Get-WinEvent -ListLog Security",
    }
    return Evidence(**(valeurs | champs))


# --- evenement 4624 : rien ne sort ----------------------------------------------


def test_fixture_4624_porte_les_valeurs_du_critere() -> None:
    brut = EVENEMENT_4624.read_text(encoding="utf-8")
    for valeur in VALEURS:
        assert valeur in brut
    donnees = json.loads(brut)["facts"][FAIT]["value"]["EventData"]
    assert donnees == {
        "TargetUserName": "jdupont",
        "IpAddress": "10.1.2.3",
        "WorkstationName": "PC-COMPTA",
    }


def test_evenement_4624_refuse_a_la_lecture() -> None:
    with pytest.raises(FactsFormatError, match="contenu d'événement refusé") as erreur:
        load_facts(EVENEMENT_4624)
    for valeur in VALEURS:
        assert valeur not in str(erreur.value)


@pytest.mark.parametrize(
    ("valeur", "nom"),
    [
        ({"TargetUserName": "jdupont"}, "TargetUserName"),
        ({"IpAddress": "10.1.2.3"}, "IpAddress"),
        ({"WorkstationName": "PC-COMPTA"}, "WorkstationName"),
        ({"message": "Ouverture de session de jdupont"}, "Message"),
        ({"PROPERTIES": ["jdupont"]}, "Properties"),
        ({"userid": "S-1-5-21-1-2-3-1104"}, "UserId"),
        ({"evenements": [{"id": 4624, "MachineName": "PC-COMPTA"}]}, "MachineName"),
        ({"config": {"EventData": {}}}, "EventData"),
    ],
)
def test_fait_au_contenu_d_evenement_refuse(valeur: dict[str, Any], nom: str) -> None:
    with pytest.raises(FactsFormatError) as erreur:
        Fact.ok(FAIT, valeur, source="collecteur factice", collected_at=INSTANT)
    message = str(erreur.value)
    # le nom cite est celui du module, jamais la cle ni la valeur recues
    assert f"({nom})" in message
    for interdit in VALEURS:
        assert interdit not in message


def test_fait_de_configuration_accepte() -> None:
    fait = Fact.ok(
        "windows.eventlog.config:Security",
        {
            "max_size_bytes": 20971520,
            "record_count": 31337,
            "log_mode": "Circular",
            "oldest_event_utc": "2026-10-17T09:30:00Z",
        },
        source="Get-WinEvent -ListLog Security",
        collected_at=INSTANT,
    )
    assert fait.available


def test_champs_de_contenu_d_evenement() -> None:
    for nom in (*EVENT_PROPERTIES, *EVENT_DATA_FIELDS):
        assert event_content_field(nom) == nom
        assert event_content_field(nom.upper()) == nom
    admis: tuple[object, ...] = ("max_size_bytes", "TimeCreated", "LogMode", "", 4624)
    for cle in admis:
        assert event_content_field(cle) is None


class _CheckDuPlusAncien(Check):
    """Check factice qui exige le fait du plus ancien evenement."""

    id = "test.plus_ancien"
    title = "Check factice : plus ancien evenement"
    requires_facts = (FAIT,)

    def evaluate(self, facts: FactSet, ctx: Context) -> CheckResult:
        return CheckResult.passed(self.id, ctx.target.id)


class _CheckBavard(Check):
    """Check factice fautif : recopie l'evenement brut dans sa preuve."""

    id = "test.bavard"
    title = "Check factice : preuve hors schema"
    question_ids = ("Q-WIN-RDP-LOGON",)

    def evaluate(self, facts: FactSet, ctx: Context) -> CheckResult:
        donnees = json.loads(EVENEMENT_4624.read_text(encoding="utf-8"))
        evenement = donnees["facts"][FAIT]["value"]["EventData"]
        gap = Gap(
            check_id=self.id,
            target=ctx.target.id,
            resource="Security",
            question_id="Q-WIN-RDP-LOGON",
            question="Qui s'est connecte ?",
            reason="journal factice",
            severity=Severity.HIGH,
            evidence=_preuve(details=evenement),
            remediation="agrandir le journal factice",
        )
        return CheckResult.with_gaps(self.id, ctx.target.id, [gap])


class _CollecteurDeBundle:
    """Lit le fichier de faits pendant la collecte, comme un import de bundle."""

    def collect(
        self, target: Target, names: Iterable[str], *, timeout: float
    ) -> FactSet:
        return FixtureCollector(EVENEMENT_4624).collect(target, names, timeout=timeout)


@pytest.mark.parametrize("journal_json", [False, True])
def test_evenement_4624_absent_du_rapport_du_journal_et_des_sorties(
    journal_json: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    # critere de #41 : ni le compte, ni l'adresse IP, ni le poste du 4624
    # n'apparaissent dans le rapport, le journal d'execution, stdout ou stderr,
    # que l'evenement arrive par un fait ou qu'un check tente de le recopier
    def fabrique(target: Target) -> Collector:
        return _CollecteurDeBundle()

    monkeypatch.setattr(cli, "_collecteur", fabrique)
    monkeypatch.setattr(
        cli, "default_checks", lambda: [_CheckDuPlusAncien(), _CheckBavard()]
    )
    rapport, journal = tmp_path / "rapport.json", tmp_path / "amnesia.log"
    options = ["--debug", "--log-file", str(journal)]
    if journal_json:
        options += ["--log-format", "json"]
    with caplog.at_level(logging.DEBUG):
        code = main(["audit", *options, "--format", "json", "--out", str(rapport)])
    assert code != OK
    sorties = capsys.readouterr()
    textes = {
        "rapport": rapport.read_text(encoding="utf-8"),
        "journal": journal.read_text(encoding="utf-8"),
        "stdout": sorties.out,
        "stderr": sorties.err,
        "journalisation": caplog.text,
    }
    for nom in ("rapport", "journal", "stdout"):
        assert textes[nom], nom
    for nom, texte in textes.items():
        for valeur in VALEURS:
            assert valeur not in texte, (nom, valeur)
    # aucun des deux checks n'a conclu : jamais conforme, et le refus est dit
    resultats = {r["check_id"]: r for r in json.loads(textes["rapport"])["results"]}
    assert {r["status"] for r in resultats.values()} == {"error"}
    assert "contenu d'événement refusé" in resultats["test.plus_ancien"]["message"]
    assert "hors du schéma des preuves" in resultats["test.bavard"]["message"]
    assert json.loads(textes["rapport"])["gaps"] == []


# --- preuve d'un Gap : schema ferme ---------------------------------------------


def test_gap_a_la_preuve_en_texte_libre_refuse() -> None:
    # critere de #41 : Gap(evidence={"message": "texte libre"}) est refuse
    champs: dict[str, Any] = {
        "check_id": "win.event_log_retention",
        "target": "winrm://srv-file",
        "resource": "Security",
        "question_id": "Q-WIN-RDP-LOGON",
        "question": "Qui s'est connecte en RDP ?",
        "reason": "Le journal Security fait 20 Mo.",
        "severity": Severity.HIGH,
        "remediation": "Porter le journal Security a 4 Go au moins.",
    }
    with pytest.raises((TypeError, ValueError)):
        Gap(**champs, evidence={"message": "texte libre"})  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="hors du schéma des preuves") as erreur:
        Gap(**champs, evidence=_preuve(details={"message": "texte libre"}))
    # ni la cle inconnue ni sa valeur ne sont reprises
    assert "message" not in str(erreur.value)
    assert "texte libre" not in str(erreur.value)


def test_preuve_relue_hors_schema_refusee() -> None:
    relue = _preuve().to_dict()
    with pytest.raises(ValueError, match="clé"):
        Evidence.from_dict(relue | {"message": "texte libre"})
    with pytest.raises(ValueError, match="hors du schéma des preuves"):
        Evidence.from_dict(relue | {"details": {"message": "texte libre"}})


def test_preuve_conforme_au_schema() -> None:
    details: dict[str, Any] = {
        "max_size_bytes": 20971520,
        "file_size_bytes": 20975616,
        "record_count": 31337,
        "log_mode": "Circular",
        "oldest_event_utc": datetime(2026, 10, 17, 9, 30, tzinfo=UTC),
        "newest_event_utc": "2026-10-21T09:30:00+02:00",
        "events_per_day": 7834.25,
        "retention_days": 0,
        "enabled": False,
        "setting": "EnableScriptBlockLogging",
        "settings": [
            "{0CCE9215-69AE-11D9-BED3-505054503030}",
            "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell",
        ],
        "channels": ["Security", "Microsoft-Windows-Sysmon/Operational"],
    }
    assert set(details) == set(EVIDENCE_FIELDS)
    preuve = _preuve(details=details)
    assert Evidence.from_dict(preuve.to_dict()) == preuve
    # une valeur absente de la cible reste exprimable
    assert _preuve(details=dict.fromkeys(("log_mode", "max_size_bytes", "enabled")))
    assert _preuve(
        observed=["Circular", 20971520],
        expected={"log_mode": "AutoBackup", "max_size_bytes": 4294967296},
    )


@pytest.mark.parametrize(
    "details",
    [
        {"max_size_bytes": "grand"},
        {"max_size_bytes": True},
        {"record_count": [1, 2]},
        {"oldest_event_utc": "hier"},
        {"oldest_event_utc": "2026-10-17T09:30:00"},
        {"oldest_event_utc": 1760693400},
        {"retention_days": -1},
        {"enabled": 1},
        {"enabled": "oui"},
        {"log_mode": 3},
        {"log_mode": "x" * (SETTING_MAX_LENGTH + 1)},
        {"log_mode": {"valeur": "Circular"}},
        {"channels": "Security"},
        {"channels": ["Security", 4624]},
        {"channels": ["Security", None]},
        {"channels": [["Security"]]},
    ],
)
def test_valeur_de_preuve_d_une_autre_nature_refusee(details: dict[str, Any]) -> None:
    (cle,) = details
    with pytest.raises(ValueError, match=rf"details\['{cle}'\] : valeur hors schéma"):
        _preuve(details=details)


@pytest.mark.parametrize(
    "valeur",
    [
        "x" * (SETTING_MAX_LENGTH + 1),
        ["Circular", "y" * (SETTING_MAX_LENGTH + 1)],
        [["Circular"]],
        [{"log_mode": "Circular"}],
        {"message": "texte libre"},
        {"log_mode": 3},
    ],
)
@pytest.mark.parametrize("champ", ["observed", "expected"])
def test_observe_et_attendu_hors_schema_refuses(champ: str, valeur: Any) -> None:
    with pytest.raises(ValueError, match=f"{champ}.* hors ") as erreur:
        _preuve(**{champ: valeur})
    assert "texte libre" not in str(erreur.value)


def test_horodatage_de_preuve_sans_fuseau_refuse() -> None:
    # appel direct, sans passer par Evidence (qui fige d'abord les datetime en
    # texte) : un datetime sans fuseau n'est pas un horodatage du schema
    avec_fuseau = datetime(2026, 1, 1, tzinfo=UTC)
    sans_fuseau = avec_fuseau.replace(tzinfo=None)
    check_evidence({"oldest_event_utc": avec_fuseau})
    with pytest.raises(ValueError, match=r"oldest_event_utc.* valeur hors schéma"):
        check_evidence({"oldest_event_utc": sans_fuseau})
    with pytest.raises(ValueError, match=r"newest_event_utc.* valeur hors schéma"):
        check_evidence({"newest_event_utc": sans_fuseau})


def test_cles_de_preuve_jugees_avant_toute_copie() -> None:
    class _ValeurJamaisLue:
        def __iter__(self) -> Any:
            raise AssertionError("valeur lue avant le refus de sa clé")

    for champ in ("observed", "expected", "details"):
        with pytest.raises(ValueError, match=f"{champ} : clé hors du schéma"):
            _preuve(**{champ: {"message": _ValeurJamaisLue()}})
    # seules les cles textuelles sont jugees ici : le reste releve du typage
    check_evidence_keys({"max_size_bytes": object(), 4624: "x"})
    check_evidence_keys(["message"])
    check_evidence_keys("message")
    with pytest.raises(ValueError, match="hors du schéma des preuves"):
        check_evidence_keys({"max_size_bytes": 1, "message": 2})


def test_check_evidence_exige_un_dictionnaire() -> None:
    with pytest.raises(TypeError, match="details doit être un dictionnaire"):
        check_evidence(["max_size_bytes"])
    with pytest.raises(ValueError, match="hors du schéma"):
        check_evidence({4624: 1})


# --- rapport : champs texte admis -----------------------------------------------


def _rapport_d_audit(tmp_path: Path) -> dict[str, Any]:
    chemin = tmp_path / "rapport.json"
    main(["audit", "--out", str(chemin)])
    rapport: dict[str, Any] = json.loads(chemin.read_text(encoding="utf-8"))
    return rapport


@pytest.mark.parametrize(
    "chemin", ["tests/golden/report.json", "tests/fixtures/report-min.json"]
)
def test_rapports_de_reference_sans_champ_texte_hors_schema(chemin: str) -> None:
    rapport = json.loads((RACINE / chemin).read_text(encoding="utf-8"))
    assert rapport["gaps"], "rapport de référence sans Gap : test sans objet"
    assert report_text_violations(rapport) == []


@pytest.mark.usefixtures("registre_factice")
def test_rapport_d_audit_sans_champ_texte_hors_schema(tmp_path: Path) -> None:
    # critere de #41 : tout champ texte du rapport figure dans le schema
    rapport = _rapport_d_audit(tmp_path)
    assert rapport["gaps"]
    assert rapport["results"]
    assert report_text_violations(rapport) == []


def test_rapport_du_registre_reel_sans_champ_texte_hors_schema(tmp_path: Path) -> None:
    assert report_text_violations(_rapport_d_audit(tmp_path)) == []


@pytest.mark.usefixtures("registre_factice")
def test_champ_texte_hors_schema_detecte(tmp_path: Path) -> None:
    rapport = _rapport_d_audit(tmp_path)
    rapport["run"]["operator"] = "jdupont"
    rapport["results"][0]["notes"] = ["PC-COMPTA"]
    rapport["gaps"][0]["evidence"]["details"]["message"] = "connexion de 10.1.2.3"
    rapport["gaps"][0]["evidence"]["details"]["jdupont"] = 1
    rapport["gaps"][0]["evidence"]["details"]["max_size_bytes"] = "vingt"
    rapport["gaps"][0]["evidence"]["observed"] = {"log_mode": ["Circular"]}
    rapport["inconnu"] = {"texte": "libre"}
    ecarts = report_text_violations(rapport)
    assert sorted(e.split(" : ")[0] for e in ecarts) == [
        "gaps[].evidence.details",
        "gaps[].evidence.details",
        "gaps[].evidence.details.max_size_bytes",
        "gaps[].evidence.observed.log_mode[]",
        "inconnu.texte",
        "results[].notes[]",
        "run.operator",
    ]
    # un ecart donne le chemin, jamais la valeur ni une cle de preuve inconnue
    for valeur in (*VALEURS, "vingt", "libre", "message"):
        assert not [e for e in ecarts if valeur in e]


def test_compte_de_l_auditeur_exclu_du_rapport() -> None:
    # decision du proprietaire : le compte operateur ne va que dans le journal
    # d'execution (#40), jamais dans le rapport remis au client
    assert not [c for c in REPORT_TEXT_FIELDS if "operator" in c or "user" in c]
    (operateur,) = [p for p in PERSONAL_FIELDS if p.name == "operator_account"]
    assert "jamais le rapport" in operateur.location


def test_schema_json_du_rapport_ferme_les_cles_de_details() -> None:
    preuve = load_schema()["$defs"]["evidence"]["properties"]
    assert preuve["details"]["propertyNames"]["enum"] == list(EVIDENCE_FIELDS)


def test_champs_texte_de_la_mission_admis_et_classes() -> None:
    # champs apportes par le fichier de mission (#36) : saisis par l'auditeur,
    # jamais lus sur la cible ; chaque champ texte du schema y est classe
    schema = load_schema()["properties"]
    for champ in schema["mission"]["properties"]:
        assert "mission" in REPORT_TEXT_FIELDS[f"mission.{champ}"], champ
    assert "run.config_source" in REPORT_TEXT_FIELDS
    assert "config_hash" in REPORT_TEXT_FIELDS
    # le nom declare par l'auditeur est une donnee personnelle admise, distincte
    # du compte local qui lance l'audit
    (declare,) = [p for p in PERSONAL_FIELDS if p.name == "declared_auditor"]
    assert "mission.auditor" in declare.location
    assert "declared_auditor" in REPORT_TEXT_FIELDS["mission.auditor"]
    rapport: dict[str, Any] = {
        "run": {"profile": "standard", "config_source": "--config"},
        "mission": {
            "client": "Client fictif",
            "reference": "M-0001",
            "auditor": "Equipe fictive",
            "start": "2026-10-01",
            "end": "2026-10-31",
            "tlp": "TLP:AMBER",
        },
        "config_hash": "0" * 64,
    }
    assert report_text_violations(rapport) == []
    rapport["mission"]["contact"] = "jdupont"
    assert report_text_violations(rapport) == [
        "mission.contact : champ texte hors schéma"
    ]


def test_champs_texte_des_preuves_derives_du_schema() -> None:
    racine = "gaps[].evidence"
    for bloc in ("observed", "expected", "details"):
        assert f"{racine}.{bloc}.log_mode" in REPORT_TEXT_FIELDS
        assert f"{racine}.{bloc}.channels[]" in REPORT_TEXT_FIELDS
        assert f"{racine}.{bloc}.oldest_event_utc" in REPORT_TEXT_FIELDS
        # un nombre n'est jamais un champ texte
        assert f"{racine}.{bloc}.max_size_bytes" not in REPORT_TEXT_FIELDS


# --- sorties brutes : jamais sur disque sans --keep-raw --------------------------


class _FauxRun:
    """Remplace subprocess.run : rend une sortie brute, n'execute rien."""

    def __call__(
        self, *args: Any, **options: Any
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(args[0], 0, b"sortie brute", b"")


@pytest.fixture
def faux_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "run", _FauxRun())


def _mode(chemin: Path) -> int:
    return stat.S_IMODE(chemin.stat().st_mode)


@pytest.mark.usefixtures("faux_run")
def test_sans_keep_raw_aucune_sortie_brute_sur_disque(tmp_path: Path) -> None:
    resultat = run_command([WEVTUTIL, "gl", "Security"], timeout=5)
    assert resultat.stdout == b"sortie brute"
    # le repertoire courant du test est tmp_path (conftest) : rien n'y est ne
    assert list(tmp_path.rglob("*")) == []


@pytest.mark.usefixtures("faux_run")
def test_avec_keep_raw_sortie_brute_dans_un_dossier_prive(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        depot = keep_raw(run_id=RUN_ID)
    # un sous-dossier par execution, nomme d'apres le run.id du rapport
    dossier = tmp_path / "amnesia-out" / RAW_DIR / RUN_ID
    assert depot.directory.resolve() == dossier.resolve()
    (avertissement,) = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert "--keep-raw" in avertissement.getMessage()
    assert "données personnelles" in avertissement.getMessage()
    run_command([WEVTUTIL, "gl", "Security"], timeout=5, raw=depot)
    run_command([WEVTUTIL, "gl", "System"], timeout=5, raw=depot)
    fichiers = sorted(f.name for f in dossier.iterdir())
    assert fichiers == ["0001-wevtutil.bin", "0002-wevtutil.bin"]
    assert (dossier / fichiers[0]).read_bytes() == b"sortie brute"
    # ignores par git, comme le rapport
    assert (dossier.parent / ".gitignore").read_bytes() == b"*\n"
    if sys.platform != "win32":
        assert _mode(dossier) == 0o700
        assert _mode(dossier.parent) == 0o700
        assert _mode(dossier.parent.parent) == 0o700
        assert _mode(dossier / fichiers[0]) == 0o600


@posix
def test_dossier_brut_existant_ramene_en_0700(tmp_path: Path) -> None:
    dossier = tmp_path / "brut"
    dossier.mkdir(mode=0o755)
    dossier.chmod(0o755)
    depot = keep_raw(dossier)
    assert _mode(dossier) == 0o700
    assert depot.directory.parent == dossier
    assert _mode(depot.directory) == 0o700


def test_nom_de_sortie_brute_reduit_a_un_nom_de_fichier(tmp_path: Path) -> None:
    depot = RawStore(tmp_path)
    depot("../../etc/passwd", b"a")
    depot("", b"b")
    assert sorted(f.name for f in tmp_path.iterdir()) == [
        "0001-______etc_passwd.bin",
        "0002-sortie.bin",
    ]


@pytest.mark.usefixtures("registre_factice")
def test_audit_sans_keep_raw_n_ecrit_que_le_rapport(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["audit", "--out", str(tmp_path / "rapport.json")])
    assert [f.name for f in tmp_path.rglob("*")] == ["rapport.json"]
    assert "--keep-raw" not in capsys.readouterr().err


@pytest.mark.usefixtures("registre_factice")
def test_audit_avec_keep_raw_dossier_prive_et_avertissement(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rapport = tmp_path / "rapport.json"
    main(["audit", "--keep-raw", "--out", str(rapport)])
    texte = rapport.read_text(encoding="utf-8")
    # le dossier de l'execution porte le run.id du rapport
    dossier = tmp_path / "amnesia-out" / RAW_DIR / json.loads(texte)["run"]["id"]
    assert dossier.is_dir()
    if sys.platform != "win32":
        assert _mode(dossier) == 0o700
        assert _mode(dossier.parent) == 0o700
    erreur = capsys.readouterr().err
    assert erreur.count("--keep-raw") == 1
    assert "données personnelles" in erreur
    # les sorties brutes n'entrent jamais dans le rapport
    assert RAW_DIR not in json.loads(texte)
    assert report_text_violations(json.loads(texte)) == []


def test_keep_raw_refuse_si_le_dossier_ne_peut_pas_etre_prepare(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "amnesia-out").write_text("pas un dossier", encoding="utf-8")
    rapport = tmp_path / "rapport.json"
    code = main(["audit", "--keep-raw", "--out", str(rapport)])
    assert code != OK
    assert "--keep-raw" in capsys.readouterr().err
    # l'audit n'a pas ete lance : aucun rapport
    assert not rapport.exists()


def test_collecteur_local_recoit_le_depot_des_sorties_brutes(tmp_path: Path) -> None:
    depot = RawStore(tmp_path)
    local = Target.parse("local")
    avec = cli._collecteur(local, depot)
    sans = cli._collecteur(local)
    assert isinstance(avec, LocalCollector)
    assert isinstance(sans, LocalCollector)
    assert avec.raw is depot
    assert sans.raw is None


# --- seconde revue : schema ferme des faits (constat 1) ---------------------------

JOURNAL = "windows.eventlog.config:Security"
AUDITPOL = "windows.auditpol.backup"
GUID_LOGON = "{0CCE9215-69AE-11D9-BED3-505054503030}"
PHRASE = "Account Name: alice"


def _fait(valeur: object, nom: str = JOURNAL) -> Fact:
    return Fact.ok(nom, valeur, source="collecteur factice", collected_at=INSTANT)


@pytest.mark.parametrize(
    ("cle", "nom"),
    [
        ("message ", "Message"),
        (" Message\t", "Message"),
        # espace sans chasse, pleine chasse (formes de compatibilite, NFKC)
        ("Message\u200b", "Message"),
        ("\uff2d\uff45\uff53\uff53\uff41\uff47\uff45", "Message"),
        ("MESSAGE", "Message"),
        ("target_user_name", "TargetUserName"),
        ("Target-User.Name", "TargetUserName"),
        ("event_data", "EventData"),
        ("ip address", "IpAddress"),
        ("machine_name", "MachineName"),
        ("Xml", "Xml"),
        ("User", "User"),
        ("account_name", "AccountName"),
        ("Computer", "Computer"),
        ("LogonId", "LogonId"),
        ("TargetSid", "TargetSid"),
        ("process_name", "ProcessName"),
        ("COMMANDLINE", "CommandLine"),
    ],
)
def test_champ_d_evenement_reconnu_quelle_que_soit_sa_graphie(
    cle: str, nom: str
) -> None:
    assert event_content_field(cle) == nom
    with pytest.raises(FactsFormatError, match="contenu d'événement refusé") as erreur:
        _fait({cle: PHRASE})
    # le nom cite est celui du module ; ni la cle recue ni la valeur
    assert f"({nom})" in str(erreur.value)
    assert "alice" not in str(erreur.value)


def test_normalisation_des_cles() -> None:
    assert normalize_key("Target_User-Name \u200b") == "targetusername"
    assert normalize_key("\uff2d\uff53\uff47") == "msg"
    # un homoglyphe cyrillique n'est pas ramene a sa lettre latine : il n'est
    # pas reconnu ici, et c'est le schema ferme qui le refuse
    assert event_content_field("\u041cessage") is None
    assert normalize_key("") == ""


@pytest.mark.parametrize(
    "valeur",
    [
        # contournements de la liste noire releves en revue : cle abregee,
        # homoglyphe, champ reel absent de la liste, contenu glisse dans une valeur
        {"Msg": PHRASE},
        {"\u041cessage": PHRASE},
        {"Description": PHRASE},
        {"data": [{"Name": "TargetUserName", "Value": "alice"}]},
        {"data": [{"k": "alice"}]},
        {"log_mode": PHRASE},
        {"log_mode": "alice" * 2000},
        {"log_mode": ["alice"]},
        {"max_size_bytes": "alice"},
        {"max_size_bytes": {"alice": 1}},
        {"oldest_event_utc": "alice"},
        {"oldest_event_utc": "2026-10-17T09:30:00Z alice"},
        {"enabled": "alice"},
        {"record_count": ["alice"]},
        "alice",
        ["alice"],
        [{"log_mode": "Circular"}],
    ],
)
def test_contournement_de_la_liste_noire_refuse_par_le_schema(valeur: Any) -> None:
    with pytest.raises(FactsFormatError, match=r"hors (du )?schéma") as erreur:
        _fait(valeur)
    message = str(erreur.value)
    # ni la valeur, ni la cle recue
    for interdit in ("alice", "Msg", "essage", "Description", "data"):
        assert interdit not in message
    assert "windows.eventlog.config" in message


@pytest.mark.parametrize(
    "nom",
    [
        "windows.inconnu",
        "windows.eventlog.oldest:Security",
        "aws.cloudtrail.trails",
        "ad.krbtgt.password_last_set",
    ],
)
@pytest.mark.parametrize("valeur", [None, True, 1, {"enabled": True}, "texte"])
def test_fait_sans_schema_declare_refuse(nom: str, valeur: Any) -> None:
    assert nom.partition(":")[0] not in FACT_SCHEMAS
    with pytest.raises(FactsFormatError, match="aucun schéma déclaré"):
        _fait(valeur, nom)
    # un fait indisponible n'a pas de valeur : aucun schema a lui opposer
    indisponible = Fact.unavailable(
        nom, UnavailableReason.NOT_COLLECTED, source="s", collected_at=INSTANT
    )
    assert not indisponible.available


def test_qualificatif_admis_seulement_si_le_schema_le_declare() -> None:
    assert _fait(None, "windows.eventlog.config:Windows PowerShell").available
    assert _fait(None, AUDITPOL).available
    with pytest.raises(FactsFormatError, match="qualificatif hors du schéma") as erreur:
        _fait(None, f"{AUDITPOL}:jdupont")
    assert "jdupont" not in str(erreur.value)
    check_fact_value(JOURNAL, None)
    with pytest.raises(ValueError, match="qualificatif"):
        check_fact_value("windows.eventlog.config:" + "S" * 129, None)


def test_valeurs_de_fait_bornees() -> None:
    sous_categorie = {"guid": GUID_LOGON, "setting_value": 3}
    assert _fait({"subcategories": [sous_categorie] * LIST_MAX_LENGTH}, AUDITPOL)
    assert _fait({"subcategories": None}, AUDITPOL).available
    assert _fait({"max_size_bytes": NUMBER_MAX, "record_count": -NUMBER_MAX}).available
    refus: list[tuple[str, Any]] = [
        (AUDITPOL, {"subcategories": [sous_categorie] * (LIST_MAX_LENGTH + 1)}),
        (AUDITPOL, {"subcategories": sous_categorie}),
        (AUDITPOL, {"subcategories": [None]}),
        (AUDITPOL, {"subcategories": [GUID_LOGON]}),
        (AUDITPOL, {"subcategories": [{"guid": GUID_LOGON, "nom": "Logon"}]}),
        (AUDITPOL, {"subcategories": [{"guid": "Logon de jdupont"}]}),
        (AUDITPOL, {"subcategories": [{"setting_value": "3"}]}),
        (JOURNAL, {"max_size_bytes": NUMBER_MAX + 1}),
        # entier que float() ne sait pas representer : refuse, jamais une
        # OverflowError
        (JOURNAL, {"max_size_bytes": 10**400}),
        (JOURNAL, {"events_per_day_inconnu": 1.0}),
        (JOURNAL, {"record_count": True}),
        (JOURNAL, {"enabled": 1}),
        (JOURNAL, {"oldest_event_utc": "2026-10-17T09:30:00"}),
        # fraction de seconde demesuree : fromisoformat la tronque, pas le schema
        (JOURNAL, {"oldest_event_utc": "2026-10-17T09:30:00." + "1" * 60 + "Z"}),
        ("windows.sysmon.service", {"state": "running"}),
        ("windows.sysmon.service", {"service_name": "Sysmon de jdupont"}),
        ("windows.sysmon.service", {"version": "15.15-jdupont"}),
        ("windows.sysmon.config", {"config_hash": "jdupont"}),
        ("windows.sysmon.config", {"hash_algorithms": ["SHA256", "jdupont"]}),
        ("windows.powershell.logging_policy", {"module_names": ["a b"]}),
        ("windows.powershell.logging_policy", {"module_names": ["x" * 129]}),
        ("windows.w32time.config", {"poll_interval_seconds": -1}),
        ("windows.w32time.config", {"type": "time.exemple.invalid"}),
    ]
    for nom, valeur in refus:
        with pytest.raises(FactsFormatError, match=r"hors (du )?schéma") as erreur:
            _fait(valeur, nom)
        assert "profondeur" in str(erreur.value), valeur
        assert "jdupont" not in str(erreur.value), valeur
    # appel direct, sans le modele (qui refuse deja un flottant non fini)
    for infini in (float("inf"), float("nan")):
        with pytest.raises(ValueError, match="'max_size_bytes'"):
            check_fact_value(JOURNAL, {"max_size_bytes": infini})


EXEMPLES: dict[str, dict[str, Any]] = {
    AUDITPOL: {"subcategories": [{"guid": GUID_LOGON, "setting_value": 3}]},
    JOURNAL: {
        "max_size_bytes": 20971520,
        "file_size_bytes": 20975616,
        "record_count": 31337,
        "log_mode": "Circular",
        "enabled": True,
        "oldest_event_utc": "2026-10-17T09:30:00Z",
        "newest_event_utc": "2026-10-21T09:30:00+02:00",
    },
    "windows.powershell.logging_policy": {
        "script_block_logging": True,
        "script_block_invocation_logging": False,
        "module_logging": True,
        "module_names": ["*", "Microsoft.PowerShell.*"],
        "transcription": None,
    },
    "windows.sysmon.service": {
        "installed": True,
        "service_name": "Sysmon64",
        "state": "Running",
        "start_mode": "Automatic",
        "version": "15.15",
    },
    "windows.sysmon.config": {
        "loaded": True,
        "schema_version": "4.90",
        "config_hash": "a1" * 32,
        "hash_algorithms": ["SHA256", "IMPHASH"],
        "rule_count": 412,
    },
    "windows.w32time.config": {
        "type": "NT5DS",
        "ntp_server_count": 2,
        "service_state": "Running",
        "service_start_mode": "Automatic",
        "poll_interval_seconds": 3600,
    },
    "windows.w32time.status": {
        "synchronized": True,
        "stratum": 3,
        "last_sync_utc": "2026-10-21T09:00:00Z",
        "offset_seconds": -0.0123,
        "leap_indicator": 0,
    },
}


def test_schemas_couvrent_les_faits_des_checks_livres() -> None:
    requis = {nom for meta in REGISTRY.metas() for nom in meta.requires_facts}
    assert requis
    for nom in sorted(requis):
        assert nom.partition(":")[0] in FACT_SCHEMAS, nom
        assert nom in EXEMPLES, nom
    # un exemple complet par schema livre, relu a l'identique
    assert {nom.partition(":")[0] for nom in EXEMPLES} == set(FACT_SCHEMAS)
    for nom, valeur in EXEMPLES.items():
        schema = FACT_SCHEMAS[nom.partition(":")[0]]
        assert set(valeur) == {champ.name for champ in schema.fields}, nom
        faits = FactSet([_fait(valeur, nom)])
        assert FactSet.from_dict(json.loads(json.dumps(faits.to_dict()))) == faits


def test_declaration_d_un_schema_de_fait() -> None:
    # point d'extension d'un collecteur (#48) : sans declaration, le fait est
    # refuse ; avec, il suit le schema declare, et rien d'autre
    nom = "windows.defender.status"
    schema = FactSchema(
        nom,
        "etat factice de la protection en temps reel",
        fields=(
            FactField("enabled", Nature.BOOLEAN, "protection active ou non"),
            FactField(
                "engine_version",
                Nature.SETTING,
                "version du moteur",
                format=TextFormat.VERSION,
            ),
        ),
    )
    with pytest.raises(FactsFormatError, match="aucun schéma déclaré"):
        _fait({"enabled": True}, nom)
    declare_fact_schema(schema)
    declare_fact_schema(schema)  # la meme declaration, rejouee : sans effet
    assert FACT_SCHEMAS[nom] is schema
    assert _fait({"enabled": True, "engine_version": "1.1.24090"}, nom).available
    with pytest.raises(FactsFormatError, match="'engine_version'"):
        _fait({"engine_version": "1.1 de jdupont"}, nom)
    with pytest.raises(FactsFormatError, match="clé hors du schéma du fait"):
        _fait({"enabled": True, "signature": "x"}, nom)
    with pytest.raises(FactsFormatError, match="qualificatif"):
        _fait(None, f"{nom}:Security")
    # un schema ne se remplace pas : pas de permissivite apres coup
    autre = FactSchema(nom, "autre schema", scalar=Nature.BOOLEAN)
    with pytest.raises(ValueError, match="déjà déclaré"):
        declare_fact_schema(autre)
    with pytest.raises(ValueError, match="déjà déclaré"):
        declare_fact_schema(FactSchema(AUDITPOL, "x", scalar=Nature.BOOLEAN))
    assert FACT_SCHEMAS[nom] is schema
    with pytest.raises(TypeError, match="FactSchema attendu"):
        declare_fact_schema(nom)  # type: ignore[arg-type]
    # la vue publique est en lecture seule
    with pytest.raises(TypeError):
        FACT_SCHEMAS[nom] = autre  # type: ignore[index]


def test_fait_scalaire_declare() -> None:
    declare_fact_schema(
        FactSchema("ad.essai.duree", "duree factice", scalar=Nature.DURATION)
    )
    assert _fait(12.5, "ad.essai.duree").value == 12.5
    assert _fait(None, "ad.essai.duree").available
    for valeur in (-1, True, "12", [12], {"valeur": 12}, NUMBER_MAX * 2):
        with pytest.raises(FactsFormatError, match="hors schéma, duration attendu"):
            _fait(valeur, "ad.essai.duree")


def test_aucun_schema_n_admet_un_texte_libre() -> None:
    booleen = FactField("actif", Nature.BOOLEAN, "d")
    declarations: list[Callable[[], object]] = [
        # un fait n'est jamais un texte seul, ni un objet sans champs declares
        lambda: FactSchema("windows.x", "d", scalar=Nature.SETTING),
        lambda: FactSchema("windows.x", "d", scalar=Nature.RECORD),
        lambda: FactSchema("windows.x", "d"),
        lambda: FactSchema("windows.x", "d", fields=(booleen,), scalar=Nature.NUMBER),
        lambda: FactSchema("windows.x:Security", "d", scalar=Nature.BOOLEAN),
        lambda: FactSchema("Windows", "d", scalar=Nature.BOOLEAN),
        lambda: FactSchema("windows.x", "d", fields=(booleen, booleen)),
        # un parametre declare une enumeration ou une forme, l'une des deux
        lambda: FactField("libre", Nature.SETTING, "d"),
        lambda: FactField(
            "libre", Nature.SETTING, "d", choices=("a",), format=TextFormat.GUID
        ),
        lambda: FactField("libre", Nature.SETTING, "d", choices=("",)),
        lambda: FactField("nombre", Nature.NUMBER, "d", choices=("a",)),
        lambda: FactField("nombre", Nature.NUMBER, "d", format=TextFormat.GUID),
        # un objet declare ses champs ; un scalaire n'en a pas
        lambda: FactField("objet", Nature.RECORD, "d"),
        lambda: FactField("actif", Nature.BOOLEAN, "d", fields=(booleen,)),
        # nom de champ : minuscules, jamais un champ de contenu d'evenement
        lambda: FactField("Actif", Nature.BOOLEAN, "d"),
        lambda: FactField("message", Nature.BOOLEAN, "d"),
        lambda: FactField("user_name", Nature.BOOLEAN, "d"),
        lambda: FactField("target_user_name", Nature.BOOLEAN, "d"),
        # meme regle pour les preuves
        lambda: EvidenceField("libre", Nature.SETTING, "d"),
        lambda: EvidenceField("objet", Nature.RECORD, "d"),
    ]
    for declarer in declarations:
        with pytest.raises(ValueError):
            declarer()
    with pytest.raises(TypeError, match="FactField attendus"):
        FactSchema("windows.x", "d", fields=("actif",))  # type: ignore[arg-type]
    # imbrication bornee par la declaration elle-meme
    champ = booleen
    for rang in range(4):
        champ = FactField(f"niveau_{rang}", Nature.RECORD, "d", fields=(champ,))
    with pytest.raises(ValueError, match="trop imbriqués"):
        FactSchema("windows.x", "d", fields=(champ,))
    # chaque parametre des schemas livres a son enumeration ou sa forme
    for schema in FACT_SCHEMAS.values():
        assert schema.scalar is not Nature.SETTING
    for preuve in EVIDENCE_FIELDS.values():
        if preuve.nature is Nature.SETTING:
            assert bool(preuve.choices) != (preuve.format is not None), preuve.name


def test_faits_md_decrit_chaque_schema() -> None:
    doc = (RACINE / "docs" / "dev" / "faits.md").read_text(encoding="utf-8")
    inventaire = DOC.read_text(encoding="utf-8")

    def champs(declares: tuple[FactField, ...], prefixe: str = "") -> Iterable[str]:
        for champ in declares:
            chemin = f"{prefixe}{champ.name}{'[]' if champ.repeated else ''}"
            yield chemin
            yield from champs(champ.fields, f"{chemin}.")

    for nom, schema in FACT_SCHEMAS.items():
        assert f"`{nom}`" in inventaire, nom
        assert f"`{nom}`" in doc, nom
        for chemin in champs(schema.fields):
            assert f"| `{chemin}` |" in doc, (nom, chemin)
    assert "declare_fact_schema" in doc
    assert "declare_fact_schema" in inventaire


# --- constat 5 : un refus ne cite aucune cle recue --------------------------------


@pytest.mark.parametrize(
    ("valeur", "motif"),
    [
        # un fait indexe par compte ou par poste : la cle est la donnee
        ({"jdupont": 1}, "clé hors du schéma du fait à la profondeur 0"),
        ({"PC-COMPTA": {"Message": "x"}}, r"\(profondeur 1\) : champ de contenu"),
        ({"PC-COMPTA": {"x": float("inf")}}, r"\(profondeur 2\) : flottant non fini"),
        ({"jdupont": {4624: "a"}}, r"\(profondeur 1\) : clé non textuelle"),
        ({"10.1.2.3": [object()]}, r"\(profondeur 2\) : type non JSON"),
        ({("jdupont", "PC-COMPTA"): 1}, r"\(profondeur 0\) : clé non textuelle"),
    ],
)
def test_refus_d_un_fait_sans_cle_recue(valeur: Any, motif: str) -> None:
    with pytest.raises(FactsFormatError, match=motif) as erreur:
        _fait(valeur)
    message = str(erreur.value)
    assert message.startswith("windows.eventlog.config")
    for interdit in VALEURS:
        assert interdit not in message


# --- constat 2 : preuves bornees, rapport controle avant ecriture -----------------


@pytest.mark.parametrize(
    "details",
    [
        {"log_mode": PHRASE},
        {"log_mode": "circular"},
        {"log_mode": "alice"},
        {"setting": PHRASE},
        {"setting": "Process Creation"},
        {"setting": "x" * (SETTING_MAX_LENGTH + 1)},
        {"settings": ["EnableScriptBlockLogging", "ouverture de session alice"]},
        {"settings": ["x"] * (LIST_MAX_LENGTH + 1)},
        {"channels": ["Security\nalice"]},
        {"channels": ["Security", "alice (10.1.2.3)"]},
        {"channels": ["S" * 129]},
        {"channels": ["Security"] * (LIST_MAX_LENGTH + 1)},
        {"oldest_event_utc": "2026-10-17T09:30:00." + "7" * 60 + "Z"},
    ],
)
def test_parametre_de_preuve_hors_de_sa_forme_refuse(details: dict[str, Any]) -> None:
    (cle,) = details
    with pytest.raises(
        ValueError, match=rf"details\['{cle}'\] : valeur hors schéma"
    ) as e:
        _preuve(details=details)
    assert "alice" not in str(e.value)
    # a la borne, la liste reste admise
    assert _preuve(details={"channels": ["Security"] * LIST_MAX_LENGTH})
    assert _preuve(details={"settings": [GUID_LOGON] * LIST_MAX_LENGTH})


@pytest.mark.parametrize(
    "valeur",
    [
        PHRASE,
        "connexion de jdupont depuis 10.1.2.3",
        "Windows PowerShell",
        "",
        ["Circular", "ouverture de session"],
        [0] * (LIST_MAX_LENGTH + 1),
    ],
)
@pytest.mark.parametrize("champ", ["observed", "expected"])
def test_texte_libre_refuse_dans_observe_et_attendu(champ: str, valeur: Any) -> None:
    with pytest.raises(ValueError, match=f"{champ} : valeur hors schéma") as erreur:
        _preuve(**{champ: valeur})
    for interdit in ("alice", "jdupont", "10.1.2.3"):
        assert interdit not in str(erreur.value)
    admis: list[Any] = [
        "Circular",
        "EnableScriptBlockLogging",
        "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell",
        GUID_LOGON,
        "2026-10-21T09:30:00+02:00",
        ["AutoBackup", 4294967296, None, True],
        [0] * LIST_MAX_LENGTH,
    ]
    for conforme in admis:
        assert _preuve(**{champ: conforme})


def test_source_bornee() -> None:
    limite = "x" * SOURCE_MAX_LENGTH
    assert _preuve(source=limite).source == limite
    assert _fait(None).source == "collecteur factice"
    for source in (limite + "x", "Get-WinEvent\nAccount Name: alice", " ", ""):
        with pytest.raises(ValueError) as erreur:
            _preuve(source=source)
        assert "alice" not in str(erreur.value)
        with pytest.raises(FactsFormatError) as refus:
            Fact.ok(JOURNAL, None, source=source, collected_at=INSTANT)
        assert "alice" not in str(refus.value)
    with pytest.raises(ValueError, match="source hors schéma") as longue:
        _preuve(source=limite + "x")
    assert "xxxx" not in str(longue.value)
    with pytest.raises(FactsFormatError, match="source hors schéma"):
        Fact.ok(JOURNAL, None, source=limite + "x", collected_at=INSTANT)
    for invalide in (None, 4624, limite + "x", "a\tb"):
        with pytest.raises(ValueError, match="source hors schéma"):
            check_source(invalide)


@pytest.mark.usefixtures("registre_factice")
def test_texte_de_preuve_hors_forme_detecte_dans_le_rapport(tmp_path: Path) -> None:
    rapport = _rapport_d_audit(tmp_path)
    preuve = rapport["gaps"][0]["evidence"]
    preuve["source"] = "x" * (SOURCE_MAX_LENGTH + 1)
    preuve["observed"] = "connexion de jdupont depuis 10.1.2.3"
    preuve["expected"] = ["Circular", "poste PC-COMPTA"]
    preuve["details"] = {
        "log_mode": "jdupont",
        "setting": "Process Creation",
        "settings": ["EnableScriptBlockLogging"],
        "channels": ["Security"] * (LIST_MAX_LENGTH + 1),
        "oldest_event_utc": "hier",
    }
    ecarts = report_text_violations(rapport)
    assert sorted(e.split(" : ")[0] for e in ecarts) == [
        "gaps[].evidence.details.channels",
        "gaps[].evidence.details.log_mode",
        "gaps[].evidence.details.oldest_event_utc",
        "gaps[].evidence.details.setting",
        "gaps[].evidence.expected[]",
        "gaps[].evidence.observed",
        "gaps[].evidence.source",
    ]
    for valeur in (*VALEURS, "xxxx", "hier", "Process"):
        assert not [e for e in ecarts if valeur in e]


@pytest.mark.usefixtures("registre_factice")
@pytest.mark.parametrize("sortie", ["fichier", "stdout"])
def test_rapport_hors_schema_jamais_ecrit(
    sortie: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # regression simulee : un champ texte hors schema (le compte d'un
    # utilisateur) arrive dans un Gap. Le controle joue avant toute ecriture
    origine = Gap.to_dict

    def bavard(self: Gap) -> dict[str, Any]:
        return origine(self) | {"last_user": "jdupont"}

    monkeypatch.setattr(Gap, "to_dict", bavard)
    rapport = tmp_path / "rapport.json"
    destination = str(rapport) if sortie == "fichier" else "-"
    assert main(["audit", "--out", destination]) == FATAL
    assert not rapport.exists()
    sorties = capsys.readouterr()
    assert sorties.out == ""
    assert "rapport non écrit" in sorties.err
    assert "gaps[].last_user : champ texte hors schéma" in sorties.err
    assert "jdupont" not in sorties.err


def test_erreur_de_rapport_hors_schema_sans_valeur() -> None:
    ecarts = [
        f"gaps[].evidence.details.cle_{n} : champ texte hors schéma" for n in range(7)
    ]
    erreur = ReportPrivacyError(ecarts)
    assert erreur.violations == tuple(ecarts)
    assert str(erreur).startswith("7 écart(s)")
    assert "cle_4" in str(erreur)
    assert "cle_5" not in str(erreur)
    assert "et 2 autre(s)" in str(erreur)
    assert "autre(s)" not in str(ReportPrivacyError(ecarts[:5]))


# --- constat 3 : l'avertissement de --keep-raw survit a --quiet -------------------


@pytest.fixture
def niveau_de_journal_restaure() -> Iterator[None]:
    # -q laisse le logger « amnesia » au niveau ERROR : sans effet sur la suite
    journal = logging.getLogger("amnesia")
    niveau = journal.level
    yield
    journal.setLevel(niveau)


@pytest.mark.usefixtures("registre_factice", "niveau_de_journal_restaure")
@pytest.mark.parametrize("options", [["-q"], ["--quiet"], [], ["-v"]])
def test_avertissement_keep_raw_meme_en_mode_silencieux(
    options: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rapport = tmp_path / "rapport.json"
    main(["audit", *options, "--keep-raw", "--out", str(rapport)])
    erreur = capsys.readouterr().err
    # une fois, ni zero ni deux
    assert erreur.count("--keep-raw : les sorties brutes") == 1
    assert "données personnelles" in erreur
    assert json.loads(rapport.read_text(encoding="utf-8"))["run"]["id"] in erreur


def test_avertissement_keep_raw_sous_un_journal_reduit_aux_erreurs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.ERROR, logger="amnesia"):
        depot = keep_raw(tmp_path / "brut")
    erreur = capsys.readouterr().err
    assert erreur.startswith("avertissement : --keep-raw")
    assert "données personnelles" in erreur
    assert depot.directory.name in erreur
    # journal non reduit : l'avertissement passe par lui seul, pas deux fois
    with caplog.at_level(logging.WARNING, logger="amnesia"):
        keep_raw(tmp_path / "brut")
    assert "avertissement : --keep-raw" not in capsys.readouterr().err
    assert "--keep-raw" in caplog.text


@posix
def test_avertissement_keep_raw_direct_neutralise_le_chemin(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    # ecrit hors du journal, donc hors de son formateur : le chemin, qui peut
    # venir d'un appelant, ne doit pas agir sur le terminal
    with caplog.at_level(logging.ERROR, logger="amnesia"):
        keep_raw(tmp_path / "brut\x1b[2J")
    erreur = capsys.readouterr().err
    assert "\x1b" not in erreur
    assert "\\x1b[2J" in erreur


# --- constat 4 : un dossier par execution, echec d'ecriture sans effet ------------


@pytest.mark.usefixtures("faux_run")
def test_deux_executions_keep_raw_dans_le_meme_dossier(tmp_path: Path) -> None:
    premier, second = keep_raw(), keep_raw()
    racine = tmp_path / "amnesia-out" / RAW_DIR
    assert premier.directory != second.directory
    assert premier.directory.parent.resolve() == racine.resolve()
    assert second.directory.parent.resolve() == racine.resolve()
    for depot in (premier, second):
        resultat = run_command([WEVTUTIL, "gl", "Security"], timeout=5, raw=depot)
        assert resultat.stdout == b"sortie brute"
        assert [f.name for f in depot.directory.iterdir()] == ["0001-wevtutil.bin"]
    # un identifiant d'execution ne sert qu'une fois : jamais deux lots meles
    assert keep_raw(run_id=RUN_ID.upper()).directory.name == RUN_ID
    with pytest.raises(FileExistsError):
        keep_raw(run_id=RUN_ID)
    # ... et n'est jamais un chemin
    for invalide in ("../../ailleurs", "raw", ""):
        with pytest.raises(ValueError):
            keep_raw(run_id=invalide)
    assert not (tmp_path / "ailleurs").exists()


@pytest.mark.usefixtures("registre_factice")
def test_deux_audits_keep_raw_successifs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    identifiants = set()
    for rang in (1, 2):
        rapport = tmp_path / f"rapport-{rang}.json"
        assert main(["audit", "--keep-raw", "--out", str(rapport)]) == GAPS
        identifiants.add(json.loads(rapport.read_text(encoding="utf-8"))["run"]["id"])
    racine = tmp_path / "amnesia-out" / RAW_DIR
    assert {d.name for d in racine.iterdir() if d.is_dir()} == identifiants
    assert len(identifiants) == 2
    assert "existe déjà" not in capsys.readouterr().err


@pytest.mark.usefixtures("faux_run")
def test_echec_d_ecriture_brute_sans_effet_sur_la_commande(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    def disque_plein(name: str, data: bytes) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")

    with caplog.at_level(logging.WARNING, logger="amnesia"):
        resultat = run_command(
            [WEVTUTIL, "gl", "Security"], timeout=5, raw=disque_plein
        )
    assert resultat.stdout == b"sortie brute"
    assert "sortie brute non gardée : No space left on device" in caplog.text
    # deux depots sur le meme dossier (ce que keep_raw() ne fait plus) : le
    # refus d'ecraser ne remonte pas jusqu'a la collecte
    dossier = tmp_path / "partage"
    dossier.mkdir()
    for depot in (RawStore(dossier), RawStore(dossier)):
        assert run_command([WEVTUTIL, "gl", "Security"], timeout=5, raw=depot)
    assert [f.name for f in dossier.iterdir()] == ["0001-wevtutil.bin"]
    # toute autre exception reste une erreur de programmation, et remonte

    def casse(name: str, data: bytes) -> None:
        raise RuntimeError("bug")

    with pytest.raises(RuntimeError):
        run_command([WEVTUTIL, "gl", "Security"], timeout=5, raw=casse)


def test_run_audit_garde_l_identifiant_impose() -> None:
    identifiant = new_run_id()
    assert str(uuid.UUID(identifiant)) == identifiant
    assert new_run_id() != identifiant
    audit = run_audit([], Target.parse("local"), LocalCollector(), run_id=identifiant)
    assert audit.run_id == identifiant
    libre = run_audit([], Target.parse("local"), LocalCollector())
    assert libre.run_id not in ("", identifiant)


# --- constat 6 : git consulte meme quand raw/.gitignore existe deja ---------------


def test_keep_raw_controle_git_quand_le_gitignore_existe_deja(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # sans binaire git : seul le .gitignore ecrit par amnesia (« * ») est reconnu
    monkeypatch.setattr(shutil, "which", lambda nom: None)
    (tmp_path / ".git").mkdir()
    with caplog.at_level(logging.WARNING, logger="amnesia"):
        keep_raw()
    assert "dépôt git" not in caplog.text
    caplog.clear()
    # l'auditeur a retouche raw/.gitignore, jamais reecrit : plus rien n'y est
    # ignore, et un « git add -A » emporterait les sorties brutes
    gitignore = tmp_path / "amnesia-out" / RAW_DIR / ".gitignore"
    gitignore.write_bytes(b"# rien\n")
    with caplog.at_level(logging.WARNING, logger="amnesia"):
        depot = keep_raw()
    assert gitignore.read_bytes() == b"# rien\n"
    messages = [r.getMessage() for r in caplog.records]
    assert [m for m in messages if "sans pouvoir vérifier qu'il y est ignoré" in m]
    (avertissement,) = [m for m in messages if m.startswith("--keep-raw")]
    assert "dépôt git sans y être ignoré" in avertissement
    assert depot.directory.name in avertissement


# --- scripts PowerShell : verdict sur l'inventaire de l'AST ----------------------


def _commande(nom: str, **champs: Any) -> dict[str, Any]:
    element: dict[str, Any] = {
        "kind": "command",
        "name": nom,
        "parameters": [],
        "splat": False,
        "arguments": [],
        "dynamic": False,
        "projection": "none",
        "member": None,
        "next": None,
        "line": 3,
    }
    return element | champs


def _lecture(**champs: Any) -> dict[str, Any]:
    parametres = ["LogName", "MaxEvents", "Oldest"]
    return _commande(
        "Get-WinEvent", parameters=parametres, arguments=["Security"], **champs
    )


def _selection(*noms: str, **champs: Any) -> dict[str, Any]:
    return _commande(
        "Select-Object", parameters=["Property"], arguments=list(noms), **champs
    )


def _propriete(nom: str | None) -> dict[str, Any]:
    return {"kind": "property", "name": nom, "static": False, "line": 3}


def _ecarts(*elements: dict[str, Any]) -> list[str]:
    return check_script_privacy({"errors": [], "items": list(elements)})


def test_script_de_metadonnees_conforme() -> None:
    elements = [
        _commande("Get-WinEvent", parameters=["ListLog"], arguments=["Security"]),
        _commande("Get-WinEvent", parameters=["ListP"], arguments=["*"]),
        _lecture(projection="member", member="TimeCreated"),
        _propriete("TimeCreated"),
        _lecture(projection="pipeline", next=_selection("TimeCreated", "RecordId")),
        _selection("TimeCreated", "RecordId"),
        _propriete("MaximumSizeInBytes"),
        _propriete("RecordCount"),
        {"kind": "method", "name": "ToUniversalTime", "static": False, "line": 3},
        {"kind": "assignment", "target": "VariableExpressionAst", "line": 3},
    ]
    assert _ecarts(*elements) == []
    # le verdict de lecture seule admet la lecture d'une propriete
    inventaire = {"errors": [], "items": [_propriete("TimeCreated")]}
    assert check_script_inventory(inventaire) == []


SANS_PROJECTION = "émis sans projection explicite"
HORS_METADONNEES = "projeté sur autre chose que les métadonnées admises"


@pytest.mark.parametrize(
    ("element", "motif"),
    [
        # critere de #41 : proprietes de contenu d'evenement
        (_propriete("Message"), "propriété de contenu d'événement : .Message"),
        (_propriete("properties"), "propriété de contenu d'événement : .Properties"),
        (_propriete("UserId"), "propriété de contenu d'événement : .UserId"),
        (_propriete("MACHINENAME"), "propriété de contenu d'événement : .MachineName"),
        (_propriete(None), "propriété au nom calculé"),
        (_selection("TimeCreated", "Message"), "nommée en argument : Message"),
        (
            _commande("ForEach-Object", arguments=["machinename"]),
            "nommée en argument : MachineName",
        ),
        (
            {"kind": "method", "name": "ToXml", "static": False, "line": 3},
            "méthode qui rend le contenu d'un événement : .ToXml()",
        ),
        # critere de #41 : resultat de Get-WinEvent sans projection explicite
        (_lecture(), SANS_PROJECTION),
        (_lecture(projection="pipeline"), SANS_PROJECTION),
        (
            _lecture(
                projection="pipeline", next=_commande("ConvertTo-Json", dynamic=True)
            ),
            SANS_PROJECTION,
        ),
        (_lecture(projection="pipeline", next=_selection()), SANS_PROJECTION),
        (_lecture(projection="pipeline", next=_selection("*")), SANS_PROJECTION),
        (_lecture(projection="pipeline", next=_selection("Time*")), SANS_PROJECTION),
        (
            _lecture(projection="pipeline", next=_selection("Id", dynamic=True)),
            SANS_PROJECTION,
        ),
        (
            _lecture(projection="pipeline", next=_selection("Id", splat=True)),
            SANS_PROJECTION,
        ),
        (
            _lecture(
                projection="pipeline",
                next=_commande(
                    "Select-Object", parameters=["ExpandProperty"], arguments=["Id"]
                ),
            ),
            SANS_PROJECTION,
        ),
        (
            _lecture(
                projection="pipeline",
                next=_commande(
                    "Select-Object", parameters=["Property", "First"], arguments=["Id"]
                ),
            ),
            SANS_PROJECTION,
        ),
        (_lecture(projection="inconnue"), SANS_PROJECTION),
        # revue adversariale : liste fermee de metadonnees, pas liste noire.
        # (Get-WinEvent ...).PSObject.BaseObject rend l'evenement entier
        (_lecture(projection="member", member="PSObject"), HORS_METADONNEES),
        (_lecture(projection="member", member="BaseObject"), HORS_METADONNEES),
        (_lecture(projection="member", member="ContainerLog"), HORS_METADONNEES),
        (_lecture(projection="member", member=None), HORS_METADONNEES),
        (_lecture(projection="member", member=""), HORS_METADONNEES),
        (_lecture(projection="member"), HORS_METADONNEES),
        (
            _lecture(projection="pipeline", next=_selection("TimeCreated", "PSObject")),
            HORS_METADONNEES,
        ),
        (
            _lecture(projection="pipeline", next=_selection("ActivityId")),
            HORS_METADONNEES,
        ),
        # -List seul est ambigu : PowerShell le refuse, l'analyse aussi
        (_commande("get-winevent", parameters=["List"]), SANS_PROJECTION),
        (_commande("Get-WinEvent", parameters=None), "élément d'inventaire inconnu"),
        (_commande("Get-Service", arguments=[1]), "élément d'inventaire inconnu"),
    ],
)
def test_ecart_a_la_minimisation_detecte(element: dict[str, Any], motif: str) -> None:
    (ecart,) = _ecarts(element)
    assert ecart.startswith("ligne 3 : ")
    assert motif in ecart


def test_chaque_metadonnee_admise_en_projection() -> None:
    for nom in EVENT_METADATA:
        for forme in (nom, nom.lower(), nom.upper()):
            assert _ecarts(_lecture(projection="member", member=forme)) == []
            suivant = _selection(forme)
            assert _ecarts(_lecture(projection="pipeline", next=suivant)) == []
    # aucune metadonnee admise n'est un champ de contenu d'evenement
    for nom in EVENT_METADATA:
        assert event_content_field(nom) is None


def test_evenement_entier_par_psobject_refuse() -> None:
    # inventaire de « (Get-WinEvent ...).PSObject.BaseObject » : aucune des
    # quatre proprietes interdites n'y figure, le script n'ecrit rien
    inventaire = {
        "errors": [],
        "items": [
            _lecture(projection="member", member="PSObject"),
            _propriete("PSObject"),
            _propriete("BaseObject"),
        ],
    }
    (ecart,) = check_script_privacy(inventaire)
    assert HORS_METADONNEES in ecart
    assert check_script_inventory(inventaire) == []


def test_inventaire_illisible_refuse() -> None:
    assert check_script_privacy({}) == ["inventaire illisible"]
    assert check_script_privacy({"items": ["x"]}) == ["élément d'inventaire inconnu"]


# --- documentation ---------------------------------------------------------------


def test_donnees_md_inventorie_le_schema() -> None:
    # critere de #41 : docs/DONNEES.md existe et le README y renvoie
    doc = DOC.read_text(encoding="utf-8")
    for cle in EVIDENCE_FIELDS:
        assert f"`{cle}`" in doc, cle
    for champ in PERSONAL_FIELDS:
        assert f"`{champ.name}`" in doc, champ.name
    for nom in (*EVENT_PROPERTIES, *EVENT_DATA_FIELDS, *EVENT_METADATA):
        assert f"`{nom}`" in doc, nom
    for colonne in ("Donnée", "Source", "Finalité", "Stockage", "Conservation"):
        assert colonne in doc, colonne
    for article in ("art. 5", "art. 25", "art. 28", "art. 30"):
        assert article in doc, article
    assert "--keep-raw" in doc
    assert "docs/DONNEES.md" in README.read_text(encoding="utf-8")


def test_readme_ne_promet_que_des_configurations_et_des_metadonnees() -> None:
    # critere de #41 : la formulation « pas des données métier » est corrigee
    readme = " ".join(README.read_text(encoding="utf-8").split())
    assert "lit des configurations, pas des données métier" not in readme
    assert (
        "seules des configurations et des métadonnées de journaux sortent de la "
        "cible, jamais le contenu des événements"
    ) in readme
