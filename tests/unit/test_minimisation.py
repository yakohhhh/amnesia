# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Minimisation des donnees collectees (#41) : amnesia.privacy et ses branchements.

Seules des configurations et des metadonnees de journaux sortent de la cible.
Le contenu d'un evenement (compte, adresse IP, poste d'un 4624) n'atteint ni un
fait, ni une preuve, ni le rapport, ni le journal, ni les sorties ; une sortie
brute n'est ecrite sur disque que sur demande (--keep-raw).
"""

from __future__ import annotations

import json
import logging
import stat
import subprocess
import sys
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from amnesia import cli
from amnesia.checks import Check
from amnesia.checks.base import (
    CheckResult,
    Confidence,
    Evidence,
    Gap,
    Severity,
)
from amnesia.checks.context import Context
from amnesia.cli import main
from amnesia.exitcodes import OK
from amnesia.facts import (
    Collector,
    Fact,
    FactSet,
    FactsFormatError,
    FixtureCollector,
    LocalCollector,
    load_facts,
    run_command,
)
from amnesia.output import RAW_DIR, RawStore, keep_raw
from amnesia.privacy import (
    EVENT_DATA_FIELDS,
    EVENT_METADATA,
    EVENT_PROPERTIES,
    EVIDENCE_FIELDS,
    PERSONAL_FIELDS,
    REPORT_TEXT_FIELDS,
    SETTING_MAX_LENGTH,
    check_evidence,
    check_evidence_keys,
    check_script_privacy,
    event_content_field,
    report_text_violations,
)
from amnesia.readonly import check_script_inventory
from amnesia.report import load_schema
from amnesia.target import Target

RACINE = Path(__file__).resolve().parents[2]
EVENEMENT_4624 = RACINE / "tests" / "fixtures" / "facts" / "evenement_4624.json"
DOC = RACINE / "docs" / "DONNEES.md"
README = RACINE / "README.md"
FAIT = "windows.eventlog.oldest:Security"
INSTANT = datetime(2026, 10, 21, 9, 30, tzinfo=UTC)
# valeurs fictives du critere d'acceptation : compte, adresse IP, poste
VALEURS = ("jdupont", "10.1.2.3", "PC-COMPTA")
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
        "settings": ["Logon", "Process Creation"],
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
        depot = keep_raw()
    dossier = tmp_path / "amnesia-out" / RAW_DIR
    assert depot.directory.resolve() == dossier.resolve()
    (avertissement,) = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert "--keep-raw" in avertissement.getMessage()
    assert "données personnelles" in avertissement.getMessage()
    run_command([WEVTUTIL, "gl", "Security"], timeout=5, raw=depot)
    run_command([WEVTUTIL, "gl", "System"], timeout=5, raw=depot)
    fichiers = sorted(f.name for f in dossier.iterdir() if f.name != ".gitignore")
    assert fichiers == ["0001-wevtutil.bin", "0002-wevtutil.bin"]
    assert (dossier / fichiers[0]).read_bytes() == b"sortie brute"
    # ignores par git, comme le rapport
    assert (dossier / ".gitignore").read_bytes() == b"*\n"
    if sys.platform != "win32":
        assert _mode(dossier) == 0o700
        assert _mode(dossier.parent) == 0o700
        assert _mode(dossier / fichiers[0]) == 0o600


@posix
def test_dossier_brut_existant_ramene_en_0700(tmp_path: Path) -> None:
    dossier = tmp_path / "brut"
    dossier.mkdir(mode=0o755)
    dossier.chmod(0o755)
    keep_raw(dossier)
    assert _mode(dossier) == 0o700


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
    dossier = tmp_path / "amnesia-out" / RAW_DIR
    assert dossier.is_dir()
    if sys.platform != "win32":
        assert _mode(dossier) == 0o700
    erreur = capsys.readouterr().err
    assert "--keep-raw" in erreur
    assert "données personnelles" in erreur
    # les sorties brutes n'entrent jamais dans le rapport
    texte = rapport.read_text(encoding="utf-8")
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
