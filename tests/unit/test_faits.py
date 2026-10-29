"""Modele des faits : Fact, FactSet, forme JSON versionnee et JSON Schema."""

from __future__ import annotations

import doctest
import json
import re
from datetime import UTC, datetime, timedelta, timezone
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

from amnesia.facts import (
    FACT_DOMAINS,
    SCHEMA,
    Fact,
    FactSet,
    FactsFormatError,
    FactStatus,
    FixtureCollector,
    UnavailableReason,
    load_facts,
    validate_fact_name,
)
from amnesia.facts import model as module_model
from amnesia.facts.model import FACT_NAME_PATTERN
from amnesia.target import Target

INSTANT = datetime(2026, 10, 21, 9, 30, tzinfo=UTC)
FIXTURES = Path(__file__).parent.parent / "fixtures" / "facts"
SCHEMA_JSON: dict[str, Any] = json.loads(
    files("amnesia").joinpath("schemas/facts-1.schema.json").read_text("utf-8")
)


def _ok(nom: str = "windows.auditpol.backup", valeur: object = None) -> Fact:
    return Fact.ok(nom, valeur, source="auditpol /backup", collected_at=INSTANT)


def _ecrire(tmp_path: Path, donnees: object) -> Path:
    chemin = tmp_path / "faits.json"
    chemin.write_text(json.dumps(donnees), encoding="utf-8")
    return chemin


def test_doctest_du_module() -> None:
    resultat = doctest.testmod(module_model)
    assert resultat.attempted > 0
    assert resultat.failed == 0


@pytest.mark.parametrize(
    "nom",
    [
        "windows.auditpol.backup",
        "windows.eventlog.config:Security",
        "windows.eventlog.config:Microsoft-Windows-Sysmon/Operational",
        "windows.eventlog.config:Windows PowerShell",
        "ad.krbtgt.password_last_set",
        "m365.unified_audit_log.enabled",
        "aws.cloudtrail.trails",
        "siem.forwarding_0",
    ],
)
def test_noms_acceptes(nom: str) -> None:
    assert validate_fact_name(nom) == nom


@pytest.mark.parametrize(
    "nom",
    [
        "",
        "windows",
        "Windows.auditpol",
        "win.auditpol.backup",
        "linux.auditd",
        "windows..auditpol",
        "windows.auditpol.",
        "windows.auditpol.backup\n",
        "windows.eventlog.config:",
        "windows.eventlog.config: Security",
        "windows.eventlog.config:Security ",
        "windows.eventlog.config:Sec\x1b[31m",
        "windows.eventlog.config:Sécurité",
        "windows.eventlog.config:a;b",
        "windows." + "a" * 300,
    ],
)
def test_noms_refuses(nom: str) -> None:
    with pytest.raises(FactsFormatError, match="nom de fait invalide"):
        validate_fact_name(nom)


def test_nom_non_textuel_refuse() -> None:
    with pytest.raises(FactsFormatError, match="chaîne attendue"):
        validate_fact_name(42)


def test_valeur_absente_est_une_observation() -> None:
    # une cle de registre absente est observee : elle peut produire un Gap
    fait = _ok(valeur=None)
    assert fait.status is FactStatus.OK
    assert fait.available
    assert FactSet([fait]).value(fait.name) is None


def test_valeur_figee() -> None:
    brut: dict[str, Any] = {"journaux": ["Security"], "options": {"mode": 1}}
    fait = _ok(valeur=brut)
    brut["journaux"].append("System")
    valeur = fait.value
    assert not isinstance(valeur, dict)
    assert fait.to_dict()["value"] == {"journaux": ["Security"], "options": {"mode": 1}}
    with pytest.raises(TypeError):
        valeur["intrus"] = 1  # type: ignore[index]


def test_horodatage_ramene_en_utc() -> None:
    paris = timezone(timedelta(hours=2))
    fait = Fact.ok(
        "windows.auditpol.backup",
        1,
        source="auditpol /backup",
        collected_at=datetime(2026, 10, 21, 11, 30, tzinfo=paris),
    )
    assert fait.collected_at == INSTANT
    assert fait.collected_at.tzinfo is UTC
    assert fait.to_dict()["collected_at"] == "2026-10-21T09:30:00Z"


@pytest.mark.parametrize(
    ("champs", "motif"),
    [
        ({"status": "ok"}, "status invalide"),
        (
            {"unavailable_reason": UnavailableReason.TIMEOUT},
            "fait ok avec un motif",
        ),
        ({"status": FactStatus.UNAVAILABLE}, "sans motif"),
        (
            {
                "status": FactStatus.UNAVAILABLE,
                "unavailable_reason": UnavailableReason.TIMEOUT,
                "value": 3,
            },
            "indisponible avec valeur",
        ),
        ({"unavailable_reason": "timeout"}, "unavailable_reason invalide"),
        ({"source": ""}, "source vide"),
        ({"source": "auditpol\n/backup"}, "source non imprimable"),
        ({"collected_at": "2026-10-21"}, "doit être un datetime"),
        ({"collected_at": datetime(2026, 10, 21, 9, 30)}, "sans fuseau"),  # noqa: DTZ001
        ({"value": float("nan")}, "non fini"),
        ({"value": {1: "a"}}, "clé non textuelle"),
        ({"value": {"a": object()}}, "type non JSON"),
    ],
)
def test_fait_invalide(champs: dict[str, Any], motif: str) -> None:
    valeurs: dict[str, Any] = {
        "name": "windows.auditpol.backup",
        "status": FactStatus.OK,
        "value": None,
        "unavailable_reason": None,
        "source": "auditpol /backup",
        "collected_at": INSTANT,
    }
    valeurs.update(champs)
    with pytest.raises(FactsFormatError, match=motif):
        Fact(**valeurs)


def test_valeur_trop_imbriquee() -> None:
    valeur: object = 1
    for _ in range(40):
        valeur = [valeur]
    with pytest.raises(FactsFormatError, match="trop imbriquée"):
        _ok(valeur=valeur)


def test_factset_mapping_et_doublon() -> None:
    a = _ok("windows.auditpol.backup", 1)
    b = _ok("windows.w32time.config", {"type": "NTP"})
    faits = FactSet([a, b])
    assert len(faits) == 2
    assert list(faits) == [a.name, b.name]
    assert faits["windows.w32time.config"] is b
    assert "ad.x" not in faits
    assert faits.subset(["windows.w32time.config", "ad.x"]) == FactSet([b])
    assert faits != {"x": 1}
    assert "windows.auditpol.backup" in repr(faits)
    with pytest.raises(FactsFormatError, match="en double"):
        FactSet([a, a])
    with pytest.raises(TypeError, match="Fact attendu"):
        FactSet(["windows.auditpol.backup"])  # type: ignore[list-item]


def test_value_d_un_fait_indisponible_ou_absent() -> None:
    indisponible = Fact.unavailable(
        "windows.auditpol.backup",
        UnavailableReason.ACCESS_DENIED,
        source="auditpol /backup",
        collected_at=INSTANT,
    )
    faits = FactSet([indisponible])
    assert not indisponible.available
    with pytest.raises(KeyError):
        faits.value("windows.auditpol.backup")
    with pytest.raises(KeyError):
        faits.value("windows.sysmon.service")


def test_aller_retour_json() -> None:
    faits = load_facts(FIXTURES / "exemple.json")
    assert FactSet.from_dict(json.loads(json.dumps(faits.to_dict()))) == faits
    assert faits.to_dict()["schema"] == SCHEMA


def test_fixture_collector_charge_un_fichier_conforme() -> None:
    collecteur = FixtureCollector(FIXTURES / "exemple.json")
    faits = collecteur.collect(
        Target.parse("local"),
        ["windows.eventlog.config:Security", "windows.sysmon.service"],
        timeout=30,
    )
    assert list(faits) == ["windows.eventlog.config:Security"]
    securite = faits["windows.eventlog.config:Security"]
    assert securite.collected_at == INSTANT
    assert faits.value(securite.name) == {
        "max_size_bytes": 20971520,
        "retention": "overwrite",
    }


def test_fixture_collector_rejette_un_schema_inconnu(tmp_path: Path) -> None:
    chemin = _ecrire(tmp_path, {"schema": "amnesia.facts/99", "facts": {}})
    with pytest.raises(FactsFormatError) as erreur:
        FixtureCollector(chemin)
    message = str(erreur.value)
    assert "faits.json" in message
    assert "version de schéma de faits inconnue : 'amnesia.facts/99'" in message
    assert f"version prise en charge : {SCHEMA}" in message


@pytest.mark.parametrize(
    ("contenu", "motif"),
    [
        ("{", "JSON invalide"),
        ('{"schema": "amnesia.facts/1", "schema": "x", "facts": {}}', "en double"),
        ('{"schema": "amnesia.facts/1", "facts": {"windows.a": NaN}}', "NaN"),
        ("[]", "objet JSON attendu"),
        ('{"facts": {}}', "sans champ schema"),
        ('{"schema": "amnesia.facts/1"}', "facts"),
        ('{"schema": "amnesia.facts/1", "facts": {}, "x": 1}', "inconnu"),
        ('{"schema": "amnesia.facts/1", "facts": {"windows.a": 1}}', "objet JSON"),
        ('{"schema": "amnesia.facts/1", "facts": {"windows.a": {}}}', "manquant"),
    ],
)
def test_fichier_de_faits_invalide(tmp_path: Path, contenu: str, motif: str) -> None:
    chemin = tmp_path / "faits.json"
    chemin.write_text(contenu, encoding="utf-8")
    with pytest.raises(FactsFormatError, match=motif):
        load_facts(chemin)


def _fait_json(**champs: object) -> dict[str, object]:
    fait: dict[str, object] = {
        "status": "ok",
        "value": 1,
        "source": "auditpol /backup",
        "collected_at": "2026-10-21T09:30:00Z",
    }
    fait.update(champs)
    return {"schema": SCHEMA, "facts": {"windows.auditpol.backup": fait}}


@pytest.mark.parametrize(
    ("champs", "motif"),
    [
        ({"status": "absent"}, "absent"),
        ({"status": "unavailable", "unavailable_reason": "panne"}, "panne"),
        ({"intrus": 1}, "inconnu"),
        ({"collected_at": 1}, "doit être une chaîne"),
        ({"collected_at": "hier"}, "ISO 8601"),
        ({"collected_at": "2026-10-21T09:30:00"}, "sans fuseau"),
        ({"status": "unavailable", "value": None}, "sans motif"),
    ],
)
def test_fait_json_invalide(champs: dict[str, object], motif: str) -> None:
    with pytest.raises(FactsFormatError, match=motif):
        FactSet.from_dict(_fait_json(**champs))


def test_fait_json_indisponible() -> None:
    faits = FactSet.from_dict(
        _fait_json(status="unavailable", value=None, unavailable_reason="timeout")
    )
    fait = faits["windows.auditpol.backup"]
    assert fait.unavailable_reason is UnavailableReason.TIMEOUT
    assert fait.to_dict()["unavailable_reason"] == "timeout"


# --- JSON Schema : concordance avec le modele Python ------------------------


def test_json_schema_version_et_statuts() -> None:
    proprietes = SCHEMA_JSON["properties"]
    assert SCHEMA_JSON["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert proprietes["schema"]["const"] == SCHEMA
    fait = SCHEMA_JSON["$defs"]["fact"]
    assert fait["properties"]["status"]["enum"] == [s.value for s in FactStatus]
    motifs = fait["properties"]["unavailable_reason"]["enum"]
    assert motifs == [None, *(m.value for m in UnavailableReason)]
    assert set(fait["required"]) | {"unavailable_reason"} == set(fait["properties"])


def test_json_schema_motif_des_noms() -> None:
    noms = SCHEMA_JSON["properties"]["facts"]["propertyNames"]
    # JSON Schema n'ancre pas ses motifs : ^...$ equivaut a fullmatch ici
    assert noms["pattern"] == f"^{FACT_NAME_PATTERN}$"
    assert all(d in noms["pattern"] for d in FACT_DOMAINS)
    assert re.fullmatch(FACT_NAME_PATTERN, "windows.eventlog.config:Security")


def test_fixtures_conformes_au_modele() -> None:
    fichiers = sorted(FIXTURES.glob("*.json"))
    assert fichiers
    for chemin in fichiers:
        brut = json.loads(chemin.read_text(encoding="utf-8"))
        assert brut["schema"] == SCHEMA, chemin.name
        assert len(load_facts(chemin)) == len(brut["facts"]), chemin.name
