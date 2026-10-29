"""Modele Gap v1 : severite typee, preuve, references, empreinte, to_dict()."""

from __future__ import annotations

import copy
import dataclasses
import json
import pickle
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from enum import IntEnum
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from amnesia.checks.base import (
    JSON,
    CheckResult,
    Confidence,
    Evidence,
    Gap,
    Reference,
    ReferenceKind,
    Severity,
)

GRILLE = Path(__file__).resolve().parents[2] / "docs" / "severite.md"
VALEURS = "critical, high, medium, low, info"
EMPREINTE = re.compile(r"[0-9a-f]{64}")


def _preuve(**champs: Any) -> Evidence:
    valeurs: dict[str, Any] = {
        "observed": 4,
        "expected": 90,
        "unit": "days",
        "observed_window_days": 4,
        "required_window_days": 90,
        "confidence": Confidence.MEASURED,
        "source": "Get-WinEvent -LogName Security -Oldest -MaxEvents 1",
    }
    return Evidence(**(valeurs | champs))


def _gap(**champs: Any) -> Gap:
    valeurs: dict[str, Any] = {
        "check_id": "win.security_log_size",
        "target": "winrm://srv-file",
        "resource": "Security",
        "question": "Qui s'est connecte en RDP sur SRV-FILE il y a trois semaines ?",
        "reason": "Le journal Security fait 20 Mo et a ete ecrase il y a 4 jours.",
        "severity": Severity.HIGH,
        "evidence": _preuve(),
        "remediation": "Porter le journal Security a 4 Go au moins.",
    }
    return Gap(**(valeurs | champs))


def _gap_complet() -> Gap:
    """Gap dont chaque champ est renseigne, preuve imbriquee comprise."""
    return _gap(
        question_id="Q-RDP-001",
        evidence=_preuve(
            observed=[20971520, "Circular"],
            expected={"max_size_bytes": 4294967296, "log_mode": "Circular"},
            confidence="estimated",
            details={
                "max_size_bytes": 20971520,
                "log_mode": "Circular",
                # 11:30 a Paris (UTC+2) : 09:30 UTC
                "oldest_event_utc": datetime(
                    2026, 10, 17, 11, 30, tzinfo=timezone(timedelta(hours=2))
                ),
                "canaux": ["Security", {"nom": "System", "taille_mo": 20.5}],
                "absent": None,
                "archivage": False,
            },
        ),
        remediation_id="REM-LOG-SIZE",
        references=(
            Reference(
                ReferenceKind.ATTACK,
                "T1021.001",
                url="https://attack.mitre.org/techniques/T1021/001/",
                version="v20",
            ),
            Reference(ReferenceKind.ATTACK, "DC0067", version="v20"),
            Reference(ReferenceKind.ANSSI, "journalisation-windows"),
            Reference(
                ReferenceKind.MICROSOFT,
                "4624",
                url="https://learn.microsoft.com/fr-fr/",
            ),
            Reference(ReferenceKind.CIS, "18.9.27.2.1"),
            Reference(ReferenceKind.OTHER, "note-interne"),
        ),
        compromise_indicator=True,
    )


# --- Severity ----------------------------------------------------------------


def test_severite_inconnue_liste_les_cinq_valeurs() -> None:
    with pytest.raises(ValueError, match="hihg") as erreur:
        _gap(severity="hihg")
    assert VALEURS in str(erreur.value)
    with pytest.raises(ValueError, match=VALEURS):
        Severity.parse("hihg")


def test_severite_en_chaine_convertie() -> None:
    assert _gap(severity="high").severity is Severity.HIGH
    for niveau in Severity:
        assert Severity.parse(niveau.value) is niveau
        assert Severity.parse(niveau) is niveau


@pytest.mark.parametrize("valeur", ["HIGH", " high", "", "moyenne"])
def test_severite_stricte(valeur: str) -> None:
    with pytest.raises(ValueError, match=VALEURS):
        Severity.parse(valeur)


def test_severite_non_textuelle_refusee() -> None:
    with pytest.raises(TypeError, match="severity"):
        Severity.parse(3)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="severity"):
        _gap(severity=None)


def test_ordre_des_severites_par_rang() -> None:
    assert Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    # l'ordre alphabetique des valeurs donnerait l'inverse
    assert not ("medium" < "high" < "critical")
    assert sorted(Severity) == [
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]
    assert [s.rank for s in sorted(Severity)] == [0, 1, 2, 3, 4]
    assert max(Severity) is Severity.CRITICAL
    assert min(Severity) is Severity.INFO
    assert Severity.HIGH <= Severity.HIGH
    assert Severity.HIGH >= Severity.LOW
    assert Severity.LOW > Severity.INFO


@pytest.mark.parametrize("autre", ["medium", 2, None])
def test_severite_comparee_a_autre_chose_refusee(autre: Any) -> None:
    # jamais de repli silencieux sur l'ordre alphabetique de str, dans un sens
    # comme dans l'autre (operateur reflechi)
    haut = Severity.HIGH
    comparaisons: list[Callable[[], bool]] = [
        lambda: haut < autre,
        lambda: haut <= autre,
        lambda: haut > autre,
        lambda: haut >= autre,
        lambda: autre < haut,
        lambda: autre >= haut,
    ]
    for comparaison in comparaisons:
        with pytest.raises(TypeError, match=r"Severity\.parse"):
            comparaison()


def test_severite_egale_a_sa_valeur() -> None:
    valeur: str = "high"
    assert valeur == Severity.HIGH
    assert str(Severity.HIGH) == "high"
    assert f"{Severity.CRITICAL}" == "critical"


# --- tri canonique -------------------------------------------------------------


def test_tri_canonique() -> None:
    attendus = [
        _gap(severity="critical", question="Z ?", target="winrm://b"),
        _gap(severity="high", question="A ?", target="winrm://b"),
        _gap(severity="high", question="B ?", target="winrm://a"),
        _gap(severity="high", question="B ?", target="winrm://b"),
        _gap(severity="medium", question="A ?", target="winrm://a"),
        _gap(severity="low", question="A ?", target="winrm://a"),
        _gap(severity="info", question="A ?", target="winrm://a"),
    ]
    for melange in (list(reversed(attendus)), attendus[3:] + attendus[:3]):
        assert sorted(melange) == attendus
    assert [g.severity.value for g in attendus] == [
        "critical",
        "high",
        "high",
        "high",
        "medium",
        "low",
        "info",
    ]


def test_tri_alphabetique_sans_accents_ni_casse() -> None:
    qui = _gap(question="Qui s'est connecte ?")
    etait = _gap(question="Était-il administrateur ?")
    adresse = _gap(question="adresse source ?")
    assert sorted([qui, etait, adresse]) == [adresse, etait, qui]


def test_tri_deterministe_entre_ex_aequo() -> None:
    a = _gap(resource="Security")
    b = _gap(resource="System")
    assert sorted([b, a]) == sorted([a, b]) == [a, b]


def test_gap_compare_a_autre_chose_refuse() -> None:
    with pytest.raises(TypeError):
        _ = _gap() < "gap"


# --- to_dict / from_dict -------------------------------------------------------


def test_aller_retour_complet() -> None:
    g = _gap_complet()
    d = g.to_dict()
    assert Gap.from_dict(d) == g
    texte = json.dumps(d, ensure_ascii=False)
    assert Gap.from_dict(json.loads(texte)) == g
    # enums rendus en vraies chaines
    assert '"severity": "high"' in texte
    assert '"confidence": "estimated"' in texte
    assert "Severity." not in texte
    assert "Confidence." not in texte


def test_to_dict_cles_stables() -> None:
    d = _gap().to_dict()
    assert list(d) == [
        "fingerprint",
        "check_id",
        "target",
        "resource",
        "question_id",
        "question",
        "reason",
        "severity",
        "evidence",
        "remediation",
        "remediation_id",
        "references",
        "compromise_indicator",
    ]
    assert list(d["evidence"]) == [
        "observed",
        "expected",
        "unit",
        "observed_window_days",
        "required_window_days",
        "confidence",
        "source",
        "details",
    ]
    assert d["question_id"] is None
    assert d["references"] == []
    assert d["compromise_indicator"] is False
    assert type(d["severity"]) is str
    assert type(d["evidence"]["confidence"]) is str


def test_to_dict_preuve_et_references() -> None:
    d = _gap_complet().to_dict()
    assert d["evidence"]["observed"] == [20971520, "Circular"]
    assert d["evidence"]["details"]["canaux"] == [
        "Security",
        {"nom": "System", "taille_mo": 20.5},
    ]
    assert d["references"][0] == {
        "kind": "attack",
        "id": "T1021.001",
        "version": "v20",
        "url": "https://attack.mitre.org/techniques/T1021/001/",
    }
    assert d["fingerprint"] == _gap_complet().fingerprint


def test_from_dict_champs_facultatifs_absents() -> None:
    d = _gap().to_dict()
    for cle in ("fingerprint", "question_id", "remediation_id", "references"):
        del d[cle]
    del d["evidence"]["details"]
    assert Gap.from_dict(d) == _gap()


def test_from_dict_cle_inconnue_refusee() -> None:
    d = _gap().to_dict()
    d["score"] = 12
    with pytest.raises(ValueError, match="'score'"):
        Gap.from_dict(d)
    d = _gap().to_dict()
    d["evidence"]["brut"] = "x"
    with pytest.raises(ValueError, match="'brut'"):
        Gap.from_dict(d)


def test_from_dict_cle_manquante_refusee() -> None:
    d = _gap().to_dict()
    del d["severity"]
    with pytest.raises(ValueError, match="severity"):
        Gap.from_dict(d)


def test_from_dict_empreinte_alteree_refusee() -> None:
    d = _gap().to_dict()
    d["target"] = "winrm://autre"
    with pytest.raises(ValueError, match="fingerprint"):
        Gap.from_dict(d)


@pytest.mark.parametrize(
    "modification",
    [
        {"severity": "hihg"},
        {"evidence": "pas un dict"},
        {"references": "attack"},
        {"references": [{"kind": "attack", "id": "DS0028", "version": "v18"}]},
    ],
)
def test_from_dict_donnees_invalides(modification: dict[str, Any]) -> None:
    d = _gap().to_dict() | modification
    with pytest.raises((ValueError, TypeError)):
        Gap.from_dict(d)


def test_from_dict_exige_un_dictionnaire() -> None:
    with pytest.raises(TypeError, match="dictionnaire"):
        Gap.from_dict(["pas", "un", "dict"])  # type: ignore[arg-type]


# --- Evidence : contenu serialisable et fige ------------------------------------


@pytest.mark.parametrize(
    "champs",
    [
        {"observed": object()},
        {"expected": {1, 2}},
        {"details": {"brut": object()}},
        {"details": {"liste": [1, object()]}},
        {"details": {"octets": b"\x00"}},
        {"details": {"jour": datetime(2026, 10, 17, tzinfo=UTC).date()}},
        {"details": {1: "cle entiere"}},
        {"details": ["pas", "un", "dict"]},
    ],
)
def test_preuve_non_serialisable_refusee(champs: dict[str, Any]) -> None:
    with pytest.raises(TypeError):
        _preuve(**champs)


def test_preuve_avec_object_refusee() -> None:
    with pytest.raises(TypeError, match="non sérialisable"):
        _preuve(details={"brut": object()})


@pytest.mark.parametrize("valeur", [float("nan"), float("inf"), -float("inf")])
def test_flottant_non_fini_refuse(valeur: float) -> None:
    with pytest.raises(ValueError, match="non fini"):
        _preuve(observed=valeur)


def test_datetime_converti_en_iso_utc() -> None:
    paris = timezone(timedelta(hours=2))
    preuve = _preuve(
        observed=datetime(2026, 10, 17, 11, 30, tzinfo=paris),
        details={"oldest_event_utc": datetime(2026, 10, 17, 9, 30, 0, 5, tzinfo=UTC)},
    )
    assert preuve.observed == "2026-10-17T09:30:00Z"
    assert preuve.details["oldest_event_utc"] == "2026-10-17T09:30:00.000005Z"
    assert json.dumps(preuve.to_dict())
    assert datetime.fromisoformat("2026-10-17T09:30:00Z") == datetime(
        2026, 10, 17, 9, 30, tzinfo=UTC
    )


def test_datetime_sans_fuseau_refuse() -> None:
    with pytest.raises(ValueError, match="fuseau"):
        _preuve(details={"oldest_event_utc": datetime(2026, 10, 17, 9, 30)})  # noqa: DTZ001


def test_sous_classes_ramenees_au_type_de_base() -> None:
    class Niveau(IntEnum):
        HAUT = 3

    preuve = _preuve(observed=Severity.HIGH, expected=Niveau.HAUT)
    assert type(preuve.observed) is str
    assert type(preuve.expected) is int
    assert json.dumps(preuve.to_dict())


def test_preuve_trop_imbriquee_refusee() -> None:
    imbrique: list[Any] = []
    courant = imbrique
    for _ in range(100):
        courant.append([])
        courant = courant[0]
    with pytest.raises(ValueError, match="imbriquée"):
        _preuve(details={"profond": imbrique})


def test_preuve_figee() -> None:
    details: dict[str, Any] = {"max_size_bytes": 20971520, "canaux": ["Security"]}
    preuve = _preuve(details=details)
    # la preuve ne suit pas les modifications ulterieures de l'appelant
    details["max_size_bytes"] = 0
    details["canaux"].append("System")
    assert preuve.details["max_size_bytes"] == 20971520
    assert preuve.details["canaux"] == ("Security",)
    assert len(preuve.details) == 2
    assert (
        repr(preuve.details) == "{'max_size_bytes': 20971520, 'canaux': ('Security',)}"
    )
    with pytest.raises(TypeError):
        preuve.details["max_size_bytes"] = 0  # type: ignore[index]
    with pytest.raises(dataclasses.FrozenInstanceError):
        preuve.observed = 5  # type: ignore[misc]


@pytest.mark.parametrize(
    ("champs", "exception"),
    [
        ({"observed_window_days": -1}, ValueError),
        ({"required_window_days": float("nan")}, ValueError),
        ({"observed_window_days": True}, TypeError),
        ({"observed_window_days": "4"}, TypeError),
        ({"confidence": "sure"}, ValueError),
        ({"confidence": None}, TypeError),
        ({"source": ""}, ValueError),
        ({"source": "wevtutil\x1b[2J"}, ValueError),
        ({"unit": ""}, ValueError),
        ({"unit": 3}, TypeError),
    ],
)
def test_preuve_champs_invalides(
    champs: dict[str, Any], exception: type[Exception]
) -> None:
    with pytest.raises(exception):
        _preuve(**champs)


def test_preuve_minimale() -> None:
    preuve = Evidence(
        observed=False,
        expected=True,
        confidence=Confidence.ASSUMED,
        source="Get-Service Sysmon64",
    )
    assert preuve.unit is None
    assert preuve.observed_window_days is None
    assert preuve.details == {}
    assert Evidence.from_dict(preuve.to_dict()) == preuve


def test_confiance_en_chaine_convertie() -> None:
    assert _preuve(confidence="assumed").confidence is Confidence.ASSUMED
    with pytest.raises(ValueError, match="measured, estimated, assumed"):
        _preuve(confidence="sure")


# valeurs JSON arbitraires (sans NaN ni infini, hors JSON)
VALEURS_JSON: st.SearchStrategy[JSON] = st.recursive(
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(),
    lambda enfants: (
        st.lists(enfants, max_size=4) | st.dictionaries(st.text(), enfants, max_size=4)
    ),
    max_leaves=10,
)


@given(observe=VALEURS_JSON, details=st.dictionaries(st.text(), VALEURS_JSON))
def test_aller_retour_de_toute_preuve_json(
    observe: JSON, details: dict[str, JSON]
) -> None:
    g = _gap(evidence=_preuve(observed=observe, details=details))
    texte = json.dumps(g.to_dict())
    assert Gap.from_dict(json.loads(texte)) == g
    assert Gap.from_dict(g.to_dict()) == g


# --- empreinte -----------------------------------------------------------------


def test_empreinte_independante_du_texte() -> None:
    a = _gap()
    b = _gap(reason="Autre formulation de la raison.")
    assert a.fingerprint == b.fingerprint
    assert EMPREINTE.fullmatch(a.fingerprint)
    # ni la severite, ni la question, ni la preuve n'y entrent
    c = _gap(severity="low", question="Autre ?", evidence=_preuve(observed=1))
    assert c.fingerprint == a.fingerprint


@pytest.mark.parametrize(
    "champs",
    [
        {"target": "winrm://srv-file2"},
        {"resource": "System"},
        {"check_id": "win.sysmon"},
        {"question_id": "Q-RDP-001"},
    ],
)
def test_empreinte_change_avec_l_identite(champs: dict[str, Any]) -> None:
    assert _gap(**champs).fingerprint != _gap().fingerprint


def test_empreinte_sans_ambiguite_de_separateur() -> None:
    a = _gap(target="winrm://a", resource="b|c")
    b = _gap(target="winrm://a|b", resource="c")
    assert a.fingerprint != b.fingerprint


# --- validation du Gap ---------------------------------------------------------


@pytest.mark.parametrize(
    ("champs", "exception"),
    [
        ({"check_id": ""}, ValueError),
        ({"target": "srv\n"}, ValueError),
        ({"resource": "Security\u202e"}, ValueError),
        ({"resource": None}, TypeError),
        ({"question_id": ""}, ValueError),
        ({"remediation_id": "\x1b[31m"}, ValueError),
        ({"question": "   "}, ValueError),
        ({"reason": None}, TypeError),
        ({"remediation": ""}, ValueError),
        ({"evidence": {"observed": 4}}, TypeError),
        ({"references": [Reference(ReferenceKind.CIS, "1.1")]}, TypeError),
        ({"references": ("T1021.001",)}, TypeError),
        ({"compromise_indicator": 1}, TypeError),
    ],
)
def test_gap_champs_invalides(
    champs: dict[str, Any], exception: type[Exception]
) -> None:
    with pytest.raises(exception):
        _gap(**champs)


def test_gap_par_mot_cle_uniquement() -> None:
    with pytest.raises(TypeError):
        Gap("win.sysmon", "local")  # type: ignore[call-arg]


def test_gap_fige_hachable_picklable() -> None:
    g = _gap_complet()
    with pytest.raises(dataclasses.FrozenInstanceError):
        g.severity = Severity.LOW  # type: ignore[misc]
    assert len({g, _gap_complet()}) == 1
    assert pickle.loads(pickle.dumps(g)) == g  # noqa: S301 - donnees du test
    assert copy.deepcopy(g) == g


# --- Reference -----------------------------------------------------------------


def test_reference_attack() -> None:
    ref = Reference(ReferenceKind.ATTACK, "T1021.001", version="v20")
    assert ref.kind is ReferenceKind.ATTACK
    assert Reference.from_dict(ref.to_dict()) == ref


def test_data_source_attack_refusee() -> None:
    with pytest.raises(ValueError, match="dépréciées depuis la v18"):
        Reference(ReferenceKind.ATTACK, "DS0028", version="v20")


@pytest.mark.parametrize("identifiant", ["T1021.1", "t1021", "TA0008", "DC67"])
def test_identifiant_attack_invalide(identifiant: str) -> None:
    with pytest.raises(ValueError, match="ATT&CK invalide"):
        Reference(ReferenceKind.ATTACK, identifiant, version="v20")


def test_version_attack_obligatoire() -> None:
    with pytest.raises(ValueError, match="version ATT&CK obligatoire"):
        Reference(ReferenceKind.ATTACK, "T1021.001")
    # facultative pour les autres referentiels
    assert Reference(ReferenceKind.CIS, "18.9.27.2.1").version is None


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",
        "http://attack.mitre.org/",
        "https://",
        "https://audit:secret@exemple.invalid/",
        "https://attack.mitre.org\\@exemple.invalid/",
        "https://exemple.invalid/a b",
        "https://exemple.invalid/\u202e",
    ],
)
def test_url_refusee(url: str) -> None:
    with pytest.raises(ValueError, match="url invalide"):
        Reference(ReferenceKind.OTHER, "x", url=url)


def test_url_non_textuelle_refusee() -> None:
    with pytest.raises(TypeError, match="url"):
        Reference(ReferenceKind.OTHER, "x", url=3)  # type: ignore[arg-type]


def test_type_de_reference_en_chaine() -> None:
    ref = Reference("attack", "T1021", version="v20")  # type: ignore[arg-type]
    assert ref.kind is ReferenceKind.ATTACK
    with pytest.raises(ValueError, match="attack, anssi, microsoft, cis, other"):
        Reference("nist", "800-92")  # type: ignore[arg-type]


# --- rattachement a un CheckResult ---------------------------------------------


def test_check_result_porte_les_gaps_de_son_check_et_de_sa_cible() -> None:
    g = _gap()
    r = CheckResult.with_gaps(g.check_id, g.target, [g])
    assert r.to_dict()["gaps"] == [g.to_dict()]
    with pytest.raises(ValueError, match=r"win\.security_log_size"):
        CheckResult.with_gaps("win.sysmon", g.target, [g])
    with pytest.raises(ValueError, match="winrm://srv-file"):
        CheckResult.with_gaps(g.check_id, "local", [g])


# --- documentation -------------------------------------------------------------


def test_docstring_reprend_l_exemple_du_readme() -> None:
    assert Gap.__doc__ is not None
    for fragment in (
        "RDP sur SRV-FILE",
        "20 Mo",
        "4 jours",
        "evidence=Evidence(",
        "expected=",
        "remediation=",
        "references=",
    ):
        assert fragment in Gap.__doc__, fragment


def test_grille_de_severite_documentee() -> None:
    texte = GRILLE.read_text(encoding="utf-8")
    sections = {
        entete.partition("\n")[0]: entete.partition("\n")[2]
        for entete in re.split(r"^## ", texte, flags=re.MULTILINE)[1:]
    }
    for niveau in Severity:
        titres = [t for t in sections if t.startswith(f"`{niveau.value}`")]
        assert len(titres) == 1, niveau
        corps = sections[titres[0]]
        assert "Ex. :" in corps, niveau
