"""Statuts de resultat des checks : invariants, regle « non evalue », to_dict()."""

from __future__ import annotations

import copy
import dataclasses
import doctest
import json
import pickle
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from amnesia.checks import base
from amnesia.checks.base import (
    CheckResult,
    CheckSkipped,
    ErrorInfo,
    Gap,
    NotApplicable,
    Reason,
    Status,
)

GAP_RDP = Gap(
    question="Qui s'est connecte en RDP sur SRV-FILE il y a trois semaines ?",
    reason="journal Security de 20 Mo, ecrase il y a 4 jours",
    severity="high",
)
ERREUR = ErrorInfo(type="PermissionError", message="Acces refuse")

MOTIFS_SKIPPED = {
    Reason.USER_EXCLUDED,
    Reason.MISSING_PRIVILEGE,
    Reason.NOT_IMPLEMENTED,
    Reason.NOT_COLLECTED,
}
MOTIFS_ERROR = {
    Reason.ACCESS_DENIED,
    Reason.TIMEOUT,
    Reason.UNREACHABLE,
    Reason.INTERNAL_ERROR,
}


def _champs_valides(status: Status) -> dict[str, Any]:
    """Gaps et ErrorInfo exiges par le statut, motif exclu."""
    return {
        "gaps": (GAP_RDP,) if status is Status.GAP else (),
        "error": ERREUR if status is Status.ERROR else None,
    }


def _resultats_valides() -> list[CheckResult]:
    """Un resultat valide par statut sans motif, et un par motif."""
    sans_motif = [
        CheckResult("win.sysmon", "dc01", s, **_champs_valides(s))
        for s in (Status.PASS, Status.GAP, Status.NOT_APPLICABLE)
    ]
    avec_motif = [
        CheckResult(
            "win.sysmon", "dc01", m.status, reason=m, **_champs_valides(m.status)
        )
        for m in Reason
    ]
    return sans_motif + avec_motif


def _id(r: CheckResult) -> str:
    return r.status.value if r.reason is None else f"{r.status.value}-{r.reason.value}"


def test_api_exposee_par_base() -> None:
    for nom in ("Status", "Reason", "CheckResult", "CheckSkipped", "NotApplicable"):
        assert hasattr(base, nom), nom


# --- gap <=> au moins un Gap ------------------------------------------------


def test_pass_avec_un_gap_refuse() -> None:
    with pytest.raises(ValueError, match="statut pass avec 1 Gap"):
        CheckResult("win.sysmon", "dc01", Status.PASS, gaps=(GAP_RDP,))


def test_gap_sans_gap_refuse() -> None:
    with pytest.raises(ValueError, match="statut gap sans aucun Gap"):
        CheckResult("win.sysmon", "dc01", Status.GAP)
    with pytest.raises(ValueError, match="statut gap sans aucun Gap"):
        CheckResult.with_gaps("win.sysmon", "dc01", [])


@pytest.mark.parametrize("resultat", _resultats_valides(), ids=_id)
def test_seul_gap_porte_des_gaps(resultat: CheckResult) -> None:
    if resultat.status is Status.GAP:
        return
    with pytest.raises(ValueError, match="Gap"):
        dataclasses.replace(resultat, gaps=(GAP_RDP,))


# --- motif compatible avec le statut ----------------------------------------


def test_partition_des_motifs() -> None:
    assert {m for m in Reason if m.status is Status.SKIPPED} == MOTIFS_SKIPPED
    assert {m for m in Reason if m.status is Status.ERROR} == MOTIFS_ERROR
    assert set(Reason) == MOTIFS_SKIPPED | MOTIFS_ERROR


@pytest.mark.parametrize(
    ("motif", "statut"),
    [(m, s) for m in Reason for s in Status if s is not m.status],
    ids=lambda v: v.value,
)
def test_motif_incompatible_refuse(motif: Reason, statut: Status) -> None:
    with pytest.raises(ValueError, match="motif"):
        CheckResult(
            "win.sysmon", "dc01", statut, reason=motif, **_champs_valides(statut)
        )


@pytest.mark.parametrize("motif", list(Reason), ids=lambda m: m.value)
def test_motif_compatible_accepte(motif: Reason) -> None:
    r = CheckResult(
        "win.sysmon",
        "dc01",
        motif.status,
        reason=motif,
        **_champs_valides(motif.status),
    )
    assert r.reason is motif


@pytest.mark.parametrize("statut", [Status.ERROR, Status.SKIPPED], ids=str)
def test_error_et_skipped_exigent_un_motif(statut: Status) -> None:
    with pytest.raises(ValueError, match="sans motif"):
        CheckResult("win.sysmon", "dc01", statut, **_champs_valides(statut))


def test_error_exige_une_error_info() -> None:
    with pytest.raises(ValueError, match="sans ErrorInfo"):
        CheckResult("win.sysmon", "dc01", Status.ERROR, reason=Reason.TIMEOUT)


@pytest.mark.parametrize(
    "statut", [s for s in Status if s is not Status.ERROR], ids=str
)
def test_error_info_reservee_au_statut_error(statut: Status) -> None:
    motif = Reason.NOT_COLLECTED if statut is Status.SKIPPED else None
    champs = _champs_valides(statut) | {"error": ERREUR}
    with pytest.raises(ValueError, match="avec une ErrorInfo"):
        CheckResult("win.sysmon", "dc01", statut, reason=motif, **champs)


# --- non evalue n'est jamais conforme ---------------------------------------


@pytest.mark.parametrize("resultat", _resultats_valides(), ids=_id)
def test_verified_et_compliant(resultat: CheckResult) -> None:
    s = resultat.status
    assert resultat.compliant is (s is Status.PASS)
    assert resultat.verified is (s in {Status.PASS, Status.GAP, Status.NOT_APPLICABLE})
    if s in {Status.ERROR, Status.SKIPPED}:
        # user_excluded compris : ni verifie ni conforme, mais compte a part
        assert not resultat.verified
        assert not resultat.compliant
        assert resultat.excluded is (resultat.reason is Reason.USER_EXCLUDED)
        assert resultat.not_evaluated is (resultat.reason is not Reason.USER_EXCLUDED)
    else:
        assert not resultat.excluded
        assert not resultat.not_evaluated


# --- construction et to_dict() par statut -----------------------------------

CAS_PAR_STATUT: list[tuple[Status, Callable[[], CheckResult], dict[str, Any]]] = [
    (
        Status.PASS,
        lambda: CheckResult.passed(
            "win.security_log_size", "dc01", message="4 Go, 120 jours", duration_s=1.5
        ),
        {
            "status": "pass",
            "reason": None,
            "message": "4 Go, 120 jours",
            "gaps": [],
            "error": None,
            "duration_s": 1.5,
        },
    ),
    (
        Status.GAP,
        lambda: CheckResult.with_gaps(
            "win.security_log_size", "dc01", (g for g in [GAP_RDP])
        ),
        {
            "status": "gap",
            "reason": None,
            "message": "",
            "gaps": [
                {
                    "question": GAP_RDP.question,
                    "reason": GAP_RDP.reason,
                    "severity": "high",
                }
            ],
            "error": None,
            "duration_s": None,
        },
    ),
    (
        Status.ERROR,
        lambda: CheckResult.failed(
            "win.security_log_size",
            "dc01",
            Reason.ACCESS_DENIED,
            PermissionError("Acces refuse"),
            duration_s=0,
        ),
        {
            "status": "error",
            "reason": "access_denied",
            "message": "Acces refuse",
            "gaps": [],
            "error": {
                "type": "PermissionError",
                "message": "Acces refuse",
                "traceback": None,
            },
            "duration_s": 0,
        },
    ),
    (
        Status.SKIPPED,
        lambda: CheckResult.skipped(
            "win.security_log_size", "dc01", Reason.NOT_IMPLEMENTED, "run() a ecrire"
        ),
        {
            "status": "skipped",
            "reason": "not_implemented",
            "message": "run() a ecrire",
            "gaps": [],
            "error": None,
            "duration_s": None,
        },
    ),
    (
        Status.NOT_APPLICABLE,
        lambda: CheckResult.not_applicable(
            "win.security_log_size", "dc01", "hote hors perimetre du check"
        ),
        {
            "status": "not_applicable",
            "reason": None,
            "message": "hote hors perimetre du check",
            "gaps": [],
            "error": None,
            "duration_s": None,
        },
    ),
]


def test_un_cas_par_statut() -> None:
    assert [statut for statut, _, _ in CAS_PAR_STATUT] == list(Status)


@pytest.mark.parametrize(
    ("statut", "fabrique", "attendu"),
    CAS_PAR_STATUT,
    ids=[s for s, _, _ in CAS_PAR_STATUT],
)
def test_construction_et_to_dict(
    statut: Status, fabrique: Callable[[], CheckResult], attendu: dict[str, Any]
) -> None:
    r = fabrique()
    assert r.status is statut
    d = r.to_dict()
    assert d == {"check_id": "win.security_log_size", "target": "dc01", **attendu}
    # cles stables, dans un ordre fixe, quel que soit le statut
    assert list(d) == [
        "check_id",
        "target",
        "status",
        "reason",
        "message",
        "gaps",
        "error",
        "duration_s",
    ]
    # enums rendus en vraies chaines : jamais « Status.PASS »
    assert type(d["status"]) is str
    assert d["reason"] is None or type(d["reason"]) is str
    texte = json.dumps(d)
    assert f'"status": "{statut.value}"' in texte
    assert "Status." not in texte
    assert "Reason." not in texte


@pytest.mark.parametrize("valeur", [*Status, *Reason], ids=str)
def test_enums_formates_par_leur_valeur(valeur: Status | Reason) -> None:
    # piege des (str, Enum) : format() donne « Status.PASS » a partir de 3.11
    assert str(valeur) == valeur.value
    assert f"{valeur}" == valeur.value
    assert format(valeur, "") == valeur.value


# --- failed() et ErrorInfo --------------------------------------------------


def test_failed_sans_trace_par_defaut() -> None:
    try:
        raise TimeoutError
    except TimeoutError as exc:
        r = CheckResult.failed("win.time_sync", "dc01", Reason.TIMEOUT, exc)
    assert r.error == ErrorInfo(type="TimeoutError", message="", traceback=None)
    # message vide : le type de l'exception reste lisible
    assert r.message == "TimeoutError"
    assert not r.verified
    assert not r.compliant


def test_failed_avec_trace_et_type_qualifie() -> None:
    try:
        json.loads("{")
    except json.JSONDecodeError as exc:
        r = CheckResult.failed(
            "win.sysmon",
            "dc01",
            Reason.INTERNAL_ERROR,
            exc,
            message="sortie illisible",
            with_traceback=True,
        )
    assert r.message == "sortie illisible"
    assert r.error is not None
    assert r.error.type == "json.decoder.JSONDecodeError"
    assert r.error.traceback is not None
    assert "Traceback" in r.error.traceback


# --- failed() : secrets et texte hostile -------------------------------------

# secret construit a l'execution : jamais en clair dans le source (gitleaks)
MDP = "S3cr3t-" + "Pass!"
ARGV = ["wevtutil", "gl", "Security", "/r:dc01", "/u:CORP\\audit", f"/p:{MDP}"]


def _failed(exc: BaseException, **options: Any) -> CheckResult:
    return CheckResult.failed(
        "win.security_log_size", "dc01", Reason.ACCESS_DENIED, exc, **options
    )


@pytest.mark.parametrize(
    ("exc", "attendu"),
    [
        (subprocess.CalledProcessError(5, ARGV), "commande 'wevtutil' : code 5"),
        (subprocess.TimeoutExpired(ARGV, 30), "commande 'wevtutil' : delai de 30 s"),
        # chaine passee au shell, executable designe par son chemin
        (
            subprocess.CalledProcessError(1, "/usr/bin/" + " ".join(ARGV)),
            "commande 'wevtutil' : code 1",
        ),
    ],
    ids=["CalledProcessError", "TimeoutExpired", "shell"],
)
def test_failed_ne_garde_que_l_executable(exc: BaseException, attendu: str) -> None:
    r = _failed(exc)
    assert r.message == attendu
    assert r.error is not None
    assert r.error.message == attendu
    assert MDP not in json.dumps(r.to_dict())


@pytest.mark.parametrize(
    "texte",
    [
        f"winrm://audit:{MDP}@dc01:5986",
        # « @ » dans le mot de passe ; coupe en deux pour gitleaks
        "ssh://audit:" + f"ab@{MDP}@srv-file/",
        f"wevtutil gl Security /p:{MDP}",
        f"Invoke-Command -Password {MDP}",
        f"connexion --password={MDP}",
        f"password={MDP}",
        f"client_secret: {MDP}",
        f"Authorization: Bearer {MDP}",
    ],
)
def test_failed_caviarde_les_secrets(texte: str) -> None:
    r = _failed(ValueError(f"echec : {texte}"))
    assert MDP not in json.dumps(r.to_dict())
    assert "***" in r.message


@pytest.mark.parametrize("chainage", ["implicite", "explicite", "note"])
def test_trace_sans_exceptions_chainees_ni_notes(chainage: str) -> None:
    try:
        try:
            raise subprocess.CalledProcessError(5, ARGV)
        except subprocess.CalledProcessError as origine:
            erreur = PermissionError("wevtutil : acces refuse")
            if chainage == "explicite":
                raise erreur from origine
            if chainage == "note":
                erreur.add_note(f"cmd: {' '.join(ARGV)}")
            raise erreur  # noqa: B904 - chainage implicite voulu
    except PermissionError as exc:
        r = _failed(exc, with_traceback=True)
    assert r.message == "wevtutil : acces refuse"
    assert r.error is not None
    assert r.error.traceback is not None
    assert 'File "test_resultats_checks.py"' in r.error.traceback
    # ni secret, ni chemin absolu de la machine de l'auditeur
    assert MDP not in json.dumps(r.to_dict())
    assert str(Path(__file__).parent) not in r.error.traceback


def test_failed_quand_str_de_l_exception_leve() -> None:
    class Illisible(Exception):
        def __str__(self) -> str:
            raise RuntimeError("boom")

    r = _failed(Illisible(), with_traceback=True)
    assert r.status is Status.ERROR
    assert r.message == "<message illisible>"
    assert r.error is not None
    assert r.error.type.endswith("Illisible")


def test_failed_neutralise_les_caracteres_de_controle() -> None:
    r = _failed(OSError("\x1b[2J\x1b[31mOK\r\nfake\u202e"))
    assert r.message == "\\x1b[2J\\x1b[31mOK\\r\\nfake\\u202e"
    assert r.message.isprintable()


# --- exceptions levables par un check ----------------------------------------


@pytest.mark.parametrize("motif", sorted(MOTIFS_SKIPPED), ids=str)
def test_check_skipped_accepte_les_motifs_de_skipped(motif: Reason) -> None:
    exc = CheckSkipped(motif, "bundle sans configuration Sysmon")
    assert exc.reason is motif
    assert exc.message == "bundle sans configuration Sysmon"
    for copie in (pickle.loads(pickle.dumps(exc)), copy.copy(exc)):  # noqa: S301
        assert (copie.reason, copie.message) == (exc.reason, exc.message)


@pytest.mark.parametrize("motif", sorted(MOTIFS_ERROR), ids=str)
def test_check_skipped_refuse_les_motifs_d_erreur(motif: Reason) -> None:
    with pytest.raises(ValueError, match="invalide pour CheckSkipped"):
        CheckSkipped(motif, "timeout")


def test_not_applicable() -> None:
    exc = NotApplicable("serveur hors domaine")
    assert exc.message == str(exc) == "serveur hors domaine"
    copie = pickle.loads(pickle.dumps(exc))  # noqa: S301
    assert copie.message == "serveur hors domaine"


# --- types et immuabilite ----------------------------------------------------


def test_resultat_immuable() -> None:
    r = CheckResult.passed("win.sysmon", "dc01")
    with pytest.raises(dataclasses.FrozenInstanceError):
        r.status = Status.GAP  # type: ignore[misc]


@pytest.mark.parametrize(
    ("champs", "exception"),
    [
        ({"check_id": ""}, ValueError),
        ({"target": ""}, ValueError),
        ({"check_id": "win.sysmon\n"}, ValueError),
        ({"target": "dc01\x1b]0;pwn\x07"}, ValueError),
        ({"target": "dc01\u202e"}, ValueError),
        ({"status": "pass"}, TypeError),
        ({"gaps": [GAP_RDP]}, TypeError),
        ({"gaps": ("pas un Gap",)}, TypeError),
        ({"reason": "timeout"}, TypeError),
        ({"message": None}, TypeError),
        ({"duration_s": True}, TypeError),
        ({"duration_s": -1.0}, ValueError),
        ({"duration_s": float("nan")}, ValueError),
        ({"duration_s": float("inf")}, ValueError),
    ],
)
def test_champs_invalides_refuses(
    champs: dict[str, Any], exception: type[Exception]
) -> None:
    valeurs: dict[str, Any] = {
        "check_id": "win.sysmon",
        "target": "dc01",
        "status": Status.GAP,
        "gaps": (GAP_RDP,),
    }
    with pytest.raises(exception):
        CheckResult(**(valeurs | champs))


# --- docstring du module -----------------------------------------------------


@pytest.mark.parametrize("terme", [*Status, *Reason], ids=str)
def test_docstring_definit_chaque_statut_et_motif(terme: Status | Reason) -> None:
    assert base.__doc__ is not None
    lignes = base.__doc__.splitlines()
    debut = lignes.index(terme.value) + 1
    definition = []
    for ligne in lignes[debut:]:
        if not ligne.startswith("    "):
            break
        definition.append(ligne)
    assert definition, terme
    assert "Ex. :" in " ".join(definition), terme


def test_exemple_de_la_docstring() -> None:
    resultat = doctest.testmod(base)
    assert resultat.attempted > 0
    assert resultat.failed == 0
