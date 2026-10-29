"""Journalisation : verbosite, separation stdout/stderr, loggers tiers, expurgation.

Les faux secrets sont assembles a l'execution, pour ne jamais figurer tels quels
dans le depot (gitleaks).
"""

import json
import logging
import os
import stat
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from amnesia import log
from amnesia.cli import build_parser, main

CLE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"
JWT = "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiJhdWRpdCJ9.c2lnbmF0dXJl"


@pytest.fixture(autouse=True)
def journal_propre() -> Iterator[None]:
    """Retire les handlers d'amnesia et restaure les niveaux apres chaque test."""
    noms = ["", log.LOGGER, *log.TIERS]
    niveaux = {nom: logging.getLogger(nom).level for nom in noms}
    yield
    racine = logging.getLogger()
    for handler in log._handlers:
        racine.removeHandler(handler)
        handler.close()
    log._handlers.clear()
    log._secrets.clear()
    for nom, niveau in niveaux.items():
        logging.getLogger(nom).setLevel(niveau)


def _verbosite(argv: list[str]) -> tuple[int, bool]:
    args = build_parser().parse_args(argv)
    return args.verbose, args.quiet


# le registre factice porte un Gap high : « audit » sort en code 1 (#24),
# « list-checks » en 0
CODE_AUDIT_FACTICE = 1


@pytest.mark.usefixtures("registre_factice")
@pytest.mark.parametrize(
    ("argv", "code"),
    [
        (["-v", "audit"], CODE_AUDIT_FACTICE),
        (["audit", "-v"], CODE_AUDIT_FACTICE),
        (["--verbose", "list-checks"], 0),
    ],
)
def test_v_accepte_avant_et_apres_la_sous_commande(argv: list[str], code: int) -> None:
    assert _verbosite(argv) == (1, False)
    assert main(argv) == code
    assert logging.getLogger(log.LOGGER).level == logging.INFO


@pytest.mark.usefixtures("registre_factice")
@pytest.mark.parametrize("argv", [["-vv", "audit"], ["audit", "-vv"]])
def test_vv_donne_debug_pour_amnesia(argv: list[str]) -> None:
    assert main(argv) == CODE_AUDIT_FACTICE
    assert logging.getLogger(log.LOGGER).level == logging.DEBUG
    assert logging.getLogger().level >= logging.WARNING


@pytest.mark.parametrize(
    "argv",
    [
        ["-q", "-v", "audit"],
        ["-q", "audit", "-v"],
        ["-v", "audit", "-q"],
        ["audit", "-q", "--debug"],
    ],
)
def test_q_et_v_incompatibles(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2
    assert "incompatible" in capsys.readouterr().err


@pytest.mark.usefixtures("registre_factice")
@pytest.mark.parametrize("argv", [["-q", "audit"], ["audit", "-q"]])
def test_q_silencieux_sans_erreur(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(argv) == CODE_AUDIT_FACTICE
    logging.getLogger("amnesia.check.win.sysmon").warning("avertissement masque")
    sortie = capsys.readouterr()
    assert sortie.err == ""
    assert "angle mort" in sortie.out


def test_q_laisse_passer_les_erreurs(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["-q", "list-checks"]) == 0
    logging.getLogger("amnesia.check.win.sysmon").error("echec du check")
    assert "echec du check" in capsys.readouterr().err


@pytest.mark.usefixtures("registre_factice")
def test_diagnostics_v_sur_stderr_jamais_sur_stdout(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["-v", "audit"]) == CODE_AUDIT_FACTICE
    logging.getLogger("amnesia.check.win.sysmon").info("diagnostic du check")
    sortie = capsys.readouterr()
    assert "INFO amnesia.cli" in sortie.err
    assert "diagnostic du check" in sortie.err
    assert "INFO" not in sortie.out
    assert "diagnostic" not in sortie.out
    assert "angle mort" in sortie.out


@pytest.mark.usefixtures("registre_factice")
def test_sans_option_pas_de_diagnostic_info(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["audit"]) == CODE_AUDIT_FACTICE
    assert capsys.readouterr().err == ""


def test_debug_ne_touche_ni_la_racine_ni_les_tiers() -> None:
    assert main(["--debug", "list-checks"]) == 0
    assert logging.getLogger(log.LOGGER).level == logging.DEBUG
    assert logging.getLogger().level > logging.DEBUG
    for nom in ("botocore", "boto3", "urllib3", "msal", "spnego", "pypsrp", "azure"):
        assert logging.getLogger(nom).getEffectiveLevel() >= logging.WARNING, nom
        assert logging.getLogger(f"{nom}.enfant").getEffectiveLevel() >= (
            logging.WARNING
        )


def test_requete_botocore_absente_de_toute_sortie(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    journal = tmp_path / "debug.log"
    assert main(["--debug", "--log-file", str(journal), "list-checks"]) == 0
    jeton = "AWS4-HMAC-SHA256 Credential=" + CLE_AWS + "/20261026/eu-west-3/s3"
    logging.getLogger("botocore.endpoint").debug(
        "Making request: headers={'Authorization': %r}", jeton
    )
    sortie = capsys.readouterr()
    assert not [r for r in caplog.records if r.name.startswith("botocore")]
    for texte in (caplog.text, sortie.out, sortie.err, journal.read_text("utf-8")):
        assert "Authorization" not in texte
        assert CLE_AWS not in texte


def test_logger_tiers_remis_en_debug_reste_filtre(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # setLevel(DEBUG) apres coup ; boto3.set_stream_logger, qui pose en plus son
    # propre handler hors filtre, est interdit par ruff (TID251)
    journal = tmp_path / "debug.log"
    assert main(["--debug", "--log-file", str(journal), "list-checks"]) == 0
    endpoint = logging.getLogger("botocore.endpoint")
    endpoint.setLevel(logging.DEBUG)
    try:
        endpoint.debug("headers={'Authorization': 'Bearer %s'}", JWT)
    finally:
        endpoint.setLevel(logging.NOTSET)
    sortie = capsys.readouterr()
    for texte in (sortie.out, sortie.err, journal.read_text("utf-8")):
        assert "Authorization" not in texte
        assert JWT not in texte


@pytest.mark.parametrize(
    ("message", "secret"),
    [
        ("connexion password=" + "hunter2 refusee", "hunter2"),
        ("cle " + CLE_AWS + " rejetee", CLE_AWS),
        ("Authorization: Bearer " + JWT, JWT),
        ("Authorization: Bearer " + "eyJhbGciOi...", "eyJhbGciOi"),
        ("jeton nu " + JWT, JWT),
        ("X-Amz-Security-Token: " + "FwoGZXIvYXdzEJr" + "//tronque", "FwoGZXIvYXdz"),
        ("[('Authorization', 'Basic " + "dXNlcjpQQHNzdzByZA==')]", "dXNlcjpQ"),
        ("[(b'Authorization', b'NTLM " + "TlRMTVNTUAADAAAA')]", "TlRMTVNT"),
        ("('X-Amz-Security-Token', '" + "FwoGZXIvYXdzEJr//x')", "FwoGZXIvYXdz"),
        ("en-tete : Negotiate " + "YIIGhgYJKoZIhvcSAQICAQBu", "YIIGhgYJ"),
        (
            "https://acme.blob.core.windows.net/c?sv=2025&sig=" + "a1b2c3%3D&se=1",
            "a1b2",
        ),
        ("token=" + "s3cr3t-valeur", "s3cr3t"),
        ("client_secret=" + "Zx9~valeur", "Zx9~"),
        ("winrm://audit:" + "P@ss:w0rd@dc01:5986", "P@ss:w0rd"),
        (
            "-----BEGIN " + "PRIVATE KEY-----\nMIIEvQIBADAN\n-----END PRIVATE KEY-----",
            "MIIEvQIBADAN",
        ),
    ],
    ids=[
        "password",
        "cle-aws",
        "bearer-jwt",
        "bearer-tronque",
        "jwt-nu",
        "x-amz-security-token",
        "tuple-basic",
        "tuple-ntlm",
        "tuple-x-amz-security-token",
        "negotiate",
        "sas-azure",
        "token",
        "client-secret",
        "url-winrm",
        "pem",
    ],
)
@pytest.mark.parametrize("log_format", log.FORMATS)
def test_message_expurge(
    message: str, secret: str, log_format: str, capsys: pytest.CaptureFixture[str]
) -> None:
    log.setup_logging(verbosity=1, log_format=log_format)
    logging.getLogger("amnesia.collector.winrm").info(message)
    err = capsys.readouterr().err
    assert secret not in err
    assert log.MASQUE in err


@pytest.mark.parametrize("log_format", log.FORMATS)
def test_secret_enregistre_expurge(
    log_format: str, capsys: pytest.CaptureFixture[str]
) -> None:
    secret = "valeur-" + "tres-privee/+"
    log.register_secret(secret)
    log.setup_logging(verbosity=1, log_format=log_format)
    autre = logging.getLogger("amnesia.collector.graph")
    autre.info("reponse %s", secret)
    autre.info("url ?x=%s", "valeur-tres-privee%2F%2B")
    autre.info("sans rapport", extra={"target": "dc01-" + secret})
    err = capsys.readouterr().err
    assert "tres-privee" not in err
    assert err.count(log.MASQUE) >= 2


def test_message_ordinaire_intact() -> None:
    texte = "check win.sysmon : 3 angles morts sur dc01 en 120 ms"
    assert log.redact(texte) == texte


@pytest.mark.parametrize(
    "texte",
    [
        "a" * 100_000,
        "eyJ-" * 25_000,
        "://a:" * 20_000,
        "authorization" * 8_000,
        "-----BEGIN A" * 10_000,
    ],
    ids=["mot-long", "base64url", "url", "en-tete", "pem"],
)
def test_expurgation_en_temps_lineaire(texte: str) -> None:
    # ReDoS : un blob renvoye par un hote audite ne doit pas figer l'audit
    debut = time.perf_counter()
    log.redact(texte)
    assert time.perf_counter() - debut < 1


@pytest.mark.parametrize("log_format", log.FORMATS)
def test_controles_neutralises(
    log_format: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # OSC 52 (presse-papiers), effacement de ligne et fausse entree de journal
    journal = tmp_path / "x.log"
    log.setup_logging(verbosity=1, log_file=journal, log_format=log_format)
    faux = "\x1b]52;c;cHduZWQ=\x07\x1b[2K\r\n2026-10-26T00:00:00Z INFO amnesia.x: ok"
    logging.getLogger("amnesia.collector.winrm").warning("hote %s", "dc01" + faux)
    logging.getLogger("amnesia.collector.winrm").warning("csi %s", "\x9b2K\u2028")
    for texte in (capsys.readouterr().err, journal.read_text("utf-8")):
        assert len(texte.splitlines()) == 2
        assert not any(c in texte for c in "\x1b\x07\r\x9b\u2028")
        if log_format == "json":
            assert json.loads(texte.splitlines()[0])["msg"] == "hote dc01" + faux


@pytest.mark.parametrize("log_format", log.FORMATS)
def test_nom_de_fichier_non_utf8_journalise(
    log_format: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    journal = tmp_path / "x.log"
    log.setup_logging(verbosity=1, log_file=journal, log_format=log_format)
    # ce que os.fsdecode rend sous POSIX pour b"rapport-\xe9t\xe9.evtx" (octets non
    # UTF-8 en surrogates) ; ecrit tel quel car os.fsdecode est strict sous Windows
    nom = "rapport-\udce9t\udce9.evtx"
    assert sys.platform == "win32" or nom == os.fsdecode(b"rapport-\xe9t\xe9.evtx")
    logging.getLogger("amnesia.collector.local").warning("fichier %s illisible", nom)
    assert "rapport-" in journal.read_text("utf-8")
    assert "Logging error" not in capsys.readouterr().err


def test_traceback_seulement_en_debug_et_expurge(
    capsys: pytest.CaptureFixture[str],
) -> None:
    log.setup_logging(verbosity=1)
    try:
        raise RuntimeError("password=" + "hunter2")
    except RuntimeError:
        logging.getLogger("amnesia.cli").exception("echec")
    assert "Traceback" not in capsys.readouterr().err

    log.setup_logging(debug=True)
    try:
        raise RuntimeError("password=" + "hunter2")
    except RuntimeError:
        logging.getLogger("amnesia.cli").exception("echec")
    err = capsys.readouterr().err
    assert "Traceback" in err
    assert "hunter2" not in err


@pytest.mark.usefixtures("registre_factice")
def test_json_dans_fichier(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    journal = tmp_path / "x.jsonl"
    argv = ["--log-format", "json", "--log-file", str(journal), "-v", "audit"]
    assert main(argv) == CODE_AUDIT_FACTICE
    logging.getLogger("amnesia.check.win.sysmon").info(
        "ligne\nsuivante", extra={"target": "dc01", "duration_ms": 12}
    )
    lignes = journal.read_text("utf-8").splitlines()
    # la commande, le moteur (debut, fin de chaque check...) puis la ligne du test
    assert len(lignes) >= 2
    entrees = [json.loads(ligne) for ligne in lignes]
    for entree in entrees:
        assert {
            "ts",
            "level",
            "logger",
            "check_id",
            "target",
            "duration_ms",
            "msg",
        } <= (entree.keys())
        assert entree["ts"].endswith("+00:00")
    assert entrees[-1]["check_id"] == "win.sysmon"
    assert entrees[-1]["target"] == "dc01"
    assert entrees[-1]["duration_ms"] == 12
    assert entrees[-1]["msg"] == "ligne\nsuivante"
    # le meme journal sur stderr, en JSON aussi ; rien sur stdout
    sortie = capsys.readouterr()
    assert [json.loads(ligne) for ligne in sortie.err.splitlines()] == entrees
    assert "{" not in sortie.out


@pytest.mark.skipif(sys.platform == "win32", reason="droits POSIX")
def test_fichier_de_journal_en_0600(tmp_path: Path) -> None:
    journal = tmp_path / "x.jsonl"
    assert main(["--log-file", str(journal), "list-checks"]) == 0
    assert stat.S_IMODE(journal.stat().st_mode) == 0o600

    # fichier preexistant trop ouvert : droits resserres
    ancien = tmp_path / "ancien.log"
    ancien.write_text("", encoding="utf-8")
    ancien.chmod(0o644)
    assert main(["--log-file", str(ancien), "list-checks"]) == 0
    assert stat.S_IMODE(ancien.stat().st_mode) == 0o600


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="O_NOFOLLOW requis")
def test_lien_symbolique_refuse(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cible = tmp_path / "cible.log"
    cible.write_text("", encoding="utf-8")
    lien = tmp_path / "lien.log"
    lien.symlink_to(cible)
    with pytest.raises(SystemExit) as exc:
        main(["--log-file", str(lien), "list-checks"])
    assert exc.value.code == 2
    assert "--log-file" in capsys.readouterr().err


def test_format_de_journal_inconnu() -> None:
    with pytest.raises(ValueError, match="format"):
        log.setup_logging(log_format="xml")


def test_reconfiguration_sans_doublon(capsys: pytest.CaptureFixture[str]) -> None:
    log.setup_logging(verbosity=1)
    log.setup_logging(verbosity=1)
    logging.getLogger("amnesia").info("une seule fois")
    assert capsys.readouterr().err.count("une seule fois") == 1


def test_loggers_enfants() -> None:
    assert log.check_logger("win.sysmon").name == "amnesia.check.win.sysmon"
    assert log.collector_logger("winrm").name == "amnesia.collector.winrm"
