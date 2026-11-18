# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Secrets et CLI : aucune option à valeur secrète, sources, fuites (#38)."""

from __future__ import annotations

import argparse
import getpass
import io
import json
import logging
import os
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest

from amnesia import cli, log, secrets
from amnesia.checks.base import Check, CheckResult
from amnesia.checks.context import Context
from amnesia.cli import ENV_MOT_DE_PASSE_WINRM, build_parser, main
from amnesia.exitcodes import FATAL, USAGE
from amnesia.facts import FactSet
from amnesia.report import redact_argv
from amnesia.target import Target, Transport

# valeur factice, coupee en deux : aucun motif de secret dans le depot
CONNU = "hunter2" + "-Factice/9"
CIBLE = "winrm://dc01"

MOTS_SENSIBLES = ("password", "passwd", "secret", "token", "key", "credential")

posix = pytest.mark.skipif(sys.platform == "win32", reason="droits POSIX")


@pytest.fixture(autouse=True)
def _etat_propre(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Ni variable, ni secret enregistré, ni journal ouvert d'un test à l'autre."""
    monkeypatch.delenv(ENV_MOT_DE_PASSE_WINRM, raising=False)
    yield
    log._secrets.clear()
    # --log-file : fichier ferme avant le menage de tmp_path (Windows)
    racine = logging.getLogger()
    for handler in log._handlers:
        racine.removeHandler(handler)
        handler.close()
    log._handlers.clear()


def _fichier(tmp_path: Path, mode: int = 0o600, contenu: str = CONNU) -> Path:
    chemin = tmp_path / "winrm.txt"
    chemin.write_text(contenu + "\n", encoding="utf-8")
    chemin.chmod(mode)
    return chemin


def _espionner(monkeypatch: pytest.MonkeyPatch) -> list[secrets.Secret | None]:
    """Note ce que ``cli._mot_de_passe`` rend à ``amnesia audit``."""
    recus: list[secrets.Secret | None] = []
    lire = cli._mot_de_passe

    def espion(
        args: argparse.Namespace,
        argv: Sequence[str],
        parser: argparse.ArgumentParser,
    ) -> secrets.Secret | None:
        recus.append(lire(args, argv, parser))
        return recus[-1]

    monkeypatch.setattr(cli, "_mot_de_passe", espion)
    return recus


# --- aucune option ne prend une valeur secrete ---


def _actions(parser: argparse.ArgumentParser) -> Iterator[argparse.Action]:
    """Actions du parseur et de toutes ses sous-commandes, récursivement."""
    for action in parser._actions:
        yield action
        if isinstance(action, argparse._SubParsersAction):
            for sous_parseur in action.choices.values():
                yield from _actions(sous_parseur)


def _options_a_valeur_secrete(parser: argparse.ArgumentParser) -> list[str]:
    """Options au nom sensible qui prennent une valeur, hors ``-file`` → chemin."""
    interdites = []
    for action in _actions(parser):
        for option in action.option_strings:
            nom = option.lower()
            if not any(mot in nom for mot in MOTS_SENSIBLES):
                continue
            # nargs=0 : drapeau (store_true, count...), aucune valeur sur argv
            if action.nargs == 0:
                continue
            if nom.endswith("-file") and action.type is Path:
                continue
            interdites.append(option)
    return interdites


def test_aucune_option_ne_prend_une_valeur_secrete() -> None:
    parser = build_parser()
    options = [o for a in _actions(parser) for o in a.option_strings]
    # le parcours atteint bien les sous-commandes
    assert "--password-file" in options
    assert "--target" in options
    assert "--min-severity" in options
    assert _options_a_valeur_secrete(parser) == []


@pytest.mark.parametrize(
    "option",
    ["--password", "--client-secret", "--token", "--api-key", "--secret-file-content"],
)
def test_le_parcours_detecte_une_option_a_valeur_secrete(option: str) -> None:
    parser = argparse.ArgumentParser()
    sous = parser.add_subparsers().add_parser("audit")
    sous.add_argument(option)
    sous.add_argument("--ask-password", action="store_true")
    sous.add_argument("--token-file", type=Path)
    assert _options_a_valeur_secrete(parser) == [option]


def test_option_password_file_texte_refusee_par_le_parcours() -> None:
    # « -file » ne suffit pas : l'option doit designer un chemin
    parser = argparse.ArgumentParser()
    parser.add_argument("--password-file")
    assert _options_a_valeur_secrete(parser) == ["--password-file"]


@pytest.mark.parametrize(
    "arguments",
    [
        ["audit", "--target", CIBLE, "--token", CONNU],
        ["audit", "--target", CIBLE, "--secret", CONNU],
        ["audit", "--target", CIBLE, f"--secret={CONNU}"],
        ["audit", "--target", CIBLE, "--client-secret", CONNU],
        ["audit", "--target", CIBLE, "--passwd", CONNU],
        ["audit", "--target", CIBLE, "--api-key", CONNU],
        ["audit", "--target", CIBLE, "-p", CONNU],
        ["audit", "--target", CIBLE, f"-p{CONNU}"],
        ["audit", "--target", CIBLE, f"--token{CONNU}"],
        ["--pass", CONNU, "audit"],
        ["--password", CONNU, "audit", "--target", CIBLE],
        ["--token", CONNU, "audit"],
    ],
)
def test_option_a_valeur_secrete_inconnue_de_la_cli(
    arguments: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    # argparse recopierait la valeur (« unrecognized arguments », « invalid
    # choice ») sur stderr : le refus tombe avant, sans la citer
    with pytest.raises(SystemExit) as exc:
        main(arguments)
    assert exc.value.code == USAGE
    sorties = capsys.readouterr()
    assert "aucune option ne prend de valeur secrète" in sorties.err
    assert "hunter2" not in sorties.out + sorties.err


@pytest.mark.parametrize(
    "arguments",
    [
        ["--password", CONNU],
        [f"--password={CONNU}"],
        ["--pass", CONNU],
        [f"--password-fil={CONNU}"],
    ],
)
@pytest.mark.parametrize("cible", [CIBLE, "local"])
def test_password_file_abregee_refusee_sans_echo(
    arguments: list[str],
    cible: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # « --password » abrege « --password-file » pour argparse : la valeur, prise
    # pour un chemin, n'est ni lue ni recopiee, meme si un fichier porte ce nom
    monkeypatch.chdir(tmp_path)
    Path("hunter2-Factice").mkdir()
    Path(CONNU).write_text("x\n", encoding="utf-8")
    Path(CONNU).chmod(0o600)
    with pytest.raises(SystemExit) as exc:
        main(["audit", "--target", cible, *arguments])
    assert exc.value.code == USAGE
    sorties = capsys.readouterr()
    assert "aucune option ne prend de valeur secrète" in sorties.err
    assert "--password-file" in sorties.err
    assert "hunter2" not in sorties.out + sorties.err


def test_option_a_valeur_secrete_reconnue() -> None:
    reconnue = cli._option_a_valeur_secrete
    assert reconnue(["audit", "--password", "x"]) == "--password"
    assert reconnue(["--pa=x"]) == "--pa"
    assert reconnue(["audit", "-p", "x"]) == "-p"
    assert reconnue(["audit", "--Client-Secret", "x"]) == "option en « secret »"
    assert reconnue(["audit", "--password-file", "x", "--out", "-"]) is None
    assert reconnue(["audit", "--password-file=x"]) is None
    assert reconnue(["audit", "--log-file", "token.log", "-q", "-v"]) is None
    assert reconnue(["audit", "--", "--password"]) is None
    assert reconnue(["--", "-"]) is None


# --- --password-file ---


@posix
@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604])
def test_password_file_trop_ouvert_code_2(
    tmp_path: Path, mode: int, capsys: pytest.CaptureFixture[str]
) -> None:
    chemin = _fichier(tmp_path, mode)
    with pytest.raises(SystemExit) as exc:
        main(["audit", "--target", CIBLE, "--password-file", str(chemin)])
    assert exc.value.code == USAGE
    sorties = capsys.readouterr()
    assert "trop larges" in sorties.err
    assert f"{mode:04o}" in sorties.err
    assert CONNU not in sorties.out + sorties.err
    # refuse avant l'audit : aucun rapport
    assert not Path("amnesia-out").exists()


def test_password_file_prive_accepte(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    registre_factice: Sequence[Check],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recus = _espionner(monkeypatch)
    chemin = _fichier(tmp_path, 0o600)
    out = tmp_path / "rapport.json"
    argv = ["audit", "--target", CIBLE, "--password-file", str(chemin)]
    # le registre factice porte un Gap high : code 1, comme sans mot de passe
    assert main([*argv, "--out", str(out)]) == 1
    assert len(recus) == 1
    assert recus[0] is not None
    assert recus[0].reveal() == CONNU
    sorties = capsys.readouterr()
    texte = out.read_text(encoding="utf-8")
    assert CONNU not in sorties.out + sorties.err + texte
    # run.argv ne garde que le nom du fichier, pas son repertoire
    rapport_argv = json.loads(texte)["run"]["argv"]
    assert "winrm.txt" in rapport_argv
    assert str(tmp_path) not in " ".join(rapport_argv)


def test_password_file_absent_code_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["audit", "--target", CIBLE, "--password-file", str(tmp_path / "absent")])
    assert exc.value.code == USAGE
    assert "mot de passe WinRM" in capsys.readouterr().err


def test_password_file_sans_objet_pour_une_cible_locale(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    chemin = _fichier(tmp_path)
    with pytest.raises(SystemExit) as exc:
        main(["audit", "--target", "local", "--password-file", str(chemin)])
    assert exc.value.code == USAGE
    assert "--password-file" in capsys.readouterr().err


def test_chemin_de_password_file_reduit_dans_argv() -> None:
    argv = ["audit", "--password-file", "/home/auditeur/secrets/winrm.txt"]
    assert redact_argv(argv) == ["audit", "--password-file", "winrm.txt"]
    assert redact_argv(["--password-file=/home/auditeur/w.txt"]) == [
        "--password-file=w.txt"
    ]


# --- variable d'environnement ---


def test_variable_lue_puis_retiree_de_l_environnement(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    registre_factice: Sequence[Check],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recus = _espionner(monkeypatch)
    collecteur = cli._collecteur

    def sans_variable(cible: Target) -> object:
        # deja retiree quand le collecteur (et ses sous-processus) demarre
        assert ENV_MOT_DE_PASSE_WINRM not in os.environ
        return collecteur(cible)

    monkeypatch.setattr(cli, "_collecteur", sans_variable)
    monkeypatch.setenv(ENV_MOT_DE_PASSE_WINRM, CONNU)
    out = tmp_path / "rapport.json"
    assert main(["audit", "--target", CIBLE, "--out", str(out)]) == 1
    assert ENV_MOT_DE_PASSE_WINRM not in os.environ
    assert recus[0] is not None
    assert recus[0].reveal() == CONNU
    sorties = capsys.readouterr()
    assert CONNU not in sorties.out + sorties.err + out.read_text(encoding="utf-8")


def test_variable_retiree_meme_pour_une_cible_locale(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    registre_factice: Sequence[Check],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(ENV_MOT_DE_PASSE_WINRM, CONNU)
    out = tmp_path / "rapport.json"
    assert main(["audit", "--target", "local", "--out", str(out)]) == 1
    assert ENV_MOT_DE_PASSE_WINRM not in os.environ
    sorties = capsys.readouterr()
    assert ENV_MOT_DE_PASSE_WINRM in sorties.err
    assert CONNU not in sorties.out + sorties.err + out.read_text(encoding="utf-8")


# --- sans terminal ---


def _saisie_interdite(*_args: object, **_kwargs: object) -> str:
    raise AssertionError("getpass appelé sans terminal")


def test_sans_terminal_ni_source_echec_immediat(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # le collecteur WinRM (#63) declarera son transport ; simule ici
    monkeypatch.setattr(cli, "TRANSPORTS_A_MOT_DE_PASSE", frozenset({Transport.WINRM}))
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    monkeypatch.setattr(getpass, "getpass", _saisie_interdite)
    with pytest.raises(SystemExit) as exc:
        main(["audit", "--target", CIBLE])
    assert exc.value.code == USAGE
    err = capsys.readouterr().err
    assert "mot de passe WinRM" in err
    assert "aucun terminal" in err
    assert "--password-file" in err
    assert ENV_MOT_DE_PASSE_WINRM in err
    assert not Path("amnesia-out", "amnesia-report.json").exists()


def test_mot_de_passe_requis_saisi_au_terminal(
    tmp_path: Path,
    registre_factice: Sequence[Check],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Terminal(io.StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(cli, "TRANSPORTS_A_MOT_DE_PASSE", frozenset({Transport.WINRM}))
    monkeypatch.setattr(sys, "stdin", Terminal())
    monkeypatch.setattr(getpass, "getpass", lambda invite: CONNU)
    out = tmp_path / "rapport.json"
    assert main(["audit", "--target", CIBLE, "--out", str(out)]) == 1
    assert CONNU not in out.read_text(encoding="utf-8")


def test_sans_mot_de_passe_requis_aucune_invite(
    tmp_path: Path,
    registre_factice: Sequence[Check],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # tant qu'aucun collecteur n'exige de mot de passe, l'audit ne demande rien
    monkeypatch.setattr(getpass, "getpass", _saisie_interdite)
    assert main(["audit", "--target", CIBLE, "--out", str(tmp_path / "r.json")]) == 1


# --- aucune fuite apres un echec d'authentification ---


class _AuthentificationRefusee(Check):
    """Check dont l'évaluation échoue comme un transport qui cite le secret."""

    def __init__(self, id: str, secret: str) -> None:
        self.id = id
        self.title = "Authentification refusée (simulation)"
        self._secret = secret

    def evaluate(self, facts: FactSet, ctx: Context) -> CheckResult:
        raise PermissionError(
            f"authentification refusée pour auditeur avec {self._secret} "
            f"(winrm://auditeur:{self._secret}@dc01)"
        )


@pytest.mark.parametrize("debug", [False, True])
def test_echec_d_authentification_sans_fuite(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    debug: bool,
) -> None:
    checks = [_AuthentificationRefusee("test.auth", CONNU)]
    monkeypatch.setattr(cli, "default_checks", lambda: list(checks))
    chemin = _fichier(tmp_path)
    out = tmp_path / "rapport.json"
    journal = tmp_path / "journal.log"
    argv = ["audit", "--target", CIBLE, "--password-file", str(chemin)]
    argv += ["--out", str(out), "--log-file", str(journal), "-vv"]
    if debug:
        argv.append("--debug")
    code = main(argv)
    assert code not in (0, USAGE)
    sorties = capsys.readouterr()
    texte = out.read_text(encoding="utf-8")
    rapport = json.loads(texte)
    # l'erreur est bien rapportee, et masquee
    erreur = rapport["results"][0]["error"]
    assert erreur["type"] == "PermissionError"
    assert log.MASQUE in erreur["message"]
    for lieu in (
        sorties.out,
        sorties.err,
        caplog.text,
        texte,
        journal.read_text(encoding="utf-8"),
        "".join(str(r.__dict__) for r in caplog.records),
    ):
        assert CONNU not in lieu
        assert "hunter2" not in lieu


@pytest.mark.parametrize("debug", [False, True])
def test_erreur_fatale_sans_fuite(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    debug: bool,
) -> None:
    def refus(cible: Target) -> object:
        raise ConnectionRefusedError(f"401 : {CONNU} refusé")

    monkeypatch.setattr(cli, "_collecteur", refus)
    chemin = _fichier(tmp_path)
    argv = ["audit", "--target", CIBLE, "--password-file", str(chemin)]
    if debug:
        argv.append("--debug")
    assert main(argv) == FATAL
    sorties = capsys.readouterr()
    assert "erreur fatale" in sorties.err
    assert log.MASQUE in sorties.err
    assert ("Traceback" in sorties.err) is debug
    assert CONNU not in sorties.out + sorties.err
    assert all(CONNU not in r.getMessage() for r in caplog.records)
    # en --debug aussi : la trace est caviardee avant d'atteindre le journal,
    # un handler pose par l'hote (caplog) ne recoit jamais l'exception brute
    assert CONNU not in caplog.text
    assert all(CONNU not in str(r.__dict__) for r in caplog.records)


def test_secret_masque_partout_dans_le_rapport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # dernier filet : une valeur de secret arrivee dans un champ quelconque,
    # cle d'une preuve ou d'un bloc inconnu comprise
    from amnesia.report import dumps_report

    secrets.Secret(CONNU)
    rapport = {
        "results": [{"message": f"vu {CONNU}", "evidence": [CONNU, 3]}],
        "gaps": [
            {
                "resource": CONNU,
                "evidence": {
                    "source": f"cmd {CONNU}",
                    "details": {f"user={CONNU}": True, "v": {CONNU: [CONNU]}},
                },
            }
        ],
        "inconnu": {CONNU: 1, "k": CONNU},
    }
    texte = dumps_report(rapport)
    assert CONNU not in texte
    relu = json.loads(texte)
    assert relu["results"][0]["evidence"] == [log.MASQUE, 3]
    assert relu["inconnu"] == {log.MASQUE: 1, "k": log.MASQUE}
    preuve = relu["gaps"][0]["evidence"]
    assert preuve["details"] == {
        f"user={log.MASQUE}": True,
        "v": {log.MASQUE: [log.MASQUE]},
    }


@pytest.mark.parametrize("mot_de_passe", ["high", "igh", "amnesia", "days"])
def test_mot_de_passe_egal_a_une_valeur_du_schema(
    mot_de_passe: str,
    tmp_path: Path,
    registre_factice: list[Check],
    capsys: pytest.CaptureFixture[str],
) -> None:
    # le masquage ne doit ni invalider le rapport ni changer le code de sortie
    import jsonschema

    from amnesia.exitcodes import GAPS
    from amnesia.report import load_schema

    chemin = _fichier(tmp_path, contenu=mot_de_passe)
    out = tmp_path / "rapport.json"
    argv = ["audit", "--target", CIBLE, "--password-file", str(chemin)]
    assert main([*argv, "--out", str(out)]) == GAPS
    rapport = json.loads(out.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(load_schema()).validate(rapport)
    assert rapport["gaps"][0]["severity"] == "high"
    assert rapport["tool"]["name"] == "amnesia"
    assert rapport["gaps"][0]["evidence"]["unit"] == "days"
    assert "fatale" not in capsys.readouterr().err


@pytest.mark.parametrize("mot_de_passe", ["high", "igh", "amnesia", "days", "fail"])
def test_champs_structurels_jamais_masques(mot_de_passe: str) -> None:
    # un mot de passe egal a une valeur d'enumeration ne doit ni invalider le
    # rapport ni servir d'oracle (« severity » : « h*** »)
    from amnesia.report import _sans_surrogates

    secrets.Secret(mot_de_passe)
    rapport: dict[str, Any] = {
        "schema_version": "1.0",
        "tool": {"name": "amnesia", "version": "0.1", "catalog_version": "1"},
        "run": {"id": "high", "started_at": "high", "argv": ["high"]},
        "targets": [{"id": "x", "kind": "high", "transport": "high"}],
        "results": [
            {
                "check_id": "win.high",
                "status": "fail",
                "reason": "high",
                "message": "high days fail amnesia",
                "error": {"type": "high", "message": "high days fail amnesia"},
            }
        ],
        "gaps": [
            {
                "check_id": "win.high",
                "severity": "high",
                "reason": "high days fail amnesia",
                "evidence": {"unit": "days", "confidence": "high"},
                "references": [{"kind": "attack", "id": "high"}],
            }
        ],
        "summary": {"by_severity": {"high": 1}, "by_status": {"fail": 1}},
    }
    rendu = _sans_surrogates(rapport)
    assert rendu["tool"] == rapport["tool"]
    assert rendu["summary"] == rapport["summary"]
    assert rendu["run"]["id"] == "high"
    assert rendu["targets"][0]["kind"] == "high"
    assert rendu["results"][0]["status"] == "fail"
    assert rendu["results"][0]["reason"] == "high"
    assert rendu["results"][0]["error"]["type"] == "high"
    assert rendu["gaps"][0]["severity"] == "high"
    assert rendu["gaps"][0]["evidence"] == rapport["gaps"][0]["evidence"]
    assert rendu["gaps"][0]["references"] == rapport["gaps"][0]["references"]
    # le texte libre, lui, reste masque
    assert mot_de_passe not in rendu["results"][0]["message"]
    assert mot_de_passe not in rendu["results"][0]["error"]["message"]
    assert mot_de_passe not in rendu["gaps"][0]["reason"]
    assert mot_de_passe not in rendu["run"]["argv"][0]
