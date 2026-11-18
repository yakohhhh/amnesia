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


@pytest.mark.parametrize("option", ["--token", "--secret", "--client-secret"])
def test_option_a_valeur_secrete_inconnue_de_la_cli(
    option: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["audit", "--target", CIBLE, option, CONNU])
    assert exc.value.code == USAGE
    assert "hunter2" not in capsys.readouterr().out


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
    assert "--password-file s'écrit en entier" in sorties.err
    assert "hunter2" not in sorties.out + sorties.err


def test_option_abregee_reconnue() -> None:
    assert cli._option_abregee(["audit", "--password", "x"])
    assert cli._option_abregee(["--pa=x"])
    assert not cli._option_abregee(["audit", "--password-file", "x", "--out", "-"])
    assert not cli._option_abregee(["audit", "--password-file=x"])
    # apres « -- », ce ne sont plus des options
    assert not cli._option_abregee(["audit", "--", "--password"])
    assert not cli._option_abregee(["--", "-"])


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
    if not debug:
        # en --debug, la trace part en exc_info : les handlers d'amnesia la
        # masquent (stderr ci-dessus), pas un handler pose avant eux par l'hote
        assert CONNU not in caplog.text


def test_secret_masque_partout_dans_le_rapport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # dernier filet : une valeur de secret arrivee dans un champ quelconque
    from amnesia.report import dumps_report

    secrets.Secret(CONNU)
    rapport = {"results": [{"message": f"vu {CONNU}", "evidence": [CONNU, 3]}]}
    texte = dumps_report(rapport)
    assert CONNU not in texte
    assert json.loads(texte)["results"][0]["evidence"] == [log.MASQUE, 3]
