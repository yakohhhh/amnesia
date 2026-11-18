# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Sentinelles « hors ligne par défaut » (#26), sous le blocage réseau de #5.

Chaque commande de la CLI tourne ici avec sockets et DNS coupés par
tests/conftest.py : une connexion, même avalée par la boucle principale, ferait
échouer le test (code de sortie, journal). Le témoin positif montre que le
blocage est bien actif dans ce processus.
"""

from __future__ import annotations

import json
import logging
import os
import socket
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import pytest
from pytest_socket import SocketBlockedError

from amnesia import cli
from amnesia.checks import Check, Domain
from amnesia.checks.base import CheckResult
from amnesia.checks.context import Context
from amnesia.cli import main
from amnesia.exitcodes import GAPS, INCOMPLETE, OK
from amnesia.facts import (
    SUBPROCESS_ENV,
    Collector,
    FactSet,
    FixtureCollector,
    subprocess_env,
)
from amnesia.target import Kind, Target

RACINE = Path(__file__).resolve().parents[2]
FIXTURE = RACINE / "tests" / "fixtures" / "report-min.json"
FAITS = RACINE / "tests" / "fixtures" / "facts" / "exemple.json"
GOLDENS = RACINE / "tests" / "golden"


class CheckHorsLigne(Check):
    id = "test.hors_ligne"
    title = "Check factice conforme"
    description = "Ne touche à rien."
    domain = Domain.WINDOWS
    target_kinds = (Kind.WINDOWS_HOST,)
    version = 1
    default_severity = "low"

    def evaluate(self, facts: FactSet, ctx: Context) -> CheckResult:
        return CheckResult.passed(self.id, ctx.target.id)


class CheckQuiSeConnecte(CheckHorsLigne):
    id = "test.connexion"
    title = "Check factice qui ouvre une connexion"

    def evaluate(self, facts: FactSet, ctx: Context) -> CheckResult:
        # hors d'un collecteur reseau : interdit par TID251 et par le socle
        socket.create_connection(("192.0.2.1", 80), timeout=1)  # noqa: TID251
        return CheckResult.passed(self.id, ctx.target.id)


class CollecteurFactice:
    """Collecteur sans connexion : faits de la fixture, demandes consignées."""

    def __init__(self) -> None:
        self.interne = FixtureCollector(FAITS)
        self.demandes: list[tuple[str, tuple[str, ...]]] = []

    def collect(
        self, target: Target, names: Iterable[str], *, timeout: float
    ) -> FactSet:
        noms = tuple(names)
        self.demandes.append((target.id, noms))
        return self.interne.collect(target, noms, timeout=timeout)


def _resultats(rapport: Path) -> list[dict[str, Any]]:
    contenu: dict[str, Any] = json.loads(rapport.read_text(encoding="utf-8"))
    resultats: list[dict[str, Any]] = contenu["results"]
    return resultats


# --- temoins : le blocage de #5 est actif ici ---------------------------------


def test_temoin_connexion_bloquee() -> None:
    with pytest.raises(SocketBlockedError):
        socket.create_connection(("192.0.2.1", 80), timeout=1)  # noqa: TID251


def test_check_factice_qui_se_connecte_est_bloque() -> None:
    ctx = Context.for_check("test.connexion", Target.parse("local"))
    with pytest.raises(SocketBlockedError):
        CheckQuiSeConnecte().evaluate(FactSet(), ctx)


# --- sentinelles : chaque commande, sans connexion -----------------------------


@pytest.mark.parametrize("argv", [["--help"], ["--version"]], ids=["help", "version"])
def test_aide_et_version(argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 0
    assert capsys.readouterr().out


def test_list_checks(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["list-checks"]) == 0
    assert capsys.readouterr().out


def test_schema(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["schema"]) == 0
    assert capsys.readouterr().out.startswith("{")


@pytest.mark.parametrize("fmt", ["text", "md"])
def test_render_fixture(
    fmt: str,
    capsys: pytest.CaptureFixture[str],
    assert_no_external_resources: Callable[[str], None],
) -> None:
    assert main(["render", str(FIXTURE), "--format", fmt]) == 0
    sortie = capsys.readouterr().out
    assert "Qui s'est connecté en RDP" in sortie
    assert_no_external_resources(sortie)


def test_audit_checks_factices(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "default_checks", lambda: [CheckHorsLigne()])
    rapport = tmp_path / "rapport.json"
    with caplog.at_level(logging.WARNING):
        assert main(["audit", "--target", "local", "--out", str(rapport)]) == 0
    # une connexion avalee par la boucle principale laisserait une trace ici
    assert "SocketBlockedError" not in caplog.text
    assert "erreur fatale" not in caplog.text
    assert "SocketBlockedError" not in capsys.readouterr().err


@pytest.mark.parametrize("cible", ["local", "winrm://dc01.invalid"])
def test_audit_collecteur_factice(
    cible: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # checks du registre, collecteur factice : seul un collecteur joint la
    # cible ; ni le moteur, ni le rapport, ni le rendu n'ouvrent de connexion,
    # meme pour une cible distante
    collecteur = CollecteurFactice()

    def fabrique(target: Target) -> Collector:
        return collecteur

    monkeypatch.setattr(cli, "_collecteur", fabrique)
    rapport = tmp_path / "rapport.json"
    with caplog.at_level(logging.DEBUG):
        code = main(["audit", "--target", cible, "--out", str(rapport)])
    assert code in {OK, GAPS, INCOMPLETE}
    assert collecteur.demandes, "le collecteur factice n'a pas servi"
    resultats = _resultats(rapport)
    assert resultats
    assert [r["error"] for r in resultats if r["status"] == "error"] == []
    assert "SocketBlockedError" not in caplog.text


def test_audit_check_qui_se_connecte_jamais_silencieux(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # la tentative bloquee devient un resultat error et un audit incomplet,
    # jamais un pass ni une erreur fatale
    monkeypatch.setattr(cli, "default_checks", lambda: [CheckQuiSeConnecte()])
    rapport = tmp_path / "rapport.json"
    code = main(["audit", "--target", "winrm://dc01.invalid", "--out", str(rapport)])
    assert code == INCOMPLETE
    (resultat,) = _resultats(rapport)
    assert resultat["status"] == "error"
    assert resultat["error"]["type"] == "pytest_socket.SocketBlockedError"


# --- rendus : aucune ressource externe -----------------------------------------


@pytest.mark.parametrize(
    "contenu",
    [
        # exemples des criteres d'acceptation de #26
        "![](https://cdn.example/logo.png)",
        '<link href="https://cdn.example/style.css">',
        "![logo](https://cdn.example/logo.png)",
        "![logo]( <https://cdn.example/logo.png> )",
        "![logo](//cdn.example/logo.png)",
        "![logo][ref]\n\n[ref]: https://cdn.example/logo.png",
        "![logo][Ref]\n\n[REF]: <https://cdn.example/logo.png> 'titre'",
        '<link href="https://cdn.example/style.css" rel="stylesheet">',
        "<link\n  rel=stylesheet\n  href=https://cdn.example/a.css>",
        '<script src="https://cdn.example/app.js"></script>',
        "<img src='//cdn.example/pixel.gif'>",
        '<iframe src="https://evil.example"></iframe>',
        "<style>body { background: url(https://cdn.example/bg.png) }</style>",
        "<style>@import url(style.css);</style>",
        "<style>@font-face { src: url('https://fonts.example/a.woff2') }</style>",
        '<meta http-equiv="refresh" content="0;url=https://evil.example">',
        '<use xlink:href="https://cdn.example/sprite.svg#a"/>',
        '<IMG SRC="HTTPS://CDN.EXAMPLE/A.PNG">',
        '<body background="https://cdn.example/fond.png">',
        '<td style="background: url(//cdn.example/fond.png)">',
        # HTML : <base>, srcset, entites, normalisation de l'URL, SVG
        '<base href="https://cdn.example/"><img src="logo.png">',
        '<img src="a.png" srcset="a.png 1x, https://cdn.example/b.png 2x">',
        '<img src="https&#58;//cdn.example/x.png">',
        '<img src="https:&#47;&#47;cdn.example/x.png">',
        '<img src="https:/\\cdn.example/x.png">',
        '<img src="https:cdn.example/x.png">',
        '<img src=" ht&#9;tps://cdn.example/x.png">',
        '<img src="a.png" src="https://cdn.example/x.png">',
        '<svg><feImage href="https://cdn.example/a.png"/></svg>',
        '<link rel=preload as=image imagesrcset="https://cdn.example/a.png">',
        '<a href="rapport.html" ping="https://cdn.example/p">lien</a>',
        '<iframe srcdoc="&lt;img src=https://cdn.example/x.png&gt;"></iframe>',
        # CSS : image-set, echappements, entites d'un <style> de SVG
        "<div style='background-image:image-set(\"https://cdn.example/a.png\" 1x)'>",
        "<style>a { background: u\\72l(https://cdn.example/a.png) }</style>",
        "<style>\\40import 'a.css';</style>",
        "<svg><style>a { fill: url(https&#58;//cdn.example/a.svg#f) }</style></svg>",
        # Markdown : references condensees et raccourcies, fins de ligne CRLF,
        # destination a la ligne, etiquettes normalisees, crochets dans le texte
        "![logo][]\n\n[logo]: https://cdn.example/logo.png",
        "![logo] suite\n\n[logo]: https://cdn.example/logo.png",
        "![logo][ref]\r\n\r\n[ref]: https://cdn.example/logo.png\r\n",
        "![logo][ref]\n\n[ref]:\n  https://cdn.example/logo.png",
        "![logo][my  ref]\n\n[my ref]: https://cdn.example/logo.png",
        "![a \\[b\\]](https://cdn.example/x.png)",
        "![a [b] c](https://cdn.example/x.png)",
        "![logo][ref]\n\n> [ref]: https://cdn.example/logo.png",
        "![x](https\\://cdn.example/x.png)",
        "![x](https&#58;//cdn.example/x.png)",
        "\\\\![x](https://cdn.example/x.png)",
    ],
)
def test_ressource_externe_refusee(
    contenu: str, assert_no_external_resources: Callable[[str], None]
) -> None:
    with pytest.raises(AssertionError, match="ressource"):
        assert_no_external_resources(contenu)


@pytest.mark.parametrize(
    "contenu",
    [
        "",
        "Voir https://attack.mitre.org/techniques/T1021/001/ pour T1021.001.",
        "[MITRE ATT&CK T1021.001](https://attack.mitre.org/techniques/T1021/001/)",
        "[ref][mitre]\n\n[mitre]: https://attack.mitre.org/",
        "![schéma local](images/schema.png)",
        "![logo][ref]\n\n[ref]: images/logo.png",
        '<img src="data:image/png;base64,AAAA">',
        '<a href="https://attack.mitre.org/">lien</a>',
        "<style>body { background: url(fond.png) }</style>",
        "- Cible : winrm\\://srv-file.exemple.invalid",
        '<img src="a.png" srcset="a.png 1x, images/b.png 2x">',
        "<div style=\"background: url(&quot;data:image/svg+xml,<svg xmlns='"
        "http://www.w3.org/2000/svg'/>&quot;)\">",
        '<style>body { font-family: "Segoe UI", sans-serif }</style>',
        "![logo][]\n\n[logo]: images/logo.png",
        # point d'exclamation echappe : un lien, pas une image
        "\\![pas une image](https://attack.mitre.org/)",
        "Lien vers <https://attack.mitre.org/>.",
    ],
)
def test_lien_textuel_accepte(
    contenu: str, assert_no_external_resources: Callable[[str], None]
) -> None:
    assert_no_external_resources(contenu)


@pytest.mark.parametrize("nom", ["report-min.txt", "report-min.md"])
def test_goldens_sans_ressource_externe(
    nom: str, assert_no_external_resources: Callable[[str], None]
) -> None:
    assert_no_external_resources((GOLDENS / nom).read_text(encoding="utf-8"))


def test_message_cite_la_ligne(
    assert_no_external_resources: Callable[[str], None],
) -> None:
    with pytest.raises(AssertionError, match=r"2: '!\[x\]\(https://"):
        assert_no_external_resources("texte\n![x](https://cdn.example/x.png)")


# --- sous-processus : telemetrie PowerShell coupee -----------------------------


def test_subprocess_env_impose_les_variables() -> None:
    env = subprocess_env({"PATH": "/bin", "POWERSHELL_TELEMETRY_OPTOUT": "0"})
    assert env["PATH"] == "/bin"
    assert env["POWERSHELL_TELEMETRY_OPTOUT"] == "1"
    assert env["POWERSHELL_UPDATECHECK"] == "Off"
    assert env["DOTNET_CLI_TELEMETRY_OPTOUT"] == "1"
    assert dict(SUBPROCESS_ENV).items() <= env.items()


def test_subprocess_env_part_de_l_environnement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AMNESIA_TEST_VAR", "x")
    monkeypatch.delenv("POWERSHELL_TELEMETRY_OPTOUT", raising=False)
    env = subprocess_env()
    assert env["AMNESIA_TEST_VAR"] == "x"
    assert env["POWERSHELL_TELEMETRY_OPTOUT"] == "1"
    # os.environ n'est pas modifie
    assert "POWERSHELL_TELEMETRY_OPTOUT" not in os.environ


def test_subprocess_env_casse_des_noms_windows() -> None:
    # Windows ignore la casse des noms : aucun homonyme ne reste a cote de la
    # valeur imposee, qui pourrait sinon perdre dans le bloc d'environnement
    env = subprocess_env(
        {
            "Path": r"C:\Windows",
            "powershell_telemetry_optout": "0",
            "PowerShell_UpdateCheck": "Default",
        }
    )
    assert env == {"Path": r"C:\Windows", **SUBPROCESS_ENV}
