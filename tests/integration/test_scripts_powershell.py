# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Scripts PowerShell analyses par le vrai pwsh : garantie de lecture seule (#39).

scripts/inventaire_ps.ps1 dresse l'inventaire de l'AST de chaque script
(Parser::ParseFile : commandes, appels de methodes .NET, affectations,
redirections) ; amnesia.readonly.check_script_inventory rend le verdict. Les
scripts fixtures qui ecrivent sur la cible doivent chacun etre refuses, le
script fixture conforme et les scripts reels de src/amnesia/ps/ acceptes.

pwsh est pris dans PWSH_BIN ou dans le PATH (preinstalle sur les runners
ubuntu-latest et windows-latest). Sans lui, ces tests sont ignores sur un
poste de developpement, mais echouent sur la CI : une garantie qui ne
s'execute pas n'en est pas une. Le verdict lui-meme est teste sans pwsh dans
tests/unit/test_readonly.py.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from amnesia.facts import subprocess_env
from amnesia.readonly import SCRIPTS, check_script_inventory

RACINE = Path(__file__).resolve().parents[2]
INVENTAIRE = RACINE / "scripts" / "inventaire_ps.ps1"
FIXTURES = RACINE / "tests" / "fixtures" / "ps"
SCRIPTS_REELS = RACINE / "src" / "amnesia" / "ps"
# chaine vide si absent : subprocess.run n'accepte pas None dans ses arguments
PWSH = os.environ.get("PWSH_BIN") or shutil.which("pwsh") or ""
SUR_LA_CI = os.environ.get("GITHUB_ACTIONS") == "true"

sans_pwsh = pytest.mark.skipif(not PWSH, reason="binaire pwsh absent")

# script fixture -> extrait attendu d'au moins un ecart
REFUSES = {
    # criteres d'acceptation de #39
    "set_itemproperty.ps1": "verbe interdit (Set-) : Set-ItemProperty",
    "alias_sc.ps1": "alias ou exécutable (nom complet de cmdlet attendu) : sc",
    "limit_eventlog.ps1": "cmdlet interdite : Limit-EventLog",
    "clearlog_dotnet.ps1": "méthode hors allowlist : .ClearLog()",
    # autres voies d'ecriture
    "propriete_journal.ps1": "affectation à autre chose qu'une variable simple",
    "redirection_fichier.ps1": "redirection vers un fichier",
    "commande_dynamique.ps1": "commande au nom calculé à l'exécution",
    "executable_externe.ps1": "alias ou exécutable",
}
CONFORME = "lecture_conforme.ps1"
# element que pwsh doit inventorier dans chaque script refuse : verifie sans
# pwsh que les ecarts attendus ci-dessus sont bien ceux du verdict
TEMOINS: dict[str, dict[str, Any]] = {
    "set_itemproperty.ps1": {"kind": "command", "name": "Set-ItemProperty"},
    "alias_sc.ps1": {"kind": "command", "name": "sc"},
    "limit_eventlog.ps1": {"kind": "command", "name": "Limit-EventLog"},
    "clearlog_dotnet.ps1": {
        "kind": "method",
        "name": "ClearLog",
        "static": False,
        "type": None,
    },
    "propriete_journal.ps1": {
        "kind": "assignment",
        "target": "MemberExpressionAst",
        "drive": False,
    },
    "redirection_fichier.ps1": {
        "kind": "redirection",
        "name": "'C:\\Windows\\Temp\\services.txt'",
    },
    "commande_dynamique.ps1": {"kind": "command", "name": None},
    "executable_externe.ps1": {"kind": "command", "name": "wevtutil.exe"},
}


def _inventaires(scripts: Sequence[Path]) -> dict[str, dict[str, Any]]:
    options = ["-NoLogo", "-NoProfile", "-NonInteractive"]
    if sys.platform == "win32":
        options += ["-ExecutionPolicy", "Bypass"]
    # binaire designe par le developpeur ou la CI (PWSH_BIN), pas de shell
    sortie = subprocess.run(  # noqa: S603
        [PWSH, *options, "-File", str(INVENTAIRE), *(str(s) for s in scripts)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
        check=False,
        env=subprocess_env(),
    )
    assert sortie.returncode == 0, sortie.stderr
    inventaires = json.loads(sortie.stdout)
    assert len(inventaires) == len(scripts), sortie.stdout
    return {inventaire["path"]: inventaire for inventaire in inventaires}


@pytest.fixture(scope="module")
def inventaires() -> dict[str, dict[str, Any]]:
    return _inventaires(sorted(FIXTURES.glob("*.ps1")))


def test_pwsh_present_sur_la_ci() -> None:
    if SUR_LA_CI:
        assert PWSH, "pwsh introuvable : l'analyse des scripts ne serait pas jouee"


def test_fixtures_toutes_attendues() -> None:
    assert {f.name for f in FIXTURES.glob("*")} == {*REFUSES, CONFORME}


@pytest.mark.parametrize("script", sorted(REFUSES))
def test_ecart_attendu_coherent_avec_le_verdict(script: str) -> None:
    inventaire = {"errors": [], "items": [{**TEMOINS[script], "line": 2}]}
    (ecart,) = check_script_inventory(inventaire)
    assert REFUSES[script] in ecart


@sans_pwsh
@pytest.mark.parametrize("script", sorted(REFUSES))
def test_script_qui_ecrit_refuse(
    inventaires: dict[str, dict[str, Any]], script: str
) -> None:
    ecarts = check_script_inventory(inventaires[script])
    assert any(REFUSES[script] in ecart for ecart in ecarts), ecarts


@sans_pwsh
def test_script_de_lecture_accepte(inventaires: dict[str, dict[str, Any]]) -> None:
    inventaire = inventaires[CONFORME]
    assert check_script_inventory(inventaire) == []
    # l'inventaire a bien vu le script : commandes, methodes, affectations
    genres = {element["kind"] for element in inventaire["items"]}
    assert genres == {"command", "method", "assignment", "redirection"}
    commandes = {e["name"] for e in inventaire["items"] if e["kind"] == "command"}
    assert {"Get-WinEvent", "Get-ItemProperty", "Set-StrictMode"} <= commandes


@sans_pwsh
def test_script_illisible_refuse(tmp_path: Path) -> None:
    script = tmp_path / "tronque.ps1"
    script.write_bytes(b"if ($true) {\r\n")
    (inventaire,) = _inventaires([script]).values()
    assert "erreur d'analyse du script" in check_script_inventory(inventaire)


@sans_pwsh
def test_scripts_reels_conformes() -> None:
    # src/amnesia/ps/ : vide tant que le collecteur PowerShell (#48) n'a rien livre
    scripts = sorted(SCRIPTS_REELS.glob("*.ps1"))
    assert {s.name for s in scripts} == set(SCRIPTS)
    if not scripts:
        return
    for nom, inventaire in _inventaires(scripts).items():
        assert check_script_inventory(inventaire) == [], nom
