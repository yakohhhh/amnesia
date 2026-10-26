"""Le socle de tests applique bien ses regles (tests/conftest.py, pyproject).

Chaque cas lance un pytest distinct (pytester, sous-processus) avec le conftest
et le pyproject du depot : les reglages verifies sont ceux de la vraie suite.
"""

import re
import socket
import sys
import tomllib
from pathlib import Path

import pytest
import yaml
from pytest_socket import SocketBlockedError

RACINE = Path(__file__).resolve().parent.parent
PYPROJECT = tomllib.loads((RACINE / "pyproject.toml").read_text(encoding="utf-8"))
SUR_OPTION = ["admin", "lab", "cloud", "network"]


def _suite(pytester: pytest.Pytester, source: str, *options: str) -> pytest.RunResult:
    pytester.makeconftest((RACINE / "tests" / "conftest.py").read_text("utf-8"))
    pytester.makepyprojecttoml((RACINE / "pyproject.toml").read_text("utf-8"))
    fichier = pytester.makepyfile(test_cas=source)
    return pytester.runpytest_subprocess(fichier, *options)


def test_marqueur_non_declare_refuse(pytester):
    source = "import pytest\n\n@pytest.mark.inconnu\ndef test_a():\n    pass\n"
    resultat = _suite(pytester, source)
    assert resultat.ret != pytest.ExitCode.OK
    resultat.stdout.fnmatch_lines(["*'inconnu' not found in `markers`*"])


def test_windows_ignore_hors_windows(pytester):
    source = "import pytest\n\n@pytest.mark.windows\ndef test_a():\n    pass\n"
    resultat = _suite(pytester, source)
    if sys.platform == "win32":
        resultat.assert_outcomes(passed=1)
    else:
        resultat.assert_outcomes(skipped=1)
        # -ra : la raison figure dans le resume
        resultat.stdout.fnmatch_lines(["SKIPPED * test Windows (plateforme : *)"])


SOURCE_SUR_OPTION = "import pytest\n" + "".join(
    f"\n@pytest.mark.{m}\ndef test_{m}():\n    pass\n" for m in SUR_OPTION
)


def test_marqueurs_ignores_sans_option(pytester):
    resultat = _suite(pytester, SOURCE_SUR_OPTION)
    resultat.assert_outcomes(skipped=len(SUR_OPTION))
    for marqueur in SUR_OPTION:
        resultat.stdout.fnmatch_lines([f"SKIPPED * relancer avec --run-{marqueur}"])


@pytest.mark.parametrize("marqueur", SUR_OPTION)
def test_option_lance_seulement_son_marqueur(pytester, marqueur):
    resultat = _suite(pytester, SOURCE_SUR_OPTION, f"--run-{marqueur}", "-v")
    resultat.assert_outcomes(passed=1, skipped=len(SUR_OPTION) - 1)
    resultat.stdout.fnmatch_lines([f"*::test_{marqueur} PASSED*"])


SOURCE_SOCKETS = """
import socket

import pytest


def test_sans_marqueur():
    socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()


@pytest.mark.network
def test_reseau():
    socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()
"""


def test_socket_refusee_hors_marqueur_network(pytester):
    resultat = _suite(pytester, SOURCE_SOCKETS)
    resultat.assert_outcomes(failed=1, skipped=1)
    resultat.stdout.fnmatch_lines(
        ["FAILED *::test_sans_marqueur - *SocketBlockedError*"]
    )


def test_socket_autorisee_pour_network_avec_option(pytester):
    resultat = _suite(pytester, SOURCE_SOCKETS, "--run-network")
    resultat.assert_outcomes(failed=1, passed=1)
    resultat.stdout.fnmatch_lines(
        ["FAILED *::test_sans_marqueur - *SocketBlockedError*"]
    )


@pytest.mark.parametrize(
    "derogation",
    [
        "@pytest.mark.enable_socket\ndef test_a():",
        "@pytest.mark.allow_hosts(['127.0.0.1'])\ndef test_a():",
        "def test_a(socket_enabled):",
    ],
    ids=["enable_socket", "allow_hosts", "socket_enabled"],
)
def test_derogation_reseau_reservee_a_network(pytester, derogation):
    # sans ce garde-fou, pytest-socket rouvrirait le reseau a n'importe quel test
    resultat = _suite(pytester, f"import pytest\n\n{derogation}\n    pass\n")
    assert resultat.ret == pytest.ExitCode.USAGE_ERROR
    resultat.stderr.fnmatch_lines(["*acces reseau reserve aux tests marques network"])


def test_socket_bloquee_dans_cette_suite():
    with pytest.raises(SocketBlockedError):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def test_repertoire_courant_hors_du_depot(tmp_path):
    assert Path.cwd() == tmp_path
    assert RACINE not in Path.cwd().parents


def test_fixtures_communes(registre_factice, horloge_figee):
    (sans_gap, avec_gap) = registre_factice
    assert sans_gap.run("dc01") == []
    assert [g.severity for g in avec_gap.run("dc01")] == ["high"]
    assert avec_gap.cibles == ["dc01"]
    assert horloge_figee() == horloge_figee()
    assert horloge_figee().utcoffset().total_seconds() == 0


def test_seuil_de_couverture_bloquant(pytester):
    # meme mecanisme que la CI : --cov seul, le seuil vient de [tool.coverage]
    seuil = PYPROJECT["tool"]["coverage"]["report"]["fail_under"]
    assert seuil >= 80
    pytester.makepyprojecttoml(
        f'[tool.coverage.run]\nsource = ["partiel"]\n\n'
        f"[tool.coverage.report]\nfail_under = {seuil}\n"
    )
    pytester.makepyfile(
        partiel="def a():\n    return 1\n\n\ndef b():\n    return 2\n",
        test_partiel="import partiel\n\n\ndef test_a():\n    assert partiel.a()\n",
    )
    resultat = pytester.runpytest_subprocess("--cov", "--cov-report=term-missing")
    assert resultat.ret != pytest.ExitCode.OK
    resultat.stdout.fnmatch_lines([f"*Required test coverage of {seuil}*not reached*"])


def test_ci_mesure_la_couverture_et_l_absence_d_artefacts():
    config = PYPROJECT["tool"]["coverage"]
    assert config["run"]["branch"] is True
    assert config["run"]["source"] == ["amnesia"]
    workflow = (RACINE / ".github" / "workflows" / "ci.yml").read_text("utf-8")
    job = yaml.safe_load(workflow)["jobs"]["test"]
    commandes = [e["run"] for e in job["steps"] if "run" in e]
    (pytest_ci,) = [c for c in commandes if re.search(r"\bpytest\b", c)]
    assert "--cov" in pytest_ci.split()
    assert "--cov-report=term-missing" in pytest_ci
    assert "||" not in pytest_ci
    assert not any(e.get("continue-on-error") for e in job["steps"])
    assert any("git status --porcelain" in c for c in commandes)
