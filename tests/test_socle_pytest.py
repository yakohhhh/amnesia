"""Le socle de tests applique bien ses regles (tests/conftest.py, pyproject).

Chaque cas lance un pytest distinct (pytester, sous-processus) avec le conftest
et le pyproject du depot : les reglages verifies sont ceux de la vraie suite.
"""

from __future__ import annotations

import re
import socket
import sys
import tomllib
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import yaml
from pytest_socket import SocketBlockedError

from amnesia.checks.base import Status
from amnesia.checks.context import Context
from amnesia.facts import FactSet
from amnesia.target import Target

if TYPE_CHECKING:
    from conftest import CheckFactice

RACINE = Path(__file__).resolve().parent.parent
PYPROJECT = tomllib.loads((RACINE / "pyproject.toml").read_text(encoding="utf-8"))
SUR_OPTION = ["admin", "lab", "cloud", "network"]


def _suite(pytester: pytest.Pytester, source: str, *options: str) -> pytest.RunResult:
    pytester.makeconftest((RACINE / "tests" / "conftest.py").read_text("utf-8"))
    pytester.makepyprojecttoml((RACINE / "pyproject.toml").read_text("utf-8"))
    fichier = pytester.makepyfile(test_cas=source)
    return pytester.runpytest_subprocess(fichier, *options)


def test_marqueur_non_declare_refuse(pytester: pytest.Pytester) -> None:
    source = "import pytest\n\n@pytest.mark.inconnu\ndef test_a():\n    pass\n"
    resultat = _suite(pytester, source)
    assert resultat.ret != pytest.ExitCode.OK
    resultat.stdout.fnmatch_lines(["*'inconnu' not found in `markers`*"])


def test_windows_ignore_hors_windows(pytester: pytest.Pytester) -> None:
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


def test_marqueurs_ignores_sans_option(pytester: pytest.Pytester) -> None:
    resultat = _suite(pytester, SOURCE_SUR_OPTION)
    resultat.assert_outcomes(skipped=len(SUR_OPTION))
    for marqueur in SUR_OPTION:
        resultat.stdout.fnmatch_lines([f"SKIPPED * relancer avec --run-{marqueur}"])


@pytest.mark.parametrize("marqueur", SUR_OPTION)
def test_option_lance_seulement_son_marqueur(
    pytester: pytest.Pytester, marqueur: str
) -> None:
    resultat = _suite(pytester, SOURCE_SUR_OPTION, f"--run-{marqueur}", "-v")
    resultat.assert_outcomes(passed=1, skipped=len(SUR_OPTION) - 1)
    resultat.stdout.fnmatch_lines([f"*::test_{marqueur} PASSED*"])


SOURCE_SOCKETS = """
import socket

import pytest


def _ouvrir():
    socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()


@pytest.fixture
def nettoyage():
    yield
    _ouvrir()


def test_sans_marqueur():
    _ouvrir()


@pytest.mark.network
def test_reseau(nettoyage):
    _ouvrir()
"""


def test_socket_refusee_hors_marqueur_network(pytester: pytest.Pytester) -> None:
    resultat = _suite(pytester, SOURCE_SOCKETS)
    resultat.assert_outcomes(failed=1, skipped=1)
    resultat.stdout.fnmatch_lines(
        ["FAILED *::test_sans_marqueur - *SocketBlockedError*"]
    )


def test_socket_autorisee_pour_network_avec_option(pytester: pytest.Pytester) -> None:
    resultat = _suite(pytester, SOURCE_SOCKETS, "--run-network")
    resultat.assert_outcomes(failed=1, passed=1)
    resultat.stdout.fnmatch_lines(
        ["FAILED *::test_sans_marqueur - *SocketBlockedError*"]
    )


@pytest.mark.parametrize("portee", ["function", "module", "session"])
def test_socket_refusee_au_teardown_hors_network(
    pytester: pytest.Pytester, portee: str
) -> None:
    # pytest-socket rouvrait le reseau avant les finaliseurs des fixtures ; le
    # dernier test, ignore au setup, declenche le teardown module et session
    source = (
        "import socket\n\nimport pytest\n\n\n"
        f'@pytest.fixture(scope="{portee}")\n'
        "def nettoyage():\n    yield\n"
        "    socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()\n\n\n"
        "def test_a(nettoyage):\n    pass\n\n\n"
        "@pytest.mark.lab\ndef test_b():\n    pass\n"
    )
    resultat = _suite(pytester, source)
    resultat.assert_outcomes(passed=1, skipped=1, errors=1)
    resultat.stdout.fnmatch_lines(["ERROR *::test_* - *SocketBlockedError*"])


def test_socket_refusee_a_la_collecte(pytester: pytest.Pytester) -> None:
    source = (
        "import socket\n\n"
        "socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()\n\n\n"
        "def test_a():\n    pass\n"
    )
    resultat = _suite(pytester, source, "--run-network")
    resultat.assert_outcomes(errors=1)
    resultat.stdout.fnmatch_lines(["ERROR test_cas.py - *SocketBlockedError*"])


@pytest.mark.parametrize("hotes", ['["127.0.0.1"]', '("127.0.0.1",)', '"127.0.0.1"'])
def test_allow_hosts_restreint_un_test_network(
    pytester: pytest.Pytester, hotes: str
) -> None:
    # 192.0.2.1 (TEST-NET-1, RFC 5737) : jamais joint, refuse avant tout envoi
    source = f"""
import socket

import pytest
from pytest_socket import SocketConnectBlockedError


@pytest.mark.network
@pytest.mark.allow_hosts({hotes})
def test_restreint():
    with socket.create_server(("127.0.0.1", 0)) as serveur:
        socket.create_connection(serveur.getsockname()[:2], timeout=5).close()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        with pytest.raises(SocketConnectBlockedError):
            client.connect(("192.0.2.1", 9))
"""
    _suite(pytester, source, "--run-network").assert_outcomes(passed=1)


@pytest.mark.parametrize(
    ("derogation", "erreur"),
    [
        (
            "@pytest.mark.enable_socket\ndef test_a():",
            "*'enable_socket' not found in `markers`*",
        ),
        (
            "@pytest.mark.allow_hosts(['127.0.0.1'])\ndef test_a():",
            "*acces reseau reserve aux tests marques network",
        ),
        ("def test_a(socket_enabled):", "*fixture 'socket_enabled' not found*"),
    ],
    ids=["enable_socket", "allow_hosts", "socket_enabled"],
)
def test_derogation_reseau_refusee(
    pytester: pytest.Pytester, derogation: str, erreur: str
) -> None:
    # hooks de pytest-socket desactives : ses derogations n'existent plus, et
    # allow_hosts ne fait que restreindre un test network
    resultat = _suite(pytester, f"import pytest\n\n{derogation}\n    pass\n")
    assert resultat.ret != pytest.ExitCode.OK
    pytest.LineMatcher(resultat.outlines + resultat.errlines).fnmatch_lines([erreur])


def test_option_force_enable_socket_inconnue(pytester: pytest.Pytester) -> None:
    resultat = _suite(pytester, "def test_a():\n    pass\n", "--force-enable-socket")
    assert resultat.ret == pytest.ExitCode.USAGE_ERROR


def test_socket_bloquee_dans_cette_suite() -> None:
    with pytest.raises(SocketBlockedError):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)


@pytest.mark.parametrize(
    "resolution",
    [
        lambda: socket.getaddrinfo("dc01", 389),
        lambda: socket.gethostbyname("dc01"),
        lambda: socket.gethostbyname_ex("dc01"),
        lambda: socket.gethostbyaddr("192.0.2.1"),
        lambda: socket.getnameinfo(("192.0.2.1", 389), 0),
        lambda: socket.getfqdn("dc01"),
    ],
    ids=[
        "getaddrinfo",
        "gethostbyname",
        "gethostbyname_ex",
        "gethostbyaddr",
        "getnameinfo",
        "getfqdn",
    ],
)
def test_resolution_dns_bloquee_dans_cette_suite(
    resolution: Callable[[], object],
) -> None:
    # le nom d'une cible ne doit pas partir vers le resolveur du poste ou du runner
    with pytest.raises(SocketBlockedError):
        resolution()


def test_repertoire_courant_hors_du_depot(tmp_path: Path) -> None:
    assert Path.cwd() == tmp_path
    assert RACINE not in Path.cwd().parents


def test_fixtures_communes(
    registre_factice: list[CheckFactice], horloge_figee: Callable[[], datetime]
) -> None:
    (sans_gap, avec_gap) = registre_factice
    cible = Target.parse("winrm://dc01")
    contexte = Context(cible, clock=horloge_figee)
    assert sans_gap.evaluate(FactSet(), contexte).status is Status.PASS
    resultat = avec_gap.evaluate(FactSet(), contexte)
    assert resultat.status is Status.GAP
    assert [g.severity for g in resultat.gaps] == ["high"]
    # Gaps rattaches au check et a la cible recue, comme le fera le moteur (#21)
    gaps = resultat.gaps
    assert all((g.check_id, g.target) == (avec_gap.id, cible.id) for g in gaps)
    assert avec_gap.cibles == [cible]
    assert horloge_figee() == horloge_figee()
    assert horloge_figee().utcoffset() == timedelta(0)


def test_seuil_de_couverture_bloquant(pytester: pytest.Pytester) -> None:
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


def test_ci_mesure_la_couverture_et_l_absence_d_artefacts() -> None:
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
    (controle,) = [c for c in commandes if "git status --porcelain" in c]
    # les sorties d'amnesia sont ignorees par git : git status ne les voit pas
    assert "git ls-files --others --ignored" in controle
    assert "amnesia" not in controle  # aucune exception pour les rapports
