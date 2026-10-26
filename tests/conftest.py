"""Socle commun des tests : marqueurs d'environnement, reseau bloque, isolation.

Arborescence :
- tests/unit/ : code d'amnesia en processus, sans effet de bord ;
- tests/integration/ : vrais processus (CLI lancee par l'interpreteur, binaires) ;
- tests/fixtures/ : donnees de test anonymisees (raw/ n'est jamais commite) ;
- tests/*.py : outillage du depot (configuration, hooks, CI).

Marqueurs d'environnement, tous desactives par defaut :
- windows : ignore hors Windows (sys.platform != "win32") ;
- admin, lab, cloud, network : lances seulement avec --run-<marqueur>.

Le reseau est coupe par pytest-socket (--disable-socket dans addopts) et
reactive seulement pour les tests marques network. pytest-socket ne voit que le
processus de pytest : un sous-processus lance par un test n'est pas filtre.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from amnesia import cli
from amnesia.checks import Check, Gap

pytest_plugins = ["pytester"]

# marqueur -> environnement requis ; chacun ajoute l'option --run-<marqueur>
MARQUEURS_SUR_OPTION = {
    "admin": "des droits administrateur",
    "lab": "le lab Active Directory",
    "cloud": "un tenant cloud de test",
    "network": "un acces reseau",
}

# acces reseau accorde par pytest-socket, reserve aux tests marques network
DEROGATIONS_RESEAU = ("enable_socket", "allow_hosts")

INSTANT_FIGE = datetime(2026, 10, 21, 9, 30, tzinfo=UTC)


def pytest_addoption(parser: pytest.Parser) -> None:
    groupe = parser.getgroup("amnesia", "tests amnesia dependant d'un environnement")
    for marqueur, besoin in MARQUEURS_SUR_OPTION.items():
        groupe.addoption(
            f"--run-{marqueur}",
            action="store_true",
            default=False,
            help=f"lance les tests marques {marqueur} (necessitent {besoin})",
        )


def pytest_configure(config: pytest.Config) -> None:
    # declares ici et non dans pyproject : les options --run-* en derivent
    config.addinivalue_line("markers", "windows: test reserve a Windows")
    for marqueur, besoin in MARQUEURS_SUR_OPTION.items():
        config.addinivalue_line(
            "markers", f"{marqueur}: necessite {besoin} (--run-{marqueur})"
        )


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    for item in items:
        reseau = item.get_closest_marker("network") is not None
        if not reseau and (
            any(item.get_closest_marker(m) for m in DEROGATIONS_RESEAU)
            or "socket_enabled" in getattr(item, "fixturenames", ())
        ):
            raise pytest.UsageError(
                f"{item.nodeid} : acces reseau reserve aux tests marques network"
            )
        if item.get_closest_marker("windows") and sys.platform != "win32":
            item.add_marker(
                pytest.mark.skip(reason=f"test Windows (plateforme : {sys.platform})")
            )
        for marqueur, besoin in MARQUEURS_SUR_OPTION.items():
            if item.get_closest_marker(marqueur) and not config.getoption(
                f"--run-{marqueur}"
            ):
                item.add_marker(
                    pytest.mark.skip(
                        reason=f"necessite {besoin} : relancer avec --run-{marqueur}"
                    )
                )
        if reseau and config.getoption("--run-network"):
            item.add_marker(pytest.mark.enable_socket)


@pytest.fixture(autouse=True)
def _repertoire_courant_isole(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # le rapport par defaut (amnesia-report.json) est relatif au repertoire
    # courant : aucun test ne doit pouvoir l'ecrire dans le depot
    monkeypatch.chdir(tmp_path)


class CheckFactice(Check):
    """Check sans effet de bord : renvoie les Gaps fournis et note ses cibles."""

    def __init__(self, id: str, title: str, gaps: list[Gap] | None = None) -> None:
        self.id = id
        self.title = title
        self.gaps = list(gaps or [])
        self.cibles: list[str] = []

    def run(self, target: str) -> list[Gap]:
        self.cibles.append(target)
        return list(self.gaps)


@pytest.fixture
def registre_factice(monkeypatch: pytest.MonkeyPatch) -> list[Check]:
    """Remplace le registre de la CLI par deux checks factices."""
    checks: list[Check] = [
        CheckFactice("test.sans_gap", "Check factice sans angle mort"),
        CheckFactice(
            "test.avec_gap",
            "Check factice avec un angle mort",
            [Gap("Qui s'est connecte ?", "journal factice ecrase", "high")],
        ),
    ]
    monkeypatch.setattr(cli, "default_checks", lambda: list(checks))
    return checks


@pytest.fixture
def horloge_figee() -> Callable[[], datetime]:
    """Horloge a injecter : renvoie toujours INSTANT_FIGE (UTC)."""
    return lambda: INSTANT_FIGE
