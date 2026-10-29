"""Socle commun des tests : marqueurs d'environnement, reseau bloque, isolation.

Arborescence :
- tests/unit/ : code d'amnesia en processus, sans effet de bord ;
- tests/integration/ : vrais processus (CLI lancee par l'interpreteur, binaires) ;
- tests/fixtures/ : donnees de test anonymisees (raw/ n'est jamais commite) ;
- tests/*.py : outillage du depot (configuration, hooks, CI).

Marqueurs d'environnement, tous desactives par defaut :
- windows : ignore hors Windows (sys.platform != "win32") ;
- admin, lab, cloud, network : lances seulement avec --run-<marqueur>.

Le reseau (sockets et resolution DNS) est coupe des le debut de la session,
collecte comprise, et rouvert seulement pendant les tests marques network lances
avec --run-network (setup, appel et teardown, fixtures comprises), restreint
aux hotes de allow_hosts si le test en porte. Le plugin pytest-socket est
desactive (-p no:socket dans addopts) : il rouvrait le reseau avant les
finaliseurs des fixtures et offrait des derogations (enable_socket,
socket_enabled, --force-enable-socket) ; seules ses fonctions servent ici.
Limite : un sous-processus lance par un test n'est pas filtre.
"""

from __future__ import annotations

import shutil
import socket
import sys
import tempfile
from collections.abc import Callable, Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn

import pytest
import pytest_socket

from amnesia import cli
from amnesia.checks import Check, Gap
from amnesia.target import Target

pytest_plugins = ["pytester"]

# marqueur -> environnement requis ; chacun ajoute l'option --run-<marqueur>
MARQUEURS_SUR_OPTION = {
    "admin": "des droits administrateur",
    "lab": "le lab Active Directory",
    "cloud": "un tenant cloud de test",
    "network": "un acces reseau",
}

# resolutions DNS que pytest-socket laisse passer (getfqdn passe par
# gethostbyaddr) ; il ne bloque que getaddrinfo et gethostbyname
RESOLUTIONS_NON_BLOQUEES = ("gethostbyname_ex", "gethostbyaddr", "getnameinfo")
_VRAIES_RESOLUTIONS = {nom: getattr(socket, nom) for nom in RESOLUTIONS_NON_BLOQUEES}
# allow_hosts remplace connect sur la vraie classe socket : restaure a chaque bascule
_VRAIE_SOCKET = socket.socket
_VRAI_CONNECT = socket.socket.connect

INSTANT_FIGE = datetime(2026, 10, 21, 9, 30, tzinfo=UTC)


def _resolution_refusee(nom: str) -> Callable[..., NoReturn]:
    def refus(*_args: Any, **_kwargs: Any) -> NoReturn:
        raise pytest_socket.SocketBlockedError(f"A test tried to use socket.{nom}.")

    return refus


def _couper_le_reseau() -> None:
    _VRAIE_SOCKET.connect = _VRAI_CONNECT  # type: ignore[method-assign]
    pytest_socket.disable_socket()
    for nom in RESOLUTIONS_NON_BLOQUEES:
        setattr(socket, nom, _resolution_refusee(nom))


def _ouvrir_le_reseau(hotes: list[str] | None = None) -> None:
    pytest_socket.enable_socket()
    _VRAIE_SOCKET.connect = _VRAI_CONNECT  # type: ignore[method-assign]
    for nom, vraie in _VRAIES_RESOLUTIONS.items():
        setattr(socket, nom, vraie)
    if hotes is not None:
        pytest_socket.socket_allow_hosts(hotes)


def pytest_addoption(parser: pytest.Parser) -> None:
    groupe = parser.getgroup("amnesia", "tests amnesia dependant d'un environnement")
    for marqueur, besoin in MARQUEURS_SUR_OPTION.items():
        groupe.addoption(
            f"--run-{marqueur}",
            action="store_true",
            default=False,
            help=f"lance les tests marques {marqueur} (necessitent {besoin})",
        )


# dossier temporaire des caches de hypothesis, supprime en fin de session
_CACHE_HYPOTHESIS: list[Path] = []


def pytest_configure(config: pytest.Config) -> None:
    # declares ici et non dans pyproject : les options --run-* en derivent
    config.addinivalue_line("markers", "windows: test reserve a Windows")
    for marqueur, besoin in MARQUEURS_SUR_OPTION.items():
        config.addinivalue_line(
            "markers", f"{marqueur}: necessite {besoin} (--run-{marqueur})"
        )
    config.addinivalue_line(
        "markers", "allow_hosts(hotes): restreint un test network a ces hotes"
    )
    # caches de hypothesis (exemples, constantes, donnees Unicode) hors du depot :
    # sinon .hypothesis/ est cree dans le repertoire courant, et la CI refuse
    # tout fichier ecrit dans le depot par les tests
    from hypothesis.configuration import set_hypothesis_home_dir

    _CACHE_HYPOTHESIS.append(Path(tempfile.mkdtemp(prefix="amnesia-hypothesis-")))
    set_hypothesis_home_dir(_CACHE_HYPOTHESIS[0])


@pytest.hookimpl(tryfirst=True)
def pytest_sessionstart(session: pytest.Session) -> None:
    # avant la collecte : le code execute a l'import des tests est couvert
    _couper_le_reseau()


def pytest_unconfigure(config: pytest.Config) -> None:
    _ouvrir_le_reseau()
    for dossier in _CACHE_HYPOTHESIS:
        shutil.rmtree(dossier, ignore_errors=True)


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    for item in items:
        if item.get_closest_marker("allow_hosts") and not item.get_closest_marker(
            "network"
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


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item: pytest.Item) -> None:
    # avant les fixtures : elles suivent la politique reseau du test
    if item.get_closest_marker("network") and item.config.getoption("--run-network"):
        marque = item.get_closest_marker("allow_hosts")
        if marque is None:
            _ouvrir_le_reseau()
            return
        # pytest-socket ne restreint rien s'il recoit autre chose qu'une liste
        hotes = marque.args[0]
        _ouvrir_le_reseau(hotes.split(",") if isinstance(hotes, str) else list(hotes))
    else:
        _couper_le_reseau()


@pytest.hookimpl(wrapper=True)
def pytest_runtest_teardown(item: pytest.Item) -> Generator[None, None, None]:
    # apres les finaliseurs des fixtures, y compris de portee module ou session
    try:
        return (yield)
    finally:
        _couper_le_reseau()


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
        self.cibles: list[Target] = []

    def run(self, target: Target) -> list[Gap]:
        self.cibles.append(target)
        return list(self.gaps)


@pytest.fixture
def registre_factice(monkeypatch: pytest.MonkeyPatch) -> list[CheckFactice]:
    """Remplace le registre de la CLI par deux checks factices."""
    checks = [
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
