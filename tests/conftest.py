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

import dataclasses
import re
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
from amnesia.checks.base import CheckResult, Confidence, Evidence, Severity
from amnesia.checks.context import Context
from amnesia.facts import FactSet
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
    """Check sans effet de bord : rend les Gaps fournis et note ses cibles.

    Les Gaps sont rattaches a ce check et a la cible recue, comme l'exige
    CheckResult : le moteur (#21) peut les executer sur n'importe quelle cible.
    """

    def __init__(self, id: str, title: str, gaps: list[Gap] | None = None) -> None:
        self.id = id
        self.title = title
        self.gaps = list(gaps or [])
        self.cibles: list[Target] = []

    def evaluate(self, facts: FactSet, ctx: Context) -> CheckResult:
        self.cibles.append(ctx.target)
        gaps = [
            dataclasses.replace(g, check_id=self.id, target=ctx.target.id)
            for g in self.gaps
        ]
        if gaps:
            return CheckResult.with_gaps(self.id, ctx.target.id, gaps)
        return CheckResult.passed(self.id, ctx.target.id)


@pytest.fixture
def registre_factice(monkeypatch: pytest.MonkeyPatch) -> list[CheckFactice]:
    """Remplace le registre de la CLI par deux checks factices."""
    checks = [
        CheckFactice("test.sans_gap", "Check factice sans angle mort"),
        CheckFactice(
            "test.avec_gap",
            "Check factice avec un angle mort",
            [
                Gap(
                    check_id="test.avec_gap",
                    target="local",
                    resource="Security",
                    question="Qui s'est connecte ?",
                    reason="journal factice ecrase",
                    severity=Severity.HIGH,
                    evidence=Evidence(
                        observed=4,
                        expected=90,
                        unit="days",
                        confidence=Confidence.MEASURED,
                        source="journal factice",
                    ),
                    remediation="agrandir le journal factice",
                )
            ],
        ),
    ]
    monkeypatch.setattr(cli, "default_checks", lambda: list(checks))
    return checks


@pytest.fixture
def horloge_figee() -> Callable[[], datetime]:
    """Horloge a injecter : renvoie toujours INSTANT_FIGE (UTC)."""
    return lambda: INSTANT_FIGE


# --- rendus sans ressource externe (#26, reutilise par le HTML de #77) --------

# cible absolue : un schema (https:, file:, ftp:...) ou une URL relative au
# protocole (//cdn.example) ; une cible relative ou data: ne charge rien a distance
_CIBLE_DISTANTE = r"(?:[a-z][a-z0-9+.\-]*:)?//"
_RESSOURCES_EXTERNES = (
    # image Markdown en ligne : ![alt](https://...) ou ![alt](<https://...>)
    re.compile(r"!\[[^\]]*\]\(\s*<?\s*" + _CIBLE_DISTANTE, re.I),
    # elements HTML qui chargent une ressource des l'affichage (image, script,
    # feuille de style, police, cadre, media, SVG <use>/<image>)
    re.compile(
        r"<(?:img|script|link|iframe|frame|embed|object|source|track|video|audio"
        r"|use|image|input)\b[^>]*?\b(?:src|href|data|poster|srcset|xlink:href)"
        r"\s*=\s*[\"']?\s*" + _CIBLE_DISTANTE,
        re.I | re.S,
    ),
    # CSS : url(https://...) (fond, police @font-face) et @import
    re.compile(r"url\(\s*[\"']?\s*" + _CIBLE_DISTANTE, re.I),
    re.compile(r"@import\b", re.I),
    # redirection automatique
    re.compile(r"<meta\b[^>]*http-equiv\s*=\s*[\"']?refresh", re.I | re.S),
)
# image Markdown par reference : ![alt][ref] puis [ref]: https://...
_IMAGE_PAR_REFERENCE = re.compile(r"!\[[^\]]*\]\s*\[([^\]]*)\]")
_DEFINITION = re.compile(r"^[ \t]*\[([^\]]+)\]:[ \t]*<?(\S+?)>?[ \t]*(?:$|[ \t])", re.M)
_DISTANTE = re.compile(_CIBLE_DISTANTE, re.I)


def assert_no_external_resources(content: str) -> None:
    """Echoue si ``content`` (Markdown, HTML ou texte) charge une ressource
    externe a l'affichage : image, script, feuille de style, police, cadre,
    media, redirection. Les liens de reference restent du texte et passent.
    """
    trouves = [
        f"{content.count(chr(10), 0, t.start()) + 1}: {t.group(0)[:60]!r}"
        for motif in _RESSOURCES_EXTERNES
        for t in motif.finditer(content)
    ]
    definitions = {e.lower(): c for e, c in _DEFINITION.findall(content)}
    for t in _IMAGE_PAR_REFERENCE.finditer(content):
        cible = definitions.get(t.group(1).lower(), "")
        if _DISTANTE.match(cible):
            ligne = content.count("\n", 0, t.start()) + 1
            trouves.append(f"{ligne}: {t.group(0)[:60]!r} -> {cible[:60]!r}")
    assert not trouves, "ressource(s) externe(s) dans le rendu : " + ", ".join(
        sorted(trouves)
    )


@pytest.fixture(name="assert_no_external_resources")
def _assert_no_external_resources() -> Callable[[str], None]:
    """Le helper ci-dessus, sous forme de fixture : importable par tout test."""
    return assert_no_external_resources
