# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

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
import html
import re
import shutil
import socket
import sys
import tempfile
from collections.abc import Callable, Generator
from datetime import UTC, datetime
from html.parser import HTMLParser
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
_VRAIE_SOCKET = socket.socket  # noqa: TID251 - restaure, n'ouvre rien
_VRAI_CONNECT = _VRAIE_SOCKET.connect

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
    # le rapport par defaut (amnesia-out/amnesia-report.json) est relatif au repertoire
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
#
# Liste blanche : une cible de ressource n'est admise que relative (ni schema ni
# //) ou en data:. Le HTML passe par html.parser, qui decode les entites des
# attributs comme le navigateur ; le CSS est lu apres ses echappements ; le
# Markdown suit CommonMark (references condensees et raccourcies, etiquettes
# normalisees, crochets imbriques ou echappes, definitions n'importe ou).

# schema en tete (https:, file:, javascript:...) : « https:cdn.example », sans
# //, est distant aussi (schema special, barres obliques facultatives)
_SCHEMA = re.compile(r"[a-z][a-z0-9+.\-]*:", re.I)
# ce que l'analyseur d'URL ignore : controles C0 et espace en tete et en queue,
# tabulations et sauts de ligne partout
_ROGNES = "".join(map(chr, range(0x21)))
_IGNORES = str.maketrans("", "", "\t\n\r")


def _cible_distante(valeur: str) -> bool:
    """Vrai si ``valeur``, lue comme le ferait un navigateur, charge hors du
    document : schéma autre que ``data:``, ou URL relative au protocole."""
    url = valeur.strip(_ROGNES).translate(_IGNORES).replace("\\", "/")
    if url.startswith("//"):
        return True
    schema = _SCHEMA.match(url)
    return schema is not None and schema.group(0).lower() != "data:"


# CSS : echappements (\72 ou \r), commentaires, chaines et url() non citees
_ECHAPPEMENT_CSS = re.compile(r"\\(?:([0-9a-fA-F]{1,6})[ \t\n\r\f]?|(.))", re.S)
_COMMENTAIRE_CSS = re.compile(r"/\*.*?(?:\*/|\Z)", re.S)
_JETON_CSS = re.compile(
    r"\"((?:\\.|[^\"\\])*)\"|'((?:\\.|[^'\\])*)'|url\(\s*([^\s\"')][^\s)]*)",
    re.I | re.S,
)


def _sans_echappement_css(texte: str) -> str:
    def car(m: re.Match[str]) -> str:
        if m.group(1) is None:
            return m.group(2)
        point = int(m.group(1), 16)
        return chr(point) if 0 < point <= 0x10FFFF else "\ufffd"

    return _ECHAPPEMENT_CSS.sub(car, texte)


def _css_distant(css: str) -> list[tuple[int, str]]:
    """(ligne relative, extrait) des ressources distantes d'une feuille de
    style : ``@import``, ``url()``, ``image-set()``, ``src()``... Toute chaîne
    CSS qui commence par un schéma compte, même hors d'une fonction (strict)."""
    trouves: list[tuple[int, str]] = []
    # deux lectures : brute (chaines a guillemets echappes intactes) et sans
    # echappements (u\72l( redevient url( ; \40import, @import)
    for texte in (css, _sans_echappement_css(css)):
        texte = _COMMENTAIRE_CSS.sub(" ", texte)
        trouves.extend(
            (texte.count("\n", 0, m.start()), m.group(0)[:60])
            for m in re.finditer(r"@import\b", texte, re.I)
        )
        for m in _JETON_CSS.finditer(texte):
            valeur = next(g for g in m.groups() if g is not None)
            if _cible_distante(_sans_echappement_css(valeur)):
                trouves.append((texte.count("\n", 0, m.start()), m.group(0)[:60]))
    return trouves


# attributs dont la valeur est une URL chargee a l'affichage (ou a l'envoi d'un
# formulaire, ou au clic pour ping) ; href compte hors de <a> et <area>, ou il
# n'est qu'un lien
_ATTRIBUTS_URL = frozenset(
    {
        "src",
        "data",
        "poster",
        "background",
        "xlink:href",
        "action",
        "formaction",
        "manifest",
        "codebase",
        "lowsrc",
        "dynsrc",
        "longdesc",
        "icon",
    }
)
_LIENS = frozenset({"a", "area"})


def _urls_d_attribut(balise: str, nom: str, valeur: str) -> list[str]:
    if nom in {"srcset", "imagesrcset"}:
        # candidats separes par des virgules : URL puis descripteur (2x, 640w)
        return [c.split()[0] for c in valeur.split(",") if c.split()]
    if nom == "ping":
        return valeur.split()
    if nom in _ATTRIBUTS_URL or (nom == "href" and balise not in _LIENS):
        return [valeur]
    return []


class _AnalyseHtml(HTMLParser):
    """Relève les ressources distantes d'un document HTML (ou du HTML brut d'un
    Markdown). Le contenu d'un ``<script>`` en ligne n'est pas analysé."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.trouves: list[tuple[int, str]] = []
        self._dans_style = False

    def _noter(self, extrait: str, decalage: int = 0) -> None:
        self.trouves.append((self.getpos()[0] + decalage, extrait[:60]))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # <base href> rend distante toute URL relative du document
        if tag == "base":
            self._noter(self.get_starttag_text() or "<base>")
        # chaque occurrence d'un attribut, pas seulement la premiere ou la
        # derniere : le navigateur garde la premiere, un dict la derniere
        valeurs = [(nom, valeur) for nom, valeur in attrs if valeur is not None]
        if tag == "meta" and any(
            nom == "http-equiv" and "refresh" in valeur.lower()
            for nom, valeur in valeurs
        ):
            self._noter(self.get_starttag_text() or "<meta>")
        for nom, valeur in valeurs:
            if any(_cible_distante(u) for u in _urls_d_attribut(tag, nom, valeur)):
                self._noter(f"<{tag} {nom}={valeur!r}>")
            elif nom == "style":
                for decalage, extrait in _css_distant(valeur):
                    self._noter(extrait, decalage)
            elif nom == "srcdoc":
                # document d'un <iframe>, deja decode : analyse a son tour
                for _ligne, extrait in _html_distant(valeur):
                    self._noter(f"srcdoc: {extrait}")
        if tag == "style":
            self._dans_style = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "style":
            self._dans_style = False

    def handle_data(self, data: str) -> None:
        if self._dans_style:
            # html.unescape en plus : un <style> de SVG decode ses entites
            for css in {data, html.unescape(data)}:
                for decalage, extrait in _css_distant(css):
                    self._noter(extrait, decalage)


def _html_distant(texte: str) -> list[tuple[int, str]]:
    analyse = _AnalyseHtml()
    analyse.feed(texte)
    analyse.close()
    return analyse.trouves


# Markdown : echappements de ponctuation ASCII, decodes dans une destination
_ECHAPPEMENT_MD = re.compile(r"\\([!-/:-@\[-`{-~])")
# definition de reference, n'importe ou (bloc de citation, liste...) :
# [etiquette]: destination, sur la meme ligne ou la suivante
_DEFINITION = re.compile(
    r"\[((?:\\.|[^\[\]\\])+)\]:[ \t]*(?:\n[ \t>]*)?<?([^\s>]*)", re.S
)


def _destination_md(valeur: str) -> str:
    return html.unescape(_ECHAPPEMENT_MD.sub(r"\1", valeur))


def _etiquette(texte: str) -> str:
    # normalisation CommonMark : espaces reduits, casse repliee
    return " ".join(texte.split()).casefold()


def _echappe(texte: str, i: int) -> bool:
    # texte[i] precede d'un nombre impair de barres obliques inverses
    n = 0
    while i - n > 0 and texte[i - n - 1] == "\\":
        n += 1
    return n % 2 == 1


def _crochet_fermant(texte: str, i: int) -> int | None:
    # indice du ] qui ferme le [ de texte[i], crochets imbriques et echappes
    profondeur = 0
    while i < len(texte):
        if texte[i] == "\\":
            i += 2
            continue
        if texte[i] == "[":
            profondeur += 1
        elif texte[i] == "]":
            profondeur -= 1
            if profondeur == 0:
                return i
        i += 1
    return None


def _markdown_distant(texte: str) -> list[tuple[int, str]]:
    definitions: dict[str, list[str]] = {}
    for m in _DEFINITION.finditer(texte):
        definitions.setdefault(_etiquette(m.group(1)), []).append(m.group(2))
    trouves: list[tuple[int, str]] = []
    for m in re.finditer(r"!\[", texte):
        if _echappe(texte, m.start()):
            continue
        fin = _crochet_fermant(texte, m.start() + 1)
        if fin is None:
            continue
        ligne = texte.count("\n", 0, m.start()) + 1
        suite = texte[fin + 1 :]
        # en ligne : ![alt](destination), ![alt](<destination>)
        en_ligne = re.match(r"\(\s*<?\s*([^\s)>]*)", suite)
        if en_ligne and _cible_distante(_destination_md(en_ligne.group(1))):
            trouves.append((ligne, texte[m.start() : fin + 1 + en_ligne.end()]))
            continue
        # par reference : complete ![alt][ref], condensee ![alt][] ou raccourcie
        # ![alt] ; l'etiquette et le texte alternatif sont cherches tous deux
        etiquettes = [texte[m.start() + 2 : fin]]
        reference = re.match(r"[ \t]*\n?[ \t]*\[", suite)
        if reference:
            debut = fin + 1 + reference.end() - 1
            fin_ref = _crochet_fermant(texte, debut)
            if fin_ref is not None:
                etiquettes.append(texte[debut + 1 : fin_ref])
        cibles = [
            cible
            for etiquette in etiquettes
            for cible in definitions.get(_etiquette(etiquette), [])
            if _cible_distante(_destination_md(cible))
        ]
        if cibles:
            trouves.append((ligne, f"{texte[m.start() : fin + 1]} -> {cibles[0]}"))
    return trouves


def assert_no_external_resources(content: str) -> None:
    """Echoue si ``content`` (Markdown, HTML ou texte) charge une ressource
    externe a l'affichage : image, script, feuille de style, police, cadre,
    media, redirection, ``<base>``. Les liens (``<a href>``, liens Markdown,
    URL dans le texte) restent du texte et passent.

    Liste blanche : une cible n'est admise que relative ou en ``data:``, après
    décodage des entités HTML, des échappements CSS et Markdown, et
    normalisation (``\\`` vaut ``/``, tabulations et sauts de ligne ignorés).
    Strict : une chaîne CSS qui commence par un schéma est refusée, même hors
    d'une fonction ``url()``.
    """
    texte = content.replace("\r\n", "\n").replace("\r", "\n")
    trouves = sorted({*_html_distant(texte), *_markdown_distant(texte)})
    assert not trouves, "ressource(s) externe(s) dans le rendu : " + ", ".join(
        f"{ligne}: {extrait!r}" for ligne, extrait in trouves
    )


@pytest.fixture(name="assert_no_external_resources")
def _assert_no_external_resources() -> Callable[[str], None]:
    """Le helper ci-dessus, sous forme de fixture : importable par tout test."""
    return assert_no_external_resources
