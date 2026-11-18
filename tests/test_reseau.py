# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Frontière réseau (#26) : seuls les collecteurs listés peuvent se connecter.

Garde-fous indépendants :
- la règle ruff TID251 (banned-api) interdit les API réseau hors des chemins
  de ``per-file-ignores`` (vérifiée sur cas dans tests/test_regles_ruff.py),
  sans dérogation par ``noqa`` dans ``src/`` ;
- ce fichier parcourt l'AST de ``src/`` hors de MODULES_RESEAU : aucun import
  d'un module réseau (bibliothèque standard ou SDK), ``importlib.import_module``
  et ``__import__`` d'un nom littéral compris, ni aucune méthode de connexion
  (``loop.create_connection``...) quel que soit l'objet qui la porte ; et
  MODULES_RESEAU est exactement la liste des ``per-file-ignores`` de TID251 ;
- ruff lève TID251 en entier dans les collecteurs, pas seulement ses API
  réseau : les autres API interdites y sont vérifiées par ruff relancé sur
  ``src/`` et ``tests/`` sans dérogation ni ``noqa``, et ``set_stream_logger``
  est refusé sur l'AST de ``src/`` et de ``tests/``, quel que soit son
  receveur ;
- chaque sous-processus lancé depuis ``src/`` reçoit ``env=subprocess_env()``
  (télémétrie et mises à jour de PowerShell coupées), ``loop.subprocess_exec``
  et ``loop.subprocess_shell`` compris ;
- l'engagement écrit : README (section « Confidentialité ») et docs.

Limite : une analyse statique ne voit pas un nom calculé (``getattr``,
``import_module(variable)``) ; les sentinelles en processus et en
sous-processus (tests/unit/test_sans_reseau.py, tests/sans_reseau.py) couvrent
l'exécution réelle des commandes.
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
import tomllib
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import pytest

RACINE = Path(__file__).resolve().parent.parent
SRC = RACINE / "src"
TESTS = RACINE / "tests"
PYPROJECT = RACINE / "pyproject.toml"
README = RACINE / "README.md"

MODULES_RESEAU = (
    # collecteurs (#20) : les seuls a joindre une cible, et seulement celle
    # que l'utilisateur a designee ; WinRM (#63) et cloud (#95) iront dans le
    # paquet collectors/
    "src/amnesia/facts/collectors.py",
    "src/amnesia/facts/collectors/**",
)
"""Chemins de ``src/`` autorisés à ouvrir une connexion (motifs ruff)."""

# modules dont l'import, hors de MODULES_RESEAU, trahit un acces reseau :
# bibliotheque standard, puis SDK prevus par les collecteurs (#44, #63, #95)
MODULES_INTERDITS = (
    "socket",
    "ssl",
    "http.client",
    "http.server",
    "urllib.request",
    "ftplib",
    "smtplib",
    "poplib",
    "imaplib",
    "xmlrpc.client",
    "xmlrpc.server",
    "socketserver",
    "multiprocessing.connection",
    "multiprocessing.managers",
    "webbrowser",
    "urllib3",
    "requests",
    "httpx",
    "aiohttp",
    "websocket",
    "websockets",
    "winrm",
    "pypsrp",
    "psrp",
    "spnego",
    "ldap3",
    "msal",
    "msgraph",
    "azure",
    "boto3",
    "botocore",
)

API_RESEAU = {
    "socket.socket",
    "socket.create_connection",
    "asyncio.open_connection",
    "asyncio.start_server",
    "asyncio.open_unix_connection",
    "asyncio.start_unix_server",
    "http.client",
    "urllib.request",
    "urllib3",
    "requests",
    "httpx",
    # journaux de donnees client envoyes a un tiers (« remontee d'erreurs »)
    "logging.handlers.SocketHandler",
    "logging.handlers.DatagramHandler",
    "logging.handlers.SysLogHandler",
    "logging.handlers.HTTPHandler",
    "logging.handlers.SMTPHandler",
    "logging.config.listen",
}
"""API que la règle TID251 doit interdire (issue #26)."""

# methodes de connexion dont le receveur est dynamique (boucle asyncio, objet
# recu en parametre) : ruff ne les resout pas, l'AST les refuse par leur nom
ATTRIBUTS_RESEAU = frozenset(
    {
        "create_connection",
        "create_server",
        "create_datagram_endpoint",
        "create_unix_connection",
        "create_unix_server",
        "connect_accepted_socket",
        "sock_connect",
        "sock_sendto",
        "getaddrinfo",
        "getnameinfo",
        "open_connection",
        "start_server",
        "open_unix_connection",
        "start_unix_server",
    }
)

# importations dynamiques : leur argument litteral compte comme un import
IMPORTS_DYNAMIQUES = frozenset({"importlib.import_module", "importlib.__import__"})

# interdits partout, collecteurs et tests compris, quel que soit le receveur :
# set_stream_logger pose sur botocore un handler sans plafond ni expurgation
# (Authorization, X-Amz-Security-Token en clair), et les journaux de CI d'un
# depot public sont publics. TID251 est leve dans les collecteurs, justement
# la ou boto3 sera importe (#95) : cette interdiction ne repose pas sur ruff.
NOMS_TOUJOURS_INTERDITS = frozenset({"set_stream_logger"})


def _ruff_lint() -> dict[str, Any]:
    with PYPROJECT.open("rb") as fichier:
        outil: dict[str, Any] = tomllib.load(fichier)["tool"]["ruff"]["lint"]
    return outil


def _fichiers(racine: Path = SRC) -> list[Path]:
    fichiers = sorted(racine.rglob("*.py"))
    assert fichiers
    return fichiers


def _relatif(fichier: Path) -> str:
    return fichier.relative_to(RACINE).as_posix()


def _arbre(fichier: Path) -> ast.AST:
    return ast.parse(fichier.read_text(encoding="utf-8"), filename=str(fichier))


def _autorise(fichier: Path) -> bool:
    return any(fnmatch(_relatif(fichier), motif) for motif in MODULES_RESEAU)


def _interdit(nom: str) -> bool:
    return any(nom == m or nom.startswith(m + ".") for m in MODULES_INTERDITS)


def _alias(arbre: ast.AST) -> dict[str, str]:
    # nom local -> nom qualifie : « import subprocess as sp », « from os import system »
    noms: dict[str, str] = {}
    for noeud in ast.walk(arbre):
        if isinstance(noeud, ast.Import):
            for alias in noeud.names:
                if alias.asname:
                    noms[alias.asname] = alias.name
                else:
                    racine = alias.name.partition(".")[0]
                    noms[racine] = racine
        elif isinstance(noeud, ast.ImportFrom) and noeud.module and noeud.level == 0:
            for alias in noeud.names:
                noms[alias.asname or alias.name] = f"{noeud.module}.{alias.name}"
    return noms


def _nom_qualifie(expr: ast.expr, alias: dict[str, str]) -> str | None:
    parties: list[str] = []
    while isinstance(expr, ast.Attribute):
        parties.append(expr.attr)
        expr = expr.value
    if not isinstance(expr, ast.Name):
        return None
    return ".".join([alias.get(expr.id, expr.id), *reversed(parties)])


def _argument_litteral(appel: ast.Call) -> str | None:
    # premier argument (ou name=) d'une importation dynamique, s'il est litteral
    nommes = (m.value for m in appel.keywords if m.arg == "name")
    for valeur in [*appel.args[:1], *nommes]:
        if isinstance(valeur, ast.Constant) and isinstance(valeur.value, str):
            return valeur.value
    return None


def _imports(arbre: ast.AST) -> list[tuple[int, str]]:
    # (ligne, module importe) : « import a.b », « from a.b import c » (c compris
    # quand a.b est un paquet : « from http import client »), et l'argument
    # litteral de importlib.import_module("a.b") ou __import__("a.b")
    alias = _alias(arbre)
    trouves: list[tuple[int, str]] = []
    for noeud in ast.walk(arbre):
        if isinstance(noeud, ast.Import):
            trouves.extend((noeud.lineno, nom.name) for nom in noeud.names)
        elif isinstance(noeud, ast.ImportFrom) and noeud.module and noeud.level == 0:
            trouves.append((noeud.lineno, noeud.module))
            trouves.extend(
                (noeud.lineno, f"{noeud.module}.{nom.name}") for nom in noeud.names
            )
        elif isinstance(noeud, ast.Call) and (
            _nom_qualifie(noeud.func, alias) in IMPORTS_DYNAMIQUES
            or (isinstance(noeud.func, ast.Name) and noeud.func.id == "__import__")
        ):
            module = _argument_litteral(noeud)
            if module is not None:
                trouves.append((noeud.lineno, module))
    return trouves


def _attributs_reseau(arbre: ast.AST) -> list[tuple[int, str]]:
    # (ligne, nom) de chaque methode de connexion, en attribut ou importee
    trouves: list[tuple[int, str]] = []
    for noeud in ast.walk(arbre):
        if isinstance(noeud, ast.Attribute) and noeud.attr in ATTRIBUTS_RESEAU:
            trouves.append((noeud.lineno, noeud.attr))
        elif isinstance(noeud, ast.ImportFrom):
            trouves.extend(
                (noeud.lineno, nom.name)
                for nom in noeud.names
                if nom.name in ATTRIBUTS_RESEAU
            )
    return trouves


def _acces_reseau(arbre: ast.AST) -> list[tuple[int, str]]:
    return [
        *((ligne, nom) for ligne, nom in _imports(arbre) if _interdit(nom)),
        *_attributs_reseau(arbre),
    ]


def _noms_toujours_interdits(arbre: ast.AST) -> list[tuple[int, str]]:
    # attribut (x.set_stream_logger), nom nu, import (from boto3 import ...)
    trouves: list[tuple[int, str]] = []
    for noeud in ast.walk(arbre):
        if isinstance(noeud, ast.Attribute):
            noms = [noeud.attr]
        elif isinstance(noeud, ast.Name):
            noms = [noeud.id]
        elif isinstance(noeud, ast.Import | ast.ImportFrom):
            noms = [nom.name.rpartition(".")[2] for nom in noeud.names]
        else:
            continue
        trouves.extend(
            (noeud.lineno, nom) for nom in noms if nom in NOMS_TOUJOURS_INTERDITS
        )
    return trouves


def test_outils_du_test() -> None:
    assert _interdit("socket")
    assert _interdit("urllib.request")
    assert _interdit("http.client")
    assert _interdit("socketserver")
    assert _interdit("multiprocessing.connection")
    assert not _interdit("urllib.parse")
    assert not _interdit("http")
    assert not _interdit("multiprocessing")
    # prefixe de module, pas de chaine : socket n'interdit pas socket_local
    assert not _interdit("socket_local")
    arbre = ast.parse("import socket\nfrom http import client\nfrom . import x\n")
    assert _imports(arbre) == [(1, "socket"), (2, "http"), (2, "http.client")]
    assert _autorise(SRC / "amnesia" / "facts" / "collectors.py")
    assert _autorise(SRC / "amnesia" / "facts" / "collectors" / "winrm.py")
    assert not _autorise(SRC / "amnesia" / "cli.py")


@pytest.mark.parametrize(
    "source",
    [
        "import socketserver\n",
        "from xmlrpc.server import SimpleXMLRPCServer\n",
        "from multiprocessing.connection import Client\n",
        "from multiprocessing import managers\n",
        'import webbrowser\nwebbrowser.open("https://exemple.invalid")\n',
        'import importlib\nM = importlib.import_module("urllib.request")\n',
        'from importlib import import_module as im\nM = im(name="http.client")\n',
        'M = __import__("socket")\n',
        "import asyncio\n"
        "R = asyncio.get_running_loop().create_connection(P, 'dc01', 5985)\n",
        "async def f(loop, s):\n    await loop.sock_connect(s, ('dc01', 5985))\n",
        "async def f(loop):\n    await loop.getaddrinfo('dc01', 5985)\n",
        "async def f(loop):\n    await loop.create_datagram_endpoint(P)\n",
        "from asyncio import open_connection\n",
        "import asyncio\nS = asyncio.start_server(rappel, port=0)\n",
    ],
    ids=[
        "socketserver",
        "xmlrpc-server",
        "multiprocessing-connection",
        "multiprocessing-managers",
        "webbrowser",
        "import-module",
        "import-module-alias",
        "dunder-import",
        "loop-create-connection",
        "sock-connect",
        "loop-getaddrinfo",
        "datagram",
        "from-asyncio",
        "start-server",
    ],
)
def test_acces_reseau_detecte(source: str) -> None:
    assert _acces_reseau(ast.parse(source))


@pytest.mark.parametrize(
    "source",
    [
        "import urllib.parse\n",
        "import importlib\nM = importlib.import_module(nom)\n",
        'import importlib\nM = importlib.import_module("amnesia.checks.windows")\n',
        "import multiprocessing\n",
        "import logging.handlers\nH = logging.handlers.RotatingFileHandler\n",
    ],
    ids=["urllib-parse", "import-dynamique", "import-local", "multiprocessing", "log"],
)
def test_acces_local_accepte(source: str) -> None:
    assert _acces_reseau(ast.parse(source)) == []


def test_aucun_acces_reseau_hors_des_collecteurs() -> None:
    trouves = [
        f"{_relatif(fichier)}:{ligne} {nom}"
        for fichier in _fichiers()
        if not _autorise(fichier)
        for ligne, nom in _acces_reseau(_arbre(fichier))
    ]
    assert not trouves


def test_aucun_acces_reseau_meme_dans_les_collecteurs_actuels() -> None:
    # aujourd'hui aucun collecteur reseau n'existe : la derogation est posee
    # pour #63 et #95, pas encore utilisee. A retirer quand elle le sera.
    trouves = [
        f"{_relatif(fichier)}:{ligne} {nom}"
        for fichier in _fichiers()
        if _autorise(fichier)
        for ligne, nom in _acces_reseau(_arbre(fichier))
    ]
    assert not trouves


def test_liste_des_collecteurs_reseau_identique_a_pyproject() -> None:
    # une seule liste : les per-file-ignores de TID251, tests/ compris (TID251
    # y reste actif, avec des noqa cibles)
    ignores = _ruff_lint()["per-file-ignores"]
    assert isinstance(ignores, dict)
    avec_tid251 = {motif for motif, regles in ignores.items() if "TID251" in regles}
    assert avec_tid251 == set(MODULES_RESEAU)
    # aucune derogation plus large (src/**, *.py...) ni fichier inexistant
    for motif in MODULES_RESEAU:
        assert motif.startswith("src/amnesia/")
        if "*" not in motif:
            assert (RACINE / motif).is_file(), motif


def test_tid251_active_et_api_interdites() -> None:
    lint = _ruff_lint()
    assert "TID251" in lint["select"]
    bannies = lint["flake8-tidy-imports"]["banned-api"]
    assert set(bannies) >= API_RESEAU
    for api in API_RESEAU:
        assert "#26" in bannies[api]["msg"]


def test_aucune_derogation_tid251_par_noqa() -> None:
    # un collecteur reseau s'ajoute aux per-file-ignores, jamais par un noqa
    motif = re.compile(r"#\s*(?:ruff\s*:\s*)?noqa\b[^\n]*\bTID251\b", re.IGNORECASE)
    trouves = [
        f"{_relatif(fichier)}:{numero}"
        for fichier in _fichiers()
        for numero, ligne in enumerate(
            fichier.read_text(encoding="utf-8").splitlines(), start=1
        )
        if motif.search(ligne)
    ]
    assert not trouves


# --- API interdites hors reseau : actives partout ---------------------------


@pytest.mark.parametrize(
    "source",
    [
        'import boto3\nboto3.set_stream_logger("")\n',
        "def f(session):\n    session.set_stream_logger('botocore')\n",
        "from boto3 import set_stream_logger as journal\n",
        "import boto3\nF = boto3.set_stream_logger\n",
    ],
    ids=["boto3", "session", "import", "reference"],
)
def test_set_stream_logger_detecte(source: str) -> None:
    assert _noms_toujours_interdits(ast.parse(source))


def test_set_stream_logger_cite_en_texte_accepte() -> None:
    # une chaine ou un commentaire n'installe aucun handler
    source = '# pas de set_stream_logger\nMSG = "set_stream_logger"\n'
    assert _noms_toujours_interdits(ast.parse(source)) == []


def test_set_stream_logger_nulle_part() -> None:
    # src/ (collecteurs compris, ou TID251 est leve) et tests/ (dont ceux de
    # --run-cloud, qui manipulent de vrais identifiants)
    trouves = [
        f"{_relatif(fichier)}:{ligne} {nom}"
        for fichier in [*_fichiers(SRC), *_fichiers(TESTS)]
        for ligne, nom in _noms_toujours_interdits(_arbre(fichier))
    ]
    assert not trouves


def _ruff_hors_reseau(
    *args: str, source: str | None = None
) -> subprocess.CompletedProcess[str]:
    """ruff TID251 avec les seules API interdites hors réseau (sans « #26 »),
    sans ``per-file-ignores`` ni ``noqa`` : ce qui reste interdit partout."""
    pytest.importorskip("ruff")
    bannies = _ruff_lint()["flake8-tidy-imports"]["banned-api"]
    table = ", ".join(
        f'"{api}" = {{ msg = "hors reseau" }}'
        for api, regle in sorted(bannies.items())
        if "#26" not in regle["msg"]
    )
    assert table
    return subprocess.run(  # noqa: S603 - interpreteur courant, arguments du test
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            "--no-cache",
            "--ignore-noqa",
            "--output-format=concise",
            "--select=TID251",
            "--config=lint.per-file-ignores = {}",
            f"--config=lint.flake8-tidy-imports.banned-api = {{ {table} }}",
            *args,
        ],
        input=source,
        capture_output=True,
        encoding="utf-8",
        check=False,
        cwd=RACINE,
        timeout=120,
    )


def test_api_interdites_hors_reseau_temoin() -> None:
    # temoin : ni la derogation des collecteurs ni un noqa ne jouent dans ce
    # controle
    sortie = _ruff_hors_reseau(
        "--stdin-filename=src/amnesia/facts/collectors.py",
        "-",
        source='import boto3\n\nboto3.set_stream_logger("")  # noqa: TID251\n',
    )
    assert sortie.returncode == 1, sortie.stdout + sortie.stderr
    assert "TID251" in sortie.stdout


def test_api_interdites_hors_reseau_actives_partout() -> None:
    # TID251 est leve en entier dans les collecteurs, et un noqa reseau d'un
    # test eteindrait toute la regle sur sa ligne : les API interdites pour
    # une autre raison que le reseau restent refusees partout
    sortie = _ruff_hors_reseau("src", "tests")
    assert sortie.returncode == 0, sortie.stdout + sortie.stderr


# --- sous-processus : environnement de subprocess_env() -------------------------

# lanceurs qui acceptent env= : chaque appel le recoit de subprocess_env(), sans
# quoi un pwsh enverrait sa telemetrie et verifierait ses mises a jour
LANCEURS_AVEC_ENV = frozenset(
    {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
    }
)
# methodes de boucle asyncio (receveur dynamique), reconnues par leur nom
METHODES_LANCEURS = frozenset({"subprocess_exec", "subprocess_shell"})
# lanceurs sans env= controlable (ou qui heritent de l'environnement) : interdits
LANCEURS_INTERDITS = re.compile(
    r"os\.(?:system|popen|startfile|exec\w*|spawn\w*|posix_spawn\w*)"
    r"|subprocess\.(?:getoutput|getstatusoutput)|pty\.spawn"
)


def _lanceur(expr: ast.expr, alias: dict[str, str]) -> str | None:
    # nom du lanceur a env= que designe expr, sinon None
    if isinstance(expr, ast.Attribute) and expr.attr in METHODES_LANCEURS:
        return f"<boucle>.{expr.attr}"
    nom = _nom_qualifie(expr, alias)
    return nom if nom in LANCEURS_AVEC_ENV else None


def _env_impose(appel: ast.Call) -> bool:
    # env=subprocess_env(...) explicite ; un **options ne se verifie pas
    for mot in appel.keywords:
        if mot.arg == "env":
            valeur = mot.value
            return isinstance(valeur, ast.Call) and (
                (
                    isinstance(valeur.func, ast.Name)
                    and valeur.func.id == "subprocess_env"
                )
                or (
                    isinstance(valeur.func, ast.Attribute)
                    and valeur.func.attr == "subprocess_env"
                )
            )
    return False


def _lancements_non_conformes(source: str) -> list[str]:
    """(ligne, lanceur) de chaque sous-processus lancé sans ``subprocess_env()``.

    Toute référence à un lanceur compte, pas seulement un appel direct :
    ``functools.partial(subprocess.run, ...)`` ou un alias échapperaient sinon
    à la vérification de ``env=``.
    """
    arbre = ast.parse(source)
    alias = _alias(arbre)
    conformes = {
        id(noeud.func)
        for noeud in ast.walk(arbre)
        if isinstance(noeud, ast.Call)
        and _lanceur(noeud.func, alias) is not None
        and _env_impose(noeud)
    }
    trouves: list[str] = []
    for noeud in ast.walk(arbre):
        if not isinstance(noeud, ast.Name | ast.Attribute) or id(noeud) in conformes:
            continue
        lanceur = _lanceur(noeud, alias)
        if lanceur is not None:
            trouves.append(f"{noeud.lineno} {lanceur}")
            continue
        nom = _nom_qualifie(noeud, alias)
        if nom is not None and LANCEURS_INTERDITS.fullmatch(nom):
            trouves.append(f"{noeud.lineno} {nom}")
    return trouves


@pytest.mark.parametrize(
    "source",
    [
        'import subprocess\nsubprocess.run(["pwsh"], check=True)\n',
        'import subprocess as sp\nsp.Popen(["pwsh"], env={"A": "1"})\n',
        "import os\nfrom subprocess import check_output as co\n"
        'co(["pwsh"], env=os.environ)\n',
        'import subprocess\nsubprocess.run(["pwsh"], **OPTIONS)\n',
        'import asyncio\nasyncio.create_subprocess_exec("pwsh")\n',
        'import os\nos.system("pwsh")\n',
        'from os import execvpe\nexecvpe("pwsh", ["pwsh"], {})\n',
        'import subprocess\nsubprocess.getoutput("pwsh")\n',
        "import functools, subprocess\n"
        "F = functools.partial(subprocess.run, env=subprocess_env())\n",
        "import asyncio\n"
        'T = asyncio.get_running_loop().subprocess_exec(Protocole, "pwsh")\n',
        'async def f(loop):\n    await loop.subprocess_shell(P, "pwsh", env={})\n',
    ],
    ids=[
        "sans-env",
        "env-litteral",
        "env-os-environ",
        "env-implicite",
        "asyncio-sans-env",
        "os-system",
        "os-exec",
        "getoutput",
        "reference",
        "loop-subprocess-exec",
        "loop-subprocess-shell",
    ],
)
def test_lancement_non_conforme_detecte(source: str) -> None:
    assert _lancements_non_conformes(source)


@pytest.mark.parametrize(
    "source",
    [
        "import subprocess\n"
        "from amnesia.facts import subprocess_env\n"
        'subprocess.run(["pwsh"], env=subprocess_env(), timeout=30)\n',
        "import asyncio\nfrom amnesia import facts\n"
        'asyncio.create_subprocess_exec("pwsh", env=facts.subprocess_env())\n',
        "from subprocess import Popen\n"
        'Popen(["pwsh"], env=subprocess_env({"PATH": "/bin"}))\n',
        "import subprocess\nE = subprocess.CalledProcessError\n",
        "async def f(loop):\n"
        '    await loop.subprocess_exec(P, "pwsh", env=subprocess_env())\n',
    ],
    ids=["run", "asyncio", "popen-from", "autre-attribut", "loop-subprocess-exec"],
)
def test_lancement_conforme_accepte(source: str) -> None:
    assert _lancements_non_conformes(source) == []


def test_tout_sous_processus_recoit_subprocess_env() -> None:
    trouves = [
        f"{_relatif(fichier)}:{lanceur}"
        for fichier in _fichiers()
        for lanceur in _lancements_non_conformes(fichier.read_text(encoding="utf-8"))
    ]
    assert not trouves


# --- engagement ecrit -----------------------------------------------------------


def _section(texte: str, titre: str) -> str:
    for morceau in re.split(r"^## ", texte, flags=re.MULTILINE)[1:]:
        entete, _, corps = morceau.partition("\n")
        if entete.strip() == titre:
            return " ".join(corps.split())
    raise AssertionError(f"section {titre!r} absente")


def test_readme_section_confidentialite() -> None:
    corps = _section(README.read_text(encoding="utf-8"), "Confidentialité")
    for engagement in (
        "télémétrie",
        "vérification de mise à jour",
        "rapport de plantage",
        "sans accès Internet",
        "cibles",
        "`POWERSHELL_TELEMETRY_OPTOUT=1`",
        "ressource externe",
        "hors ligne",
    ):
        assert engagement in corps, engagement


@pytest.mark.parametrize(
    ("document", "attendu"),
    [
        ("SECURITY.md", "README.md#confidentialité"),
        ("docs/dev/faits.md", "TID251"),
        ("docs/dev/faits.md", "subprocess_env()"),
        ("docs/dev/faits.md", "tests/test_reseau.py"),
        ("docs/dev/faits.md", "env=subprocess_env(...)"),
        ("README.md", "amnesia.facts.subprocess_env()"),
        ("CHANGELOG.md", "POWERSHELL_TELEMETRY_OPTOUT=1"),
    ],
)
def test_docs_renvoient_a_la_frontiere_reseau(document: str, attendu: str) -> None:
    assert attendu in (RACINE / document).read_text(encoding="utf-8")
