# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Le jeu de regles ruff attrape bien ce qu'il doit attraper.

Garde-fou contre un select trop etroit : chaque cas est lint comme s'il etait
dans src/amnesia/, avec la configuration du depot.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("ruff")

RACINE = Path(__file__).resolve().parent.parent


def _codes(source: str, fichier: str = "src/amnesia/_cas.py") -> set[str]:
    sortie = subprocess.run(  # noqa: S603 - interpreteur courant, chemins du test
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            "--no-cache",
            "--output-format=json",
            f"--stdin-filename={fichier}",
            "-",
        ],
        input=source,
        capture_output=True,
        encoding="utf-8",
        cwd=RACINE,
        check=False,
    )
    return {d["code"] for d in json.loads(sortie.stdout)}


@pytest.mark.parametrize(
    ("source", "code"),
    [
        ("import datetime\n\nNOW = datetime.datetime.now()\n", "DTZ005"),
        ('print("x")\n', "T201"),
        ("X = eval(input())\n", "S307"),
        ("X = eval(input())  # noqa\n", "PGH004"),
        ('ROLE = "user\u202e"\n', "PLE2502"),
        ('ROLE = "ad\u200bmin"\n', "PLE2515"),
        # collecteurs (#20) : argv en liste, jamais de shell
        ('import subprocess\n\nsubprocess.run("auditpol /get", shell=True)\n', "S602"),
        ('import os\n\nos.system("auditpol /get")\n', "S605"),
        (
            "def lancer(*a: object, **k: object) -> None: ...\n\n\n"
            'lancer("auditpol /get", shell=True)\n',
            "S604",
        ),
        # lecture seule (#39) : programme designe par son chemin complet
        ('import subprocess\n\nsubprocess.run(["auditpol", "/get"])\n', "S607"),
        # frontiere reseau (#26) : API reseau interdites hors des collecteurs
        ("import urllib.request\n", "TID251"),
        ('import socket\n\nsocket.create_connection(("dc01", 5985))\n', "TID251"),
        ("import socket\n\nS = socket.socket()\n", "TID251"),
        ('import asyncio\n\nC = asyncio.open_connection("dc01", 5985)\n', "TID251"),
        ("import http.client\n", "TID251"),
        ("import requests\n", "TID251"),
        ("import httpx\n", "TID251"),
        ("import urllib3\n", "TID251"),
        ("from urllib.request import urlopen\n", "TID251"),
        ("import asyncio\n\nS = asyncio.start_server(rappel, port=0)\n", "TID251"),
        (
            "import logging.handlers\n\n"
            'H = logging.handlers.HTTPHandler("exemple.invalid", "/")\n',
            "TID251",
        ),
        ("from logging.handlers import SysLogHandler\n", "TID251"),
        ("import logging.config\n\nT = logging.config.listen(9030)\n", "TID251"),
        # set_stream_logger reste interdit hors des collecteurs ; dans les
        # collecteurs, c'est tests/test_reseau.py qui le tient
        ('import boto3\n\nboto3.set_stream_logger("")\n', "TID251"),
    ],
    ids=[
        "datetime-sans-fuseau",
        "print",
        "eval",
        "noqa-nu",
        "bidi",
        "zwsp",
        "shell-subprocess",
        "shell-os-system",
        "shell-autre-appel",
        "chemin-partiel",
        "urllib-request",
        "create-connection",
        "socket",
        "asyncio-open-connection",
        "http-client",
        "requests",
        "httpx",
        "urllib3",
        "from-urllib-request",
        "asyncio-start-server",
        "http-handler",
        "syslog-handler",
        "logging-config-listen",
        "set-stream-logger",
    ],
)
def test_regle_detectee(source: str, code: str) -> None:
    assert code in _codes(source)


def test_typographie_francaise_acceptee() -> None:
    assert _codes('MSG = "l’audit – partiel"\n') == set()


# chemins autorises a ouvrir une connexion : per-file-ignores de TID251
# (tests/test_reseau.py verifie que la liste est exactement celle-ci)
COLLECTEURS = (
    "src/amnesia/facts/collectors.py",
    "src/amnesia/facts/collectors/winrm.py",
)


@pytest.mark.parametrize("fichier", COLLECTEURS)
def test_reseau_accepte_dans_les_collecteurs(fichier: str) -> None:
    # critere d'acceptation de #26 : meme import, chemin du paquet des collecteurs
    source = "import urllib.request\n\nurllib.request.urlopen\n"
    assert "TID251" in _codes(source, "src/amnesia/report.py")
    assert "TID251" not in _codes(source, fichier)


def test_urllib_parse_accepte() -> None:
    # amnesia.log expurge des URL : urllib.parse ne joint rien
    assert "TID251" not in _codes("from urllib.parse import quote\n\nquote\n")


# Fichiers importes (#35) : ni execution ni deserialisation de code, ni
# analyseur XML ou extraction d'archive sans garde-fou. S320 (lxml) a ete
# retiree de ruff.
ENTREES_HOSTILES = [
    ("S102", 'exec("X = 1")\n'),
    ("S301", 'import pickle\n\nX = pickle.loads(b"")\n'),
    ("S301", 'import shelve\n\nD = shelve.open("etat")\n'),
    ("S302", 'import marshal\n\nX = marshal.loads(b"")\n'),
    ("S307", "X = eval(input())\n"),
    ("S313", 'import xml.etree.cElementTree as ET\n\nX = ET.fromstring("<a/>")\n'),
    ("S314", 'import xml.etree.ElementTree as ET\n\nX = ET.fromstring("<a/>")\n'),
    ("S315", "from xml.sax import expatreader\n\nP = expatreader.create_parser()\n"),
    (
        "S316",
        'from xml.dom import expatbuilder\n\nD = expatbuilder.parseString("<a/>")\n',
    ),
    ("S317", "import xml.sax\n\nP = xml.sax.make_parser()\n"),
    ("S318", 'from xml.dom import minidom\n\nD = minidom.parseString("<a/>")\n'),
    ("S319", 'from xml.dom import pulldom\n\nD = pulldom.parseString("<a/>")\n'),
    ("S506", 'import yaml\n\nX = yaml.load("a: 1")\n'),
    ("S202", 'import tarfile\n\ntarfile.open("bundle.tar").extractall()\n'),
]


@pytest.mark.parametrize(
    ("code", "source"),
    ENTREES_HOSTILES,
    ids=[
        "exec",
        "pickle",
        "shelve",
        "marshal",
        "eval",
        "celementtree",
        "elementtree",
        "expatreader",
        "expatbuilder",
        "sax",
        "minidom",
        "pulldom",
        "yaml-load",
        "tarfile-extractall",
    ],
)
@pytest.mark.parametrize(
    "fichier",
    ["src/amnesia/_cas.py", "src/amnesia/inputs.py", "tests/unit/test_cas.py"],
)
def test_regles_des_fichiers_importes_actives(
    code: str, source: str, fichier: str
) -> None:
    # critere d'acceptation de #35 : actives partout, y compris dans
    # amnesia.inputs (aucune derogation par fichier) et dans les tests
    assert code in _codes(source, fichier)


def test_regles_des_fichiers_importes_toutes_couvertes() -> None:
    attendues = {"S102", "S202", "S301", "S302", "S307", "S506"} | {
        f"S{numero}" for numero in range(313, 320)
    }
    assert {code for code, _ in ENTREES_HOSTILES} == attendues


def test_yaml_safe_load_accepte() -> None:
    assert _codes('import yaml\n\nX = yaml.safe_load("a: 1")\n') == set()
