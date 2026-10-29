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
        "urllib-request",
        "create-connection",
        "socket",
        "asyncio-open-connection",
        "http-client",
        "requests",
        "httpx",
        "urllib3",
        "from-urllib-request",
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
