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


def _codes(source: str) -> set[str]:
    sortie = subprocess.run(
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            "--no-cache",
            "--output-format=json",
            "--stdin-filename=src/amnesia/_cas.py",
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
    ],
    ids=["datetime-sans-fuseau", "print", "eval", "noqa-nu", "bidi", "zwsp"],
)
def test_regle_detectee(source: str, code: str) -> None:
    assert code in _codes(source)


def test_typographie_francaise_acceptee() -> None:
    assert _codes('MSG = "l’audit – partiel"\n') == set()
