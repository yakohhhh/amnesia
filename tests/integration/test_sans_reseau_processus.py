"""« Hors ligne par défaut » (#26) : la CLI dans un vrai processus sans réseau.

Le blocage en processus de tests/conftest.py (#5) ne filtre pas un
sous-processus : ici chaque commande tourne sous tests/sans_reseau.py, qui
coupe sockets et résolution DNS avant d'importer amnesia et sort en 99 à la
moindre tentative, quoi qu'amnesia en fasse.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
SANS_RESEAU = RACINE / "sans_reseau.py"
FIXTURE = RACINE / "fixtures" / "report-min.json"
CODE_RESEAU = 99


def _python(tmp_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    # interpreteur courant, script du depot : rien ne vient d'une entree ;
    # -X warn_default_encoding -W error : un open() sans encoding casse la CLI
    return subprocess.run(  # noqa: S603
        [sys.executable, "-X", "warn_default_encoding", "-W", "error", *args],
        capture_output=True,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        encoding="utf-8",
        check=False,
        cwd=tmp_path,
        timeout=120,
    )


def _amnesia(tmp_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return _python(tmp_path, str(SANS_RESEAU), *args)


@pytest.mark.parametrize(
    "args",
    [
        ("--help",),
        ("--version",),
        ("list-checks",),
        ("schema",),
        ("render", str(FIXTURE)),
        ("render", str(FIXTURE), "--format", "md"),
        ("audit", "--target", "local", "--out", "rapport.json"),
    ],
    ids=["help", "version", "list-checks", "schema", "render", "render-md", "audit"],
)
def test_commande_sans_connexion(tmp_path: Path, args: tuple[str, ...]) -> None:
    sortie = _amnesia(tmp_path, *args)
    assert "connexion(s) tentee(s)" not in sortie.stderr, sortie.stderr
    assert sortie.returncode != CODE_RESEAU, sortie.stderr
    # audit : les checks actuels sont des stubs, mais le code n'est jamais 4
    # (erreur fatale, qui avalerait une tentative) ; aide et rendu valent 0
    assert sortie.returncode in {0, 1, 3}, (sortie.returncode, sortie.stderr)
    if args[0] != "audit":
        assert sortie.returncode == 0, sortie.stderr
    assert "Traceback" not in sortie.stderr
    assert sortie.stdout


def test_temoin_le_garde_refuse_bien(tmp_path: Path) -> None:
    # temoin positif : une main d'amnesia qui ouvrirait une connexion sort en 99,
    # meme si elle avale l'exception, et la tentative est decrite sur stderr
    code = (
        "import socket, sys\n"
        f"sys.path.insert(0, {str(RACINE)!r})\n"
        "import sans_reseau\n"
        "import amnesia.cli\n"
        "def faux_main(argv):\n"
        "    try:\n"
        "        socket.create_connection(('192.0.2.1', 80), timeout=1)\n"
        "    except Exception:\n"
        "        return 4\n"
        "amnesia.cli.main = faux_main\n"
        "raise SystemExit(sans_reseau.main(['list-checks']))\n"
    )
    sortie = _python(tmp_path, "-c", code)
    assert sortie.returncode == CODE_RESEAU, sortie.stderr
    assert "socket.create_connection" in sortie.stderr


@pytest.mark.parametrize(
    "appel",
    [
        "socket.socket()",
        "socket.create_connection(('192.0.2.1', 80), timeout=1)",
        "socket.getaddrinfo('dc01.invalid', 5985)",
        "socket.gethostbyname('dc01.invalid')",
        "socket.getfqdn('dc01')",
    ],
)
def test_temoin_chaque_fonction_est_coupee(tmp_path: Path, appel: str) -> None:
    code = (
        "import socket, sys\n"
        f"sys.path.insert(0, {str(RACINE)!r})\n"
        "import sans_reseau\n"
        "sans_reseau.couper_le_reseau()\n"
        "try:\n"
        f"    {appel}\n"
        "except sans_reseau.ReseauInterdit:\n"
        "    raise SystemExit(len(sans_reseau.TENTATIVES))\n"
        "raise SystemExit(0)\n"
    )
    sortie = _python(tmp_path, "-c", code)
    assert sortie.returncode == 1, (sortie.returncode, sortie.stderr)
