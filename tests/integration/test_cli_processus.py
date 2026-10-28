"""La CLI lancee comme un utilisateur le ferait, dans un vrai processus."""

import subprocess
import sys

from amnesia import __version__


def _amnesia(*args: str) -> subprocess.CompletedProcess[str]:
    # interpreteur courant (celui de uv run) et arguments constants, sans shell
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "amnesia", *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def test_python_m_amnesia_help() -> None:
    sortie = _amnesia("--help")
    assert sortie.returncode == 0, sortie.stderr
    assert sortie.stdout.startswith("usage: amnesia")
    for commande in ("audit", "list-checks"):
        assert commande in sortie.stdout


def test_python_m_amnesia_version() -> None:
    sortie = _amnesia("--version")
    assert sortie.returncode == 0, sortie.stderr
    assert sortie.stdout.strip() == f"amnesia {__version__}"


def test_python_m_amnesia_sans_sous_commande() -> None:
    assert _amnesia().returncode == 2
