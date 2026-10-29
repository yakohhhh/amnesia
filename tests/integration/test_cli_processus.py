"""La CLI lancee comme un utilisateur le ferait, dans un vrai processus."""

import os
import subprocess
import sys

from amnesia import __version__


def _amnesia(*args: str) -> subprocess.CompletedProcess[str]:
    # interpreteur courant (celui de uv run) et arguments constants, sans shell
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "amnesia", *args],
        capture_output=True,
        # le processus fils ecrit en UTF-8 (aide accentuee) meme sous Windows, ou
        # un pipe est sinon encode dans la page ANSI (docs/dev/encodage.md)
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        encoding="utf-8",
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


# SDK des collecteurs (#20, #44), absents sans les extras
SDK = ("boto3", "botocore", "msal", "msgraph", "azure", "winrm", "pypsrp", "ldap3")


def _python(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - interpreteur courant, code constant
        [sys.executable, "-c", code],
        capture_output=True,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        encoding="utf-8",
        check=False,
        timeout=60,
    )


def test_list_checks_sans_sdk() -> None:
    # sys.modules[nom] = None : tout « import nom » leve ImportError, comme sans
    # l'extra installe ; pose avant le premier import d'amnesia
    sortie = _python(
        "import sys\n"
        f"for nom in {SDK!r}:\n"
        "    sys.modules[nom] = None\n"
        "from amnesia.cli import main\n"
        "raise SystemExit(main(['list-checks']))\n"
    )
    assert sortie.returncode == 0, sortie.stderr
    lignes = sortie.stdout.splitlines()
    assert len(lignes) == 5
    assert all(" à implémenter " in ligne for ligne in lignes)


def test_import_ne_charge_aucun_check() -> None:
    # chargement paresseux : le registre importe les checks au premier besoin
    sortie = _python(
        "import sys\n"
        "import amnesia.cli\n"
        "print(sorted(m for m in sys.modules if m.startswith('amnesia.checks.')))\n"
    )
    assert sortie.returncode == 0, sortie.stderr
    assert sortie.stdout.strip() == "['amnesia.checks.base', 'amnesia.checks.registry']"
