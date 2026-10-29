"""Tests de fumee de la CLI."""

from collections.abc import Sequence
from importlib.metadata import entry_points
from pathlib import Path

import pytest

from amnesia import __version__
from amnesia.checks import Check, default_checks
from amnesia.cli import build_parser, main
from amnesia.target import Target


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"amnesia {__version__}"


def test_list_checks(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["list-checks"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == len(default_checks())
    for check, line in zip(default_checks(), lines, strict=True):
        assert line.startswith(check.id)


def test_commande_amnesia_pointe_sur_main() -> None:
    # [project.scripts] : une cible cassee laisserait la commande inutilisable
    (commande,) = entry_points(group="console_scripts", name="amnesia")
    assert commande.load() is main


def test_audit_valeurs_par_defaut() -> None:
    args = build_parser().parse_args(["audit"])
    assert (args.target, args.out) == (Target.parse("localhost"), "amnesia-report.json")


def test_audit_stub(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    registre_factice: Sequence[Check],
) -> None:
    # un nom nu (« dc01 ») est refuse depuis #18 : le transport est explicite
    assert main(["audit", "--target", "winrm://dc01"]) == 0
    sortie = capsys.readouterr().out
    assert all(c.id in sortie for c in registre_factice)
    assert list(tmp_path.iterdir()) == []  # cwd isole par le conftest


def test_sans_sous_commande_code_2(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 2
    assert capsys.readouterr().out.startswith("usage: amnesia")
