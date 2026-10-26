"""Tests de fumee de la CLI."""

from importlib.metadata import entry_points

import pytest

from amnesia import __version__
from amnesia.checks import default_checks
from amnesia.cli import build_parser, main


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


def test_audit_valeurs_par_defaut():
    args = build_parser().parse_args(["audit"])
    assert (args.target, args.out) == ("localhost", "amnesia-report.json")


def test_audit_stub(capsys, tmp_path, registre_factice):
    assert main(["audit", "--target", "dc01"]) == 0
    sortie = capsys.readouterr().out
    assert all(c.id in sortie for c in registre_factice)
    assert list(tmp_path.iterdir()) == []  # cwd isole par le conftest


def test_sans_sous_commande_code_2(capsys):
    assert main([]) == 2
    assert capsys.readouterr().out.startswith("usage: amnesia")
