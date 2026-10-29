"""Tests de fumee de la CLI."""

from collections.abc import Sequence
from importlib.metadata import entry_points
from pathlib import Path

import pytest

from amnesia import __version__, cli
from amnesia.checks import Check, Domain, Gap, Registry, default_checks
from amnesia.cli import build_parser, main
from amnesia.target import Kind, Target


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"amnesia {__version__}"


def test_list_checks(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["list-checks"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == len(default_checks()) == 5
    for check, line in zip(default_checks(), lines, strict=True):
        # id, domaine, etat et titre ; les 5 checks actuels sont des stubs
        identifiant, domaine, *_ = line.split()
        assert (identifiant, domaine) == (check.id, "windows")
        assert " à implémenter " in line
        assert line.endswith(f"  {check.title}")


def test_list_checks_etat_et_colonnes(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    class Implemente(Check):
        id = "ad.implemente_long"
        title = "Check implémenté"
        description = "Surcharge run()."
        domain = Domain.AD
        target_kinds = (Kind.WINDOWS_HOST,)
        version = 1
        default_severity = "low"

        def run(self, target: Target) -> list[Gap]:
            return []

    class Stub(Check):
        id = "win.stub"
        title = "Check à écrire"
        description = "Ne surcharge pas run()."
        domain = Domain.WINDOWS
        target_kinds = (Kind.WINDOWS_HOST,)
        version = 1
        default_severity = "low"

    registre = Registry()
    registre.register(Implemente)
    registre.register(Stub)
    monkeypatch.setattr(cli, "REGISTRY", registre)
    assert main(["list-checks"]) == 0
    assert capsys.readouterr().out.splitlines() == [
        "ad.implemente_long  ad       implémenté     Check implémenté",
        "win.stub            windows  à implémenter  Check à écrire",
    ]


def test_list_checks_registre_vide(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "REGISTRY", Registry())
    assert main(["list-checks"]) == 0
    assert capsys.readouterr().out == ""


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
