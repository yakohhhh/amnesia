"""Tests de fumee de la CLI."""

import pytest

from amnesia import __version__
from amnesia.checks import default_checks
from amnesia.cli import main


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"amnesia {__version__}"


def test_list_checks(capsys):
    assert main(["list-checks"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == len(default_checks())
    for check, line in zip(default_checks(), lines, strict=True):
        assert line.startswith(check.id)
