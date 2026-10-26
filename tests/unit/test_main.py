"""Points d'entree : python -m amnesia et arguments lus dans sys.argv."""

import runpy

import pytest

from amnesia.checks import default_checks
from amnesia.cli import main


def test_arguments_lus_dans_sys_argv(capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["amnesia", "list-checks"])
    assert main() == 0
    assert len(capsys.readouterr().out.splitlines()) == len(default_checks())


def test_module_main(capsys, monkeypatch):
    # python -m amnesia, en processus pour la couverture ; le vrai sous-processus
    # est dans tests/integration/
    monkeypatch.setattr("sys.argv", ["amnesia"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("amnesia", run_name="__main__", alter_sys=True)
    assert exc.value.code == 2
    assert capsys.readouterr().out.startswith("usage: amnesia")
