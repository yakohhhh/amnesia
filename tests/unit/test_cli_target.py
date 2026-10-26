"""Validation de --target par la CLI : erreur d'usage et affichage normalise."""

import pytest

from amnesia.cli import build_parser, main
from amnesia.target import Target

NOM_254 = ".".join(["a" * 63] * 3 + ["b" * 62])


def _refus(capsys, cible: str) -> str:
    with pytest.raises(SystemExit) as exc:
        main(["audit", "--target", cible])
    assert exc.value.code == 2
    sortie = capsys.readouterr()
    assert sortie.out == ""
    return sortie.err


@pytest.mark.parametrize(
    "cible",
    [
        "",
        "winrm://",
        "dc01; Remove-Item C:\\ -Recurse",
        "winrm://$(whoami)",
        "winrm://dc01`nGet-Process",
        "winrm://user:pass@dc01",
        "winrm://-dc01",
        f"winrm://{NOM_254}",
        "winrm://dc01\x1b[2J\x1b[31m",
        "winrm://d\u0441\u0030\u0031",  # c cyrillique (U+0441)
        "http://dc01",
    ],
    ids=[
        "vide",
        "winrm-sans-hote",
        "injection-powershell",
        "substitution",
        "accent-grave",
        "identifiants",
        "tiret-initial",
        "nom-254",
        "echappement-ansi",
        "homoglyphe-cyrillique",
        "schema-inconnu",
    ],
)
def test_cibles_refusees_en_code_2(capsys, cible):
    assert len(NOM_254) == 254
    err = _refus(capsys, cible)
    assert "argument --target: " in err
    # message en francais, sans reprise brute de la saisie
    assert "cible" in err or "hote" in err or "schema" in err
    assert not cible or cible not in err
    assert "\x1b" not in err


def test_nom_nu_suggere_winrm(capsys):
    err = _refus(capsys, "dc01")
    assert "transport manquant : utiliser winrm://dc01" in err


def test_audit_affiche_la_forme_normalisee(capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["audit", "--target", "WINRM://SRV-FILE.Corp.Local.:5986"]) == 0
    sortie = capsys.readouterr().out
    assert "audit de winrm://srv-file.corp.local:5986 -> " in sortie
    assert "SRV-FILE" not in sortie


def test_cible_par_defaut_locale():
    args = build_parser().parse_args(["audit"])
    assert args.target == Target.parse("localhost")
    assert args.target.id == "local"
