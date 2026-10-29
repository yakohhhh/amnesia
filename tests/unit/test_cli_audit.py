"""Commande audit reelle : --out, --format, --fail-on et codes de sortie (#24)."""

from __future__ import annotations

import dataclasses
import json
import re
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from amnesia import cli, exitcodes
from amnesia.checks import Check, Gap
from amnesia.checks.base import CheckResult, Confidence, Evidence, Severity
from amnesia.checks.context import Context
from amnesia.cli import main
from amnesia.facts import FactSet
from amnesia.report import load_schema

RACINE = Path(__file__).resolve().parents[2]
FIXTURE = RACINE / "tests" / "fixtures" / "report-min.json"
README = RACINE / "README.md"
VALIDATEUR = jsonschema.Draft202012Validator(load_schema())


class CheckFactice(Check):
    """Check sans effet de bord : rend les Gaps fournis sur la cible recue."""

    def __init__(self, id: str, title: str, gaps: list[Gap] | None = None) -> None:
        self.id = id
        self.title = title
        self.gaps = list(gaps or [])

    def evaluate(self, facts: FactSet, ctx: Context) -> CheckResult:
        gaps = [
            dataclasses.replace(g, check_id=self.id, target=ctx.target.id)
            for g in self.gaps
        ]
        if gaps:
            return CheckResult.with_gaps(self.id, ctx.target.id, gaps)
        return CheckResult.passed(self.id, ctx.target.id)


def _gap(severite: str) -> Gap:
    # check_id et target sont remplaces par CheckFactice a l'evaluation
    return Gap(
        check_id="test.x",
        target="local",
        resource="Security",
        question="Qui s'est connecté ?",
        reason="journal factice écrasé",
        severity=Severity.parse(severite),
        evidence=Evidence(
            observed=4,
            expected=90,
            unit="days",
            confidence=Confidence.MEASURED,
            source="journal factice",
        ),
        remediation="agrandir le journal factice",
    )


def avec_gap(severite: str) -> CheckFactice:
    return CheckFactice(f"test.gap_{severite}", f"Gap {severite}", [_gap(severite)])


def conforme() -> CheckFactice:
    return CheckFactice("test.conforme", "Check conforme")


class EnErreur(Check):
    """Check qui plante : resultat error / internal_error."""

    id = "test.erreur"
    title = "Check en erreur"

    def evaluate(self, facts: FactSet, ctx: Context) -> CheckResult:
        raise RuntimeError("accès refusé")


class Interrompu(Check):
    """Check pendant lequel l'operateur presse Ctrl-C."""

    id = "test.interruption"
    title = "Check interrompu"

    def evaluate(self, facts: FactSet, ctx: Context) -> CheckResult:
        raise KeyboardInterrupt


def _registre(monkeypatch: pytest.MonkeyPatch, *checks: Check) -> None:
    monkeypatch.setattr(cli, "default_checks", lambda: list(checks))


def _rapport(chemin: Path) -> dict[str, Any]:
    donnees: dict[str, Any] = json.loads(chemin.read_text(encoding="utf-8"))
    VALIDATEUR.validate(donnees)
    return donnees


# --- codes de sortie ------------------------------------------------------------


@pytest.mark.parametrize(
    ("checks", "fail_on", "attendu"),
    [
        ((conforme,), "low", exitcodes.OK),
        ((lambda: avec_gap("high"),), "low", exitcodes.GAPS),
        ((EnErreur,), "low", exitcodes.INCOMPLETE),
        # --fail-on high : un Gap medium ne suffit pas
        ((lambda: avec_gap("medium"),), "high", exitcodes.OK),
        ((lambda: avec_gap("medium"),), "medium", exitcodes.GAPS),
        ((lambda: avec_gap("low"),), "medium", exitcodes.OK),
        # never neutralise le code 1 sur un audit complet...
        ((lambda: avec_gap("critical"),), "never", exitcodes.OK),
        # ... jamais le code 3
        ((lambda: avec_gap("critical"), EnErreur), "never", exitcodes.INCOMPLETE),
        # un Gap au-dessus du seuil prime sur un check en erreur
        ((lambda: avec_gap("high"), EnErreur), "low", exitcodes.GAPS),
    ],
    ids=[
        "complet-sans-gap-0",
        "gap-high-1",
        "erreur-3",
        "fail-on-high-gap-medium-0",
        "fail-on-medium-gap-medium-1",
        "fail-on-medium-gap-low-0",
        "never-gap-critical-0",
        "never-erreur-3",
        "gap-et-erreur-1",
    ],
)
def test_codes_de_sortie(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    checks: tuple[type[Check], ...],
    fail_on: str,
    attendu: int,
) -> None:
    _registre(monkeypatch, *(c() for c in checks))
    rapport = tmp_path / "r.json"
    code = main(["audit", "--out", str(rapport), "--fail-on", fail_on])
    assert code == attendu
    donnees = _rapport(rapport)
    assert donnees["run"]["complete"] is not any(c is EnErreur for c in checks)


def test_fail_on_par_defaut_low(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _registre(monkeypatch, avec_gap("low"))
    assert main(["audit", "--out", str(tmp_path / "r.json")]) == exitcodes.GAPS
    _registre(monkeypatch, avec_gap("info"))
    assert main(["audit", "--out", str(tmp_path / "r2.json")]) == exitcodes.OK


def test_fail_on_valeur_inconnue_code_2(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["audit", "--fail-on", "urgent"])
    assert exc.value.code == exitcodes.USAGE
    assert "--fail-on" in capsys.readouterr().err


def test_interruption_code_130_et_rapport_partiel(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _registre(monkeypatch, avec_gap("critical"), Interrompu(), conforme())
    rapport = tmp_path / "r.json"
    assert main(["audit", "--out", str(rapport)]) == exitcodes.INTERRUPTED
    donnees = _rapport(rapport)
    assert donnees["run"]["interrupted"] is True
    assert donnees["run"]["complete"] is False
    # le check d'avant l'interruption est dans le rapport, pas ceux d'apres
    assert [r["check_id"] for r in donnees["results"]] == ["test.gap_critical"]
    assert "Traceback" not in capsys.readouterr().err


def test_interruption_hors_des_checks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def interrompre(*args: object, **kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "run_audit", interrompre)
    assert main(["audit", "--out", str(tmp_path / "r.json")]) == exitcodes.INTERRUPTED


def test_erreur_fatale_code_4_sans_traceback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def planter(*args: object, **kwargs: object) -> None:
        raise RuntimeError("winrm://audit:" + "hunter2" + "@dc01 injoignable")

    monkeypatch.setattr(cli, "run_audit", planter)
    assert main(["audit", "--out", str(tmp_path / "r.json")]) == exitcodes.FATAL
    sortie = capsys.readouterr()
    assert sortie.out == ""
    assert "erreur fatale : RuntimeError" in sortie.err
    assert "hunter2" not in sortie.err
    assert "Traceback" not in sortie.err


def test_rapport_impossible_a_ecrire_code_4(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _registre(monkeypatch, conforme())
    rapport = tmp_path / "absent" / "r.json"
    assert main(["audit", "--out", str(rapport)]) == exitcodes.FATAL
    assert not rapport.exists()
    sortie = capsys.readouterr()
    assert sortie.out == ""
    assert "écriture impossible" in sortie.err


def test_sans_sous_commande_aide_sur_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == exitcodes.USAGE
    sortie = capsys.readouterr()
    assert sortie.out == ""
    assert sortie.err.startswith("usage: amnesia")


def test_main_ne_rend_que_des_codes_connus() -> None:
    codes = {
        exitcodes.OK,
        exitcodes.GAPS,
        exitcodes.USAGE,
        exitcodes.INCOMPLETE,
        exitcodes.FATAL,
        exitcodes.INTERRUPTED,
    }
    assert codes == {code for code, _ in exitcodes.TABLE} == {0, 1, 2, 3, 4, 130}
    assert cli.CODE_RAPPORT_ILLISIBLE == exitcodes.FATAL


# --- --out ----------------------------------------------------------------------


def test_out_fichier_json_valide_un_resultat_par_check(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _registre(monkeypatch, conforme(), avec_gap("high"), EnErreur())
    rapport = tmp_path / "r.json"
    # un nom nu (« dc01 ») est refuse depuis #18 : le transport est explicite
    code = main(["audit", "--target", "winrm://dc01", "--out", str(rapport)])
    assert code == exitcodes.GAPS
    donnees = _rapport(rapport)
    assert sorted(r["check_id"] for r in donnees["results"]) == [
        "test.conforme",
        "test.erreur",
        "test.gap_high",
    ]
    assert {r["target"] for r in donnees["results"]} == {"winrm://dc01"}
    assert donnees["run"]["argv"] == [
        "audit",
        "--target",
        "winrm://dc01",
        "--out",
        "r.json",
    ]
    sortie = capsys.readouterr()
    assert "[stub]" not in sortie.out
    assert "Cibles : winrm://dc01" in sortie.out
    assert f"Rapport JSON : {rapport}" in sortie.out
    # le check en erreur est journalise en WARNING, jamais avec sa trace
    assert "Traceback" not in sortie.err
    assert "JSON" not in sortie.err


def test_out_par_defaut_dans_le_repertoire_courant(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _registre(monkeypatch, conforme())
    assert main(["audit"]) == exitcodes.OK
    assert [p.name for p in tmp_path.iterdir()] == [cli.DEFAULT_OUT]
    _rapport(tmp_path / cli.DEFAULT_OUT)


def test_out_tiret_json_sur_stdout_texte_sur_stderr(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _registre(monkeypatch, avec_gap("medium"))
    assert main(["audit", "--out", "-"]) == exitcodes.GAPS
    sortie = capsys.readouterr()
    donnees = json.loads(sortie.out)
    VALIDATEUR.validate(donnees)
    assert donnees["run"]["argv"] == ["audit", "--out", "-"]
    assert sortie.err.startswith("amnesia — questions d'enquête sans réponse")
    assert "→ Impossible : journal factice écrasé" in sortie.err
    assert "Rapport JSON" not in sortie.err
    assert list(tmp_path.iterdir()) == []


def test_out_tiret_format_json_rien_sur_stderr(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _registre(monkeypatch, conforme())
    assert main(["audit", "--out", "-", "--format", "json"]) == exitcodes.OK
    sortie = capsys.readouterr()
    assert json.loads(sortie.out)["summary"]["total"] == 1
    assert sortie.err == ""


def test_format_json_sur_stdout_et_fichier(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _registre(monkeypatch, conforme())
    rapport = tmp_path / "r.json"
    assert main(["audit", "--out", str(rapport), "--format", "json"]) == exitcodes.OK
    sortie = capsys.readouterr()
    assert sortie.out == rapport.read_text(encoding="utf-8")
    assert sortie.err == ""


def test_fichier_existant_refuse_sans_overwrite(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _registre(monkeypatch, conforme())
    rapport = tmp_path / "r.json"
    rapport.write_text("{}", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main(["audit", "--out", str(rapport)])
    assert exc.value.code == exitcodes.USAGE
    assert "existe déjà" in capsys.readouterr().err
    assert rapport.read_text(encoding="utf-8") == "{}"
    assert main(["audit", "--out", str(rapport), "--overwrite"]) == exitcodes.OK
    assert _rapport(rapport)["summary"]["total"] == 1


def test_lien_symbolique_refuse(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _registre(monkeypatch, conforme())
    lien = tmp_path / "r.json"
    cible = tmp_path / "ailleurs.json"
    try:
        lien.symlink_to(cible)
    except (OSError, NotImplementedError):
        pytest.skip("liens symboliques indisponibles")
    # lien casse : exists() est faux, mais le mode x refuse de le suivre
    assert main(["audit", "--out", str(lien)]) == exitcodes.FATAL
    assert not cible.exists()


def test_lien_symbolique_avec_overwrite_cible_intacte(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _registre(monkeypatch, conforme())
    cible = tmp_path / "victime.txt"
    cible.write_text("SECRET\n", encoding="utf-8")
    lien = tmp_path / "r.json"
    try:
        lien.symlink_to(cible)
    except (OSError, NotImplementedError):
        pytest.skip("liens symboliques indisponibles")
    # --overwrite remplace le lien lui-meme, jamais ce qu'il pointe (CWE-59)
    assert main(["audit", "--out", str(lien), "--overwrite"]) == exitcodes.OK
    assert cible.read_text(encoding="utf-8") == "SECRET\n"
    assert not lien.is_symlink()
    assert _rapport(lien)["summary"]["total"] == 1


def test_lien_physique_avec_overwrite_cible_intacte(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _registre(monkeypatch, conforme())
    cible = tmp_path / "victime.txt"
    cible.write_text("SECRET\n", encoding="utf-8")
    lien = tmp_path / "r.json"
    try:
        lien.hardlink_to(cible)
    except (OSError, NotImplementedError):
        pytest.skip("liens physiques indisponibles")
    assert main(["audit", "--out", str(lien), "--overwrite"]) == exitcodes.OK
    assert cible.read_text(encoding="utf-8") == "SECRET\n"
    assert _rapport(lien)["summary"]["total"] == 1


def test_overwrite_sur_un_repertoire_code_4(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _registre(monkeypatch, conforme())
    dossier = tmp_path / "r.json"
    dossier.mkdir()
    (dossier / "temoin").write_text("", encoding="utf-8")
    assert main(["audit", "--out", str(dossier), "--overwrite"]) == exitcodes.FATAL
    assert (dossier / "temoin").exists()
    assert "écriture impossible" in capsys.readouterr().err


def test_chemin_out_neutralise_sur_le_terminal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _registre(monkeypatch, conforme())
    rapport = tmp_path / "x\x1b[31mrouge\x1b[0m\x1b]0;titre\x07.json"
    assert main(["audit", "--out", str(rapport)]) == exitcodes.OK
    sortie = capsys.readouterr()
    assert "Rapport JSON : " in sortie.out
    assert "\x1b" not in sortie.out
    assert "\x07" not in sortie.out
    assert "\\x1b[31mrouge" in sortie.out
    with pytest.raises(SystemExit) as exc:
        main(["audit", "--out", str(rapport)])
    assert exc.value.code == exitcodes.USAGE
    sortie = capsys.readouterr()
    assert "existe déjà" in sortie.err
    assert "\x1b" not in sortie.err
    assert "\x07" not in sortie.err


def test_rapport_ecrit_en_utf8_sans_bom_fins_de_ligne_lf(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _registre(monkeypatch, avec_gap("high"))
    rapport = tmp_path / "r.json"
    assert main(["audit", "--out", str(rapport)]) == exitcodes.GAPS
    octets = rapport.read_bytes()
    assert not octets.startswith(b"\xef\xbb\xbf")
    assert b"\r\n" not in octets
    assert "écrasé".encode() in octets
    assert octets.endswith(b"}\n")


def test_argv_masque_dans_le_rapport(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _registre(monkeypatch, conforme())
    rapport = tmp_path / "secret" / "r.json"
    rapport.parent.mkdir()
    monkeypatch.setattr("sys.argv", ["amnesia", "audit", "--out", str(rapport)])
    assert main() == exitcodes.OK
    assert _rapport(rapport)["run"]["argv"] == ["audit", "--out", "r.json"]


def test_cible_distante_sans_collecteur_audit_incomplet(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class AvecFait(CheckFactice):
        requires_facts = ("windows.sysmon.service",)

    _registre(monkeypatch, AvecFait("test.fait", "Check à fait requis"))
    rapport = tmp_path / "r.json"
    cible = "winrm://dc01.invalid"
    assert main(["audit", "--target", cible, "--out", str(rapport)]) == 3
    (resultat,) = _rapport(rapport)["results"]
    assert (resultat["status"], resultat["reason"]) == ("skipped", "not_collected")


# --- stdout : couleurs et aide --------------------------------------------------


def test_sans_terminal_pas_de_couleur(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _registre(monkeypatch, avec_gap("high"))
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert main(["audit", "--out", str(tmp_path / "r.json")]) == exitcodes.GAPS
    assert "\x1b" not in capsys.readouterr().out


def test_aide_audit_table_des_codes(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["audit", "--help"])
    assert exc.value.code == 0
    aide = capsys.readouterr().out
    for option in ("--out", "--overwrite", "--format", "--no-color", "--fail-on"):
        assert option in aide
    assert "codes de sortie" in aide
    for code, _ in exitcodes.TABLE:
        assert re.search(rf"^  {code} ", aide, re.MULTILINE), code
    # la table est repliee a 79 colonnes, quelle que soit la largeur du terminal
    table = aide.split("codes de sortie :", 1)[1]
    assert max(len(ligne) for ligne in table.splitlines()) <= 79


def test_readme_section_codes_de_sortie() -> None:
    texte = README.read_text(encoding="utf-8")
    section = texte.split("## Codes de sortie", 1)[1].split("\n## ", 1)[0]
    for code, _ in exitcodes.TABLE:
        assert re.search(rf"^\| `{code}` ", section, re.MULTILINE), code
    assert "--fail-on" in section


# --- amnesia render --fail-on ---------------------------------------------------


@pytest.mark.parametrize(
    ("args", "attendu"),
    [
        # le rendu seul affiche : toujours 0
        ((), exitcodes.OK),
        # fixture : Gaps high et medium, un check en erreur, un non execute
        (("--fail-on", "high"), exitcodes.GAPS),
        (("--fail-on", "critical"), exitcodes.INCOMPLETE),
        (("--fail-on", "never"), exitcodes.INCOMPLETE),
    ],
)
def test_render_fail_on(
    capsys: pytest.CaptureFixture[str], args: tuple[str, ...], attendu: int
) -> None:
    assert main(["render", str(FIXTURE), *args]) == attendu
    assert "questions d'enquête sans réponse" in capsys.readouterr().out


def test_render_fail_on_rapport_complet(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    donnees = json.loads(FIXTURE.read_text(encoding="utf-8"))
    donnees["run"]["complete"] = True
    chemin = tmp_path / "complet.json"
    chemin.write_text(json.dumps(donnees), encoding="utf-8")
    assert main(["render", str(chemin), "--fail-on", "never"]) == exitcodes.OK
    assert main(["render", str(chemin), "--fail-on", "medium"]) == exitcodes.GAPS
    capsys.readouterr()


# --- exitcodes.exit_code --------------------------------------------------------


def _rapport_minimal(severites: list[str], complete: bool) -> dict[str, Any]:
    return {
        "gaps": [{"severity": s} for s in severites],
        "run": {"complete": complete},
    }


@pytest.mark.parametrize(
    ("severites", "complete", "fail_on", "attendu"),
    [
        ([], True, "low", 0),
        ([], False, "low", 3),
        (["info"], True, "low", 0),
        (["low"], True, "low", 1),
        (["high"], False, "low", 1),
        (["critical"], True, "never", 0),
        (["critical"], False, "never", 3),
    ],
)
def test_exit_code(
    severites: list[str], complete: bool, fail_on: str, attendu: int
) -> None:
    rapport = _rapport_minimal(severites, complete)
    assert exitcodes.exit_code(rapport, fail_on) == attendu


def test_exit_code_seuil_inconnu() -> None:
    with pytest.raises(ValueError, match="severity"):
        exitcodes.exit_code(_rapport_minimal([], True), "urgent")


def test_fail_on_valeurs() -> None:
    assert exitcodes.FAIL_ON == ("critical", "high", "medium", "low", "info", "never")
    assert exitcodes.DEFAULT_FAIL_ON == "low"
    assert exitcodes.threshold("never") is None
    assert exitcodes.threshold("high") is Severity.HIGH
