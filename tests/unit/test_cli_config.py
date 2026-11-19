# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Fichier de mission vu de la CLI : init, config show, audit (#36)."""

from __future__ import annotations

import json
import logging
import re
import stat
import sys
import warnings
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from amnesia import cli, exitcodes
from amnesia.checks import Check
from amnesia.checks.base import CheckResult
from amnesia.checks.context import Context
from amnesia.cli import main
from amnesia.config import DEFAULT_FILE, Config, example_toml, load_config
from amnesia.facts import FactSet
from amnesia.report import load_schema

VALIDATEUR = jsonschema.Draft202012Validator(load_schema())
SEUIL = "thresholds.security_log_min_retention_days"

MISSION = """\
profile = "pme"

[mission]
client = "Client Exemple"
reference = "MISSION-0001"
tlp = "TLP:AMBER+STRICT"

[report]
lang = "fr"

[thresholds]
security_log_min_retention_days = 400
"""


@pytest.fixture(autouse=True)
def _repertoire(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # chaque test part d'un repertoire courant vide : aucun amnesia.toml herite
    monkeypatch.chdir(tmp_path)


def _mission(texte: str = MISSION, nom: str = DEFAULT_FILE) -> Path:
    chemin = Path(nom)
    chemin.write_bytes(texte.encode("utf-8"))
    # droits fixes : un fichier non designe est refuse s'il est inscriptible
    # par le groupe, ce que donnerait un umask 002
    chemin.chmod(0o600)
    return chemin


def _lignes(sortie: str) -> dict[str, list[str]]:
    """Lignes de « config show » : clé → [valeur, origine]."""
    return {
        mots[0]: [" ".join(mots[1:-1]), mots[-1]]
        for mots in (ligne.split() for ligne in sortie.splitlines())
        if mots and ("." in mots[0] or mots[0] == "profile")
    }


def _refus(capsys: pytest.CaptureFixture[str], *args: str) -> str:
    with pytest.raises(SystemExit) as exc:
        main(list(args))
    assert exc.value.code == exitcodes.USAGE == 2
    sortie = capsys.readouterr()
    assert sortie.out == ""
    assert "Traceback" not in sortie.err
    return sortie.err


class Temoin(Check):
    """Check conforme qui retient les réglages reçus."""

    id = "test.temoin"
    title = "Check témoin"

    def __init__(self) -> None:
        self.config: Mapping[str, Any] | None = None

    def evaluate(self, facts: FactSet, ctx: Context) -> CheckResult:
        self.config = ctx.config
        return CheckResult.passed(self.id, ctx.target.id)


# --- amnesia init ----------------------------------------------------------------


def test_init_ecrit_un_exemple_qui_se_charge_sans_avertissement(
    capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    assert main(["init"]) == exitcodes.OK
    sortie = capsys.readouterr()
    assert sortie.out == f"Fichier de mission écrit : {DEFAULT_FILE}\n"
    assert sortie.err == ""
    chemin = Path(DEFAULT_FILE)
    # octets de l'exemple, sans traduction des fins de ligne ni BOM
    assert chemin.read_bytes() == example_toml().encode("utf-8")
    if sys.platform != "win32":
        assert stat.S_IMODE(chemin.stat().st_mode) == 0o600

    with warnings.catch_warnings(), caplog.at_level(logging.DEBUG):
        warnings.simplefilter("error")
        assert main(["config", "show", "--config", DEFAULT_FILE]) == exitcodes.OK
    sortie = capsys.readouterr()
    assert sortie.err == ""
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    lignes = _lignes(sortie.out)
    assert lignes["mission.client"] == ['"Client Exemple"', "fichier"]
    assert lignes["mission.tlp"] == ['"TLP:AMBER"', "fichier"]
    assert lignes["profile"] == ["(non renseigné)", "défaut"]
    assert f"Fichier de mission : {DEFAULT_FILE}" in sortie.out


def test_init_n_ecrase_rien_sans_overwrite(capsys: pytest.CaptureFixture[str]) -> None:
    chemin = _mission("# le mien\n")
    erreur = _refus(capsys, "init")
    assert "existe déjà" in erreur
    assert chemin.read_bytes() == b"# le mien\n"
    assert main(["init", "--overwrite"]) == exitcodes.OK
    assert chemin.read_bytes() == example_toml().encode("utf-8")


def test_init_vers_un_autre_fichier(capsys: pytest.CaptureFixture[str]) -> None:
    Path("missions").mkdir()
    cible = Path("missions") / "exemple.toml"
    assert main(["init", str(cible)]) == exitcodes.OK
    assert not Path(DEFAULT_FILE).exists()
    assert main(["config", "show", "--config", str(cible)]) == exitcodes.OK
    assert f"Fichier de mission : {cible}" in capsys.readouterr().out


# --- amnesia config show -------------------------------------------------------


def test_config_show_sans_fichier(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["config", "show"]) == exitcodes.OK
    sortie = capsys.readouterr().out
    assert "Fichier de mission : aucun" in sortie
    lignes = _lignes(sortie)
    assert {origine for _, origine in lignes.values()} == {"défaut"}
    assert lignes[SEUIL] == ["90", "défaut"]
    assert f"config_hash : {Config.defaults().config_hash()}" in sortie


def test_priorite_cli_fichier_defaut(capsys: pytest.CaptureFixture[str]) -> None:
    _mission()
    assert main(["config", "show", "--set", f"{SEUIL}=500"]) == exitcodes.OK
    avec = capsys.readouterr().out
    assert _lignes(avec)[SEUIL] == ["500", "cli"]

    assert main(["config", "show"]) == exitcodes.OK
    sans = capsys.readouterr().out
    assert _lignes(sans)[SEUIL] == ["400", "fichier"]
    assert _lignes(sans)["thresholds.ntp_max_offset_seconds"] == ["5.0", "défaut"]
    # la valeur effective change : le condensat aussi
    assert avec.splitlines()[-1] != sans.splitlines()[-1]


def test_lang_de_la_cli_l_emporte_sur_le_fichier(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _mission()
    assert main(["config", "show"]) == exitcodes.OK
    assert _lignes(capsys.readouterr().out)["report.lang"] == ['"fr"', "fichier"]
    assert main(["config", "show", "--lang", "en"]) == exitcodes.OK
    assert _lignes(capsys.readouterr().out)["report.lang"] == ['"en"', "cli"]
    # --lang l'emporte aussi sur --set
    assert (
        main(["config", "show", "--lang", "en", "--set", "report.lang=fr"])
        == exitcodes.OK
    )
    assert _lignes(capsys.readouterr().out)["report.lang"] == ['"en"', "cli"]


@pytest.mark.parametrize("commande", [("config", "show"), ("audit", "--out", "-")])
def test_cle_inconnue_code_2_chemin_et_suggestion(
    capsys: pytest.CaptureFixture[str], commande: tuple[str, ...]
) -> None:
    _mission("[thresholds]\nsecurty_log_min_retention_days = 400\n")
    erreur = _refus(capsys, *commande)
    assert "thresholds.securty_log_min_retention_days" in erreur
    assert "voulais-tu dire « thresholds.security_log_min_retention_days »" in erreur
    assert DEFAULT_FILE in erreur


@pytest.mark.parametrize("commande", [("config", "show"), ("audit", "--out", "-")])
def test_mot_de_passe_dans_le_fichier_code_2(
    capsys: pytest.CaptureFixture[str], commande: tuple[str, ...]
) -> None:
    _mission('password = "x-valeur-secrete"\n')
    erreur = _refus(capsys, *commande)
    assert "« password »" in erreur
    assert "aucun secret" in erreur
    assert "--password-file" in erreur
    assert "docs/SECRETS.md" in erreur
    assert "x-valeur-secrete" not in erreur


def test_secret_dans_set_code_2_sans_echo(capsys: pytest.CaptureFixture[str]) -> None:
    erreur = _refus(capsys, "config", "show", "--set", "mission.token=valeur-jeton")
    assert "aucun secret" in erreur
    assert "valeur-jeton" not in erreur


def test_tlp_white_refuse(capsys: pytest.CaptureFixture[str]) -> None:
    _mission('[mission]\ntlp = "TLP:WHITE"\n')
    erreur = _refus(capsys, "config", "show")
    assert "mission.tlp" in erreur
    assert "TLP 1.0" in erreur
    assert "TLP:CLEAR" in erreur


def test_config_absent_ou_valeur_hors_bornes_code_2(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert "absent.toml" in _refus(capsys, "config", "show", "--config", "absent.toml")
    erreur = _refus(capsys, "config", "show", "--set", f"{SEUIL}=0")
    assert SEUIL in erreur
    assert "hors bornes" in erreur
    assert "invalid choice" in _refus(capsys, "config", "show", "--lang", "de")


def test_chemin_hostile_neutralise(capsys: pytest.CaptureFixture[str]) -> None:
    erreur = _refus(capsys, "config", "show", "--config", "absent\x1b[31m.toml")
    assert "\x1b" not in erreur


# --- amnesia audit -------------------------------------------------------------


def test_rapport_porte_mission_profil_et_config_hash(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    temoin = Temoin()
    monkeypatch.setattr(cli, "default_checks", lambda: [temoin])
    chemin = _mission(nom="mission-exemple.toml")
    code = main(
        [
            "audit",
            "--config",
            str(chemin.resolve()),
            "--set",
            f"{SEUIL}=500",
            "--out",
            "-",
            "--format",
            "json",
        ]
    )
    assert code == exitcodes.OK
    rapport = json.loads(capsys.readouterr().out)
    VALIDATEUR.validate(rapport)
    assert rapport["mission"] == {
        "client": "Client Exemple",
        "reference": "MISSION-0001",
        "auditor": None,
        "start": None,
        "end": None,
        "tlp": "TLP:AMBER+STRICT",
    }
    assert rapport["run"]["profile"] == "pme"
    assert rapport["run"]["config_source"] == "--config"
    attendu = load_config(chemin, overrides=[f"{SEUIL}=500"])
    assert rapport["config_hash"] == attendu.config_hash()
    assert rapport["config_hash"] != load_config(chemin).config_hash()
    # le chemin du poste de l'auditeur ne passe pas dans le rapport
    assert rapport["run"]["argv"][:3] == ["audit", "--config", "mission-exemple.toml"]
    # les seuils effectifs arrivent aux checks, en lecture seule
    assert temoin.config is not None
    assert temoin.config["thresholds"]["security_log_min_retention_days"] == 500


def test_rapport_sans_fichier_de_mission(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "default_checks", lambda: [Temoin()])
    assert main(["audit", "--out", "-", "--format", "json"]) == exitcodes.OK
    rapport = json.loads(capsys.readouterr().out)
    VALIDATEUR.validate(rapport)
    assert set(rapport["mission"].values()) == {None}
    assert rapport["run"]["profile"] is None
    assert rapport["run"]["config_source"] is None
    assert rapport["config_hash"] == Config.defaults().config_hash()


def test_fichier_refuse_rien_n_est_ecrit(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "default_checks", lambda: [Temoin()])
    _mission("[mission]\nstart = 2026-01-16\nend = 2026-01-12\n")
    erreur = _refus(capsys, "audit")
    assert "mission.end" in erreur
    assert [p.name for p in Path().iterdir()] == [DEFAULT_FILE]


# --- fichier non designe et constats de revue ----------------------------------


def test_fichier_non_designe_avertissement_visible_par_defaut(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _mission()
    # sans -v : l'avertissement sort quand meme, une fois, sur stderr
    assert main(["config", "show"]) == exitcodes.OK
    sortie = capsys.readouterr()
    assert sortie.err.count("WARNING") == 1
    assert "sans avoir été désigné" in sortie.err
    assert f"--config {DEFAULT_FILE}" in sortie.err
    assert "(trouvé dans le répertoire courant, sans --config)" in sortie.out

    # designe : ni avertissement ni mention
    assert main(["config", "show", "--config", DEFAULT_FILE]) == exitcodes.OK
    sortie = capsys.readouterr()
    assert sortie.err == ""
    assert "sans --config" not in sortie.out

    # le rapport garde la trace de l'origine
    monkeypatch.setattr(cli, "default_checks", lambda: [Temoin()])
    assert main(["audit", "--out", "-", "--format", "json"]) == exitcodes.OK
    sortie = capsys.readouterr()
    assert "sans avoir été désigné" in sortie.err
    rapport = json.loads(sortie.out)
    VALIDATEUR.validate(rapport)
    assert rapport["run"]["config_source"] == "cwd"
    assert rapport["run"]["profile"] == "pme"


@pytest.mark.parametrize("commande", [("config", "show"), ("audit", "--out", "-")])
def test_fichier_non_designe_lien_symbolique_code_2(
    capsys: pytest.CaptureFixture[str], commande: tuple[str, ...]
) -> None:
    cible = _mission(nom="ailleurs.toml")
    try:
        Path(DEFAULT_FILE).symlink_to(cible)
    except (OSError, NotImplementedError):
        pytest.skip("liens symboliques indisponibles")
    erreur = _refus(capsys, *commande)
    assert "lien symbolique refusé" in erreur


@pytest.mark.skipif(sys.platform == "win32", reason="droits POSIX")
def test_fichier_non_designe_inscriptible_par_le_groupe_code_2(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _mission().chmod(0o664)
    erreur = _refus(capsys, "config", "show")
    assert "droits 0664" in erreur
    assert main(["config", "show", "--config", DEFAULT_FILE]) == exitcodes.OK


@pytest.mark.parametrize(
    "texte",
    [
        "[thresholds]\nsecurity_log_min_retention_days = 0x" + "F" * 6000 + "\n",
        "[mission]\ntlp = 0x" + "F" * 6000 + "\n",
        "[report]\nformats = [0x" + "F" * 6000 + "]\n",
    ],
    ids=["seuil", "tlp", "formats"],
)
def test_entier_geant_code_2_et_non_4(
    capsys: pytest.CaptureFixture[str], texte: str
) -> None:
    _mission(texte)
    erreur = _refus(capsys, "config", "show", "--config", DEFAULT_FILE)
    assert re.search(r"thresholds\.security_log|mission\.tlp|report\.formats", erreur)
    assert "erreur fatale" not in erreur


def test_secret_dans_un_champ_libre_code_2_sans_echo(
    capsys: pytest.CaptureFixture[str],
) -> None:
    erreur = _refus(
        capsys, "config", "show", "--set", "mission.client=password=hunter2"
    )
    assert "mission.client" in erreur
    assert "ressemble à un secret" in erreur
    assert "hunter2" not in erreur
    _mission('[mission]\nauditor = "https://bob:motdepasse@hote.exemple.invalid/x"\n')
    erreur = _refus(capsys, "audit", "--out", "-", "--config", DEFAULT_FILE)
    assert "mission.auditor" in erreur
    assert "motdepasse" not in erreur


def test_init_avertit_dans_un_depot_git(capsys: pytest.CaptureFixture[str]) -> None:
    Path(".git").mkdir()
    assert main(["init"]) == exitcodes.OK
    sortie = capsys.readouterr()
    assert "dépôt git" in sortie.err
    assert DEFAULT_FILE in sortie.err
    assert f"Fichier de mission écrit : {DEFAULT_FILE}" in sortie.out


def test_espace_insecable_dans_le_rapport(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "default_checks", lambda: [Temoin()])
    _mission('[mission]\nclient = "Dupont\u00a0& Fils"\n')
    code = main(["audit", "--config", DEFAULT_FILE, "--out", "-", "--format", "json"])
    assert code == exitcodes.OK
    rapport = json.loads(capsys.readouterr().out)
    VALIDATEUR.validate(rapport)
    assert rapport["mission"]["client"] == "Dupont\u00a0& Fils"
