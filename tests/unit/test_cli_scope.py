# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Périmètre autorisé vu de la CLI (#37) : refus avant toute collecte, traces.

Le réseau est coupé par tests/conftest.py (fonctions de pytest-socket) : une
connexion ouverte par un audit refusé ferait échouer le test.
"""

from __future__ import annotations

import io
import json
import logging
import socket
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn

import jsonschema
import pytest
from pytest_socket import SocketBlockedError

from amnesia import cli, exitcodes
from amnesia.checks import Check
from amnesia.checks.base import CheckResult
from amnesia.checks.context import Context
from amnesia.cli import main
from amnesia.config import DEFAULT_FILE, Config, ConfigError, load_config
from amnesia.facts import FactSet
from amnesia.report import load_schema
from amnesia.scope import SOURCE_MISSION, SOURCE_OPTION, load_scope
from amnesia.target import Target

VALIDATEUR = jsonschema.Draft202012Validator(load_schema())
CIBLE = "winrm://srv01.corp.example"
HORS = "winrm://srv01.autre.example"
# la fixture autouse remplace cette fonction : l'originale, pour ses propres tests
TERMINAL_REEL = cli._terminal_interactif


def _jour(decalage: int) -> str:
    return (datetime.now(UTC) + timedelta(days=decalage)).date().isoformat()


def _toml(
    include: str = 'dns = ["*.corp.example"]',
    exclude: str = "",
    debut: int = -1,
    fin: int = 1,
) -> str:
    # periode autour d'aujourd'hui : un jour de marge de chaque cote, pour que
    # la date du poste et la date UTC y soient toutes deux
    return (
        "[scope]\n"
        'mission_id = "MISSION-0001"\n'
        f"valid_from = {_jour(debut)}\n"
        f"valid_until = {_jour(fin)}\n"
        "\n[scope.authorization]\n"
        'reference = "LM-2026-001"\n'
        f"date = {_jour(debut - 7)}\n"
        'signatory = "Prénom Nom"\n'
        'signatory_role = "RSSI"\n'
        f"\n[scope.include]\n{include}\n"
        f"\n[scope.exclude]\n{exclude}\n"
    )


def _perimetre(texte: str | None = None, nom: str = "perimetre.toml") -> Path:
    chemin = Path(nom)
    chemin.write_bytes((_toml() if texte is None else texte).encode("utf-8"))
    # droits fixes : un amnesia.toml non designe est refuse s'il est
    # inscriptible par le groupe, ce que donnerait un umask 002
    chemin.chmod(0o600)
    return chemin


class Temoin(Check):
    """Check conforme qui compte ses évaluations."""

    id = "test.temoin"
    title = "Check témoin"

    def __init__(self) -> None:
        self.cibles: list[str] = []

    def evaluate(self, facts: FactSet, ctx: Context) -> CheckResult:
        self.cibles.append(ctx.target.id)
        return CheckResult.passed(self.id, ctx.target.id)


@pytest.fixture(autouse=True)
def _operateur_au_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    # remplace l'operateur simule de tests/conftest.py : ici, aucun terminal,
    # quel que soit celui d'ou pytest est lance ; les tests de la confirmation
    # en posent un
    monkeypatch.setattr(cli, "_terminal_interactif", lambda: False)


@pytest.fixture
def temoin(monkeypatch: pytest.MonkeyPatch) -> Temoin:
    check = Temoin()
    monkeypatch.setattr(cli, "default_checks", lambda: [check])
    return check


@pytest.fixture
def collecte_interdite(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Fait échouer le test si l'audit dépasse le contrôle du périmètre."""
    appels: list[str] = []

    def interdit(nom: str) -> Any:
        def appel(*_args: Any, **_kwargs: Any) -> NoReturn:
            appels.append(nom)
            raise AssertionError(f"{nom} appelé malgré le refus")

        return appel

    for nom in (
        "run_audit",
        "_collecteur",
        "default_checks",
        "_mot_de_passe",
        "_preparer_out",
        "write_private",
        "warn_if_not_ignored",
    ):
        monkeypatch.setattr(cli, nom, interdit(nom))
    return appels


def _terminal(monkeypatch: pytest.MonkeyPatch, saisie: str) -> None:
    monkeypatch.setattr(cli, "_terminal_interactif", lambda: True)
    monkeypatch.setattr("sys.stdin", io.StringIO(saisie))


def _refus(capsys: pytest.CaptureFixture[str], *args: str) -> str:
    """Audit refusé : code 5, rien sur stdout, rien sur le disque."""
    avant = sorted(p.name for p in Path().iterdir())
    assert main(["audit", *args]) == exitcodes.OUT_OF_SCOPE == 5
    sortie = capsys.readouterr()
    assert sortie.out == ""
    assert "audit refusé avant toute collecte" in sortie.err
    assert "Traceback" not in sortie.err
    # ni rapport, ni dossier amnesia-out
    assert sorted(p.name for p in Path().iterdir()) == avant
    return sortie.err


def _usage(capsys: pytest.CaptureFixture[str], *args: str) -> str:
    with pytest.raises(SystemExit) as exc:
        main(list(args))
    assert exc.value.code == exitcodes.USAGE == 2
    sortie = capsys.readouterr()
    assert sortie.out == ""
    assert "Traceback" not in sortie.err
    return sortie.err


def _rapport(capsys: pytest.CaptureFixture[str], *args: str) -> dict[str, Any]:
    code = main(["audit", *args, "--out", "-", "--format", "json"])
    sortie = capsys.readouterr()
    assert code == exitcodes.OK, sortie.err
    rapport: dict[str, Any] = json.loads(sortie.out)
    VALIDATEUR.validate(rapport)
    return rapport


# --- critere : cible hors perimetre, code dedie, aucune connexion ---


def test_temoin_le_reseau_est_coupe() -> None:
    # temoin positif : dans ce processus, toute connexion leve
    with pytest.raises(SocketBlockedError):
        socket.create_connection(("192.0.2.1", 5985), timeout=1)  # noqa: TID251


@pytest.mark.parametrize(
    ("cible", "include", "exclude", "motif"),
    [
        (HORS, 'dns = ["*.corp.example"]', "", "hors du périmètre autorisé"),
        ("winrm://198.51.100.7", 'cidrs = ["192.0.2.0/24"]', "", "adresse hors"),
        (
            CIBLE,
            'dns = ["*.corp.example"]',
            'hosts = ["srv01.corp.example"]',
            "exclue du périmètre",
        ),
        (
            "winrm://192.0.2.200",
            'cidrs = ["192.0.2.0/24"]',
            'cidrs = ["192.0.2.128/25"]',
            "exclue du périmètre",
        ),
        # nom que seule une plage pourrait couvrir : aucune resolution, refus
        (CIBLE, 'cidrs = ["192.0.2.0/24"]', "", "aucune résolution de nom"),
    ],
)
def test_cible_hors_perimetre_code_dedie_sans_connexion(
    cible: str,
    include: str,
    exclude: str,
    motif: str,
    collecte_interdite: list[str],
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    chemin = _perimetre(_toml(include=include, exclude=exclude))
    with caplog.at_level(logging.DEBUG):
        erreur = _refus(capsys, "--target", cible, "--scope", str(chemin))
    assert motif in erreur
    # ni collecte, ni lecture de secret, ni ecriture ; aucune connexion tentee
    assert collecte_interdite == []
    assert "SocketBlockedError" not in caplog.text
    assert "SocketBlockedError" not in erreur


def test_cible_dans_le_perimetre_auditee(
    temoin: Temoin, capsys: pytest.CaptureFixture[str]
) -> None:
    chemin = _perimetre()
    rapport = _rapport(capsys, "--target", CIBLE, "--scope", str(chemin.resolve()))
    assert temoin.cibles == [CIBLE]
    # critere : scope.sha256, mission_id et reference de l'autorisation
    scope = rapport["scope"]
    attendu = load_scope(chemin)
    assert scope["sha256"] == attendu.sha256()
    assert scope["mission_id"] == "MISSION-0001"
    assert scope["authorization"] == {
        "reference": "LM-2026-001",
        "date": _jour(-8),
    }
    assert (scope["basis"], scope["source"]) == ("scope", SOURCE_OPTION)
    assert (scope["valid_from"], scope["valid_until"]) == (_jour(-1), _jour(1))
    assert scope["active_tests"] is False
    assert scope["include"]["dns"] == ["*.corp.example"]
    assert scope["exclude"] == attendu.exclude.to_dict()
    # le chemin du poste de l'auditeur ne passe pas dans le rapport
    argv = rapport["run"]["argv"]
    assert argv[argv.index("--scope") + 1] == "perimetre.toml"
    assert "Prénom Nom" not in json.dumps(rapport, ensure_ascii=False)


def test_perimetre_verifie_journalise(
    temoin: Temoin, caplog: pytest.LogCaptureFixture
) -> None:
    chemin = _perimetre()
    with caplog.at_level(logging.INFO, logger="amnesia.cli"):
        assert main(["audit", "--target", CIBLE, "--scope", str(chemin)]) == 0
    (ligne,) = [r.getMessage() for r in caplog.records if "périmètre" in r.message]
    assert load_scope(chemin).sha256() in ligne
    assert "MISSION-0001" in ligne
    assert "LM-2026-001" in ligne
    assert CIBLE in ligne
    # rien au niveau avertissement : la sortie d'un audit couvert reste propre
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


# --- critere : periode de validite ---


@pytest.mark.parametrize(
    ("debut", "fin", "motif"),
    [(-10, -2, "périmètre expiré"), (2, 10, "périmètre pas encore valide")],
)
def test_perimetre_hors_periode_refuse(
    debut: int,
    fin: int,
    motif: str,
    collecte_interdite: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    chemin = _perimetre(_toml(debut=debut, fin=fin))
    erreur = _refus(capsys, "--target", CIBLE, "--scope", str(chemin))
    assert motif in erreur
    assert "LM-2026-001" in erreur
    assert collecte_interdite == []


# --- critere : sans terminal, sans perimetre, sans --authorized-by ---


@pytest.mark.parametrize("cible", [(), ("--target", "local"), ("--target", CIBLE)])
def test_sans_terminal_sans_perimetre_sans_reference_refuse(
    cible: tuple[str, ...],
    collecte_interdite: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    erreur = _refus(capsys, *cible)
    assert "aucun périmètre déclaré" in erreur
    assert "--authorized-by" in erreur
    assert collecte_interdite == []


def test_authorized_by_lance_l_audit_et_laisse_une_trace(
    temoin: Temoin,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="amnesia.cli"):
        rapport = _rapport(capsys, "--target", CIBLE, "--authorized-by", "LM-2026-001")
    assert temoin.cibles == [CIBLE]
    scope = rapport["scope"]
    assert scope["basis"] == "authorized-by"
    assert scope["authorization"] == {"reference": "LM-2026-001", "date": None}
    assert scope["sha256"] is scope["mission_id"] is scope["source"] is None
    assert scope["include"] is scope["exclude"] is None
    assert rapport["run"]["argv"][3:5] == ["--authorized-by", "LM-2026-001"]
    # la cible n'est comparee a rien : dit sans -v
    (avertissement,) = [r.getMessage() for r in caplog.records]
    assert "aucun périmètre déclaré" in avertissement
    assert "LM-2026-001" in avertissement


@pytest.mark.parametrize("reference", ["", "  ", "LM\x1b[2J", "password=hunter2"])
def test_authorized_by_refusee_sans_echo(
    reference: str, capsys: pytest.CaptureFixture[str]
) -> None:
    erreur = _usage(capsys, "audit", "--authorized-by", reference)
    assert "--authorized-by" in erreur
    assert "\x1b" not in erreur
    assert "hunter2" not in erreur


def test_authorized_by_refusee_avec_un_perimetre(
    collecte_interdite: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    chemin = _perimetre()
    erreur = _usage(
        capsys,
        "audit",
        "--target",
        CIBLE,
        "--scope",
        str(chemin),
        "--authorized-by",
        "LM-2026-999",
    )
    assert "--authorized-by : sans objet quand un périmètre est déclaré" in erreur
    assert collecte_interdite == []


# --- sans perimetre, au terminal : confirmation du nom exact ---


@pytest.mark.parametrize(
    ("cible", "saisie"),
    [
        ((), "local\n"),
        (("--target", "localhost"), "LOCAL\n"),
        (("--target", f"{CIBLE}:5986"), "srv01.corp.example\n"),
    ],
)
def test_confirmation_au_terminal(
    cible: tuple[str, ...],
    saisie: str,
    temoin: Temoin,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _terminal(monkeypatch, saisie)
    code = main(["audit", *cible, "--out", "-", "--format", "json"])
    sortie = capsys.readouterr()
    assert code == exitcodes.OK
    # la question va sur stderr : stdout ne porte que le rapport
    rapport = json.loads(sortie.out)
    VALIDATEUR.validate(rapport)
    assert rapport["scope"]["basis"] == "confirmation"
    assert rapport["scope"]["authorization"] == {"reference": None, "date": None}
    assert "Aucun périmètre déclaré" in sortie.err
    assert f"Cible : {rapport['targets'][0]['id']}" in sortie.err
    assert f"({saisie.strip().lower()}) : " in sortie.err
    assert len(temoin.cibles) == 1


@pytest.mark.parametrize(
    "saisie", ["", "\n", "oui\n", "srv01\n", "srv02.corp.example\n"]
)
def test_confirmation_refusee(
    saisie: str,
    collecte_interdite: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _terminal(monkeypatch, saisie)
    erreur = _refus(capsys, "--target", CIBLE)
    assert "confirmation refusée" in erreur
    assert collecte_interdite == []


def test_aucune_question_avec_un_perimetre_ou_une_reference(
    temoin: Temoin, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # terminal present, mais rien a confirmer : stdin n'est pas lu
    monkeypatch.setattr(cli, "_terminal_interactif", lambda: True)

    class Illisible(io.StringIO):
        def readline(self, *_args: Any) -> NoReturn:
            raise AssertionError("stdin lu sans raison")

    monkeypatch.setattr("sys.stdin", Illisible())
    chemin = _perimetre()
    assert main(["audit", "--target", CIBLE, "--scope", str(chemin)]) == 0
    assert main(["audit", "--authorized-by", "LM-2026-001", "--overwrite"]) == 0
    assert "Aucun périmètre déclaré" not in capsys.readouterr().err


class _Flux(io.StringIO):
    def __init__(self, terminal: bool) -> None:
        super().__init__()
        self._terminal = terminal

    def isatty(self) -> bool:
        return self._terminal


@pytest.mark.parametrize(
    ("entree", "erreurs", "attendu"),
    [(True, True, True), (True, False, False), (False, True, False)],
)
def test_terminal_interactif_exige_stdin_et_stderr(
    entree: bool, erreurs: bool, attendu: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "_terminal_interactif", TERMINAL_REEL)
    monkeypatch.setattr("sys.stdin", _Flux(entree))
    monkeypatch.setattr("sys.stderr", _Flux(erreurs))
    assert cli._terminal_interactif() is attendu
    assert (cli._confirmation_au_terminal() is not None) is attendu


def test_terminal_interactif_flux_absent_ou_ferme(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "_terminal_interactif", TERMINAL_REEL)
    monkeypatch.setattr("sys.stdin", None)
    assert cli._terminal_interactif() is False
    ferme = _Flux(True)
    ferme.close()
    monkeypatch.setattr("sys.stdin", ferme)
    assert cli._terminal_interactif() is False


def test_saisie_illisible_vaut_absence(monkeypatch: pytest.MonkeyPatch) -> None:
    ferme = io.StringIO("local\n")
    ferme.close()
    monkeypatch.setattr("sys.stdin", ferme)
    cible = Target.parse("local")
    assert cli._saisir_confirmation(cible, "local") is None


# --- bundle : aucun systeme joint ---


def test_bundle_sans_controle_ni_question(
    temoin: Temoin, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dossier = tmp_path / "collecte"
    dossier.mkdir()
    rapport = _rapport(capsys, "--target", f"bundle:{dossier}")
    assert rapport["scope"]["basis"] == "offline"
    assert rapport["scope"]["sha256"] is None
    # un perimetre expire ne bloque pas la relecture, et reste trace
    chemin = _perimetre(_toml(debut=-10, fin=-2))
    rapport = _rapport(capsys, "--target", f"bundle:{dossier}", "--scope", str(chemin))
    assert rapport["scope"]["basis"] == "offline"
    assert rapport["scope"]["sha256"] == load_scope(chemin).sha256()


# --- machine locale ---


def test_machine_locale_comparee_par_son_nom(
    temoin: Temoin,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    chemin = _perimetre()
    monkeypatch.setattr("platform.node", lambda: "SRV01.corp.example")
    rapport = _rapport(capsys, "--scope", str(chemin))
    assert rapport["scope"]["basis"] == "scope"
    assert temoin.cibles == ["local"]


def test_machine_locale_hors_perimetre_nom_hostile_neutralise(
    collecte_interdite: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    chemin = _perimetre()
    monkeypatch.setattr(
        "platform.node", lambda: "poste\x1b[2J" + chr(0x202E) + "auditeur"
    )
    erreur = _refus(capsys, "--scope", str(chemin))
    assert "machine locale" in erreur
    assert "\x1b" not in erreur
    assert chr(0x202E) not in erreur
    monkeypatch.setattr("platform.node", lambda: "poste-auditeur")
    assert "poste-auditeur" in _refus(capsys, "--scope", str(chemin))
    assert collecte_interdite == []


# --- declaration : fichier de mission, --scope, erreurs d'usage ---


def test_section_scope_du_fichier_de_mission(
    temoin: Temoin, capsys: pytest.CaptureFixture[str]
) -> None:
    mission = '[mission]\nclient = "Client Exemple"\n\n'
    chemin = _perimetre(mission + _toml(), nom="mission.toml")
    rapport = _rapport(capsys, "--target", CIBLE, "--config", str(chemin))
    scope = rapport["scope"]
    assert (scope["basis"], scope["source"]) == ("scope", SOURCE_MISSION)
    # meme perimetre, meme condensat, quel que soit le fichier qui le porte
    seul = _perimetre()
    assert scope["sha256"] == load_scope(seul).sha256()
    # le perimetre a son propre condensat : config_hash ne le couvre pas
    sans = _perimetre(mission, nom="sans-perimetre.toml")
    assert rapport["config_hash"] == load_config(sans).config_hash()
    assert rapport["mission"]["client"] == "Client Exemple"


def test_fichier_de_mission_du_repertoire_courant(
    collecte_interdite: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    # ./amnesia.toml applique sans --config : son perimetre vaut aussi
    _perimetre(nom=DEFAULT_FILE)
    erreur = _refus(capsys, "--target", HORS)
    assert "hors du périmètre autorisé" in erreur
    assert collecte_interdite == []


def test_load_config_porte_le_perimetre() -> None:
    assert Config.defaults().scope is None
    assert load_config(_perimetre(nom="mission.toml")).scope is not None
    seul = _perimetre()
    config = load_config(scope_path=seul)
    assert config.scope == load_scope(seul)
    assert config.source is None
    # le perimetre n'entre ni dans les valeurs ni dans config_hash
    assert config.config_hash() == Config.defaults().config_hash()
    assert not [cle for cle in config.values if cle.startswith("scope")]


def test_deux_perimetres_refuses(capsys: pytest.CaptureFixture[str]) -> None:
    mission = _perimetre(nom="mission.toml")
    seul = _perimetre()
    for commande in (("audit", "--target", CIBLE), ("config", "show")):
        erreur = _usage(
            capsys, *commande, "--config", str(mission), "--scope", str(seul)
        )
        assert "deux périmètres déclarés" in erreur


@pytest.mark.parametrize(
    "surcharge",
    ["scope.mission_id=AUTRE", "scope.include.hosts=srv01.autre.example", "scope=x"],
)
def test_perimetre_jamais_surcharge_par_set(
    surcharge: str, capsys: pytest.CaptureFixture[str]
) -> None:
    chemin = _perimetre()
    erreur = _usage(
        capsys, "audit", "--target", HORS, "--scope", str(chemin), "--set", surcharge
    )
    assert "ne se surcharge pas" in erreur
    with pytest.raises(ConfigError, match="ne se surcharge pas"):
        load_config(overrides=[surcharge])


@pytest.mark.parametrize(
    ("texte", "motif"),
    [
        (_toml(include='hosts = ["*.corp.example"]'), "scope.include.hosts[0]"),
        (_toml(include='cidrs = ["10.0.1.7/16"]'), "scope.include.cidrs[0]"),
        (_toml(include=""), "scope.include : au moins une inclusion"),
        (_toml().replace("mission_id", "mission"), "clé inconnue 'scope.mission'"),
        (_toml(debut=3, fin=1), "précède"),
        ('[mission]\nclient = "Client Exemple"\n', "section [scope] absente"),
        ("[scope\n", "TOML"),
    ],
)
def test_fichier_de_perimetre_refuse_code_2(
    texte: str,
    motif: str,
    collecte_interdite: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    chemin = _perimetre(texte)
    for commande in (("audit", "--target", CIBLE), ("config", "show")):
        erreur = _usage(capsys, *commande, "--scope", str(chemin))
        assert "perimetre.toml" in erreur
        assert motif in erreur
    assert collecte_interdite == []


def test_section_scope_refusee_dans_le_fichier_de_mission(
    capsys: pytest.CaptureFixture[str],
) -> None:
    chemin = _perimetre(_toml(include='aws_accounts = ["123"]'), nom="mission.toml")
    erreur = _usage(capsys, "audit", "--config", str(chemin))
    assert "mission.toml" in erreur
    assert "scope.include.aws_accounts[0]" in erreur
    # une cle au nom de secret est refusee dans le perimetre comme ailleurs
    secret = _toml().replace("[scope.exclude]", 'token = "hunter2"\n[scope.exclude]')
    erreur = _usage(capsys, "audit", "--config", str(_perimetre(secret, "m2.toml")))
    assert "aucun secret" in erreur
    assert "hunter2" not in erreur


def test_fichier_de_perimetre_absent_chemin_neutralise(
    capsys: pytest.CaptureFixture[str],
) -> None:
    erreur = _usage(capsys, "audit", "--scope", "absent\x1b[31m.toml")
    assert "configuration" in erreur
    assert "\x1b" not in erreur


# --- amnesia config show ---


def test_config_show_affiche_le_perimetre(capsys: pytest.CaptureFixture[str]) -> None:
    chemin = _perimetre(
        _toml(
            include='dns = ["*.corp.example"]\ncidrs = ["192.0.2.0/24"]',
            exclude='hosts = ["srv09.corp.example"]',
        )
    )
    assert main(["config", "show", "--scope", str(chemin)]) == exitcodes.OK
    sortie = capsys.readouterr().out
    lignes = sortie.splitlines()
    attendu = load_scope(chemin)
    assert f"Périmètre autorisé : {SOURCE_OPTION}" in lignes
    assert f"scope.sha256 : {attendu.sha256()}" in lignes
    # config_hash reste la derniere ligne, et ne depend pas du perimetre
    assert lignes[-1] == f"config_hash : {Config.defaults().config_hash()}"
    champs = {ligne.split()[0]: ligne.split(maxsplit=1)[1] for ligne in lignes[1:]}
    assert champs["scope.mission_id"] == '"MISSION-0001"'
    assert champs["scope.authorization.reference"] == '"LM-2026-001"'
    assert champs["scope.authorization.signatory"] == '"Prénom Nom"'
    assert champs["scope.valid_from"] == f'"{_jour(-1)}"'
    assert champs["scope.active_tests"] == "false"
    assert champs["scope.include.dns"] == '["*.corp.example"]'
    assert champs["scope.include.cidrs"] == '["192.0.2.0/24"]'
    assert champs["scope.exclude.hosts"] == '["srv09.corp.example"]'
    # un type sans entree n'est pas affiche
    assert "scope.include.hosts" not in champs


def test_config_show_sans_perimetre(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["config", "show"]) == exitcodes.OK
    sortie = capsys.readouterr().out
    assert "Périmètre autorisé : aucun" in sortie
    assert "--authorized-by" in sortie
    assert "scope.sha256" not in sortie


def test_config_show_perimetre_expire_affiche_sans_audit(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # config show lit et valide, sans juger la periode : c'est audit qui refuse
    chemin = _perimetre(_toml(debut=-10, fin=-2))
    assert main(["config", "show", "--scope", str(chemin)]) == exitcodes.OK
    assert "scope.sha256" in capsys.readouterr().out


# --- aide ---


def test_aide_documente_le_code_dedie_et_les_options(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["audit", "--help"])
    assert exc.value.code == 0
    aide = " ".join(capsys.readouterr().out.split())
    assert "--scope FICHIER" in aide
    assert "--authorized-by REFERENCE" in aide
    assert "5 audit refusé avant toute collecte" in aide
    assert "hors du périmètre autorisé" in aide


def test_collecteur_jamais_construit_avant_l_autorisation(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # ordre des etapes : le perimetre est verifie avant le mot de passe, le
    # dossier des livrables, les checks et le collecteur
    etapes: list[str] = []

    def tracer(nom: str) -> None:
        vraie = getattr(cli, nom)

        def enveloppe(*args: Any, **kwargs: Any) -> Any:
            etapes.append(nom)
            return vraie(*args, **kwargs)

        monkeypatch.setattr(cli, nom, enveloppe)

    for nom in ("_autoriser", "_mot_de_passe", "_preparer_out", "_collecteur"):
        tracer(nom)
    chemin = _perimetre()
    assert main(["audit", "--target", CIBLE, "--scope", str(chemin)]) in {0, 1, 3}
    assert etapes == ["_autoriser", "_mot_de_passe", "_preparer_out", "_collecteur"]
    capsys.readouterr()


def _noms(chemins: Iterable[Path]) -> list[str]:
    return sorted(chemin.name for chemin in chemins)


def test_refus_ne_laisse_rien_sur_le_disque(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    chemin = _perimetre()
    _refus(capsys, "--target", HORS, "--scope", str(chemin), "--out", "r.json")
    _refus(capsys, "--target", HORS, "--scope", str(chemin))
    assert _noms(tmp_path.iterdir()) == ["perimetre.toml"]
