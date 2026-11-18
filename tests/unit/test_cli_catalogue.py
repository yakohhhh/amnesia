# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Commandes ``amnesia catalog list``, ``show`` et ``validate`` (#46)."""

import dataclasses
import shutil
from importlib import resources
from pathlib import Path

import pytest

from amnesia import cli
from amnesia.catalog import (
    Catalog,
    QuestionStatus,
    Theme,
    load_catalog,
    read_catalog,
)
from amnesia.cli import main
from amnesia.exitcodes import FATAL, OK, USAGE

EMBARQUE = Path(str(resources.files("amnesia.catalog")))


@pytest.fixture
def copie(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Copie modifiable du catalogue, lue par la CLI à la place de l'embarqué."""
    racine = tmp_path / "catalogue"
    racine.mkdir()
    for nom in ("VERSION", "ids.lock"):
        shutil.copyfile(EMBARQUE / nom, racine / nom)
    for dossier in ("questions", "sources"):
        shutil.copytree(EMBARQUE / dossier, racine / dossier)
    monkeypatch.setattr(cli, "load_catalog", lambda: read_catalog(racine))
    return racine


def _remplacer(racine: Path, fichier: str, ancien: str, nouveau: str) -> None:
    chemin = racine / fichier
    texte = chemin.read_text(encoding="utf-8")
    assert texte.count(ancien) == 1, (fichier, ancien, texte.count(ancien))
    chemin.write_text(texte.replace(ancien, nouveau), encoding="utf-8", newline="\n")


# --- validate -----------------------------------------------------------------


def test_validate_catalogue_embarque(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["catalog", "validate"]) == OK
    sortie = capsys.readouterr()
    catalogue = load_catalog()
    actives = sum(1 for q in catalogue if q.status is QuestionStatus.ACTIVE)
    assert sortie.out == (
        f"catalogue {catalogue.version} valide : {len(catalogue)} questions, "
        f"{len(catalogue.sources)} sources, {actives} questions reliées à un check\n"
    )
    assert sortie.err == ""


def _echec(capsys: pytest.CaptureFixture[str]) -> list[str]:
    """Lignes d'erreur de ``catalog validate``, qui doit échouer sans rien valider."""
    assert main(["catalog", "validate"]) == FATAL != OK
    sortie = capsys.readouterr()
    assert sortie.out == ""
    lignes = sortie.err.splitlines()
    assert lignes
    assert all("catalogue invalide : " in ligne for ligne in lignes)
    return lignes


def test_validate_identifiant_duplique(
    copie: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fichier = copie / "questions" / "ad.toml"
    texte = fichier.read_text(encoding="utf-8")
    # premiere table du fichier (l'en-tete cite aussi [[question]] en commentaire)
    debut = texte.index("\n[[question]]\n") + 1
    fin = texte.index("\n[[question]]\n", debut) + 1
    fichier.write_text(texte + "\n" + texte[debut:fin], encoding="utf-8", newline="\n")
    (ligne,) = _echec(capsys)
    assert "questions/ad.toml : question n° 11 (Q-AD-PRIV-GROUP) : id : " in ligne
    assert "identifiant dupliqué 'Q-AD-PRIV-GROUP'" in ligne


def test_validate_source_inconnue(
    copie: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _remplacer(copie, "questions/ad.toml", '"SRC-AD-4724",', '"SRC-AD-0000",')
    (ligne,) = _echec(capsys)
    assert ligne.endswith(
        "questions/ad.toml : question n° 3 (Q-AD-PASSWORD-RESET) : sources : "
        "source inconnue 'SRC-AD-0000'"
    )


def test_validate_guid_mal_forme(
    copie: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _remplacer(
        copie,
        "sources/windows.toml",
        'guid = "{0CCE922B-69AE-11D9-BED3-505054503030}"',
        'guid = "{0CCE922B-69AE-11D9-BED3}"',
    )
    (ligne,) = _echec(capsys)
    assert (
        "sources/windows.toml : source n° 11 (SRC-SEC-4688-CMDLINE) : "
        "prerequisites[0].guid : GUID mal formé '{0CCE922B-69AE-11D9-BED3}'" in ligne
    )


def test_validate_question_active_sans_check(
    copie: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _remplacer(
        copie, "questions/windows.toml", 'checks = ["win.time_sync"]', "checks = []"
    )
    (ligne,) = _echec(capsys)
    assert (
        "questions/windows.toml : question n° 21 (Q-WIN-TIMELINE) : checks : "
        "question active sans check" in ligne
    )


def test_validate_check_inconnu(
    copie: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _remplacer(
        copie,
        "questions/windows.toml",
        'checks = ["win.time_sync"]',
        'checks = ["win.horloge"]',
    )
    lignes = _echec(capsys)
    assert any(
        ligne.endswith(
            "questions/windows.toml : question Q-WIN-TIMELINE : checks : check "
            "inconnu du registre 'win.horloge'"
        )
        for ligne in lignes
    )
    # et le check delaisse signale la question qui ne le liste plus
    assert any(
        "check win.time_sync" in ligne
        and "Q-WIN-TIMELINE ne liste pas ce check" in ligne
        for ligne in lignes
    )
    assert len(lignes) == 2


def test_validate_identifiant_publie_supprime(
    copie: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _remplacer(copie, "ids.lock", "Q-AD-ASREP\n", "Q-AD-ANCIENNE\nQ-AD-ASREP\n")
    (ligne,) = _echec(capsys)
    assert "ids.lock : Q-AD-ANCIENNE : identifiant publié absent du catalogue" in ligne


def test_erreur_rendue_imprimable(
    copie: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # une valeur du fichier ne pilote pas le terminal de qui valide
    _remplacer(copie, "questions/ad.toml", '"SRC-AD-4724",', '"SRC-AD-\\u001b[2J",')
    (ligne,) = _echec(capsys)
    assert "\x1b" not in ligne
    assert "(Q-AD-PASSWORD-RESET) : sources : identifiant mal formé" in ligne


@pytest.mark.parametrize("commande", [["list"], ["show", "Q-WIN-RDP-LOGON"]])
def test_catalogue_invalide_fatal_pour_toute_commande(
    copie: Path, capsys: pytest.CaptureFixture[str], commande: list[str]
) -> None:
    (copie / "VERSION").write_text("demain\n", encoding="utf-8")
    assert main(["catalog", *commande]) == FATAL
    sortie = capsys.readouterr()
    assert sortie.out == ""
    assert "catalogue invalide : VERSION : version CalVer attendue" in sortie.err


# --- list ---------------------------------------------------------------------


def test_list_groupe_par_theme_avec_statut(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["catalog", "list"]) == OK
    sortie = capsys.readouterr()
    assert sortie.err == ""
    lignes = sortie.out.splitlines()
    catalogue = load_catalog()
    assert lignes[0] == (
        f"Catalogue {catalogue.version} : {len(catalogue)} questions, "
        f"{len(catalogue.sources)} sources de télémétrie"
    )
    # un titre par theme, dans l'ordre de Theme, precede d'une ligne vide
    titres = [ligne for ligne in lignes[1:] if ligne and not ligne.startswith(" ")]
    assert titres == [theme.label for theme in Theme]
    for titre in titres:
        assert lignes[lignes.index(titre) - 1] == ""
    # sous chaque theme : ses questions triees, avec statut et gabarit
    groupes: dict[str, list[str]] = {}
    courant = ""
    for ligne in lignes[1:]:
        if ligne and not ligne.startswith(" "):
            courant = ligne
        elif ligne:
            groupes.setdefault(courant, []).append(ligne)
    for theme in Theme:
        attendues = [q for q in catalogue if q.theme is theme]
        assert len(groupes[theme.label]) == len(attendues) > 0
        for ligne, question in zip(groupes[theme.label], attendues, strict=True):
            identifiant, statut, texte = ligne.split(maxsplit=2)
            assert identifiant == question.id
            assert statut == question.status.label
            assert texte == question.text
    assert sum(len(g) for g in groupes.values()) == len(catalogue)
    rdp = next(ligne for ligne in lignes if "Q-WIN-RDP-LOGON" in ligne)
    assert rdp.split()[:2] == ["Q-WIN-RDP-LOGON", "active"]
    assert rdp.endswith("Qui s'est connecté en RDP sur {host} il y a {lookback} ?")
    assert any(ligne.split()[:2] == ["Q-AD-DCSYNC", "prévue"] for ligne in lignes)


def test_list_affiche_une_question_depreciee(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    catalogue = load_catalog()
    questions = [
        dataclasses.replace(
            q,
            status=QuestionStatus.DEPRECATED,
            checks=(),
            replaced_by="Q-WIN-SHARE-ACCESS",
        )
        if q.id == "Q-WIN-USB"
        else q
        for q in catalogue
    ]
    modifie = Catalog(catalogue.version, questions, catalogue.sources)
    monkeypatch.setattr(cli, "load_catalog", lambda: modifie)
    assert main(["catalog", "list"]) == OK
    lignes = capsys.readouterr().out.splitlines()
    assert any(ligne.split()[:2] == ["Q-WIN-USB", "dépréciée"] for ligne in lignes)
    assert main(["catalog", "show", "Q-WIN-USB"]) == OK
    fiche = capsys.readouterr().out.splitlines()
    assert fiche[0] == "Q-WIN-USB  [dépréciée]"
    assert fiche[1] == "Remplacée par : Q-WIN-SHARE-ACCESS"
    assert "Checks : aucun pour l'instant" in fiche


# --- show ---------------------------------------------------------------------


def test_show_question(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["catalog", "show", "Q-WIN-PROCESS-CMDLINE"]) == OK
    sortie = capsys.readouterr()
    assert sortie.err == ""
    lignes = sortie.out.splitlines()
    question = load_catalog().question("Q-WIN-PROCESS-CMDLINE")
    assert lignes[:8] == [
        "Q-WIN-PROCESS-CMDLINE  [active]",
        f"Question : {question.text}",
        f"Pourquoi : {question.why}",
        "Domaine : windows",
        "Thème : Exécution",
        "Rôles : contrôleur de domaine, serveur, poste",
        "Sévérité par défaut : high",
        "Checks : win.audit_policy, win.event_log_retention, win.sysmon",
    ]
    assert lignes[8] == "Sources (une seule suffit) :"
    assert "  SRC-SEC-4688-CMDLINE  Security 4688" in lignes
    assert (
        "    prérequis : sous-catégorie d'audit « Process Creation » "
        "{0CCE922B-69AE-11D9-BED3-505054503030} (succès)" in lignes
    )
    assert (
        "    prérequis : registre HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
        "\\Policies\\System\\Audit\\ProcessCreationIncludeCmdLine_Enabled = 1" in lignes
    )
    assert "    par défaut : absent d'une installation par défaut" in lignes
    assert "  SRC-SYSMON-1  Microsoft-Windows-Sysmon/Operational 1" in lignes
    assert "Références :" in lignes
    assert "  anssi ANSSI-PB-090 v1.1" in lignes
    assert any(ligne.startswith("  microsoft MS-GPAC : https://") for ligne in lignes)


def test_show_question_prevue_et_source(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["catalog", "show", "Q-AD-DCSYNC"]) == OK
    lignes = capsys.readouterr().out.splitlines()
    assert lignes[0] == "Q-AD-DCSYNC  [prévue]"
    assert "Checks : aucun pour l'instant" in lignes
    assert "    par défaut : non établi" in lignes
    assert main(["catalog", "show", "SRC-SEC-1102"]) == OK
    assert capsys.readouterr().out.splitlines() == [
        "SRC-SEC-1102  Security 1102",
        "  Effacement du journal Security",
        "  fournisseur : Microsoft-Windows-Eventlog",
        "  par défaut : journalisé sur une installation par défaut",
    ]
    assert main(["catalog", "show", "SRC-WIN-TIME-SYNC"]) == OK
    reglage = capsys.readouterr().out.splitlines()
    assert reglage[0].startswith("SRC-WIN-TIME-SYNC  réglage : ")
    assert not any("fournisseur" in ligne for ligne in reglage)


@pytest.mark.parametrize(
    "identifiant", ["Q-WIN-INCONNUE", "SRC-INCONNUE-1", "win.sysmon", "\x1b[2J"]
)
def test_show_identifiant_inconnu_erreur_d_usage(
    identifiant: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["catalog", "show", identifiant])
    assert exc.value.code == USAGE
    sortie = capsys.readouterr()
    assert sortie.out == ""
    assert "catalog show : identifiant inconnu" in sortie.err
    # la saisie n'est pas recopiee dans le terminal
    assert identifiant not in sortie.err


@pytest.mark.parametrize(
    "arguments", [["catalog"], ["catalog", "show"], ["catalog", "x"]]
)
def test_sous_commande_manquante_ou_inconnue(
    arguments: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        main(arguments)
    assert exc.value.code == USAGE
    assert capsys.readouterr().out == ""


def test_options_de_journal_de_part_et_d_autre(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["-v", "catalog", "validate"]) == OK
    assert main(["catalog", "validate", "-q"]) == OK
    assert main(["catalog", "-v", "list"]) == OK
    capsys.readouterr()


def test_aide_cite_les_trois_commandes(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["catalog", "--help"])
    assert exc.value.code == 0
    aide = capsys.readouterr().out
    for commande in ("list", "show", "validate"):
        assert commande in aide
