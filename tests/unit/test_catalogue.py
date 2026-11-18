# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Catalogue des questions d'enquête : contenu embarqué, rendu, validation (#46)."""

import copy
import dataclasses
import pickle
import re
import shutil
import time
import tomllib
from importlib import resources
from pathlib import Path

import pytest

from amnesia.catalog import (
    PLACEHOLDERS,
    Catalog,
    CatalogError,
    PrerequisiteKind,
    Question,
    QuestionStatus,
    Role,
    SourceKind,
    Theme,
    UnknownIdError,
    humanize_days,
    load_catalog,
    loader,
    read_catalog,
    render_question,
)
from amnesia.catalog.loader import FORMAT_SOURCE_ID, FORMAT_VERSION
from amnesia.catalog.model import placeholders_of
from amnesia.checks import Domain
from amnesia.checks import registry as registre_des_checks
from amnesia.checks.base import FORMAT_QUESTION_ID, ReferenceKind, Severity

EMBARQUE = Path(str(resources.files("amnesia.catalog")))

# contenu initial M1 de l'issue #46 : ces identifiants sont publies
QUESTIONS_M1 = {
    "Q-WIN-RDP-LOGON",
    "Q-WIN-NETWORK-LOGON",
    "Q-WIN-EXPLICIT-CREDS",
    "Q-WIN-PRIV-LOGON",
    "Q-WIN-LOCAL-ADMIN",
    "Q-WIN-PROCESS-CMDLINE",
    "Q-WIN-POWERSHELL",
    "Q-WIN-SERVICE-INSTALL",
    "Q-WIN-SCHTASK",
    "Q-WIN-WMI-PERSIST",
    "Q-WIN-AUTORUN",
    "Q-WIN-OUTBOUND",
    "Q-WIN-DNS",
    "Q-WIN-USB",
    "Q-WIN-SHARE-ACCESS",
    "Q-WIN-LOG-CLEARED",
    "Q-WIN-AUDIT-CHANGE",
    "Q-WIN-TIME-CHANGE",
    "Q-WIN-SHADOW-DELETE",
    "Q-WIN-DEFENDER-TAMPER",
    "Q-WIN-TIMELINE",
    "Q-AD-PRIV-GROUP",
    "Q-AD-ACCOUNT-CREATE",
    "Q-AD-PASSWORD-RESET",
    "Q-AD-DCSYNC",
    "Q-AD-KERBEROAST",
    "Q-AD-ASREP",
    "Q-AD-PWD-SPRAY",
    "Q-AD-GPO-CHANGE",
    "Q-AD-ACL-CHANGE",
    "Q-AD-CERT-ISSUE",
}


@pytest.fixture
def copie(tmp_path: Path) -> Path:
    """Copie modifiable du catalogue embarqué (données seules)."""
    racine = tmp_path / "catalogue"
    racine.mkdir()
    for nom in ("VERSION", "ids.lock"):
        shutil.copyfile(EMBARQUE / nom, racine / nom)
    for dossier in ("questions", "sources"):
        shutil.copytree(EMBARQUE / dossier, racine / dossier)
    return racine


def _remplacer(racine: Path, fichier: str, ancien: str, nouveau: str) -> None:
    chemin = racine / fichier
    texte = chemin.read_text(encoding="utf-8")
    assert texte.count(ancien) == 1, (fichier, ancien, texte.count(ancien))
    chemin.write_text(texte.replace(ancien, nouveau), encoding="utf-8", newline="\n")


def _ajouter(racine: Path, fichier: str, texte: str) -> None:
    chemin = racine / fichier
    contenu = chemin.read_text(encoding="utf-8")
    chemin.write_text(contenu + texte, encoding="utf-8", newline="\n")


def _erreurs(racine: Path) -> tuple[str, ...]:
    with pytest.raises(CatalogError) as exc:
        read_catalog(racine)
    assert exc.value.errors
    assert str(exc.value) == "\n".join(exc.value.errors)
    return exc.value.errors


def _bloc(racine: Path, fichier: str, identifiant: str) -> str:
    """Texte de la table TOML d'identifiant ``identifiant``, jusqu'à la suivante."""
    texte = (racine / fichier).read_text(encoding="utf-8")
    debut = texte.index(f'id = "{identifiant}"')
    debut = texte.rindex("[[", 0, debut)
    fin = texte.find("\n[[", debut + 2)
    return texte[debut:] if fin == -1 else texte[debut : fin + 1]


QUESTION_MINIMALE = """
[[question]]
id = "Q-WIN-NOUVELLE"
status = "planned"
domain = "windows"
theme = "execution"
roles = ["server"]
severity_default = "low"
text.fr = "Que s'est-il passé sur {host} ?"
why.fr = "Sans réponse, l'enquête piétine."
sources = ["SRC-SEC-4688-CMDLINE"]
"""


# --- contenu embarque -----------------------------------------------------------


def test_catalogue_embarque_charge_et_mis_en_cache() -> None:
    catalogue = load_catalog()
    assert isinstance(catalogue, Catalog)
    assert load_catalog() is catalogue
    assert FORMAT_VERSION.fullmatch(catalogue.version)
    version = (EMBARQUE / "VERSION").read_text(encoding="utf-8").strip()
    assert catalogue.version == version
    assert repr(catalogue) == (
        f"Catalog(version={version!r}, questions={len(catalogue)}, "
        f"sources={len(catalogue.sources)})"
    )


def test_au_moins_25_questions_et_30_sources_windows_et_ad() -> None:
    catalogue = load_catalog()
    assert len(catalogue.questions) == len(catalogue) >= 25
    assert len(catalogue.sources) >= 30
    assert {q.domain for q in catalogue} == {Domain.WINDOWS, Domain.AD}
    assert {s.domain for s in catalogue.sources} == {Domain.WINDOWS, Domain.AD}
    assert {q.id for q in catalogue} >= QUESTIONS_M1
    # tries par identifiant : affichage et rapports deterministes
    assert [q.id for q in catalogue] == sorted(q.id for q in catalogue)
    assert [s.id for s in catalogue.sources] == sorted(s.id for s in catalogue.sources)


def test_chaque_question_a_au_moins_une_source_connue() -> None:
    catalogue = load_catalog()
    utilisees: set[str] = set()
    for question in catalogue:
        sources = catalogue.sources_of(question.id)
        assert sources, question.id
        assert [s.id for s in sources] == list(question.sources)
        utilisees.update(question.sources)
    # aucune source orpheline : chacune sert au moins une question
    assert utilisees == {s.id for s in catalogue.sources}


def test_forme_des_questions_embarquees() -> None:
    for question in load_catalog():
        assert FORMAT_QUESTION_ID.fullmatch(question.id)
        assert question.id.startswith(f"Q-{question.domain.prefix.upper()}-")
        assert question.text.endswith(" ?"), question.id
        assert question.why.endswith("."), question.id
        assert question.roles
        assert set(question.placeholders) <= set(PLACEHOLDERS)
        # traduction anglaise : #138 ; scenarios : #75
        assert question.text_en == question.why_en == ""
        assert question.scenarios == ()
        # active <=> au moins un check contributeur
        assert (question.status is QuestionStatus.ACTIVE) is bool(question.checks)
        assert question.replaced_by is None
        # la correspondance ATT&CK releve de #147
        assert all(r.kind is not ReferenceKind.ATTACK for r in question.references)
    themes = {q.theme for q in load_catalog()}
    assert themes == set(Theme)


def test_questions_ad_prevues_tant_qu_aucun_check_ad_n_existe() -> None:
    ad = [q for q in load_catalog() if q.domain is Domain.AD]
    assert len(ad) == 10
    assert {q.status for q in ad} == {QuestionStatus.PLANNED}
    assert all(Role.DC in q.roles for q in ad)


def test_sources_de_l_issue() -> None:
    catalogue = load_catalog()
    rdp = catalogue.source("SRC-SEC-4624-T10")
    assert rdp.kind is SourceKind.EVENT
    assert (rdp.channel, rdp.event_ids) == ("Security", (4624,))
    assert rdp.filters == (("LogonType", 10),)
    assert rdp.summary() == "Security 4624 (LogonType = 10)"
    # 4688 : sous-categorie Process Creation et ligne de commande
    processus = catalogue.source("SRC-SEC-4688-CMDLINE")
    sous_categorie, registre = processus.prerequisites
    assert sous_categorie.kind is PrerequisiteKind.AUDIT_SUBCATEGORY
    assert sous_categorie.guid == "{0CCE922B-69AE-11D9-BED3-505054503030}"
    assert sous_categorie.success and not sous_categorie.failure
    assert registre.kind is PrerequisiteKind.REGISTRY_VALUE
    assert (registre.name, registre.value) == (
        "ProcessCreationIncludeCmdLine_Enabled",
        1,
    )
    assert processus.enabled_by_default is False
    # DCSync : les deux droits de replication, et une SACL sur la racine
    dcsync = catalogue.source("SRC-AD-4662-DCSYNC")
    droits = (
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
    )
    assert dict(dcsync.filters) == {"Properties": droits}
    (sacl,) = [p for p in dcsync.prerequisites if p.kind is PrerequisiteKind.SACL]
    assert sacl.guids == droits
    assert "SACL" in sacl.describe()
    # non etabli tant que #50 ne l'a pas confirme
    assert dcsync.enabled_by_default is None
    assert catalogue.source("SRC-AD-4769-RC4").filters == (
        ("TicketEncryptionType", "0x17"),
    )
    # la chronologie repose sur un reglage, pas sur un evenement
    horloge = catalogue.source("SRC-WIN-TIME-SYNC")
    assert horloge.kind is SourceKind.SETTING
    assert horloge.event_ids == () and horloge.channel is None
    assert horloge.summary().startswith("réglage : ")
    assert catalogue.question("Q-WIN-TIMELINE").sources == ("SRC-WIN-TIME-SYNC",)
    assert catalogue.question("Q-WIN-TIMELINE").checks == ("win.time_sync",)
    for source in catalogue.sources:
        assert FORMAT_SOURCE_ID.fullmatch(source.id)
        for prerequis in source.prerequisites:
            assert prerequis.describe()


def test_identifiant_inconnu() -> None:
    catalogue = load_catalog()
    assert "Q-WIN-RDP-LOGON" in catalogue
    assert "Q-WIN-INCONNUE" not in catalogue
    assert None not in catalogue
    assert ["Q-WIN-RDP-LOGON"] not in catalogue
    with pytest.raises(UnknownIdError, match="question inconnue"):
        catalogue.question(["Q-WIN-RDP-LOGON"])  # type: ignore[arg-type]
    with pytest.raises(UnknownIdError, match=r"question inconnue.*Q-WIN-INCONNUE"):
        catalogue.question("Q-WIN-INCONNUE")
    with pytest.raises(UnknownIdError, match=r"source inconnue.*SRC-INCONNUE-1"):
        catalogue.source("SRC-INCONNUE-1")
    with pytest.raises(UnknownIdError):
        render_question("Q-WIN-INCONNUE", host="SRV-FILE", lookback_days=21)
    # LookupError, pas KeyError : str() rend le message tel quel
    assert issubclass(UnknownIdError, LookupError)


def test_questions_d_un_check() -> None:
    catalogue = load_catalog()
    assert [q.id for q in catalogue.questions_of_check("win.time_sync")] == [
        "Q-WIN-TIMELINE"
    ]
    assert catalogue.questions_of_check("win.inconnu") == ()


# --- identifiants publies (ids.lock) ---------------------------------------------


def test_ids_lock_liste_exactement_les_questions() -> None:
    lignes = (EMBARQUE / "ids.lock").read_text(encoding="utf-8").splitlines()
    ids = [ligne for ligne in lignes if ligne and not ligne.startswith("#")]
    assert ids == sorted(set(ids))
    assert set(ids) == {q.id for q in load_catalog()} >= QUESTIONS_M1


def test_supprimer_une_question_publiee_echoue(copie: Path) -> None:
    bloc = _bloc(copie, "questions/windows.toml", "Q-WIN-USB")
    _remplacer(copie, "questions/windows.toml", bloc, "")
    (erreur,) = _erreurs(copie)
    assert erreur.startswith("ids.lock : Q-WIN-USB : identifiant publié absent")
    assert "deprecated" in erreur


def test_retirer_un_identifiant_de_ids_lock_echoue(copie: Path) -> None:
    _remplacer(copie, "ids.lock", "Q-WIN-USB\n", "")
    (erreur,) = _erreurs(copie)
    assert re.fullmatch(
        r"questions/windows\.toml : question n° \d+ \(Q-WIN-USB\) : id : "
        r"identifiant absent de ids\.lock .*",
        erreur,
    )


def test_question_nouvelle_absente_de_ids_lock_refusee(copie: Path) -> None:
    _ajouter(copie, "questions/windows.toml", QUESTION_MINIMALE)
    (erreur,) = _erreurs(copie)
    assert "(Q-WIN-NOUVELLE) : id : identifiant absent de ids.lock" in erreur
    _ajouter(copie, "ids.lock", "Q-WIN-NOUVELLE\n")
    (erreur,) = _erreurs(copie)
    assert erreur == "ids.lock : identifiants attendus triés et sans doublon"
    _remplacer(copie, "ids.lock", "Q-WIN-NOUVELLE\n", "")
    _remplacer(
        copie, "ids.lock", "Q-WIN-OUTBOUND\n", "Q-WIN-NOUVELLE\nQ-WIN-OUTBOUND\n"
    )
    catalogue = read_catalog(copie)
    assert catalogue.question("Q-WIN-NOUVELLE").status is QuestionStatus.PLANNED


def test_ids_lock_mal_forme(copie: Path) -> None:
    _ajouter(copie, "ids.lock", "q-win-minuscule\n")
    erreurs = _erreurs(copie)
    assert any(
        re.fullmatch(r"ids\.lock : ligne \d+ : identifiant de question mal formé .*", e)
        for e in erreurs
    )
    (copie / "ids.lock").unlink()
    assert "ids.lock : fichier absent" in _erreurs(copie)


def test_question_depreciee_reste_presente_avec_replaced_by(copie: Path) -> None:
    # depreciee : plus aucun check, et la question qui la remplace est nommee
    bloc = _bloc(copie, "questions/windows.toml", "Q-WIN-USB")
    deprecie = re.sub(r"checks = \[[^\]]*\]", "checks = []", bloc).replace(
        'status = "active"',
        'status = "deprecated"\nreplaced_by = "Q-WIN-SHARE-ACCESS"',
    )
    _remplacer(copie, "questions/windows.toml", bloc, deprecie)
    catalogue = read_catalog(copie)
    question = catalogue.question("Q-WIN-USB")
    assert question.status is QuestionStatus.DEPRECATED
    assert question.replaced_by == "Q-WIN-SHARE-ACCESS"
    assert question.checks == ()
    # elle se rend toujours : un ancien rapport reste lisible
    assert catalogue.render("Q-WIN-USB", host="PC-01", lookback_days=7).endswith(
        "sur PC-01 il y a une semaine ?"
    )
    assert len(catalogue) == len(load_catalog())


def test_depreciation_invalide(copie: Path) -> None:
    fichier = "questions/windows.toml"
    bloc = _bloc(copie, fichier, "Q-WIN-USB")
    sans_checks = re.sub(r"checks = \[[^\]]*\]", "checks = []", bloc)
    # sans replaced_by
    deprecie = sans_checks.replace('status = "active"', 'status = "deprecated"')
    _remplacer(copie, fichier, bloc, deprecie)
    (erreur,) = _erreurs(copie)
    assert "(Q-WIN-USB) : replaced_by : champ obligatoire" in erreur
    # replaced_by inconnu, puis elle-meme
    for cible in ("Q-WIN-INCONNUE", "Q-WIN-USB"):
        essai = deprecie.replace(
            'status = "deprecated"', f'status = "deprecated"\nreplaced_by = "{cible}"'
        )
        _remplacer(copie, fichier, deprecie, essai)
        (erreur,) = _erreurs(copie)
        assert f"(Q-WIN-USB) : replaced_by : question inconnue '{cible}'" in erreur
        _remplacer(copie, fichier, essai, deprecie)
    # avec des checks encore relies
    avec_checks = bloc.replace(
        'status = "active"', 'status = "deprecated"\nreplaced_by = "Q-WIN-DNS"'
    )
    _remplacer(copie, fichier, deprecie, avec_checks)
    (erreur,) = _erreurs(copie)
    assert "(Q-WIN-USB) : checks : question deprecated avec des checks" in erreur
    # replaced_by sur une question qui n'est pas depreciee
    _remplacer(
        copie,
        fichier,
        avec_checks,
        bloc.replace("checks", 'replaced_by = "Q-WIN-DNS"\nchecks', 1),
    )
    (erreur,) = _erreurs(copie)
    assert '(Q-WIN-USB) : replaced_by : réservé à status = "deprecated"' in erreur


def test_remplacement_par_une_question_depreciee_refuse(copie: Path) -> None:
    fichier = "questions/windows.toml"
    for identifiant, cible in (
        ("Q-WIN-USB", "Q-WIN-DNS"),
        ("Q-WIN-DNS", "Q-WIN-OUTBOUND"),
    ):
        bloc = _bloc(copie, fichier, identifiant)
        deprecie = re.sub(r"checks = \[[^\]]*\]", "checks = []", bloc).replace(
            'status = "active"', f'status = "deprecated"\nreplaced_by = "{cible}"'
        )
        _remplacer(copie, fichier, bloc, deprecie)
    (erreur,) = _erreurs(copie)
    assert "(Q-WIN-USB) : replaced_by : Q-WIN-DNS est elle-même dépréciée" in erreur


# --- rendu d'une question -------------------------------------------------------


def test_render_question_du_readme() -> None:
    assert (
        render_question("Q-WIN-RDP-LOGON", host="SRV-FILE", lookback_days=21)
        == "Qui s'est connecté en RDP sur SRV-FILE il y a trois semaines ?"
    )


@pytest.mark.parametrize(
    ("jours", "attendu"),
    [
        (1, "1 jour"),
        (2, "2 jours"),
        (4, "4 jours"),
        (7, "une semaine"),
        (10, "10 jours"),
        (14, "deux semaines"),
        (21, "trois semaines"),
        (28, "quatre semaines"),
        (30, "un mois"),
        (45, "45 jours"),
        (60, "deux mois"),
        (84, "douze semaines"),
        (90, "trois mois"),
        (91, "13 semaines"),
        (180, "six mois"),
        (210, "sept mois"),
        (360, "douze mois"),
        (365, "un an"),
        (390, "13 mois"),
        (730, "deux ans"),
    ],
)
def test_duree_humanisee(jours: int, attendu: str) -> None:
    assert humanize_days(jours) == attendu


@pytest.mark.parametrize(
    ("jours", "exception"),
    [
        (0, ValueError),
        (-7, ValueError),
        (True, TypeError),
        (1.5, TypeError),
        ("21", TypeError),
    ],
)
def test_duree_invalide_refusee(jours: object, exception: type[Exception]) -> None:
    with pytest.raises(exception, match="lookback_days"):
        humanize_days(jours)  # type: ignore[arg-type]
    with pytest.raises(exception, match="lookback_days"):
        render_question("Q-WIN-RDP-LOGON", host="SRV-FILE", lookback_days=jours)  # type: ignore[arg-type]


def test_toute_question_se_rend_avec_un_contexte_complet() -> None:
    for question in load_catalog():
        texte = question.render(
            host="SRV-FILE", lookback_days=14, account="svc-sauvegarde", share="Compta"
        )
        assert "{" not in texte and "}" not in texte, question.id
        assert "deux semaines" in texte or "lookback" not in question.placeholders


def test_valeur_manquante_ou_superflue() -> None:
    with pytest.raises(
        ValueError, match=r"Q-WIN-RDP-LOGON : valeur manquante pour host"
    ):
        render_question("Q-WIN-RDP-LOGON", lookback_days=21)
    with pytest.raises(ValueError, match="valeur manquante pour lookback_days"):
        render_question("Q-WIN-RDP-LOGON", host="SRV-FILE")
    # une valeur que le gabarit n'emploie pas est ignoree
    assert (
        render_question(
            "Q-WIN-RDP-LOGON", host="SRV-FILE", lookback_days=1, account="x", share="y"
        )
        == "Qui s'est connecté en RDP sur SRV-FILE il y a 1 jour ?"
    )
    for valeur, exception in (("", ValueError), ("  ", ValueError), (12, TypeError)):
        with pytest.raises(exception, match="host"):
            render_question("Q-WIN-RDP-LOGON", host=valeur, lookback_days=21)  # type: ignore[arg-type]


def test_valeur_demesuree_tronquee_sans_bloquer_le_rendu() -> None:
    # « a.a.a. » rend quadratique le caviardage des URL d'assainir() : sans
    # borne, 80 000 caracteres bloquaient le rendu plusieurs secondes, GIL tenu,
    # donc au-dela du delai du check. La valeur vient de l'hote audite.
    debut = time.perf_counter()
    texte = render_question("Q-WIN-RDP-LOGON", host="a." * 40_000, lookback_days=21)
    assert time.perf_counter() - debut < 1.0
    assert texte == (
        f"Qui s'est connecté en RDP sur {'a.' * 128}... il y a trois semaines ?"
    )
    # 256 caracteres passent entiers : un nom DNS complet en fait 255 au plus
    limite = "h" * 256
    assert f"sur {limite} il" in render_question(
        "Q-WIN-RDP-LOGON", host=limite, lookback_days=21
    )
    # tronquee, jamais refusee : une exception masquerait l'angle mort
    assert f"sur {limite}... il" in render_question(
        "Q-WIN-RDP-LOGON", host=limite + "h", lookback_days=21
    )


def test_valeur_superflue_demesuree_ignoree_sans_cout() -> None:
    # le gabarit n'emploie ni {account} ni {share} : rien n'est caviarde
    debut = time.perf_counter()
    texte = render_question(
        "Q-WIN-RDP-LOGON",
        host="SRV-FILE",
        lookback_days=21,
        account="x-" * 40_000,
        share="a." * 40_000,
    )
    assert time.perf_counter() - debut < 1.0
    assert texte == "Qui s'est connecté en RDP sur SRV-FILE il y a trois semaines ?"


def test_valeur_tronquee_reste_caviardee_et_imprimable() -> None:
    question = _question("Qui a lu {share} sur {host} ?")
    texte = question.render(
        host="\x1b[2J" + "h" * 400, share="winrm://audit:motdepasse@srv " + "s" * 400
    )
    assert "motdepasse" not in texte
    assert "\x1b" not in texte
    assert len(texte) < 700


def _question(gabarit: str) -> Question:
    return Question(
        id="Q-WIN-ESSAI",
        status=QuestionStatus.PLANNED,
        domain=Domain.WINDOWS,
        theme=Theme.EXECUTION,
        roles=(Role.SERVER,),
        text=gabarit,
        why="Sans réponse, l'enquête piétine.",
        severity_default=Severity.LOW,
        sources=("SRC-SEC-4688-CMDLINE",),
    )


def test_variables_compte_et_partage() -> None:
    question = _question("{account} a-t-il lu {share} sur {host} il y a {lookback} ?")
    assert question.placeholders == ("account", "share", "host", "lookback")
    assert (
        question.render(
            host="SRV-FILE", lookback_days=60, account="j.martin", share="RH$"
        )
        == "j.martin a-t-il lu RH$ sur SRV-FILE il y a deux mois ?"
    )
    # accolades litterales, variable repetee
    double = _question("{{host}} vaut {host}, et encore {host} ?")
    assert double.placeholders == ("host",)
    assert double.render(host="PC-01") == "{host} vaut PC-01, et encore PC-01 ?"


def test_valeur_venue_de_la_cible_neutralisee() -> None:
    # une valeur hostile n'est ni reinterpretee comme gabarit, ni rendue brute
    texte = render_question(
        "Q-WIN-RDP-LOGON", host="SRV\x1b[31m{lookback}\u202e", lookback_days=21
    )
    assert texte == (
        "Qui s'est connecté en RDP sur SRV\\x1b[31m{lookback}\\u202e "
        "il y a trois semaines ?"
    )
    assert texte.isprintable()
    # un secret recopie par erreur dans une valeur est caviarde
    assert "hunter2" not in render_question(
        "Q-WIN-RDP-LOGON", host="srv password=hunter2", lookback_days=21
    )


@pytest.mark.parametrize(
    "gabarit",
    [
        "Qui sur {hote} ?",
        "Qui sur {host!r} ?",
        "Qui sur {host:>20} ?",
        "Qui sur {host.__class__} ?",
        "Qui sur {host[0]} ?",
        "Qui sur {0} ?",
        "Qui sur {} ?",
        "Qui sur {host ?",
        "Qui sur host} ?",
    ],
)
def test_gabarit_hors_vocabulaire_refuse(gabarit: str) -> None:
    with pytest.raises(ValueError, match="gabarit"):
        placeholders_of(gabarit)
    with pytest.raises(ValueError, match="gabarit"):
        _question(gabarit)


def test_identifiant_de_question_valide_a_la_construction() -> None:
    with pytest.raises(ValueError, match="identifiant de question invalide"):
        dataclasses.replace(_question("Qui ?"), id="q-win-essai")


# --- validation au chargement ----------------------------------------------------


def test_copie_du_catalogue_valide(copie: Path) -> None:
    catalogue = read_catalog(copie)
    assert [q.id for q in catalogue] == [q.id for q in load_catalog()]
    assert catalogue.version == load_catalog().version
    # rien n'est mis en cache : une autre lecture rend un autre objet
    assert read_catalog(copie) is not catalogue


def test_identifiant_duplique(copie: Path) -> None:
    fichier = "questions/windows.toml"
    _ajouter(copie, fichier, "\n" + _bloc(copie, fichier, "Q-WIN-USB"))
    (erreur,) = _erreurs(copie)
    assert re.fullmatch(
        r"questions/windows\.toml : question n° 22 \(Q-WIN-USB\) : id : identifiant "
        r"dupliqué 'Q-WIN-USB', déjà défini par questions/windows\.toml : "
        r"question n° 14 \(Q-WIN-USB\)",
        erreur,
    )


def test_source_dupliquee_entre_deux_fichiers(copie: Path) -> None:
    bloc = _bloc(copie, "sources/ad.toml", "SRC-AD-4724")
    _ajouter(copie, "sources/windows.toml", "\n" + bloc)
    (erreur,) = _erreurs(copie)
    assert erreur.startswith("sources/windows.toml : source n° ")
    assert (
        "identifiant dupliqué 'SRC-AD-4724', déjà défini par sources/ad.toml" in erreur
    )


def test_source_inconnue(copie: Path) -> None:
    _remplacer(
        copie,
        "questions/windows.toml",
        '  "SRC-SEC-4648",\n',
        '  "SRC-SEC-9999",\n',
    )
    (erreur,) = _erreurs(copie)
    assert erreur == (
        "questions/windows.toml : question n° 3 (Q-WIN-EXPLICIT-CREDS) : sources : "
        "source inconnue 'SRC-SEC-9999'"
    )


@pytest.mark.parametrize(
    "guid",
    [
        "0CCE922B-69AE-11D9-BED3-505054503030",
        "{0CCE922B-69AE-11D9-BED3-50505450303}",
        "{0CCE922G-69AE-11D9-BED3-505054503030}",
        "{0CCE922B69AE11D9BED3505054503030}",
        "{0CCE922B-69AE-11D9-BED3-505054503030}\\n",
    ],
)
def test_guid_de_sous_categorie_mal_forme(copie: Path, guid: str) -> None:
    _remplacer(
        copie,
        "sources/windows.toml",
        'guid = "{0CCE922B-69AE-11D9-BED3-505054503030}"',
        f'guid = "{guid}"',
    )
    (erreur,) = _erreurs(copie)
    assert erreur.startswith(
        "sources/windows.toml : source n° 11 (SRC-SEC-4688-CMDLINE) : "
        "prerequisites[0].guid : "
    )
    assert "GUID mal formé" in erreur or "non imprimable" in erreur


def test_guid_de_droit_etendu_mal_forme(copie: Path) -> None:
    _remplacer(
        copie,
        "sources/ad.toml",
        'guids = ["1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"',
        'guids = ["1131f6aa-9c07-11d1-f79f"',
    )
    (erreur,) = _erreurs(copie)
    assert "(SRC-AD-4662-DCSYNC) : prerequisites[1].guids : GUID mal formé" in erreur


def test_question_active_sans_check(copie: Path) -> None:
    _remplacer(
        copie,
        "questions/windows.toml",
        'checks = ["win.time_sync"]',
        "checks = []",
    )
    (erreur,) = _erreurs(copie)
    assert erreur.startswith(
        "questions/windows.toml : question n° 21 (Q-WIN-TIMELINE) : checks : "
        "question active sans check"
    )


def test_question_prevue_avec_un_check(copie: Path) -> None:
    bloc = _bloc(copie, "questions/ad.toml", "Q-AD-DCSYNC")
    _remplacer(
        copie,
        "questions/ad.toml",
        bloc,
        bloc.replace("checks = []", 'checks = ["ad.dcsync"]'),
    )
    (erreur,) = _erreurs(copie)
    assert "(Q-AD-DCSYNC) : checks : question planned avec des checks" in erreur


@pytest.mark.parametrize(
    ("ancien", "nouveau", "attendu"),
    [
        (
            'status = "planned"',
            'status = "prevue"',
            "status : valeur inconnue 'prevue'",
        ),
        ('theme = "execution"', 'theme = "exécution"', "theme : valeur inconnue"),
        ('roles = ["server"]', 'roles = ["serveur"]', "roles : valeur inconnue"),
        ('roles = ["server"]', "roles = []", "roles : liste vide"),
        ('roles = ["server"]', 'roles = "server"', "roles : liste attendu(e)"),
        ('severity_default = "low"', 'severity_default = "basse"', "severity_default"),
        ('domain = "windows"', 'domain = "ad"', "domain : 'ad' dans le fichier"),
        ('id = "Q-WIN-NOUVELLE"', 'id = "Q-AD-NOUVELLE"', "id : identifiant mal formé"),
        (
            'id = "Q-WIN-NOUVELLE"',
            'id = "Q-WIN-nouvelle"',
            "id : identifiant mal formé",
        ),
        ('id = "Q-WIN-NOUVELLE"\n', "", "id : champ obligatoire manquant"),
        ("{host}", "{hote}", "text : variable de gabarit inconnue"),
        ("why.fr", "why.de", "why.fr : champ obligatoire manquant"),
        ('text.fr = "', 'text.en = 3\ntext.fr = "', "text.en : chaîne attendu(e)"),
        (
            'theme = "execution"',
            'theme = "execution"\ntheme_bis = 1',
            "clé(s) inconnue(s) : theme_bis",
        ),
        (
            'theme = "execution"',
            'theme = "execution"\nattack = ["T1021"]',
            "attack : champ réservé",
        ),
        (
            'theme = "execution"',
            'theme = "execution"\nscenarios = ["Ransomware"]',
            "scenarios : étiquette mal formé",
        ),
        ('sources = ["SRC-SEC-4688-CMDLINE"]', "sources = []", "sources : liste vide"),
        (
            'sources = ["SRC-SEC-4688-CMDLINE"]',
            'sources = ["4688"]',
            "sources : identifiant mal formé",
        ),
        (
            'sources = ["SRC-SEC-4688-CMDLINE"]',
            'sources = ["SRC-SEC-4688-CMDLINE", "SRC-SEC-4688-CMDLINE"]',
            "sources : doublon",
        ),
        (
            'theme = "execution"',
            'theme = "execution"\nreferences = '
            '[{ kind = "anssi", id = "X", url = "http://exemple.invalid/" }]',
            "references[0] : url invalide",
        ),
        (
            'theme = "execution"',
            'theme = "execution"\nreferences = '
            '[{ kind = "anssi", id = "X", titre = "x" }]',
            "references[0] : Reference : clé(s) inconnue(s) : 'titre'",
        ),
        (
            'why.fr = "Sans réponse, l\'enquête piétine."',
            'why.fr = "Ligne\\nsuivante"',
            "why.fr : texte vide ou non imprimable",
        ),
        (
            'sources = ["SRC-SEC-4688-CMDLINE"]\n',
            "",
            "sources : champ obligatoire manquant",
        ),
        (
            'sources = ["SRC-SEC-4688-CMDLINE"]',
            "sources = [4688]",
            "sources : chaîne non vide attendue",
        ),
        (
            'theme = "execution"',
            'theme = "execution"\nreferences = ["ANSSI-PB-090"]',
            "references[0] : table attendue",
        ),
        (
            'text.fr = "',
            'text.en = "a\\tb"\ntext.fr = "',
            "text.en : texte non imprimable",
        ),
    ],
)
def test_question_invalide_localisee(
    copie: Path, ancien: str, nouveau: str, attendu: str
) -> None:
    assert QUESTION_MINIMALE.count(ancien) == 1
    _ajouter(
        copie, "questions/windows.toml", QUESTION_MINIMALE.replace(ancien, nouveau)
    )
    (erreur,) = _erreurs(copie)
    assert erreur.startswith("questions/windows.toml : question n° 22")
    assert attendu in erreur, erreur


SOURCE_MINIMALE = """
[[source]]
id = "SRC-SEC-9999"
kind = "event"
title = "Événement d'essai"
channel = "Security"
provider = "Microsoft-Windows-Security-Auditing"
event_ids = [9999]
prerequisites = [
  { kind = "channel_enabled", channel = "Security" },
]
"""


@pytest.mark.parametrize(
    ("ancien", "nouveau", "attendu"),
    [
        ('id = "SRC-SEC-9999"', 'id = "SEC-9999"', "id : identifiant mal formé"),
        ('kind = "event"', 'kind = "evenement"', "kind : valeur inconnue"),
        ("event_ids = [9999]", "event_ids = []", "event_ids : liste vide"),
        ("event_ids = [9999]", 'event_ids = ["4624"]', "event_ids : Event ID invalide"),
        ("event_ids = [9999]", "event_ids = [0]", "event_ids : Event ID invalide"),
        ("event_ids = [9999]", "event_ids = [70000]", "event_ids : Event ID invalide"),
        ("event_ids = [9999]", "event_ids = [true]", "event_ids : Event ID invalide"),
        ("event_ids = [9999]", "event_ids = [1, 1]", "event_ids : doublon"),
        (
            'channel = "Security"\nprovider',
            "provider",
            "channel : champ obligatoire manquant",
        ),
        (
            "event_ids = [9999]",
            'event_ids = [9999]\nsetting = "x"',
            "clé(s) inconnue(s) : setting",
        ),
        (
            "event_ids = [9999]",
            "event_ids = [9999]\nfilters = { LogonType = true }",
            "filters.LogonType",
        ),
        (
            "event_ids = [9999]",
            "event_ids = [9999]\nfilters = { LogonType = [] }",
            "filters.LogonType",
        ),
        (
            "event_ids = [9999]",
            'event_ids = [9999]\nenabled_by_default = "oui"',
            "enabled_by_default : booléen",
        ),
        (
            'kind = "channel_enabled"',
            'kind = "service"',
            "prerequisites[0].kind : valeur inconnue",
        ),
        (
            'channel = "Security" }',
            'canal = "Security" }',
            "prerequisites[0].channel : champ obligatoire",
        ),
        (
            '{ kind = "channel_enabled", channel = "Security" }',
            '{ kind = "audit_subcategory", name = "Logon", '
            'guid = "{0CCE9215-69AE-11D9-BED3-505054503030}" }',
            "prerequisites[0].success : success ou failure doit valoir true",
        ),
        (
            '{ kind = "channel_enabled", channel = "Security" }',
            '{ kind = "registry_value", key = "HKLM", name = "x", value = true }',
            "prerequisites[0].value : chaîne ou entier",
        ),
        (
            '{ kind = "channel_enabled", channel = "Security" }',
            '{ kind = "sacl", object = "racine", guid = "x" }',
            "prerequisites[0] : clé(s) inconnue(s) : guid",
        ),
        (
            '{ kind = "channel_enabled", channel = "Security" }',
            '"canal"',
            "prerequisites[0] : table attendue",
        ),
    ],
)
def test_source_invalide_localisee(
    copie: Path, ancien: str, nouveau: str, attendu: str
) -> None:
    assert SOURCE_MINIMALE.count(ancien) == 1
    _ajouter(copie, "sources/windows.toml", SOURCE_MINIMALE.replace(ancien, nouveau))
    (erreur,) = _erreurs(copie)
    assert erreur.startswith("sources/windows.toml : source n° ")
    assert attendu in erreur, erreur


# echappements TOML : ESC (sequence ANSI), saut de ligne, U+202E (bidi, invisible
# dans un diff)
HOSTILES = pytest.mark.parametrize(
    "hostile",
    ["\\u001b[2J", "\\n", "\\u202E"],
    ids=["esc", "saut-de-ligne", "bidi"],
)


@HOSTILES
@pytest.mark.parametrize(
    ("ancien", "nouveau", "attendu"),
    [
        (
            "event_ids = [9999]",
            'event_ids = [9999]\nfilters = { "Logon%sType" = 10 }',
            "filters : nom de champ mal formé",
        ),
        (
            "event_ids = [9999]",
            'event_ids = [9999]\nfilters = { LogonType = "10%s" }',
            "filters.LogonType : texte vide ou non imprimable",
        ),
        (
            "event_ids = [9999]",
            'event_ids = [9999]\nfilters = { LogonType = [3, "10%s"] }',
            "filters.LogonType : texte vide ou non imprimable",
        ),
        (
            '{ kind = "channel_enabled", channel = "Security" }',
            '{ kind = "registry_value", key = "HKLM", name = "x", value = "1%s" }',
            "prerequisites[0].value : texte vide ou non imprimable",
        ),
        (
            "event_ids = [9999]",
            'event_ids = [9999]\n"cle%s" = 1',
            "clé(s) inconnue(s) : 'cle",
        ),
    ],
    ids=["cle-de-filtre", "valeur-de-filtre", "liste-de-filtre", "value", "cle"],
)
def test_source_non_imprimable_refusee(
    copie: Path, hostile: str, ancien: str, nouveau: str, attendu: str
) -> None:
    # affiche tel quel par « catalog show » : une sequence de terminal dans le
    # catalogue atteindrait le poste de l'auditeur
    assert SOURCE_MINIMALE.count(ancien) == 1
    _ajouter(
        copie,
        "sources/windows.toml",
        SOURCE_MINIMALE.replace(ancien, nouveau % hostile),
    )
    (erreur,) = _erreurs(copie)
    assert attendu in erreur, erreur
    # le message lui-meme ne porte ni ESC, ni saut de ligne, ni bidi
    assert erreur.isprintable(), ascii(erreur)


@pytest.mark.parametrize(
    "valeur", ['""', '"  "', '[3, ""]'], ids=["vide", "espaces", "liste"]
)
def test_valeur_de_filtre_vide_refusee(copie: Path, valeur: str) -> None:
    source = SOURCE_MINIMALE.replace(
        "event_ids = [9999]",
        f"event_ids = [9999]\nfilters = {{ LogonType = {valeur} }}",
    )
    _ajouter(copie, "sources/windows.toml", source)
    (erreur,) = _erreurs(copie)
    assert "filters.LogonType : " in erreur


@HOSTILES
def test_check_non_imprimable_refuse(copie: Path, hostile: str) -> None:
    question = QUESTION_MINIMALE.replace(
        'status = "planned"', f'status = "active"\nchecks = ["win.sysmon{hostile}"]'
    )
    _ajouter(copie, "questions/windows.toml", question)
    (erreur,) = _erreurs(copie)
    assert "(Q-WIN-NOUVELLE) : checks : id de check mal formé" in erreur
    assert erreur.isprintable(), ascii(erreur)


@HOSTILES
def test_element_de_liste_non_imprimable_refuse(copie: Path, hostile: str) -> None:
    # liste sans forme imposee (roles) : l'element est refuse avant tout affichage
    question = QUESTION_MINIMALE.replace(
        'roles = ["server"]', f'roles = ["server{hostile}"]'
    )
    _ajouter(copie, "questions/windows.toml", question)
    (erreur,) = _erreurs(copie)
    assert "(Q-WIN-NOUVELLE) : roles : texte non imprimable" in erreur
    assert erreur.isprintable(), ascii(erreur)


def test_check_mal_forme_refuse(copie: Path) -> None:
    question = QUESTION_MINIMALE.replace(
        'status = "planned"', 'status = "active"\nchecks = ["Win Sysmon"]'
    )
    _ajouter(copie, "questions/windows.toml", question)
    (erreur,) = _erreurs(copie)
    assert "checks : id de check mal formé 'Win Sysmon'" in erreur
    # meme forme que le registre des checks
    assert loader._FORMAT_CHECK_ID.pattern == registre_des_checks._FORMAT_ID.pattern


@HOSTILES
def test_identifiant_et_cle_hostiles_neutralises_dans_les_erreurs(
    copie: Path, hostile: str
) -> None:
    # CatalogError se lit aussi hors de la CLI (appelant direct de read_catalog)
    _ajouter(
        copie,
        "questions/windows.toml",
        QUESTION_MINIMALE.replace("Q-WIN-NOUVELLE", f"Q-WIN-NOUVELLE{hostile}"),
    )
    (copie / "questions" / "ad.toml").write_text(
        f'"titre{hostile}" = 1\n', encoding="utf-8"
    )
    erreurs = _erreurs(copie)
    assert len(erreurs) == 2
    assert "clé(s) inconnue(s) : 'titre" in erreurs[0]
    assert "id : texte vide ou non imprimable" in erreurs[1]
    for erreur in erreurs:
        assert erreur.isprintable(), ascii(erreur)


def test_filet_contre_un_champ_lu_sans_controle(
    copie: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # champ a venir, lu sans controle : le filet de _entrees() le refuse quand meme
    def sans_controle(e: object) -> tuple[()]:
        if e.present("filters"):  # type: ignore[attr-defined]
            e.brut("filters", dict, "table")  # type: ignore[attr-defined]
        return ()

    monkeypatch.setattr(loader, "_filtres", sans_controle)
    source = SOURCE_MINIMALE.replace(
        "event_ids = [9999]",
        'event_ids = [9999]\nfilters = { a = [1, { b = "x\\u001b[2J" }] }',
    )
    _ajouter(copie, "sources/windows.toml", source)
    (erreur,) = _erreurs(copie)
    assert "filters.a[1].b : texte non imprimable : 'x\\x1b[2J'" in erreur
    cle = SOURCE_MINIMALE.replace(
        "event_ids = [9999]", 'event_ids = [9999]\nfilters = { "a\\u202E" = 1 }'
    )
    (copie / "sources" / "ad.toml").write_text(
        cle.replace("SRC-SEC-9999", "SRC-AD-9999"), encoding="utf-8"
    )
    erreurs = _erreurs(copie)
    assert "sources/ad.toml" in erreurs[0]
    assert "filters : texte non imprimable : 'a\\u202e'" in erreurs[0]


def test_source_reglage_sans_champs_d_evenement(copie: Path) -> None:
    reglage = """
[[source]]
id = "SRC-WIN-ESSAI"
kind = "setting"
title = "Réglage d'essai"
setting = "réglage attendu"
"""
    _ajouter(copie, "sources/windows.toml", reglage + "event_ids = [1]\n")
    (erreur,) = _erreurs(copie)
    assert "(SRC-WIN-ESSAI) : clé(s) inconnue(s) : event_ids" in erreur


def test_toutes_les_erreurs_de_forme_sont_rapportees(copie: Path) -> None:
    # une ligne par erreur : l'auteur corrige tout en une passe
    _ajouter(copie, "questions/windows.toml", QUESTION_MINIMALE.replace("low", "bas"))
    _ajouter(copie, "sources/ad.toml", SOURCE_MINIMALE.replace("[9999]", "[]"))
    (copie / "VERSION").write_text("v1\n", encoding="utf-8")
    erreurs = _erreurs(copie)
    assert len(erreurs) == 3
    assert erreurs[0].startswith("VERSION : version CalVer attendue")
    assert erreurs[1].startswith("sources/ad.toml : source n° ")
    assert erreurs[2].startswith("questions/windows.toml : question n° 22")


@pytest.mark.parametrize(
    "version",
    [
        "",
        "2026.11",
        "2026.13.0",
        "2026.011.0",
        "26.11.0",
        "2026.11.0-rc1",
        "v2026.11.0",
    ],
)
def test_version_calver_exigee(copie: Path, version: str) -> None:
    (copie / "VERSION").write_text(version + "\n", encoding="utf-8")
    (erreur,) = _erreurs(copie)
    assert erreur.startswith("VERSION : version CalVer attendue (AAAA.M.N")


@pytest.mark.parametrize("version", ["2026.11.0", "2027.1.12", "2030.12.3"])
def test_version_calver_acceptee(copie: Path, version: str) -> None:
    # fin de ligne Windows comprise : le fichier peut etre extrait en CRLF
    (copie / "VERSION").write_bytes(version.encode("ascii") + b"\r\n")
    assert read_catalog(copie).version == version


def test_fichiers_absents_illisibles_ou_inconnus(copie: Path) -> None:
    (copie / "VERSION").unlink()
    (copie / "questions" / "linux.toml").write_text(QUESTION_MINIMALE, encoding="utf-8")
    (copie / "sources" / "ad.toml").write_text("[[source]\n", encoding="utf-8")
    (copie / "questions" / "ad.toml").write_bytes(b"\xff\xfe")
    erreurs = _erreurs(copie)
    assert erreurs[0] == "VERSION : fichier absent"
    assert erreurs[1].startswith("sources/ad.toml : TOML invalide : ")
    assert erreurs[2].startswith(
        "questions/linux.toml : nom de fichier inconnu (attendu : <domaine>.toml"
    )
    assert erreurs[3].startswith("questions/ad.toml : fichier illisible")
    assert len(erreurs) == 4
    # nom de fichier hostile (bidi) : rendu imprimable dans l'erreur
    (copie / "questions" / "linux.toml").rename(
        copie / "questions" / "\u202elinux.toml"
    )
    erreur = _erreurs(copie)[2]
    assert erreur.startswith("questions/'\\u202elinux.toml' : nom de fichier inconnu")
    assert erreur.isprintable()
    shutil.rmtree(copie / "sources")
    assert "sources/ : répertoire absent" in _erreurs(copie)


def test_fichier_sans_table_attendue(copie: Path) -> None:
    (copie / "questions" / "ad.toml").write_text('titre = "x"\n', encoding="utf-8")
    erreurs = _erreurs(copie)
    assert erreurs[0].startswith(
        "questions/ad.toml : seules des tables [[question]] sont attendues"
    )
    assert "titre" in erreurs[0]
    # une entree qui n'est pas une table
    (copie / "questions" / "ad.toml").write_text("question = [1]\n", encoding="utf-8")
    assert _erreurs(copie) == ("questions/ad.toml : question n° 1 : table attendue",)


def test_fins_de_ligne_windows_acceptees(copie: Path) -> None:
    # depot extrait avec core.autocrlf : le catalogue se lit quand meme
    for chemin in sorted(copie.rglob("*")):
        if chemin.is_file():
            chemin.write_bytes(chemin.read_bytes().replace(b"\n", b"\r\n"))
    assert len(read_catalog(copie)) == len(load_catalog())


def test_fichiers_embarques_en_utf8_lf_sans_bom() -> None:
    fichiers = [EMBARQUE / "VERSION", EMBARQUE / "ids.lock"]
    for dossier in ("questions", "sources"):
        fichiers += sorted((EMBARQUE / dossier).glob("*.toml"))
    assert len(fichiers) == 6
    for chemin in fichiers:
        octets = chemin.read_bytes()
        assert not octets.startswith(b"\xef\xbb\xbf"), chemin.name
        assert octets.endswith(b"\n") and not octets.endswith(b"\n\n"), chemin.name
        octets.decode("utf-8")
    for dossier in ("questions", "sources"):
        for chemin in sorted((EMBARQUE / dossier).glob("*.toml")):
            tomllib.loads(chemin.read_text(encoding="utf-8"))


def test_catalog_error_se_copie_et_se_serialise() -> None:
    erreur = CatalogError("VERSION : fichier absent", "ids.lock : fichier absent")
    for clone in (copy.copy(erreur), pickle.loads(pickle.dumps(erreur))):  # noqa: S301
        assert clone.errors == erreur.errors
        assert str(clone) == "VERSION : fichier absent\nids.lock : fichier absent"
    assert isinstance(erreur, ValueError)
