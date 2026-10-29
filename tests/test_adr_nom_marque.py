"""Forme de l'ADR 0002 sur le nom et la marque (docs/adr/0002-nom-et-marque.md).

Ces tests vérifient que l'ADR répond aux critères d'acceptation de #12 par sa
structure (décision écrite, « amnesia » et au moins trois alternatives dans des
tableaux de vérifications datées couvrant PyPI, GitHub, les domaines, les
gestionnaires de paquets et les marques, risques résiduels, actions en attente,
écart avec le code exact, liens qui existent, aucune adresse e-mail), pas que le
classement est bon : ce jugement reste celui du propriétaire.
"""

import re
import tomllib
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parent.parent
ADR = RACINE / "docs" / "adr" / "0002-nom-et-marque.md"
SECTIONS = (
    "Contexte",
    "Décision",
    "Candidats",
    "Vérifications datées",
    "Classement",
    "Risques résiduels",
    "Écart avec le code",
    "En attente",
    "Conséquences",
    "Références",
)
COLONNES_DISPONIBILITE = (
    "Nom",
    "PyPI",
    "GitHub (dépôts au nom exact / compte)",
    ".com",
    ".fr",
    ".io",
    "Homebrew / winget / Chocolatey / Debian",
    "Date",
)
COLONNES_MARQUES = (
    "Nom",
    "INPI (classes 9 et 42)",
    "EUIPO / TMview (classes 9 et 42)",
    "Homonymes dans le secteur sécurité",
    "Date",
)
DATE = re.compile(r"\b\d{2}/\d{2}/\d{4}\b")
COURRIEL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
LIEN = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")
# numero de depot de marque, ou renvoi explicite a une recherche manuelle avec
# l'URL de la recherche
MARQUE_VERIFIEE = re.compile(r"\bn[°o] ?\d+|à vérifier manuellement : <https://")
CLASSEMENT = re.compile(r"^\d+\. \*\*([a-z-]+)\*\*", re.MULTILINE)


@pytest.fixture(scope="module")
def texte() -> str:
    return ADR.read_text(encoding="utf-8")


def _section(texte: str, titre: str) -> str:
    for morceau in re.split(r"^## ", texte, flags=re.MULTILINE)[1:]:
        entete, _, corps = morceau.partition("\n")
        if entete.strip() == titre:
            return corps
    raise AssertionError(f"section {titre!r} absente")


def _tableau(corps: str, colonnes: tuple[str, ...]) -> list[list[str]]:
    # lignes de cellules du tableau dont l'en-tete est exactement colonnes,
    # separateur exclu
    lignes = [ligne for ligne in corps.splitlines() if ligne.startswith("|")]
    cellules = [
        [c.strip() for c in ligne.strip().strip("|").split("|")] for ligne in lignes
    ]
    for index, ligne in enumerate(cellules):
        if tuple(ligne) == colonnes:
            tableau = []
            for suivante in cellules[index + 2 :]:
                if len(suivante) != len(ligne):
                    break
                tableau.append(suivante)
            assert tableau, "tableau vide"
            return tableau
    raise AssertionError(f"tableau {colonnes[:2]!r} absent")


def _slug(titre: str) -> str:
    # ancre generee par GitHub : minuscules, ponctuation retiree, espaces -> tirets
    return re.sub(r"[^\w\- ]", "", titre.strip().lower()).replace(" ", "-")


def _ancres(texte: str) -> set[str]:
    return {_slug(t) for t in re.findall(r"^#{1,6} (.+)$", texte, flags=re.MULTILINE)}


def _candidats(texte: str) -> list[str]:
    # noms classes, dans l'ordre, hors « amnesia »
    return CLASSEMENT.findall(_section(texte, "Classement"))


def test_outils_du_test() -> None:
    assert _slug("Écart avec le code") == "écart-avec-le-code"
    assert _tableau("| a | b |\n|---|---|\n| 1 | 2 |\n", ("a", "b")) == [["1", "2"]]
    assert MARQUE_VERIFIEE.search("n° 4567890")
    assert MARQUE_VERIFIEE.search("à vérifier manuellement : <https://x>")
    assert not MARQUE_VERIFIEE.search("à vérifier")


def test_sections_attendues(texte: str) -> None:
    assert texte.startswith("# ADR 0002 ")
    for titre in SECTIONS:
        assert _section(texte, titre).strip(), titre


def test_statut_date_et_ticket(texte: str) -> None:
    entete = texte.split("## ", 1)[0]
    assert "**Accepté partiellement**" in entete
    assert "29/10/2026" in entete
    assert "#12" in entete


def test_decision_de_changer_de_nom(texte: str) -> None:
    decision = _section(texte, "Décision")
    assert "**Changer de nom.**" in decision
    assert "en attente" in decision.lower()
    assert "#33" in decision


def test_au_moins_cinq_candidats_classes_et_un_recommande(texte: str) -> None:
    candidats = _candidats(texte)
    assert len(candidats) >= 5
    assert len(set(candidats)) == len(candidats)
    assert "amnesia" not in candidats
    assert "(recommandé)" in _section(texte, "Classement")


@pytest.mark.parametrize(
    ("colonnes", "titre"),
    [(COLONNES_DISPONIBILITE, "disponibilité"), (COLONNES_MARQUES, "marques")],
)
def test_tableau_amnesia_et_alternatives_datees(
    texte: str, colonnes: tuple[str, ...], titre: str
) -> None:
    lignes = _tableau(_section(texte, "Vérifications datées"), colonnes)
    noms = [ligne[0] for ligne in lignes]
    assert "amnesia" in noms, titre
    # tout candidat classe est verifie, et au moins trois alternatives le sont
    assert set(_candidats(texte)) <= set(noms), titre
    assert len(set(noms) - {"amnesia", "amnesia-dfr"}) >= 3, titre
    for ligne in lignes:
        assert DATE.fullmatch(ligne[-1]), ligne[0]
        assert all(cellule for cellule in ligne), ligne[0]


def test_marques_numero_ou_recherche_manuelle_avec_url(texte: str) -> None:
    for ligne in _tableau(_section(texte, "Vérifications datées"), COLONNES_MARQUES):
        for cellule in ligne[1:3]:
            assert MARQUE_VERIFIEE.search(cellule), (ligne[0], cellule)
            assert ligne[0] in cellule, (ligne[0], cellule)


def test_methode_de_chaque_source(texte: str) -> None:
    methode = _section(texte, "Vérifications datées").partition("### ")[0]
    for source in ("PyPI", "GitHub", "RDAP", "Homebrew", "winget", "Chocolatey"):
        assert source in methode, source
    for source in ("Debian", "data.inpi.fr", "TMview", "classes de Nice 9"):
        assert source in methode, source


def test_risques_residuels(texte: str) -> None:
    risques = _section(texte, "Risques résiduels").lower()
    assert "homonyme" in risques
    assert "pypi" in risques


def test_ecart_avec_le_code_exact(texte: str) -> None:
    # l'ADR justifie l'ecart au lieu de renommer : ce qu'il decrit doit rester
    # vrai tant que le renommage n'est pas fait
    ecart = _section(texte, "Écart avec le code")
    with (RACINE / "pyproject.toml").open("rb") as fichier:
        projet = tomllib.load(fichier)["project"]
    assert f'`name = "{projet["name"]}"`' in ecart
    (script,) = projet["scripts"]
    assert f"script `{script}`" in ecart
    cli = (RACINE / "src" / "amnesia" / "cli.py").read_text(encoding="utf-8")
    (prog,) = re.findall(r'prog="([^"]+)"', cli)
    assert f'`prog="{prog}"`' in ecart
    readme = (RACINE / "README.md").read_text(encoding="utf-8")
    assert f"titre `{readme.splitlines()[0]}`" in ecart


def test_actions_en_attente_du_proprietaire(texte: str) -> None:
    attente = _section(texte, "En attente")
    for action in (
        "**Choix final**",
        "**Réservation d'au moins un domaine**",
        "**Adresse de contact projet.**",
        "**Recherche de marque**",
        "**décision de dépôt**",
    ):
        assert action in attente, action
    # aucune reservation ni depot n'est pretendu fait
    assert "Aucun domaine n'est réservé à ce jour" in attente
    assert "aucun dépôt n'est fait" in attente


def test_aucune_adresse_e_mail(texte: str) -> None:
    # depot public : l'adresse de contact provisoire est personnelle et reste
    # hors du depot, comme dans SECURITY.md
    assert not COURRIEL.findall(texte)
    assert "mailto:" not in texte


def test_liens_internes_existants(texte: str) -> None:
    ancres = _ancres(texte)
    liens = LIEN.findall(texte)
    assert liens
    for _, cible in liens:
        if cible.startswith("#"):
            assert cible[1:] in ancres, cible
        elif not cible.startswith("https://"):
            assert (ADR.parent / cible).is_file(), cible
