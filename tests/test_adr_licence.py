"""Forme de l'ADR 0001 sur le modèle de licence (docs/adr/0001-modele-de-licence.md).

Ces tests vérifient que l'ADR répond aux critères d'acceptation de #11 par sa
structure (sections attendues, trois cas d'usage par option, tableau des
éditions, choix DCO, titulaire, avis juridique explicitement en attente, totaux
de la grille pondérée justes, liens qui existent, aucune adresse e-mail), pas que
la décision est bonne : ce jugement reste celui du propriétaire et de l'avocat.
"""

import re
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parent.parent
ADR = RACINE / "docs" / "adr" / "0001-modele-de-licence.md"
SECTIONS = (
    "Contexte",
    "Décision",
    "Options comparées",
    "Critères pondérés",
    "Trois cas d'usage",
    "Fonctionnalités par édition",
    "Titulaire des droits",
    "CLA ou DCO",
    "Conséquences",
    "Publication avant la fusion de l'ADR",
    "Avis d'un avocat IP/IT",
    "Références",
)
# tickets que l'ADR doit ranger : commerciaux (#11, note de mission) et coeur
COMMERCIAUX = ("#141", "#140", "#139", "#162", "#154")
COEUR = ("#48", "#22", "#21")
COURRIEL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
LIEN = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")
TICKET = re.compile(r"#\d+")
ENTIER = re.compile(r"\d+")


@pytest.fixture(scope="module")
def texte() -> str:
    return ADR.read_text(encoding="utf-8")


def _section(texte: str, titre: str) -> str:
    for morceau in re.split(r"^## ", texte, flags=re.MULTILINE)[1:]:
        entete, _, corps = morceau.partition("\n")
        if entete.strip() == titre:
            return corps
    raise AssertionError(f"section {titre!r} absente")


def _tableau(corps: str, premiere_colonne: str) -> list[list[str]]:
    # lignes de cellules du tableau dont l'en-tete commence par premiere_colonne,
    # separateur exclu
    lignes = [ligne for ligne in corps.splitlines() if ligne.startswith("|")]
    cellules = [
        [c.strip() for c in ligne.strip().strip("|").split("|")] for ligne in lignes
    ]
    for index, ligne in enumerate(cellules):
        if ligne[0] == premiere_colonne:
            tableau = [ligne]
            for suivante in cellules[index + 2 :]:
                if len(suivante) != len(ligne):
                    break
                tableau.append(suivante)
            return tableau
    raise AssertionError(f"tableau {premiere_colonne!r} absent")


def _slug(titre: str) -> str:
    # ancre generee par GitHub : minuscules, ponctuation retiree, espaces -> tirets
    return re.sub(r"[^\w\- ]", "", titre.strip().lower()).replace(" ", "-")


def test_sections_attendues(texte: str) -> None:
    assert texte.startswith("# ADR 0001 ")
    for titre in SECTIONS:
        assert _section(texte, titre).strip(), titre


def test_statut_accepte_et_date(texte: str) -> None:
    entete = texte.split("## ", 1)[0]
    assert "**Accepté**" in entete
    assert "29/10/2026" in entete


def test_decision_open_core_coeur_mit(texte: str) -> None:
    decision = _section(texte, "Décision")
    assert "**Modèle open core.**" in decision
    assert "licence MIT" in decision
    assert "licence propriétaire" in decision
    assert "DCO" in decision


def test_quatre_options_et_une_seule_retenue(texte: str) -> None:
    options = _section(texte, "Options comparées")
    titres = re.findall(r"^### Option ([A-D]) ", options, flags=re.MULTILINE)
    assert titres == ["A", "B", "C", "D"]
    assert options.count("**Retenue**") == 1
    assert options.count("**Rejetée**") == 3


def test_grille_ponderee_totaux_justes(texte: str) -> None:
    tableau = _tableau(_section(texte, "Critères pondérés"), "Critère")
    assert len(tableau[0]) == 6, "poids + quatre options"
    *criteres, total = tableau[1:]
    assert total[0].startswith("**Total pondéré**")
    maximum = 0
    totaux = [0, 0, 0, 0]
    for ligne in criteres:
        poids = int(ligne[1])
        maximum += 3 * poids
        for colonne, cellule in enumerate(ligne[2:]):
            note = ENTIER.match(cellule)
            assert note is not None, cellule
            assert 0 <= int(note.group()) <= 3, cellule
            totaux[colonne] += poids * int(note.group())
    assert f"(sur {maximum})" in total[0]
    assert [int(c.strip("*")) for c in total[2:]] == totaux
    # l'open core (B) l'emporte
    assert totaux[1] == max(totaux)


def test_trois_cas_pour_chaque_option(texte: str) -> None:
    tableau = _tableau(_section(texte, "Trois cas d'usage"), "Cas")
    assert len(tableau[0]) == 5, "quatre options"
    cas = [ligne[0] for ligne in tableau[1:]]
    assert len(cas) == 3
    assert any("depuis son poste" in c for c in cas)
    assert any("#48" in c and "client" in c for c in cas)
    assert any("Marque blanche" in c for c in cas)
    for ligne in tableau[1:]:
        for cellule in ligne[1:]:
            assert len(cellule) > 10, ligne[0]


def test_tableau_des_editions(texte: str) -> None:
    section = _section(texte, "Fonctionnalités par édition")
    tableau = _tableau(section, "Fonctionnalité")
    assert tableau[0][2:] == ["Cœur (MIT)", "Pro (cabinet)", "MSP (multi-clients)"]
    par_ticket: dict[str, list[str]] = {}
    for ligne in tableau[1:]:
        assert TICKET.search(ligne[1]) or ligne[1].startswith("M"), ligne[0]
        for ticket in TICKET.findall(ligne[1]):
            par_ticket.setdefault(ticket, ligne[2:])
    for ticket in COMMERCIAUX:
        assert ticket in par_ticket, ticket
        assert par_ticket[ticket][0] == "—", f"{ticket} doit être hors du cœur"
        assert "oui" in par_ticket[ticket][1:], ticket
    for ticket in COEUR:
        assert ticket in par_ticket, ticket
        assert par_ticket[ticket] == ["oui", "oui", "oui"], ticket


def test_choix_dco_et_consequences_relicence(texte: str) -> None:
    section = _section(texte, "CLA ou DCO")
    assert section.lstrip().startswith("**Décision : DCO**")
    assert "relicence" in section
    assert "accord de chaque contributeur" in section
    assert "**À réexaminer**" in section


def test_titulaire_identifie(texte: str) -> None:
    section = _section(texte, "Titulaire des droits")
    assert "Ayman Mazroui" in section
    assert "personne physique" in section
    licence = (RACINE / "LICENSE").read_text(encoding="utf-8")
    assert "Copyright (c) 2026 Ayman Mazroui" in licence


def test_avis_avocat_en_attente(texte: str) -> None:
    section = _section(texte, "Avis d'un avocat IP/IT")
    assert section.lstrip().startswith("**À obtenir**")
    tableau = _tableau(section, "")
    lignes = {ligne[0]: ligne[1] for ligne in tableau}
    assert lignes["Date de l'avis"] == "à obtenir"
    assert lignes["Conclusions retenues"] == "—"
    assert len(lignes["Périmètre demandé"]) > 50


def test_publication_avant_fusion_consignee(texte: str) -> None:
    section = _section(texte, "Publication avant la fusion de l'ADR")
    assert "29/10/2026" in section
    assert "#13" in section
    assert "irrévocable" in section


def test_aucune_adresse_courriel(texte: str) -> None:
    assert COURRIEL.search("securite@example.org")
    assert not COURRIEL.findall(texte)


def test_liens_relatifs_et_ancres(texte: str) -> None:
    ancres = {
        _slug(titre.group(1))
        for titre in re.finditer(r"^#{1,6} (.+)$", texte, flags=re.MULTILINE)
    }
    liens = LIEN.findall(texte)
    assert liens
    for libelle, cible in liens:
        if cible.startswith("#"):
            assert cible[1:] in ancres, (libelle, cible)
        else:
            assert not cible.startswith(("http://", "https://")), (libelle, cible)
            chemin = (ADR.parent / cible).resolve()
            assert chemin.is_file(), (libelle, cible)
            assert RACINE in chemin.parents, (libelle, cible)
