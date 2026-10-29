"""Politique de sécurité : SECURITY.md et ses renvois (#28).

Ces tests vérifient la forme (sections attendues, canal de signalement sans
adresse e-mail, liens vers des fichiers et des titres qui existent, renvoi de
chaque règle des « Données manipulées » vers une menace définie dans
docs/threat-model.md), pas la justesse des règles : ce jugement reste celui de la
revue.
"""

import re
from pathlib import Path
from urllib.parse import unquote

import pytest

RACINE = Path(__file__).resolve().parent.parent
SECURITE = RACINE / "SECURITY.md"
MODELE = RACINE / "docs" / "threat-model.md"
GITHUB_MD = RACINE / "docs" / "dev" / "github.md"
DEPOT = "https://github.com/yakohhhh/amnesia"
BLOB = f"{DEPOT}/blob/main/"
FORMULAIRE = f"{DEPOT}/security/advisories/new"
# menaces (M01) et risques residuels (RR1) du modele de menace
IDENT = re.compile(r"\b(?:M\d{2}|RR\d+)\b")
# lien en ligne [texte](cible) ou par reference [texte][etiquette]
LIEN = re.compile(r"\[([^\]]+)\](?:\(([^)\s]+)\)|\[([^\]]+)\])")
DEFINITION = re.compile(r"^\[([^\]]+)\]:[ \t]*(\S+)[ \t]*$", re.MULTILINE)
COURRIEL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def _texte(fichier: Path) -> str:
    return fichier.read_text(encoding="utf-8")


def _section(texte: str, titre: str) -> str:
    for morceau in re.split(r"^## ", texte, flags=re.MULTILINE)[1:]:
        entete, _, corps = morceau.partition("\n")
        if entete.strip() == titre:
            return corps
    raise AssertionError(f"section {titre!r} absente")


def _aplati(texte: str) -> str:
    # les retours a la ligne du Markdown coupent les expressions cherchees
    return " ".join(texte.split())


def _elements(corps: str) -> list[str]:
    # elements de liste de premier niveau, lignes de continuation comprises
    elements: list[str] = []
    ouvert = False
    for ligne in corps.splitlines():
        if ligne.startswith("- "):
            elements.append(ligne[2:])
            ouvert = True
        elif ouvert and ligne.startswith("  "):
            elements[-1] += " " + ligne.strip()
        elif ligne.strip():
            ouvert = False
    return elements


def _slug(titre: str) -> str:
    # ancre generee par GitHub : minuscules, ponctuation retiree, espaces -> tirets
    return re.sub(r"[^\w\- ]", "", titre.strip().lower()).replace(" ", "-")


def _ancres(fichier: Path) -> set[str]:
    ancres: set[str] = set()
    dans_code = False
    for ligne in _texte(fichier).splitlines():
        if ligne.lstrip().startswith("```"):
            dans_code = not dans_code
        elif not dans_code and (titre := re.match(r"#{1,6} (.+)", ligne)):
            ancres.add(_slug(titre.group(1)))
    return ancres


def _liens(texte: str, document: str | None = None) -> list[tuple[str, str]]:
    # (libelle, cible) ; references resolues par les definitions du document
    # entier, que texte en soit un extrait ou non
    source = texte if document is None else document
    definitions = {e.lower(): c for e, c in DEFINITION.findall(source)}
    liens: list[tuple[str, str]] = []
    for trouve in LIEN.finditer(texte):
        libelle, cible, etiquette = trouve.groups()
        if cible is None:
            assert etiquette.lower() in definitions, f"[{etiquette}] non défini"
            cible = definitions[etiquette.lower()]
        liens.append((libelle, cible))
    return liens


def _definis_par_ancre() -> dict[str, set[str]]:
    # identifiants definis dans les tableaux du modele, ranges par section
    definis: dict[str, set[str]] = {}
    for morceau in re.split(r"^## ", _texte(MODELE), flags=re.MULTILINE)[1:]:
        entete, _, corps = morceau.partition("\n")
        idents = definis.setdefault(_slug(entete), set())
        for ligne in corps.splitlines():
            premiere = ligne.strip("|").split("|")[0].strip()
            if ligne.startswith("|") and IDENT.fullmatch(premiere):
                idents.add(premiere)
    return definis


def test_outils_du_test() -> None:
    assert _slug("Risques résiduels") == "risques-résiduels"
    assert _slug("Ce que la publication (#33) doit garantir") == (
        "ce-que-la-publication-33-doit-garantir"
    )
    assert COURRIEL.search("securite@example.org")
    assert _elements("- a\n  b\n\nsuite\n  c\n- d") == ["a b", "d"]
    texte = "[M01][menaces] et [x](https://a)\n\n[menaces]: https://b\n"
    assert _liens(texte) == [("M01", "https://b"), ("x", "https://a")]


@pytest.mark.parametrize(
    "titre",
    [
        "Versions supportées",
        "Signaler une vulnérabilité",
        "Délais",
        "Périmètre",
        "Recherche de bonne foi",
        "Divulgation et correctifs",
        "Vérifier les artefacts",
        "Données manipulées",
    ],
)
def test_sections_de_security_md(titre: str) -> None:
    # a la racine : GitHub l'affiche dans l'onglet Security du depot
    assert _section(_texte(SECURITE), titre).strip()


def test_seule_la_derniere_version_supportee() -> None:
    versions = _aplati(_section(_texte(SECURITE), "Versions supportées"))
    assert "seule la dernière version publiée" in versions


def test_canal_prive_sans_adresse_e_mail() -> None:
    texte = _texte(SECURITE)
    signaler = _aplati(_section(texte, "Signaler une vulnérabilité"))
    assert "Private Vulnerability Reporting" in signaler
    assert FORMULAIRE in signaler
    # le canal est le formulaire GitHub : aucune adresse, personnelle ou non
    assert not COURRIEL.findall(texte)
    assert "mailto:" not in texte


def test_delais_de_traitement() -> None:
    delais = _aplati(_section(_texte(SECURITE), "Délais"))
    for delai in ("72 h", "7 jours", "90 jours"):
        assert delai in delais, delai


def test_perimetre_et_divulgation() -> None:
    texte = _texte(SECURITE)
    perimetre = _section(texte, "Périmètre")
    assert "**Dans le périmètre :**" in perimetre
    assert "**Hors périmètre :**" in perimetre
    divulgation = _aplati(_section(texte, "Divulgation et correctifs"))
    for element in ("Divulgation coordonnée", "GHSA", "CVE", "« Sécurité »"):
        assert element in divulgation, element


def test_liens_absolus_vers_des_fichiers_et_titres_existants() -> None:
    # liens absolus, comme le README : le document est aussi affiche hors du
    # depot (onglet Security), ou un lien relatif ne se resout pas
    liens = _liens(_texte(SECURITE))
    assert liens
    for _, cible in liens:
        assert cible.startswith("https://"), cible
        if not cible.startswith(BLOB):
            continue
        chemin, _, ancre = cible.removeprefix(BLOB).partition("#")
        assert (RACINE / chemin).is_file(), cible
        if ancre:
            assert unquote(ancre) in _ancres(RACINE / chemin), cible


def test_identifiants_cites_definis_dans_le_modele_de_menace() -> None:
    texte = _texte(SECURITE)
    definis = _definis_par_ancre()
    tous = {ident for idents in definis.values() for ident in idents}
    assert set(IDENT.findall(texte)) - tous == set()
    # un lien [M15] mene a la section du modele qui definit M15
    for libelle, cible in _liens(texte):
        if IDENT.fullmatch(libelle):
            page, _, ancre = cible.partition("#")
            assert page == f"{BLOB}docs/threat-model.md", libelle
            assert libelle in definis.get(unquote(ancre), set()), libelle


def test_chaque_regle_des_donnees_manipulees_renvoie_a_une_menace() -> None:
    texte = _texte(SECURITE)
    regles = _elements(_section(texte, "Données manipulées"))
    assert len(regles) >= 8
    for regle in regles:
        liens = _liens(regle, texte)
        # le lien lui-meme est verifie par le test des identifiants cites
        assert any(IDENT.fullmatch(libelle) for libelle, _ in liens), regle[:60]


@pytest.mark.parametrize(
    "element",
    [
        "Ce que lit amnesia",
        "Ce que contient un rapport",
        "disque chiffré",
        "Transmission",
        "Rétention",
        "ligne de commande",
        "trousseau",
        "issue, une PR",
        "Aucune télémétrie",
    ],
)
def test_elements_minimaux_des_donnees_manipulees(element: str) -> None:
    assert element in _aplati(_section(_texte(SECURITE), "Données manipulées"))


def test_readme_scope_et_legal_renvoie_vers_security_md() -> None:
    # lien absolu : le README est la long_description publiee sur PyPI
    scope = _section(_texte(RACINE / "README.md"), "Scope & légal")
    assert f"]({BLOB}SECURITY.md)" in scope


def test_checklist_de_passage_en_public_active_le_signalement_prive() -> None:
    checklist = _elements(_section(_texte(GITHUB_MD), "Passage en public"))
    (signalement,) = [e for e in checklist if "Private Vulnerability Reporting" in e]
    assert signalement.startswith("[x] ")
    assert "private-vulnerability-reporting" in signalement
    cibles = [cible for _, cible in _liens(signalement, _texte(GITHUB_MD))]
    assert cibles == ["../../SECURITY.md"]
    assert (GITHUB_MD.parent / cibles[0]).resolve() == SECURITE
