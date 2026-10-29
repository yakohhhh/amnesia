"""Politique de versionnage : CHANGELOG.md et docs/RELEASING.md (#31).

Ces tests verifient la forme (format Keep a Changelog, table milestones ->
versions, surfaces publiques, renvois du README et du paquet), pas la justesse des
regles : ce jugement reste celui de la revue.
"""

import re
import tomllib
from datetime import date
from pathlib import Path

import pytest
import yaml

import amnesia
from amnesia.checks import default_checks

RACINE = Path(__file__).resolve().parent.parent
CHANGELOG = RACINE / "CHANGELOG.md"
RELEASING = RACINE / "docs" / "RELEASING.md"
MILESTONES = RACINE / ".github" / "milestones.yml"
DEPOT = "https://github.com/yakohhhh/amnesia"

# categories de Keep a Changelog 1.1.0, traduites une fois pour toutes, dans
# l'ordre du format (Added, Changed, Deprecated, Removed, Fixed, Security)
CATEGORIES = ("Ajouté", "Modifié", "Déprécié", "Supprimé", "Corrigé", "Sécurité")
ANGLAIS = ("Added", "Changed", "Deprecated", "Removed", "Fixed", "Security")
# X.Y.Z, pre-version (0.1.0rc1) ou version de developpement (0.2.0.dev0), en
# notation PEP 440
VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:(rc|\.dev)(\d+))?")
# une version datee est toujours une version finale
FINALE = re.compile(r"\d+\.\d+\.\d+")
# PEP 440 : 0.2.0.dev0 < 0.2.0rc1 < 0.2.0
PHASES: dict[str | None, int] = {".dev": 0, "rc": 1, None: 2}
TITRE_VERSION = re.compile(r"\[([^\]]+)\] - (\S+)")
# date.fromisoformat accepte aussi 20270115 ou 2027-W03-1 depuis Python 3.11
JOUR = re.compile(r"\d{4}-\d{2}-\d{2}")
# convention des ids de checks (#17)
ID_CHECK = re.compile(r"[a-z][a-z0-9]*(?:\.[a-z0-9_]+)+")

CHANGELOG_VALIDE = f"""# Changelog

Format : https://keepachangelog.com/fr/1.1.0/ et https://semver.org/lang/fr/

## [Unreleased]

## [0.2.0] - 2027-01-15

### Modifié

- **Incompatible** : option renommée (#2).

### Corrigé

- Correctif (#3).

## [0.1.0] - 2026-11-30

### Ajouté

- Première version (#1).

[Unreleased]: {DEPOT}/compare/v0.2.0...HEAD
[0.2.0]: {DEPOT}/compare/v0.1.0...v0.2.0
[0.1.0]: {DEPOT}/releases/tag/v0.1.0
"""


def _cle(version: str) -> tuple[int, int, int, int, int]:
    trouvee = VERSION.fullmatch(version)
    assert trouvee, version
    majeur, mineur, correctif, phase, numero = trouvee.groups()
    return (int(majeur), int(mineur), int(correctif), PHASES[phase], int(numero or 0))


def erreurs_changelog(texte: str, version: str) -> list[str]:
    """Écarts d'un CHANGELOG au format retenu (docs/RELEASING.md, « CHANGELOG »)."""
    erreurs: list[str] = []
    preambule, *sections = re.split(r"^## ", texte, flags=re.MULTILINE)
    if not preambule.startswith("# Changelog\n"):
        erreurs.append("titre « # Changelog » absent")
    for reference in ("keepachangelog.com/fr/1.1.0", "semver.org/lang/fr"):
        if reference not in preambule:
            erreurs.append(f"renvoi absent : {reference}")
    if not sections or sections[0].partition("\n")[0] != "[Unreleased]":
        erreurs.append("la première section n'est pas [Unreleased]")
    publiees: list[tuple[str, date]] = []
    etiquettes: list[str] = []
    for section in sections:
        entete, _, corps = section.partition("\n")
        if entete == "[Unreleased]":
            etiquettes.append("Unreleased")
        elif titre := TITRE_VERSION.fullmatch(entete):
            numero, jour = titre.groups()
            etiquettes.append(numero)
            # une pre-version ou une version de developpement n'est jamais datee
            if not FINALE.fullmatch(numero):
                erreurs.append(f"version invalide : {numero}")
                continue
            if not JOUR.fullmatch(jour):
                erreurs.append(f"date invalide pour {numero} : {jour}")
                continue
            try:
                publiees.append((numero, date.fromisoformat(jour)))
            except ValueError:
                erreurs.append(f"date invalide pour {numero} : {jour}")
                continue
            if not corps.count("\n- "):
                erreurs.append(f"version {numero} sans entrée")
        else:
            erreurs.append(f"section inattendue : {entete}")
            continue
        erreurs += _erreurs_categories(entete, corps)
    if len(set(etiquettes)) != len(etiquettes):
        erreurs.append("section en double")
    if [_cle(v) for v, _ in publiees] != sorted(
        (_cle(v) for v, _ in publiees), reverse=True
    ):
        erreurs.append("versions hors de l'ordre décroissant")
    if _dates_desordonnees(publiees):
        erreurs.append("dates hors de l'ordre décroissant")
    if publiees:
        erreurs += _erreurs_version(publiees[0][0], version)
    for etiquette in etiquettes:
        lien = rf"^\[{re.escape(etiquette)}\]: {re.escape(DEPOT)}/\S+$"
        if not re.search(lien, texte, flags=re.MULTILINE):
            erreurs.append(f"lien de comparaison absent : [{etiquette}]")
    return erreurs


def _dates_desordonnees(publiees: list[tuple[str, date]]) -> bool:
    # les dates ne sont ordonnees qu'au sein d'une serie MAJEUR.MINEUR : un
    # correctif d'une serie ancienne (0.1.1) peut sortir apres une mineure plus
    # recente (0.2.0). Entre series, c'est la premiere release qui est ordonnee.
    series: dict[tuple[int, int], list[date]] = {}
    for numero, jour in publiees:
        majeur, mineur, *_ = _cle(numero)
        series.setdefault((majeur, mineur), []).append(jour)
    premieres = [min(jours) for jours in series.values()]
    return premieres != sorted(premieres, reverse=True) or any(
        jours != sorted(jours, reverse=True) for jours in series.values()
    )


def _erreurs_version(derniere: str, version: str) -> list[str]:
    # derniere : version datee la plus recente ; version : __version__
    trouvee = VERSION.fullmatch(version)
    if not trouvee:
        return [f"__version__ invalide : {version}"]
    if FINALE.fullmatch(version):
        # le bump de __version__ et la datation du CHANGELOG vont dans la meme PR
        if derniere != version:
            return [f"dernière version {derniere} ≠ __version__ {version}"]
        return []
    # pre-version ou version de developpement : jamais datee, elle prepare une
    # version finale posterieure a la derniere version publiee
    finale = ".".join(trouvee.groups()[:3])
    if _cle(derniere) >= _cle(finale):
        return [f"__version__ {version} ne suit pas la dernière version {derniere}"]
    return []


def _erreurs_categories(entete: str, corps: str) -> list[str]:
    erreurs: list[str] = []
    blocs = re.split(r"^### ", corps, flags=re.MULTILINE)[1:]
    vues = [bloc.partition("\n")[0] for bloc in blocs]
    for categorie, bloc in zip(vues, blocs, strict=True):
        if categorie not in CATEGORIES:
            erreurs.append(f"{entete} : catégorie inconnue « {categorie} »")
        elif not re.search(r"^- \S", bloc, flags=re.MULTILINE):
            erreurs.append(f"{entete} : catégorie vide « {categorie} »")
    connues = [c for c in vues if c in CATEGORIES]
    if connues != sorted(set(connues), key=CATEGORIES.index):
        erreurs.append(f"{entete} : catégories en double ou hors de l'ordre")
    return erreurs


def _section(document: Path, titre: str) -> str:
    texte = document.read_text(encoding="utf-8")
    for morceau in re.split(r"^## ", texte, flags=re.MULTILINE)[1:]:
        entete, _, corps = morceau.partition("\n")
        if entete.strip() == titre:
            return corps
    raise AssertionError(f"section {titre!r} absente de {document.name}")


def _tableau(corps: str) -> list[list[str]]:
    # lignes de donnees des tableaux Markdown (ni en-tete ni separateur)
    lignes: list[list[str]] = []
    for ligne in corps.splitlines():
        ligne = ligne.strip()
        if not ligne.startswith("|") or set(ligne) <= {"|", "-", " "}:
            continue
        lignes.append([c.strip() for c in ligne.strip("|").split("|")])
    return lignes[1:] if lignes else []


def _milestones() -> list[dict[str, str]]:
    contenu = yaml.safe_load(MILESTONES.read_text(encoding="utf-8"))
    milestones: list[dict[str, str]] = contenu["milestones"]
    return milestones


# CHANGELOG.md


def test_changelog_au_format_keep_a_changelog() -> None:
    texte = CHANGELOG.read_text(encoding="utf-8")
    assert "\n## [Unreleased]\n" in texte
    assert erreurs_changelog(texte, amnesia.__version__) == []


def test_validateur_accepte_un_changelog_avec_versions() -> None:
    assert erreurs_changelog(CHANGELOG_VALIDE, "0.2.0") == []
    # PEP 440 : developpement < pre-version < version finale
    assert _cle("0.1.0.dev0") < _cle("0.1.0rc1") < _cle("0.1.0") < _cle("0.1.1")
    assert _cle("0.1.1") < _cle("0.10.0.dev0") < _cle("0.10.0")


@pytest.mark.parametrize(
    ("avant", "apres", "erreur"),
    [
        ("## [Unreleased]\n", "## [Non publié]\n", "première section"),
        ("# Changelog\n", "# Journal\n", "titre"),
        ("keepachangelog.com/fr/1.1.0/", "keepachangelog.com/", "renvoi absent"),
        ("### Corrigé", "### Fixed", "catégorie inconnue « Fixed »"),
        ("### Corrigé\n\n- Correctif (#3).\n", "### Corrigé\n", "catégorie vide"),
        ("### Modifié", "### Sécurité", "hors de l'ordre"),
        ("[0.2.0] - 2027-01-15", "[0.2.0] - 2027-13-15", "date invalide"),
        ("[0.2.0] - 2027-01-15", "[0.2.0] - 20270115", "date invalide"),
        ("[0.2.0] - 2027-01-15", "[0.2.0] - 2027-W03-5", "date invalide"),
        ("[0.2.0] - 2027-01-15", "[0.2.0] - 2026-01-15", "dates hors de l'ordre"),
        ("[0.2.0] - 2027-01-15", "[v0.2] - 2027-01-15", "version invalide"),
        # une pre-version ou une version de developpement n'est jamais datee
        ("[0.2.0] - 2027-01-15", "[0.2.0rc1] - 2027-01-15", "version invalide"),
        ("[0.2.0] - 2027-01-15", "[0.2.0.dev0] - 2027-01-15", "version invalide"),
        ("## [0.1.0] - 2026-11-30", "## 0.1.0 (2026-11-30)", "section inattendue"),
        ("[0.1.0]: ", "[0.1]: ", "lien de comparaison absent : [0.1.0]"),
        ("## [0.2.0]", "## [0.0.9]", "versions hors de l'ordre"),
        ("## [0.1.0]", "## [0.2.0]", "section en double"),
    ],
)
def test_validateur_refuse_un_changelog_mal_forme(
    avant: str, apres: str, erreur: str
) -> None:
    assert avant in CHANGELOG_VALIDE
    erreurs = erreurs_changelog(CHANGELOG_VALIDE.replace(avant, apres, 1), "0.2.0")
    assert any(erreur in e for e in erreurs), erreurs


def test_derniere_version_du_changelog_egale_a_la_version_du_paquet() -> None:
    # le bump de __version__ et la datation du CHANGELOG vont dans la meme PR
    erreurs = erreurs_changelog(CHANGELOG_VALIDE, "0.3.0")
    assert erreurs == ["dernière version 0.2.0 ≠ __version__ 0.3.0"]
    erreurs = erreurs_changelog(CHANGELOG_VALIDE, "v0.3")
    assert erreurs == ["__version__ invalide : v0.3"]


@pytest.mark.parametrize("version", ["0.3.0rc1", "0.3.0.dev0", "0.2.1.dev0"])
def test_pre_version_ou_developpement_apres_la_derniere_version(version: str) -> None:
    # PR de release d'une pre-version, ou main entre deux releases : rien de date
    assert erreurs_changelog(CHANGELOG_VALIDE, version) == []


@pytest.mark.parametrize("version", ["0.2.0rc1", "0.2.0.dev0", "0.1.1.dev0"])
def test_pre_version_ou_developpement_deja_publiee_refusee(version: str) -> None:
    erreurs = erreurs_changelog(CHANGELOG_VALIDE, version)
    assert erreurs == [f"__version__ {version} ne suit pas la dernière version 0.2.0"]


def test_correctif_d_une_serie_ancienne_publie_apres_une_mineure() -> None:
    # 0.1.1 publiee depuis maint/0.1.x apres la 0.2.0, entree reportee dans main
    # et rangee par numero de version
    correctif = "## [0.1.1] - 2027-02-01\n\n### Corrigé\n\n- Correctif (#4).\n\n"
    texte = CHANGELOG_VALIDE.replace("## [0.1.0]", correctif + "## [0.1.0]").replace(
        "[0.1.0]: ", f"[0.1.1]: {DEPOT}/compare/v0.1.0...v0.1.1\n[0.1.0]: "
    )
    assert erreurs_changelog(texte, "0.2.0") == []
    assert erreurs_changelog(texte, "0.3.0.dev0") == []
    # au sein d'une serie, les dates restent decroissantes
    texte = texte.replace("[0.1.1] - 2027-02-01", "[0.1.1] - 2026-11-01")
    assert erreurs_changelog(texte, "0.2.0") == ["dates hors de l'ordre décroissant"]


def test_version_publiee_sans_entree_refusee() -> None:
    vide = CHANGELOG_VALIDE.replace("### Ajouté\n\n- Première version (#1).\n", "")
    assert erreurs_changelog(vide, "0.2.0") == ["version 0.1.0 sans entrée"]


# docs/RELEASING.md


def test_categories_traduites_une_fois_pour_toutes() -> None:
    lignes = _tableau(_section(RELEASING, "CHANGELOG"))
    assert [tuple(ligne) for ligne in lignes] == list(
        zip(ANGLAIS, CATEGORIES, strict=True)
    )
    corps = _section(RELEASING, "CHANGELOG")
    for regle in ("[Unreleased]", "**Incompatible** :", "## [X.Y.Z] - AAAA-MM-JJ"):
        assert regle in corps, regle


def test_table_milestones_versions() -> None:
    lignes = _tableau(_section(RELEASING, "Milestones et versions"))
    table = {ligne[0]: ligne[1] for ligne in lignes}
    assert all(len(ligne) == 3 and ligne[2] for ligne in lignes)
    milestones = _milestones()
    # toutes les milestones du fichier declaratif, dans le meme ordre
    assert list(table) == [m["title"] for m in milestones]
    # table du ticket #31
    assert table["M0 — Scaffold"] == "0.1.0"
    assert table["M1 — MVP (Windows + AD)"] == "0.2.0"
    assert table["M2 — Cloud"] == "0.3.0"
    versions = [v for v in table.values() if v != "—"]
    assert all(VERSION.fullmatch(v) for v in versions)
    # une mineure par milestone, croissantes et toutes en 0.x
    assert [_cle(v) for v in versions] == sorted({_cle(v) for v in versions})
    assert all(v.startswith("0.") and v.endswith(".0") for v in versions)
    assert "**1.0.0**" in _section(RELEASING, "Milestones et versions")


def test_descriptions_des_milestones_reprennent_la_version() -> None:
    table = {
        ligne[0]: ligne[1]
        for ligne in _tableau(_section(RELEASING, "Milestones et versions"))
    }
    for milestone in _milestones():
        version = table[milestone["title"]]
        description = milestone["description"]
        if version == "—":
            assert not re.search(r"\bVersion \d", description), milestone
        else:
            assert description.startswith(f"Version {version} — "), milestone


@pytest.mark.parametrize(
    "surface",
    [
        "Ids de checks",
        "`question_id`",
        "Schéma du rapport JSON",
        "Codes de sortie",
        "Options CLI",
    ],
)
def test_surface_publique_avec_stabilite_et_depreciation(surface: str) -> None:
    lignes = _tableau(_section(RELEASING, "Surfaces publiques"))
    (ligne,) = [ligne for ligne in lignes if ligne[0].startswith(surface)]
    # Surface | Ou on la trouve | Regle de stabilite | Depreciation et retrait
    assert len(ligne) == 4
    assert all(len(cellule) > 10 for cellule in ligne[1:]), ligne


def test_regle_d_alias_des_ids_de_checks_illustree() -> None:
    corps = _section(RELEASING, "Alias de dépréciation des ids de checks")
    assert "jamais renommé sans alias" in corps
    regle, _, exemple = corps.partition("### Exemple")
    assert "jamais réattribué" in regle
    assert "N+2" in regle
    ids = re.findall(rf"`({ID_CHECK.pattern})`", exemple)
    ancien, nouveau = dict.fromkeys(ids)
    # l'ancien id est celui d'un vrai check, le nouveau est fictif
    enregistres = {c.id for c in default_checks()}
    assert ancien in enregistres
    assert nouveau not in enregistres
    # annonce, avertissement sur stderr pendant la duree de l'alias, puis retrait
    for etape in ("### Déprécié", "avertissement :", "### Supprimé"):
        assert etape in exemple, etape
    assert "**Incompatible** :" in exemple.partition("### Supprimé")[2]


def test_procedure_de_bout_en_bout_dans_l_ordre() -> None:
    corps = _section(RELEASING, "Procédure de release")
    etapes = [
        '__version__ = "X.Y.Z"',
        "## [X.Y.Z] - AAAA-MM-JJ",
        "uv run nox -s lint typecheck tests build",
        "git tag -s vX.Y.Z",
        "git tag -v vX.Y.Z",
        "git push origin vX.Y.Z",
        '__version__ = "X.Y+1.0.dev0"',
    ]
    positions = [corps.find(etape) for etape in etapes]
    assert -1 not in positions, dict(zip(etapes, positions, strict=True))
    assert positions == sorted(positions)
    assert "#33" in corps
    # git tag -v d'un tag SSH exige la liste des cles autorisees
    assert "git config gpg.ssh.allowedSignersFile .github/allowed_signers" in corps


def test_publication_verifie_signature_et_provenance_du_tag() -> None:
    # sans ces controles, un jeton vole suffit a publier un tag non signe ou pose
    # sur un commit non relu (menace M22)
    garanties = _section(RELEASING, "Procédure de release").partition(
        "### Ce que la publication (#33) doit garantir"
    )[2]
    for controle in (
        'git verify-tag "$GITHUB_REF_NAME"',
        "git show origin/main:.github/allowed_signers",
        "git merge-base --is-ancestor",
        "`.devN`",
        "environnement `pypi`",
    ):
        assert controle in garanties.partition("### Pré-versions")[0], controle
    protections = garanties.partition("### Protections côté GitHub")[2]
    for reglage in ("tags `v*`", "branches `maint/*`", "approbation obligatoire"):
        assert reglage in protections, reglage


def test_liens_relatifs_des_documents_existent() -> None:
    for document in (CHANGELOG, RELEASING):
        texte = document.read_text(encoding="utf-8")
        cibles = re.findall(r"\]\(([^)\s]+)\)", texte)
        relatifs = [c for c in cibles if not c.startswith(("https://", "#"))]
        assert relatifs, document.name
        for cible in relatifs:
            assert (document.parent / cible).is_file(), f"{document.name} : {cible}"


# Renvois du README et du paquet


def test_readme_renvoie_vers_changelog_et_releasing() -> None:
    # liens absolus : le README est la long_description publiee sur PyPI
    readme = (RACINE / "README.md").read_text(encoding="utf-8")
    for chemin in ("CHANGELOG.md", "docs/RELEASING.md"):
        assert f"]({DEPOT}/blob/main/{chemin})" in readme, chemin


def test_url_changelog_du_paquet() -> None:
    projet = tomllib.loads((RACINE / "pyproject.toml").read_text(encoding="utf-8"))
    url = projet["project"]["urls"]["Changelog"]
    assert url == f"{DEPOT}/blob/main/CHANGELOG.md"
    assert (RACINE / url.removeprefix(f"{DEPOT}/blob/main/")).is_file()
