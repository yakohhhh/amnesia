"""Guide de contribution, formulaires d'issues et modele de PR (#29).

Ces tests verifient la forme (champs obligatoires, labels, renvois, commandes),
pas le rendu sur GitHub : les verifications faites a la main au passage en
public sont listees dans docs/dev/github.md.
"""

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from amnesia.checks.registry import Domain

RACINE = Path(__file__).resolve().parent.parent
DEPOT = "https://github.com/yakohhhh/amnesia"
MODELES = RACINE / ".github" / "ISSUE_TEMPLATE"
CONTRIBUTING = RACINE / "CONTRIBUTING.md"
MODELE_PR = RACINE / ".github" / "pull_request_template.md"
CI = RACINE / ".github" / "workflows" / "ci.yml"

# fichier -> (nom affiche dans « New issue », label pose automatiquement)
FORMULAIRES = {
    "nouveau-check.yml": ("Nouveau check", "type:feature"),
    "bug.yml": ("Bug", "type:bug"),
    "fonctionnalite.yml": ("Fonctionnalité", "type:feature"),
}


def _yaml(chemin: Path) -> dict[str, Any]:
    contenu: dict[str, Any] = yaml.safe_load(chemin.read_text(encoding="utf-8"))
    return contenu


def _champ(formulaire: str, champ_id: str) -> dict[str, Any]:
    for element in _yaml(MODELES / formulaire)["body"]:
        if element.get("id") == champ_id:
            trouve: dict[str, Any] = element
            return trouve
    raise AssertionError(f"{formulaire} : champ {champ_id!r} absent")


def _texte(chemin: Path) -> str:
    return chemin.read_text(encoding="utf-8")


def _labels_declares() -> set[str]:
    return {
        label["name"] for label in _yaml(RACINE / ".github" / "labels.yml")["labels"]
    }


# Formulaires d'issues


def test_trois_formulaires_et_aucune_issue_vierge() -> None:
    fichiers = {p.name for p in MODELES.iterdir()}
    assert fichiers == {*FORMULAIRES, "config.yml"}
    for fichier, (nom, _) in FORMULAIRES.items():
        formulaire = _yaml(MODELES / fichier)
        assert formulaire["name"] == nom, fichier
        assert formulaire["description"].strip(), fichier
    # False et non une valeur equivalente : GitHub attend un booleen
    assert _yaml(MODELES / "config.yml")["blank_issues_enabled"] is False


def test_lien_de_contact_vers_la_politique_de_securite() -> None:
    liens = _yaml(MODELES / "config.yml")["contact_links"]
    assert [lien["url"] for lien in liens] == [f"{DEPOT}/blob/main/SECURITY.md"]
    assert "vulnérabilité" in liens[0]["name"]


@pytest.mark.parametrize(
    "champ_id", ["domaine", "question", "telemetrie", "collecte", "privileges"]
)
def test_champs_obligatoires_du_nouveau_check(champ_id: str) -> None:
    champ = _champ("nouveau-check.yml", champ_id)
    assert champ["validations"]["required"] is True


def test_question_d_enquete_en_premier() -> None:
    # la question d'enquete precede la source, la collecte et les privileges
    ids = [e.get("id") for e in _yaml(MODELES / "nouveau-check.yml")["body"]]
    ordre = ["question", "telemetrie", "collecte", "privileges", "seuil", "references"]
    assert [i for i in ids if i in ordre] == ordre


def test_domaines_du_formulaire_alignes_sur_le_registre() -> None:
    options = _champ("nouveau-check.yml", "domaine")["attributes"]["options"]
    assert options == [*(d.value for d in Domain), "autre"]


def test_case_d_anonymisation_obligatoire_du_bug() -> None:
    options = _champ("bug.yml", "anonymisation")["attributes"]["options"]
    assert len(options) == 1
    assert options[0]["required"] is True
    assert "noms d'hôtes, domaines, IP et identifiants de tenant" in options[0]["label"]


@pytest.mark.parametrize("champ_id", ["version", "os", "python", "cible", "sortie"])
def test_environnement_et_sortie_du_bug_obligatoires(champ_id: str) -> None:
    assert _champ("bug.yml", champ_id)["validations"]["required"] is True


@pytest.mark.parametrize("fichier", sorted(FORMULAIRES))
def test_aucune_donnee_client_rappelee(fichier: str) -> None:
    # chaque formulaire rappelle la regle avant le premier champ
    premier = _yaml(MODELES / fichier)["body"][0]
    assert premier["type"] == "markdown"
    assert "identifiant" in premier["attributes"]["value"]


@pytest.mark.parametrize("fichier", sorted(FORMULAIRES))
def test_labels_des_formulaires_dans_la_taxonomie(fichier: str) -> None:
    labels = _yaml(MODELES / fichier)["labels"]
    assert labels == [FORMULAIRES[fichier][1]]
    assert set(labels) <= _labels_declares()


# Validation par check-jsonschema


def _hook(hook_id: str) -> dict[str, Any]:
    for depot in _yaml(RACINE / ".pre-commit-config.yaml")["repos"]:
        for hook in depot["hooks"]:
            if hook["id"] == hook_id:
                trouve: dict[str, Any] = hook
                return trouve
    raise AssertionError(f"hook {hook_id} absent")


@pytest.mark.parametrize(
    ("hook_id", "schema", "valides", "ignores"),
    [
        (
            "formulaires-issues",
            "vendor.github-issue-forms",
            [*FORMULAIRES, "autre.yaml"],
            ["config.yml", "config.yaml", "sous/bug.yml", "lisez-moi.md"],
        ),
        (
            "config-issues",
            "vendor.github-issue-config",
            ["config.yml", "config.yaml"],
            [*FORMULAIRES, "sous/config.yml"],
        ),
    ],
)
def test_schemas_verifies_en_pre_commit(
    hook_id: str, schema: str, valides: list[str], ignores: list[str]
) -> None:
    hook = _hook(hook_id)
    # check-jsonschema est fige dans le groupe ci de uv.lock
    assert hook["entry"] == (
        f"uv run --locked --group ci check-jsonschema --builtin-schema {schema}"
    )
    motif = re.compile(hook["files"])
    for nom in valides:
        assert motif.search(f".github/ISSUE_TEMPLATE/{nom}"), nom
    for nom in ignores:
        assert not motif.search(f".github/ISSUE_TEMPLATE/{nom}"), nom


def test_schemas_verifies_en_ci() -> None:
    etapes = _yaml(CI)["jobs"]["workflow-lint"]["steps"]
    # lignes de continuation bash (« \ ») jointes, espaces normalises
    commandes = " ".join(
        " ".join(e.get("run", "").replace("\\\n", " ").split()) for e in etapes
    )
    assert (
        "uv run --only-group ci check-jsonschema --builtin-schema "
        'vendor.github-issue-forms "${formulaires[@]}"'
    ) in commandes
    # tous les formulaires du repertoire, sauf config.yml
    assert "for f in .github/ISSUE_TEMPLATE/*.yml .github/ISSUE_TEMPLATE/*.yaml" in (
        commandes
    )
    assert "config.yml | config.yaml) ;;" in commandes
    assert (
        "uv run --only-group ci check-jsonschema --builtin-schema "
        "vendor.github-issue-config .github/ISSUE_TEMPLATE/config.yml"
    ) in commandes


# Modele de PR


def test_modele_de_pr_unique_avec_checklist() -> None:
    # un repertoire PULL_REQUEST_TEMPLATE/ n'est pas applique par defaut
    assert not (RACINE / ".github" / "PULL_REQUEST_TEMPLATE").exists()
    texte = _texte(MODELE_PR)
    cases = [ligne for ligne in texte.splitlines() if ligne.startswith("- [ ] ")]
    attendus = [
        "Issue liée",
        "Tests",
        "Fixtures anonymisées",
        "CHANGELOG",
        "Documentation",
        "Lecture seule",
        "Modèle de menace",
    ]
    assert len(cases) == len(attendus), cases
    for case, attendu in zip(cases, attendus, strict=True):
        assert case.startswith(f"- [ ] {attendu}"), case
    assert texte.rstrip().endswith("Closes #")


# CONTRIBUTING.md


def _blocs_de_code(texte: str) -> list[str]:
    return re.findall(r"^```\w*\n(.*?)^```$", texte, flags=re.MULTILINE | re.DOTALL)


def _commandes(texte: str) -> list[str]:
    """Lignes de commande des blocs de code, sans commentaire final."""
    return [
        ligne.split("  #", 1)[0].strip()
        for bloc in _blocs_de_code(texte)
        for ligne in bloc.splitlines()
        if ligne.strip() and not ligne.lstrip().startswith("#")
    ]


def test_de_git_clone_a_une_suite_verte() -> None:
    commandes = _commandes(_texte(CONTRIBUTING))
    parcours = [
        f"git clone {DEPOT}.git",
        "cd amnesia",
        "uv sync --locked",
        "uv run pre-commit install",
        "uv run nox -s lint typecheck tests-3.11",
    ]
    debut = commandes.index(parcours[0])
    assert commandes[debut : debut + len(parcours)] == parcours
    # sessions nox citees, et 3.11 est bien le plancher de .python-version
    noxfile = _texte(RACINE / "noxfile.py")
    for session in ("lint", "typecheck", "tests", "build"):
        assert re.search(rf"^def {session}\(session: nox\.Session\)", noxfile, re.M)
    assert re.search(r'^PYTHONS = \["3\.11",', noxfile, flags=re.MULTILINE)
    assert _texte(RACINE / ".python-version").strip() == "3.11"


def test_commandes_de_la_ci_citees_a_l_identique() -> None:
    commandes = _commandes(_texte(CONTRIBUTING))
    ci = _yaml(CI)
    test = ci["jobs"]["test"]
    variables = " ".join(
        f"{cle}={valeur!r}" if " " in valeur else f"{cle}={valeur}"
        for cle, valeur in test["env"].items()
    )
    assert f"{variables} uv run pytest -q --cov" in commandes
    executees = {e.get("run") for job in ci["jobs"].values() for e in job["steps"]}
    for commande in (
        "uv run ruff check .",
        "uv run ruff format --check .",
        "uv run mypy",
    ):
        assert commande in executees
        assert commande in commandes


def test_version_d_uv_alignee_sur_la_ci() -> None:
    version = _yaml(CI)["env"]["UV_VERSION"]
    texte = _texte(CONTRIBUTING)
    citees = re.findall(r"astral\.sh/uv/([\d.]+)/install", texte)
    assert citees
    assert set(citees) == {version}
    assert f"la CI utilise la {version}" in " ".join(texte.split())


def _ancre(titre: str) -> str:
    """Ancre GitHub d'un titre : minuscules, ponctuation retiree, espaces en tirets."""
    titre = re.sub(r"[^\w\- ]", "", titre.strip().lower())
    return titre.replace(" ", "-")


def test_liens_du_guide_valides() -> None:
    texte = _texte(CONTRIBUTING)
    cibles = re.findall(r"\]\(([^)\s]+)\)", texte)
    ancres = {_ancre(t) for t in re.findall(r"^#+ (.+)$", texte, flags=re.MULTILINE)}
    assert cibles
    for cible in cibles:
        if cible.startswith("#"):
            assert cible[1:] in ancres, cible
        elif not cible.startswith("https://"):
            assert (RACINE / cible).exists(), cible


def test_renvois_securite_licence_et_guide_des_checks() -> None:
    texte = _texte(CONTRIBUTING)
    # lien absolu : SECURITY.md arrive par #28 et s'affiche aussi hors du depot
    assert f"]({DEPOT}/blob/main/SECURITY.md)" in texte
    licence = texte.partition("## Licence des contributions")[2]
    # politique non tranchee ici : renvoi vers la decision de licence et #30
    for renvoi in ("DCO", "CLA", "#11", "#30"):
        assert renvoi in licence, renvoi
    assert "#81" in texte


@pytest.mark.parametrize(
    "convention",
    [
        "uv sync --locked",
        "mypy --strict",
        "docs/dev/encodage.md",
        "--no-verify",
        "a sa branche et sa PR",
        "**squash**",
        "`ci-ok`",
        "Closes #<numéro>",
        "Aucune attribution à un outil d'IA",
        "uvx uv@",
    ],
)
def test_conventions_documentees(convention: str) -> None:
    assert convention in _texte(CONTRIBUTING)


def test_convention_de_nommage_des_branches() -> None:
    texte = " ".join(_texte(CONTRIBUTING).split())
    assert "`<type>/<numéro>-<sujet>`" in texte
    types = re.search(r"Types : ((?:`[a-z]+`(?:, |\.))+)", texte)
    assert types, "liste des types de branche absente"
    noms = re.findall(r"`([a-z]+)`", types[1])
    assert {"feat", "fix", "docs", "chore", "test"} <= set(noms)
    exemples = re.findall(r"`([a-z]+/\d+-[a-z0-9-]+)`", texte)
    assert exemples
    for exemple in exemples:
        assert exemple.split("/")[0] in noms, exemple


def test_labels_cites_dans_la_taxonomie() -> None:
    texte = _texte(CONTRIBUTING)
    cites = set(re.findall(r"`((?:type|priority|area):[a-z]+)`", texte))
    assert cites
    assert cites <= _labels_declares()
    for regle in ("**1 type**", "**1 priorité**", "**1 à 2 domaines**"):
        assert regle in texte, regle


def test_tableau_des_formulaires_aligne_sur_les_fichiers() -> None:
    lignes = re.findall(
        r"^\| \*\*(.+?)\*\* \| `([^`]+)` \|", _texte(CONTRIBUTING), flags=re.MULTILINE
    )
    assert sorted(lignes) == sorted(FORMULAIRES.values())


# Renvois


def test_readme_renvoie_vers_contributing() -> None:
    # lien absolu : le README est publie sur PyPI
    assert f"]({DEPOT}/blob/main/CONTRIBUTING.md)" in _texte(RACINE / "README.md")


def _cases(texte: str) -> list[str]:
    """Cases a cocher d'un document Markdown, lignes de continuation jointes."""
    cases: list[str] = []
    en_cours = False
    for ligne in texte.splitlines():
        if re.match(r"- \[[ x]\] ", ligne):
            cases.append(ligne)
            en_cours = True
        elif en_cours and ligne.startswith("  ") and ligne.strip():
            cases[-1] += " " + ligne.strip()
        else:
            en_cours = False
    return cases


def test_verifications_de_passage_en_public_listees() -> None:
    cases = _cases(_texte(RACINE / "docs" / "dev" / "github.md"))
    assert any(
        "« Bug »" in case and "case d'anonymisation" in case and "refusé" in case
        for case in cases
    )
    assert any("Maintainers only" in case for case in cases)
