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


def _modeles(repertoire: Path) -> set[str]:
    """Fichiers que GitHub lit comme modeles d'issues (.DS_Store, .swp, ~ ignores)."""
    return {
        p.name
        for p in repertoire.iterdir()
        if p.is_file() and p.suffix in {".yml", ".yaml", ".md"}
    }


def test_trois_formulaires_et_aucune_issue_vierge() -> None:
    assert _modeles(MODELES) == {*FORMULAIRES, "config.yml"}
    for fichier, (nom, _) in FORMULAIRES.items():
        formulaire = _yaml(MODELES / fichier)
        assert formulaire["name"] == nom, fichier
        assert formulaire["description"].strip(), fichier
    # False et non une valeur equivalente : GitHub attend un booleen
    assert _yaml(MODELES / "config.yml")["blank_issues_enabled"] is False


def test_fichiers_parasites_ignores_mais_modele_en_trop_detecte(
    tmp_path: Path,
) -> None:
    # un clone de travail sous macOS ou un editeur ouvert ne casse pas la suite
    for nom in ("bug.yml", ".DS_Store", ".bug.yml.swp", "bug.yml~"):
        (tmp_path / nom).write_text("", encoding="utf-8")
    (tmp_path / "sous").mkdir()
    assert _modeles(tmp_path) == {"bug.yml"}
    for nom in ("autre.yaml", "lisez-moi.md"):
        (tmp_path / nom).write_text("", encoding="utf-8")
    assert _modeles(tmp_path) == {"bug.yml", "autre.yaml", "lisez-moi.md"}


def test_lien_de_contact_vers_la_politique_de_securite() -> None:
    liens = _yaml(MODELES / "config.yml")["contact_links"]
    assert [lien["url"] for lien in liens] == [f"{DEPOT}/blob/main/SECURITY.md"]
    assert "vulnérabilité" in liens[0]["name"]
    assert (RACINE / "SECURITY.md").is_file()


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


def test_cases_d_anonymisation_obligatoires_du_bug() -> None:
    options = _champ("bug.yml", "anonymisation")["attributes"]["options"]
    assert [option["required"] for option in options] == [True, True]
    reproduction, remplacement = (option["label"] for option in options)
    assert "cible de test ou des données fictives" in reproduction
    assert "sans coller de sortie produite chez un client" in reproduction
    # amnesia affiche les chemins de la cible et du rapport : nom du client
    for donnee in (
        "noms de client ou de mission",
        "chemins",
        "noms d'hôtes",
        "comptes",
        "SID",
        "GUID",
        "identifiants de tenant",
        "secrets",
    ):
        assert donnee in remplacement, donnee


def test_bug_sans_sortie_produite_chez_un_client() -> None:
    # regle « Support et signalements » de SECURITY.md (#28)
    assert "**Support et signalements.**" in _texte(RACINE / "SECURITY.md")
    intro = _yaml(MODELES / "bug.yml")["body"][0]["attributes"]["value"]
    assert f"]({DEPOT}/blob/main/SECURITY.md), « Support et signalements »" in intro
    assert "ne colle jamais de journal ni de sortie produits chez un client" in intro
    for chemin in ("`bundle:`", "`--out`", "`--log-file`", "`C:\\Users\\…`"):
        assert chemin in intro, chemin
    commande = _champ("bug.yml", "commande")["attributes"]
    assert "bundle:./exemple" in commande["placeholder"]
    assert "chemins" in commande["description"]
    assert (
        "jamais une sortie produite chez un client"
        in (_champ("bug.yml", "sortie")["attributes"]["description"])
    )


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
    # blocs indentes compris (blocs de code dans une liste)
    return re.findall(r"^ *```\w*\n(.*?)^ *```$", texte, flags=re.MULTILINE | re.DOTALL)


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
    citees = re.findall(r"astral-sh/uv/releases/download/([\d.]+)/", texte)
    assert citees
    assert set(citees) == {version}
    assert f"la CI utilise la {version}" in " ".join(texte.split())


def test_binaire_d_uv_verifie_avant_extraction() -> None:
    # uv applique les empreintes de uv.lock : son binaire est verifie comme en CI
    env = _yaml(CI)["env"]
    commandes = _commandes(_texte(CONTRIBUTING))
    linux = "uv-x86_64-unknown-linux-gnu.tar.gz"
    verification = (
        f'echo "{env["UV_SHA256_LINUX_X64"]}  {linux}" | sha256sum --check --strict'
    )
    assert commandes.index(verification) < commandes.index(f"tar -xzf {linux}")
    windows = "uv-x86_64-pc-windows-msvc.zip"
    hachage = [c for c in commandes if c.startswith(f"if ((Get-FileHash {windows}")]
    assert len(hachage) == 1
    assert f'-ne "{env["UV_SHA256_WINDOWS_X64"]}") {{ throw ' in hachage[0]
    assert commandes.index(hachage[0]) < commandes.index(
        f"Expand-Archive {windows} -DestinationPath $HOME\\.local\\bin"
    )
    macos = "uv-aarch64-apple-darwin.tar.gz"
    assert commandes.index(f"shasum -a 256 -c {macos}.sha256") < commandes.index(
        f"tar -xzf {macos}"
    )
    # aucun script distant envoye directement a un shell
    for commande in commandes:
        assert not re.search(r"\|\s*(sh|bash|zsh|iex)\b", commande), commande
    assert "ExecutionPolicy" not in _texte(CONTRIBUTING)


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
    # lien absolu, comme dans SECURITY.md (#28) : valable hors du depot
    assert f"]({DEPOT}/blob/main/SECURITY.md)" in texte
    assert (RACINE / "SECURITY.md").is_file()
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


def test_parcours_depuis_un_fork() -> None:
    # contributeur externe sans droit d'ecriture : fork, upstream, push -u
    texte = _texte(CONTRIBUTING)
    commandes = _commandes(texte)
    parcours = [
        "git clone https://github.com/<compte>/amnesia.git",
        "cd amnesia",
        f"git remote add upstream {DEPOT}.git",
        "git fetch upstream",
        "git switch -c docs/29-exemple upstream/main",
        "git push -u origin docs/29-exemple",
    ]
    debut = commandes.index(parcours[0])
    assert commandes[debut : debut + len(parcours)] == parcours
    # mise a jour depuis le main d'origine, jamais celui du fork
    mise_a_jour = ["git fetch upstream", "git merge upstream/main", "git push"]
    debut = commandes.index(mise_a_jour[1]) - 1
    assert commandes[debut : debut + len(mise_a_jour)] == mise_a_jour
    plat = " ".join(texte.split())
    assert "**Sans droit d'écriture sur le dépôt**" in plat
    assert "forker `yakohhhh/amnesia`" in plat
    assert "la PR va du fork vers `yakohhhh/amnesia:main`" in plat
    assert "](#une-issue-une-branche-une-pr)" in texte


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


def _section(texte: str, titre: str) -> str:
    for morceau in re.split(r"^## ", texte, flags=re.MULTILINE)[1:]:
        entete, _, corps = morceau.partition("\n")
        if entete.strip() == titre:
            return corps
    raise AssertionError(f"section {titre!r} absente")


def test_verifications_de_passage_en_public_listees() -> None:
    # checklist de passage en public (#13) : ce que seul GitHub peut montrer
    section = _section(
        _texte(RACINE / "docs" / "dev" / "github.md"), "Passage en public"
    )
    cases = [case for case in _cases(section) if "(#29)" in case]
    assert len(cases) == 3, cases
    bug, vierge, modele = cases
    for element in (
        "« Bug »",
        "deux cases d'anonymisation",
        "refusé",
        "`required: true`",
    ):
        assert element in bug, element
    for element in ("lecture ou triage", "aucune issue vierge", "Maintainers only"):
        assert element in vierge, element
    assert "checklist du modèle" in modele
