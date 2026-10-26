"""Synchronisation des labels et milestones (scripts/sync_github.py).

Tous les appels passent par tests/faux_gh.py, lance comme un vrai gh : aucun
appel reseau, et le chemin d'erreur (code de sortie, stderr) est reellement
exerce.
"""

import importlib.util
import json
import re
import sys
import tomllib
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parent.parent
FAUX_GH = Path(__file__).resolve().parent / "faux_gh.py"
DEPOT = "proprietaire/amnesia"

# Etat laisse par l'ancien scripts/create-github-repo.sh : labels par defaut de
# GitHub, 5 labels du projet sans accents, 4 milestones.
ETAT_INITIAL = {
    "depot": DEPOT,
    "labels": [
        {"name": "bug", "color": "d73a4a", "description": "Something isn't working"},
        {"name": "documentation", "color": "0075ca", "description": "Docs"},
        {"name": "duplicate", "color": "cfd3d7", "description": "Already exists"},
        {"name": "enhancement", "color": "a2eeef", "description": "New feature"},
        {"name": "help wanted", "color": "008672", "description": None},
        {"name": "Question", "color": "d876e3", "description": "More info"},
        {"name": "type:feature", "color": "1d76db", "description": "Nouvelle fonc"},
        {"name": "good first issue", "color": "7057ff", "description": "Bon point"},
    ],
    "milestones": [
        {"number": 1, "title": "M0 — Scaffold", "description": "Mise en place"},
        {"number": 2, "title": "Backlog", "description": None, "state": "closed"},
        {"number": 3, "title": "Ancienne", "description": "hors fichier"},
    ],
    "issues": [{"number": 1, "labels": ["type:feature", "documentation"]}],
}


def _module():
    spec = importlib.util.spec_from_file_location(
        "sync_github", RACINE / "scripts" / "sync_github.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def sync(monkeypatch):
    module = _module()
    monkeypatch.setattr(module, "COMMANDE_GH", [sys.executable, str(FAUX_GH)])
    return module


@pytest.fixture
def github(tmp_path, monkeypatch):
    etat = tmp_path / "etat.json"
    journal = tmp_path / "journal.jsonl"
    etat.write_text(json.dumps(ETAT_INITIAL), encoding="utf-8")
    journal.touch()
    monkeypatch.setenv("FAUX_GH_ETAT", str(etat))
    monkeypatch.setenv("FAUX_GH_JOURNAL", str(journal))
    monkeypatch.delenv("FAUX_GH_ECHEC", raising=False)

    class Github:
        def etat(self) -> dict:
            return json.loads(etat.read_text(encoding="utf-8"))

        def ecrire(self, contenu: dict) -> None:
            etat.write_text(json.dumps(contenu), encoding="utf-8")

        def appels(self) -> list[dict]:
            lignes = journal.read_text(encoding="utf-8").splitlines()
            return [json.loads(ligne) for ligne in lignes]

        def ecritures(self) -> list[dict]:
            return [a for a in self.appels() if a.get("methode", "GET") != "GET"]

        def oublier(self) -> None:
            journal.write_text("", encoding="utf-8")

    return Github()


def _labels_fichier() -> dict[str, dict]:
    return {
        label["name"]: label for label in _module().charger_labels(_module().LABELS)
    }


def test_labels_yml_decrit_toute_la_taxonomie():
    noms = set(_labels_fichier())
    types = ["feature", "bug", "chore", "docs", "security", "test", "research"]
    zones = "core cli windows ad cloud siem report ci packaging docs legal business"
    attendus = {
        *(f"type:{t}" for t in types),
        *(f"priority:{p}" for p in ("high", "medium", "low")),
        *(f"area:{z}" for z in zones.split()),
        "good first issue",
        *("help wanted", "duplicate", "invalid", "wontfix", "question"),
    }
    assert noms == attendus
    assert len([n for n in noms if n.startswith("area:")]) == 12


def test_descriptions_accentuees():
    labels = _labels_fichier()
    assert labels["type:feature"]["description"] == "Nouvelle fonctionnalité"
    assert labels["good first issue"]["description"] == "Bon point de départ"
    # mots que l'ancien script ecrivait sans accents
    sans_accents = re.compile(
        r"\b(fonctionnalite|depart|priorite|securite|etude|integration|modele)\b",
        re.IGNORECASE,
    )
    for label in labels.values():
        assert not sans_accents.search(label["description"]), label
    for milestone in _module().charger_milestones(_module().MILESTONES):
        assert not sans_accents.search(milestone["description"]), milestone


def test_milestones_yml_titres_exacts():
    titres = [m["title"] for m in _module().charger_milestones(_module().MILESTONES)]
    assert titres == [
        "M0 — Scaffold",
        "M1 — MVP (Windows + AD)",
        "M2 — Cloud",
        "M3 — Linux & virtualisation",
        "Offre v0 — prestation pilote",
        "Backlog",
    ]


def test_dry_run_n_emet_aucune_ecriture(sync, github, capsys):
    assert sync.main(["--repo", DEPOT, "--dry-run"]) == 0
    assert github.ecritures() == []
    assert github.etat() == ETAT_INITIAL
    sortie = capsys.readouterr().out
    assert "+ label type:security" in sortie
    assert "~ label type:feature (description)" in sortie
    assert "+ milestone M3 — Linux & virtualisation" in sortie
    assert "rien n'est ecrit" in sortie


def test_dry_run_avec_prune_n_emet_aucune_ecriture(sync, github, capsys):
    github.ecrire({**ETAT_INITIAL, "issues": []})
    assert sync.main(["--repo", DEPOT, "--dry-run", "--prune"]) == 0
    assert github.ecritures() == []
    assert github.etat()["labels"] == ETAT_INITIAL["labels"]
    sortie = capsys.readouterr().out
    assert "- label bug" in sortie
    assert "- label enhancement" in sortie


def test_synchronisation_puis_relance_sans_modification(sync, github, capsys):
    assert sync.main(["--repo", DEPOT]) == 0
    assert github.ecritures()
    etat = github.etat()
    noms = {label["name"] for label in etat["labels"]}
    for nom in (
        "type:bug",
        "type:security",
        "type:test",
        "type:research",
        "priority:medium",
        "priority:low",
    ):
        assert nom in noms
    assert len([n for n in noms if n.startswith("area:")]) == 12
    # renommage par la casse, description null remplacee
    labels = {label["name"]: label for label in etat["labels"]}
    assert "Question" not in labels
    assert labels["question"]["description"] == "Précisions demandées"
    assert labels["help wanted"]["description"] == "Aide extérieure bienvenue"
    # sans --prune, rien n'est supprime ; milestone hors fichier conservee
    assert {"bug", "documentation", "enhancement"} <= noms
    milestones = {m["title"]: m for m in etat["milestones"]}
    assert len(milestones) == 7
    assert milestones["M0 — Scaffold"]["number"] == 1
    # state absent du fichier : l'etat ferme decide sur GitHub est conserve
    assert milestones["Backlog"]["state"] == "closed"
    assert milestones["Backlog"]["description"] == "Plus tard"

    github.oublier()
    capsys.readouterr()
    assert sync.main(["--repo", DEPOT]) == 0
    assert github.ecritures() == []
    assert github.etat() == etat
    assert "Aucune modification" in capsys.readouterr().out


def test_prune_supprime_les_labels_absents_non_utilises(sync, github):
    assert sync.main(["--repo", DEPOT]) == 0
    github.ecrire({**github.etat(), "issues": [{"number": 1, "labels": ["type:docs"]}]})
    github.oublier()
    assert sync.main(["--repo", DEPOT, "--prune"]) == 0
    supprimes = {a["chemin"] for a in github.ecritures() if a["methode"] == "DELETE"}
    assert supprimes == {
        f"repos/{DEPOT}/labels/bug",
        f"repos/{DEPOT}/labels/documentation",
        f"repos/{DEPOT}/labels/enhancement",
    }
    noms = {label["name"] for label in github.etat()["labels"]}
    assert noms == set(_labels_fichier())
    # les milestones ne sont jamais supprimees
    assert len(github.etat()["milestones"]) == 7


def test_prune_refuse_un_label_porte_par_une_issue(sync, github, capsys):
    assert sync.main(["--repo", DEPOT, "--prune"]) == 1
    assert github.ecritures() == []
    erreur = capsys.readouterr().err
    assert "--prune refuse" in erreur
    assert "documentation" in erreur


def test_echec_d_authentification(sync, github, monkeypatch, capsys):
    monkeypatch.setenv("FAUX_GH_ECHEC", "auth")
    assert sync.main(["--repo", DEPOT]) == 1
    erreur = capsys.readouterr().err
    assert "code 4" in erreur
    assert "gh auth login" in erreur


def test_erreur_422_arrete_a_la_premiere_ecriture(sync, github, monkeypatch, capsys):
    monkeypatch.setenv("FAUX_GH_ECHEC", "422")
    assert sync.main(["--repo", DEPOT]) == 1
    assert len(github.ecritures()) == 1
    assert github.etat() == ETAT_INITIAL
    erreur = capsys.readouterr().err
    assert "Validation Failed (HTTP 422)" in erreur
    assert '"errors"' in erreur


def test_depot_courant_par_defaut(sync, github, capsys):
    assert sync.main(["--dry-run"]) == 0
    assert f"Depot : {DEPOT}" in capsys.readouterr().out


@pytest.mark.parametrize("depot", ["../../user", "a/b?x=1", "a", "a/b/c"])
def test_depot_invalide_refuse(sync, github, depot, capsys):
    assert sync.main(["--repo", depot, "--dry-run"]) == 1
    assert "depot invalide" in capsys.readouterr().err
    assert github.appels() == []


def test_gh_introuvable(sync, github, monkeypatch, capsys):
    monkeypatch.setattr(sync, "COMMANDE_GH", ["gh-introuvable-amnesia"])
    assert sync.main(["--repo", DEPOT, "--dry-run"]) == 1
    assert "gh introuvable" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("contenu", "message"),
    [
        ("labels: []\n", "absente ou vide"),
        ("labels:\n  - {name: a, color: zzzzzz, description: d}\n", "couleur"),
        ("labels:\n  - {name: a, color: '000000'}\n", "description"),
        (
            "labels:\n  - {name: a, color: '000000', description: d}\n"
            "  - {name: A, color: '000000', description: d}\n",
            "en double",
        ),
        ("labels:\n  - {name: a, colour: '000000', description: d}\n", "invalide"),
        (
            f"labels:\n  - {{name: a, color: '000000', description: {'x' * 101}}}\n",
            "longue",
        ),
    ],
)
def test_labels_yml_invalide(
    sync, github, tmp_path, monkeypatch, capsys, contenu, message
):
    fichier = tmp_path / "labels.yml"
    fichier.write_text(contenu, encoding="utf-8")
    monkeypatch.setattr(sync, "LABELS", fichier)
    assert sync.main(["--repo", DEPOT, "--dry-run"]) == 1
    assert message in capsys.readouterr().err
    assert github.appels() == []


def test_milestone_state_invalide(sync, github, tmp_path, monkeypatch, capsys):
    fichier = tmp_path / "milestones.yml"
    fichier.write_text(
        "milestones:\n  - {title: M0, description: d, state: ferme}\n", encoding="utf-8"
    )
    monkeypatch.setattr(sync, "MILESTONES", fichier)
    assert sync.main(["--repo", DEPOT, "--dry-run"]) == 1
    assert "state invalide" in capsys.readouterr().err


def test_pyyaml_du_script_identique_au_groupe_dev():
    # les tests importent le PyYAML du groupe dev : meme version que le script,
    # dont les empreintes sont figees dans sync_github.py.lock
    texte = (RACINE / "scripts" / "sync_github.py").read_text(encoding="utf-8")
    bloc = re.search(r"^# /// script\n(.*?)^# ///$", texte, re.MULTILINE | re.DOTALL)
    lignes = bloc.group(1).splitlines()
    metadonnees = tomllib.loads("\n".join(ligne[2:] for ligne in lignes))
    pyproject = tomllib.loads((RACINE / "pyproject.toml").read_text(encoding="utf-8"))
    dev = pyproject["dependency-groups"]["dev"]
    assert metadonnees["dependencies"] == [d for d in dev if d.startswith("pyyaml==")]
    verrou = RACINE / "scripts" / "sync_github.py.lock"
    paquets = tomllib.loads(verrou.read_text(encoding="utf-8"))["package"]
    assert [f"{p['name']}=={p['version']}" for p in paquets] == ["pyyaml==6.0.3"]
