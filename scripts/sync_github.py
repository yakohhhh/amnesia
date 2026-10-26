# /// script
# requires-python = ">=3.11"
# # meme version que le groupe dev ; empreintes figees dans sync_github.py.lock
# # (uvx uv@0.13.0 lock --script scripts/sync_github.py)
# dependencies = ["pyyaml==6.0.3"]
#
# [tool.uv]
# exclude-newer = "7 days"
# ///
"""Aligne les labels et milestones du depot GitHub sur les fichiers declaratifs.

Lit .github/labels.yml et .github/milestones.yml, les compare a l'etat distant
(lu par gh api) et ne cree ou ne modifie que les ecarts : une deuxieme execution
n'a rien a faire. Voir docs/dev/github.md.

    uv run --locked scripts/sync_github.py [--repo PROPRIETAIRE/DEPOT] [--dry-run]
                                           [--prune]

--locked : PyYAML est installe depuis scripts/sync_github.py.lock (empreintes
verifiees), et uv echoue si ce lock ne correspond plus aux metadonnees ci-dessus.

--dry-run affiche le plan sans aucun appel en ecriture. --prune supprime aussi les
labels absents de labels.yml, apres avoir verifie qu'aucune issue ni PR ne les
porte ; les milestones ne sont jamais supprimees. Aucune erreur n'est avalee : un
appel gh en echec (authentification, 422...) arrete le script en code 1 avec le
message de GitHub.
"""

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

import yaml

RACINE = Path(__file__).resolve().parent.parent
LABELS = RACINE / ".github" / "labels.yml"
MILESTONES = RACINE / ".github" / "milestones.yml"
# remplacee par les tests : un gh simule, sans aucun appel reseau
COMMANDE_GH = ["gh"]

COULEUR = re.compile(r"[0-9a-fA-F]{6}")
# le nom du depot entre dans les chemins d'API : ni « .. » ni « ? » possibles
DEPOT = re.compile(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+")
DESCRIPTION_MAX = 100  # limite de GitHub pour un label
ETATS = ("open", "closed")


class Erreur(Exception):
    """Echec qui arrete la synchronisation (configuration ou appel GitHub)."""


@dataclass(frozen=True)
class Action:
    libelle: str
    methode: str
    chemin: str
    corps: dict | None = None


def _afficher(texte: str, *, erreur: bool = False) -> None:
    print(texte, file=sys.stderr if erreur else sys.stdout)


def gh(*args: str, corps: dict | None = None) -> object:
    """Lance gh, renvoie sa sortie JSON ; leve Erreur avec le message de GitHub."""
    try:
        resultat = subprocess.run(  # noqa: S603 - arguments en liste, sans shell
            [*COMMANDE_GH, *args],
            input=None if corps is None else json.dumps(corps),
            capture_output=True,
            encoding="utf-8",
            check=False,
        )
    except FileNotFoundError as exc:
        raise Erreur(f"gh introuvable ({exc}) : installer GitHub CLI") from exc
    if resultat.returncode != 0:
        # gh ecrit le statut HTTP sur stderr et le corps de la reponse sur stdout
        details = [t.strip() for t in (resultat.stderr, resultat.stdout) if t.strip()]
        raise Erreur(
            f"echec de « gh {' '.join(args)} » (code {resultat.returncode})\n"
            + "\n".join(details)
        )
    if not resultat.stdout.strip():
        return None  # 204 No Content (suppression)
    try:
        return json.loads(resultat.stdout)
    except json.JSONDecodeError as exc:
        raise Erreur(f"reponse illisible de « gh {' '.join(args)} » : {exc}") from exc


def _liste(chemin: str) -> list[dict]:
    # --slurp : toutes les pages dans un seul tableau JSON (un tableau par page)
    pages = gh("api", "--paginate", "--slurp", chemin)
    return [element for page in pages for element in page]


def _charger(fichier: Path, cle: str) -> list[dict]:
    try:
        contenu = yaml.safe_load(fichier.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise Erreur(f"{fichier.name} illisible : {exc}") from exc
    entrees = contenu.get(cle) if isinstance(contenu, dict) else None
    if not isinstance(entrees, list) or not entrees:
        raise Erreur(f"{fichier.name} : liste « {cle} » absente ou vide")
    return entrees


def _texte(entree: dict, champ: str, fichier: str, *, vide: bool = False) -> str:
    valeur = entree.get(champ)
    if not isinstance(valeur, str) or not (vide or valeur.strip()):
        raise Erreur(f"{fichier} : « {champ} » manquant ou invalide dans {entree!r}")
    return valeur


def charger_labels(fichier: Path) -> list[dict]:
    labels, vus = [], set()
    for entree in _charger(fichier, "labels"):
        if not isinstance(entree, dict) or set(entree) - {
            "name",
            "color",
            "description",
        }:
            raise Erreur(f"{fichier.name} : entree invalide {entree!r}")
        nom = _texte(entree, "name", fichier.name)
        couleur = _texte(entree, "color", fichier.name)
        description = _texte(entree, "description", fichier.name)
        if not COULEUR.fullmatch(couleur):
            raise Erreur(f"{fichier.name} : couleur invalide pour {nom} : {couleur!r}")
        if len(description) > DESCRIPTION_MAX:
            raise Erreur(f"{fichier.name} : description trop longue pour {nom}")
        # GitHub ignore la casse des noms de labels
        if nom.casefold() in vus:
            raise Erreur(f"{fichier.name} : label en double : {nom}")
        vus.add(nom.casefold())
        labels.append(
            {"name": nom, "color": couleur.lower(), "description": description}
        )
    return labels


def charger_milestones(fichier: Path) -> list[dict]:
    milestones, vus = [], set()
    for entree in _charger(fichier, "milestones"):
        if not isinstance(entree, dict) or set(entree) - {
            "title",
            "description",
            "state",
        }:
            raise Erreur(f"{fichier.name} : entree invalide {entree!r}")
        titre = _texte(entree, "title", fichier.name)
        milestone = {
            "title": titre,
            "description": _texte(entree, "description", fichier.name, vide=True),
        }
        if "state" in entree:
            if entree["state"] not in ETATS:
                raise Erreur(f"{fichier.name} : state invalide pour {titre}")
            milestone["state"] = entree["state"]
        if titre in vus:
            raise Erreur(f"{fichier.name} : milestone en double : {titre}")
        vus.add(titre)
        milestones.append(milestone)
    return milestones


def _label_utilise(depot: str, nom: str) -> bool:
    # le filtre labels de l'API separe les noms par des virgules
    if "," in nom:
        raise Erreur(f"label {nom!r} : usage inverifiable, suppression refusee")
    # issues et PR, ouvertes ou fermees ; -X GET : les champs vont dans l'URL
    champs = [f"labels={nom}", "state=all", "per_page=1"]
    args = [arg for champ in champs for arg in ("-f", champ)]
    return bool(gh("api", "-X", "GET", f"repos/{depot}/issues", *args))


def plan_labels(depot: str, voulus: list[dict], prune: bool) -> list[Action]:
    distants = _liste(f"repos/{depot}/labels?per_page=100")
    par_nom = {label["name"].casefold(): label for label in distants}
    actions = []
    for label in voulus:
        actuel = par_nom.pop(label["name"].casefold(), None)
        if actuel is None:
            actions.append(
                Action(
                    f"+ label {label['name']}", "POST", f"repos/{depot}/labels", label
                )
            )
            continue
        ecarts = {}
        # GitHub renvoie la couleur en minuscules et une description vide en null
        if (actuel.get("color") or "").lower() != label["color"]:
            ecarts["color"] = label["color"]
        if (actuel.get("description") or "") != label["description"]:
            ecarts["description"] = label["description"]
        if actuel["name"] != label["name"]:
            ecarts["new_name"] = label["name"]
        if ecarts:
            chemin = f"repos/{depot}/labels/{quote(actuel['name'], safe='')}"
            libelle = f"~ label {label['name']} ({', '.join(sorted(ecarts))})"
            actions.append(Action(libelle, "PATCH", chemin, ecarts))
    absents = sorted(label["name"] for label in par_nom.values())
    if absents and not prune:
        _afficher(
            "Labels absents de labels.yml, conserves (--prune pour les supprimer) : "
            + ", ".join(absents)
        )
    if prune:
        utilises = [nom for nom in absents if _label_utilise(depot, nom)]
        if utilises:
            raise Erreur(
                "--prune refuse : labels encore portes par des issues ou des PR : "
                + ", ".join(utilises)
            )
        for nom in absents:
            chemin = f"repos/{depot}/labels/{quote(nom, safe='')}"
            actions.append(Action(f"- label {nom}", "DELETE", chemin))
    return actions


def plan_milestones(depot: str, voulues: list[dict]) -> list[Action]:
    distantes = _liste(f"repos/{depot}/milestones?state=all&per_page=100")
    par_titre = {milestone["title"]: milestone for milestone in distantes}
    actions = []
    for milestone in voulues:
        actuelle = par_titre.pop(milestone["title"], None)
        if actuelle is None:
            chemin = f"repos/{depot}/milestones"
            libelle = f"+ milestone {milestone['title']}"
            actions.append(Action(libelle, "POST", chemin, milestone))
            continue
        ecarts = {
            champ: valeur
            for champ, valeur in milestone.items()
            if champ != "title" and (actuelle.get(champ) or "") != valeur
        }
        if ecarts:
            chemin = f"repos/{depot}/milestones/{actuelle['number']}"
            libelle = f"~ milestone {milestone['title']} ({', '.join(sorted(ecarts))})"
            actions.append(Action(libelle, "PATCH", chemin, ecarts))
    if par_titre:
        _afficher(
            "Milestones absentes de milestones.yml, conservees : "
            + ", ".join(sorted(par_titre))
        )
    return actions


def appliquer(action: Action) -> None:
    args = ["api", "-X", action.methode, action.chemin]
    if action.corps is not None:
        # corps JSON sur l'entree standard : aucune valeur interpretee par gh
        args += ["--input", "-"]
    gh(*args, corps=action.corps)


def _depot_courant() -> str:
    reponse = gh("repo", "view", "--json", "nameWithOwner")
    return reponse["nameWithOwner"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", help="PROPRIETAIRE/DEPOT (defaut : depot courant)")
    parser.add_argument(
        "--dry-run", action="store_true", help="affiche le plan sans rien ecrire"
    )
    parser.add_argument(
        "--prune",
        action="store_true",
        help="supprime les labels absents de labels.yml et portes par aucune issue",
    )
    args = parser.parse_args(argv)
    try:
        labels = charger_labels(LABELS)
        milestones = charger_milestones(MILESTONES)
        depot = args.repo or _depot_courant()
        if not DEPOT.fullmatch(depot):
            raise Erreur(f"depot invalide : {depot!r}")
        _afficher(f"Depot : {depot}")
        actions = plan_labels(depot, labels, args.prune)
        actions += plan_milestones(depot, milestones)
        if not actions:
            _afficher("Aucune modification : GitHub est a jour.")
            return 0
        if args.dry_run:
            _afficher(f"Plan (--dry-run, rien n'est ecrit) : {len(actions)} action(s)")
            for action in actions:
                _afficher(f"  {action.libelle}")
            return 0
        for action in actions:
            _afficher(f"  {action.libelle}")
            appliquer(action)
        _afficher(f"{len(actions)} modification(s) appliquee(s).")
    except Erreur as exc:
        _afficher(f"erreur : {exc}", erreur=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
