"""Refuse les chemins interdits (donnees client, fichiers de secrets) dans un depot.

Confronte tous les chemins de l'historique (merges compris) et de l'arbre courant
aux motifs des hooks interdire-sorties-amnesia et interdire-fichiers-secrets de
.pre-commit-config.yaml : la CI applique ainsi cote serveur les memes regles que
les hooks locaux, que contourne un git commit --no-verify.

    python scripts/verifier_chemins.py [--depot CHEMIN]

Les chemins sont lus separes par NUL (-z) : sans cela, git met entre guillemets et
echappe les noms accentues (« Rapport-Societe.pdf » avec accents), et les motifs
ancres ne les reconnaitraient plus.
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

import yaml

RACINE = Path(__file__).resolve().parent.parent
HOOKS = ("interdire-sorties-amnesia", "interdire-fichiers-secrets")


def motifs() -> dict[str, tuple[re.Pattern[str], re.Pattern[str] | None]]:
    config = yaml.safe_load((RACINE / ".pre-commit-config.yaml").read_text("utf-8"))
    trouves = {}
    for depot in config["repos"]:
        for hook in depot["hooks"]:
            if hook["id"] in HOOKS:
                exclusion = hook.get("exclude")
                trouves[hook["id"]] = (
                    re.compile(hook["files"]),
                    re.compile(exclusion) if exclusion else None,
                )
    manquants = set(HOOKS) - set(trouves)
    if manquants:
        raise SystemExit(f"hooks introuvables : {', '.join(sorted(manquants))}")
    return trouves


def _git(depot: Path, *args: str) -> list[str]:
    sortie = subprocess.run(  # noqa: S603 - git et arguments constants, sans shell
        ["git", "-C", str(depot), *args],  # noqa: S607 - git du PATH, comme la CI
        check=True,
        capture_output=True,
    ).stdout
    return [os.fsdecode(c) for c in sortie.split(b"\0") if c]


def chemins_du_depot(depot: Path) -> set[str]:
    # -m : un fichier ajoute dans un commit de fusion n'apparait pas sans lui
    historique = _git(depot, "log", "--all", "-m", "--name-only", "-z", "--format=")
    arbre = _git(depot, "ls-tree", "-r", "--name-only", "-z", "HEAD")
    return set(historique) | set(arbre)


def interdits(chemins: set[str]) -> list[tuple[str, str]]:
    regles = motifs()
    refus = []
    for chemin in sorted(chemins):
        for hook_id, (fichiers, exclusion) in regles.items():
            if fichiers.search(chemin) and not (exclusion and exclusion.search(chemin)):
                refus.append((hook_id, chemin))
    return refus


def _commande_workflow(texte: str) -> str:
    # un nom de fichier ne doit pas pouvoir injecter de commande de workflow
    return texte.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--depot", type=Path, default=RACINE)
    args = parser.parse_args()
    chemins = chemins_du_depot(args.depot)
    if not chemins:
        print("::error::aucun chemin trouve : verification impossible")  # noqa: T201
        return 1
    refus = interdits(chemins)
    for hook_id, chemin in refus:
        print(f"::error::{hook_id} : {_commande_workflow(chemin)}")  # noqa: T201
    print(f"{len(chemins)} chemins verifies, {len(refus)} interdits")  # noqa: T201
    return 1 if refus else 0


if __name__ == "__main__":
    sys.exit(main())
