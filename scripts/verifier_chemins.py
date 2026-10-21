"""Refuse les chemins interdits (donnees client, fichiers de secrets).

Lit une liste de chemins sur l'entree standard (un par ligne) et les confronte
aux motifs des hooks interdire-sorties-amnesia et interdire-fichiers-secrets de
.pre-commit-config.yaml : la CI applique ainsi cote serveur les memes regles que
les hooks locaux, que contourne un git commit --no-verify.

    git log --all --name-only --format= | sort -u | python scripts/verifier_chemins.py
"""

import re
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


def interdits(chemins: list[str]) -> list[tuple[str, str]]:
    regles = motifs()
    refus = []
    for chemin in chemins:
        for hook_id, (fichiers, exclusion) in regles.items():
            if fichiers.search(chemin) and not (exclusion and exclusion.search(chemin)):
                refus.append((hook_id, chemin))
    return refus


def main() -> int:
    chemins = [ligne.strip() for ligne in sys.stdin if ligne.strip()]
    refus = interdits(chemins)
    for hook_id, chemin in refus:
        print(f"::error::{hook_id} : {chemin}")  # noqa: T201 - sortie du script CI
    print(f"{len(chemins)} chemins verifies, {len(refus)} interdits")  # noqa: T201
    return 1 if refus else 0


if __name__ == "__main__":
    raise SystemExit(main())
