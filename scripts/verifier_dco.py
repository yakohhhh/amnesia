# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Exige le Signed-off-by de son auteur sur chaque commit d'une PR (DCO).

Chaque commit de TETE absent de BASE, hors commits de fusion, doit porter dans
ses trailers une ligne « Signed-off-by: Nom <courriel> » dont le courriel est
celui de l'auteur du commit (casse ignoree) : c'est l'attestation du Developer
Certificate of Origin (https://developercertificate.org/), que pose
git commit -s. Politique : section « Licence des contributions » de
CONTRIBUTING.md ; decision : docs/adr/0001-modele-de-licence.md.

    python scripts/verifier_dco.py BASE TETE [--depot CHEMIN]

- Seuls les trailers comptent (dernier paragraphe du message, lu par git) : une
  ligne Signed-off-by au milieu du corps n'est pas une signature.
- Les commits de fusion sont ignores, comme le fait l'application DCO de GitHub :
  le bouton « Update branch » en cree sans Signed-off-by.
- Une plage sans aucun commit a verifier est une erreur : elle trahit une BASE
  ou une TETE fausse et ne doit pas passer pour un succes.

Nom, courriel et trailers viennent du contributeur : un champ par ligne (git
n'admet aucun saut de ligne dans un nom ou un courriel), et neutralises avant
d'etre ecrits dans une commande de workflow (::error::).
"""

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
# nom, courriel, puis un Signed-off-by par ligne (unfold : valeur sur une ligne)
FORMAT = "%an%n%ae%n%(trailers:key=Signed-off-by,valueonly,unfold)"
SIGNATURE = re.compile(r"(?P<nom>[^<>]*?\S)\s*<(?P<courriel>[^<>\s]+)>")
GUIDE = "CONTRIBUTING.md, section « Licence des contributions »"


@dataclass(frozen=True)
class Commit:
    sha: str
    auteur: str
    courriel: str
    signatures: tuple[str, ...]


def _git(depot: Path, *args: str) -> str:
    sortie = subprocess.run(  # noqa: S603 - git et options constantes, sans shell
        ["git", "-C", str(depot), *args],  # noqa: S607 - git du PATH, comme la CI
        check=True,
        capture_output=True,
    ).stdout
    return sortie.decode("utf-8", errors="replace")


def commits_a_verifier(depot: Path, base: str, tete: str) -> list[Commit]:
    """Commits hors fusion de *tete* absents de *base*, du plus ancien au dernier."""
    # --end-of-options : BASE et TETE ne peuvent pas etre lues comme des options
    plage = ("--end-of-options", tete, f"^{base}", "--")
    shas = _git(depot, "rev-list", "--no-merges", "--reverse", *plage).split()
    commits = []
    for sha in shas:
        auteur, courriel, *signatures = _git(
            depot, "log", "-1", f"--format={FORMAT}", sha, "--"
        ).splitlines()
        commits.append(
            Commit(sha, auteur, courriel, tuple(s.strip() for s in signatures if s))
        )
    return commits


def signe_par_son_auteur(commit: Commit) -> bool:
    for signature in commit.signatures:
        trouvee = SIGNATURE.fullmatch(signature)
        if trouvee and trouvee["courriel"].casefold() == commit.courriel.casefold():
            return True
    return False


def _commande_workflow(texte: str) -> str:
    # un nom ou un trailer ne doit pas pouvoir injecter de commande de workflow
    return texte.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("base", help="branche cible de la PR (origin/main)")
    parser.add_argument("tete", help="dernier commit de la PR")
    parser.add_argument("--depot", type=Path, default=RACINE)
    args = parser.parse_args()
    try:
        commits = commits_a_verifier(args.depot, args.base, args.tete)
    except subprocess.CalledProcessError as erreur:
        message = erreur.stderr.decode("utf-8", errors="replace").strip()
        print(f"::error::git a echoue : {_commande_workflow(message)}")  # noqa: T201
        return 1
    if not commits:
        plage = _commande_workflow(f"{args.base}..{args.tete}")
        print(f"::error::aucun commit a verifier dans {plage}")  # noqa: T201
        return 1
    refus = [c for c in commits if not signe_par_son_auteur(c)]
    for commit in refus:
        identite = _commande_workflow(f"{commit.auteur} <{commit.courriel}>")
        print(  # noqa: T201
            f"::error::commit {commit.sha[:12]} sans « Signed-off-by: {identite} » "
            f"(git commit -s ; voir {GUIDE})"
        )
    print(f"{len(commits)} commits verifies, {len(refus)} sans DCO")  # noqa: T201
    return 1 if refus else 0


if __name__ == "__main__":
    sys.exit(main())
