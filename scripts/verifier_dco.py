# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Exige le Signed-off-by de son auteur sur chaque commit d'une PR (DCO).

Chaque commit de TETE absent de BASE, hors fusions propres, doit porter dans
ses trailers une ligne « Signed-off-by: Nom <courriel> » dont le courriel est
celui de l'auteur du commit (casse ignoree) : c'est l'attestation du Developer
Certificate of Origin (https://developercertificate.org/), que pose
git commit -s. Politique : section « Licence des contributions » de
CONTRIBUTING.md ; decision : docs/adr/0001-modele-de-licence.md.

    python scripts/verifier_dco.py BASE TETE [--depot CHEMIN]

- Seuls les trailers comptent (dernier paragraphe du message, lu par git) : une
  ligne Signed-off-by au milieu du corps n'est pas une signature.
- Seules les fusions propres sont ignorees : deux parents, et un arbre identique
  a celui que git calcule seul pour leur fusion (git merge-tree, git >= 2.38).
  Le bouton « Update branch » en cree sans Signed-off-by, et elles n'apportent
  rien que leurs parents n'aient deja, eux-memes verifies ou deja sur BASE. Une
  fusion qui ajoute du contenu, resout un conflit a la main ou a plus de deux
  parents est verifiee comme un commit ordinaire.
- Une plage sans aucun commit a verifier est une erreur : elle trahit une BASE
  ou une TETE fausse et ne doit pas passer pour un succes.

Nom, courriel et trailers viennent du contributeur : un champ par ligne, decoupe
sur le seul saut de ligne LF (une ligne d'en-tete de commit ou un trailer deplie
n'en contient aucun, alors que str.splitlines() coupe aussi sur U+2028, U+001C,
U+0085...), et neutralises avant d'etre ecrits dans une commande de workflow
(::error::).
"""

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
# arbre, parents, nom, courriel, puis un Signed-off-by par ligne (unfold : valeur
# sur une ligne)
FORMAT = "%T%n%P%n%an%n%ae%n%(trailers:key=Signed-off-by,valueonly,unfold)"
SIGNATURE = re.compile(r"(?P<nom>[^<>]*?\S)\s*<(?P<courriel>[^<>\s]+)>")
GUIDE = "CONTRIBUTING.md, section « Licence des contributions »"


@dataclass(frozen=True)
class Commit:
    sha: str
    auteur: str
    courriel: str
    signatures: tuple[str, ...]


def _executer(
    depot: Path, *args: str, codes: tuple[int, ...] = (0,)
) -> subprocess.CompletedProcess[bytes]:
    """Lance git ; CalledProcessError si son code de sortie n'est pas dans *codes*."""
    commande = ["git", "-C", str(depot), *args]
    resultat = subprocess.run(  # noqa: S603 - git et options constantes, sans shell
        commande,  # git du PATH, comme la CI
        check=False,
        capture_output=True,
    )
    if resultat.returncode not in codes:
        raise subprocess.CalledProcessError(
            resultat.returncode, commande, resultat.stdout, resultat.stderr
        )
    return resultat


def _git(depot: Path, *args: str) -> str:
    return _executer(depot, *args).stdout.decode("utf-8", errors="replace")


def fusion_propre(depot: Path, arbre: str, parents: list[str]) -> bool:
    """Vrai si *arbre* est exactement la fusion automatique de deux *parents*."""
    if len(parents) != 2:
        return False
    # code 1 : conflit, resolu a la main par l'auteur de la fusion, donc a verifier
    resultat = _executer(
        depot, "merge-tree", "--write-tree", "--no-messages", *parents, codes=(0, 1)
    )
    calcule = resultat.stdout.decode("ascii", errors="replace").strip()
    return resultat.returncode == 0 and calcule == arbre


def commits_a_verifier(depot: Path, base: str, tete: str) -> list[Commit]:
    """Commits de *tete* absents de *base*, hors fusions propres, du plus ancien."""
    # --end-of-options : BASE et TETE ne peuvent pas etre lues comme des options
    plage = ("--end-of-options", tete, f"^{base}", "--")
    shas = _git(depot, "rev-list", "--reverse", *plage).split()
    commits = []
    for sha in shas:
        arbre, parents, auteur, courriel, *signatures = _git(
            depot, "log", "-1", f"--format={FORMAT}", sha, "--"
        ).split("\n")
        if fusion_propre(depot, arbre, parents.split()):
            continue
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
