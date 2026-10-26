"""Faux gh pour les tests de scripts/sync_github.py : aucun appel reseau.

L'etat du depot simule (labels, milestones, issues) est lu et reecrit dans le
fichier JSON FAUX_GH_ETAT ; chaque appel est journalise dans FAUX_GH_JOURNAL.
FAUX_GH_ECHEC simule une panne : « auth » (gh non connecte, code 4 comme gh) ou
« 422 » (toute ecriture refusee, statut sur stderr et corps sur stdout comme gh).
"""

import json
import os
import sys
from pathlib import Path
from urllib.parse import parse_qsl, unquote


def _sortir(code: int, stderr: str = "", stdout: object = None) -> None:
    if stdout is not None:
        sys.stdout.write(json.dumps(stdout))
    sys.stderr.write(stderr)
    sys.exit(code)


def _analyser(args: list[str]) -> tuple[str, str, dict, dict | None]:
    methode, chemin, champs, corps = "GET", "", {}, None
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "-X":
            methode, i = args[i + 1], i + 1
        elif arg == "-f":
            cle, _, valeur = args[i + 1].partition("=")
            champs[cle], i = valeur, i + 1
        elif arg == "--input":
            corps, i = json.loads(sys.stdin.read()), i + 1
        elif arg not in {"--paginate", "--slurp"}:
            chemin = arg
        i += 1
    chemin, _, requete = chemin.partition("?")
    champs.update(parse_qsl(requete))
    return methode, chemin, champs, corps


def _api(etat: dict, methode: str, chemin: str, champs: dict, corps: dict | None):
    parties = chemin.split("/")[3:]  # repos/proprietaire/depot/...
    labels, milestones = etat["labels"], etat["milestones"]
    if parties == ["labels"] and methode == "GET":
        return [labels]
    if parties == ["labels"] and methode == "POST":
        if any(lb["name"].casefold() == corps["name"].casefold() for lb in labels):
            _sortir(1, "gh: Validation Failed (HTTP 422)\n", {"message": "exists"})
        labels.append(dict(corps))
        return corps
    if parties[0] == "labels" and len(parties) == 2:
        nom = unquote(parties[1])
        label = next((lb for lb in labels if lb["name"] == nom), None)
        if label is None:
            _sortir(1, "gh: Not Found (HTTP 404)\n", {"message": "Not Found"})
        if methode == "DELETE":
            labels.remove(label)
            return None
        label.update(corps)
        label["name"] = label.pop("new_name", label["name"])
        return label
    if parties == ["milestones"] and methode == "GET":
        return [milestones]
    if parties == ["milestones"] and methode == "POST":
        numero = max((m["number"] for m in milestones), default=0) + 1
        milestones.append({"number": numero, "state": "open", **corps})
        return milestones[-1]
    if parties[0] == "milestones" and methode == "PATCH":
        milestone = next(m for m in milestones if m["number"] == int(parties[1]))
        milestone.update(corps)
        return milestone
    if parties == ["issues"] and methode == "GET":
        portees = [i for i in etat["issues"] if champs["labels"] in i["labels"]]
        return portees[: int(champs.get("per_page", 30))]
    _sortir(1, f"gh: Not Found (HTTP 404) {methode} {chemin}\n")
    return None


def main() -> None:
    args = sys.argv[1:]
    fichier = Path(os.environ["FAUX_GH_ETAT"])
    etat = json.loads(fichier.read_text(encoding="utf-8"))
    entree, methode = {"args": args}, "GET"
    if args[0] == "api":
        methode, chemin, champs, corps = _analyser(args[1:])
        entree.update(methode=methode, chemin=chemin, corps=corps)
    journal = Path(os.environ["FAUX_GH_JOURNAL"])
    with journal.open("a", encoding="utf-8") as flux:
        flux.write(json.dumps(entree, ensure_ascii=False) + "\n")

    echec = os.environ.get("FAUX_GH_ECHEC")
    if echec == "auth":
        _sortir(4, "To get started with GitHub CLI, please run:  gh auth login\n")
    if args[:2] == ["repo", "view"]:
        _sortir(0, stdout={"nameWithOwner": etat["depot"]})
    if echec == "422" and methode != "GET":
        corps_erreur = {"message": "Validation Failed", "errors": [{"code": "invalid"}]}
        _sortir(1, "gh: Validation Failed (HTTP 422)\n", corps_erreur)
    reponse = _api(etat, methode, chemin, champs, corps)
    fichier.write_text(json.dumps(etat, ensure_ascii=False), encoding="utf-8")
    if reponse is not None:
        sys.stdout.write(json.dumps(reponse))


if __name__ == "__main__":
    main()
