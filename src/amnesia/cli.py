"""Interface en ligne de commande d'amnesia."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .checks import default_checks
from .target import FORMES, Target, TargetError


def _cible(valeur: str) -> Target:
    """Type argparse de --target : un refus devient une erreur d'usage (code 2)."""
    try:
        return Target.parse(valeur)
    except TargetError as exc:
        # ArgumentTypeError : argparse affiche ce message et non la saisie brute
        raise argparse.ArgumentTypeError(str(exc)) from None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="amnesia",
        description=(
            "Audit de forensic readiness: liste les questions d'enquete "
            "auxquelles ton SI ne pourra PAS repondre le jour de l'incident."
        ),
    )
    p.add_argument("--version", action="version", version=f"amnesia {__version__}")
    sub = p.add_subparsers(dest="cmd")

    a = sub.add_parser("audit", help="Lance les checks et liste les angles morts")
    a.add_argument(
        "--target", default="localhost", type=_cible, help=f"cible : {FORMES}"
    )
    a.add_argument("--out", default="amnesia-report.json", help="rapport de sortie")

    sub.add_parser("list-checks", help="Liste les checks disponibles")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    checks = default_checks()

    if args.cmd == "list-checks":
        for c in checks:
            print(f"{c.id:24} {c.title}")
        return 0

    if args.cmd == "audit":
        print(f"[stub] audit de {args.target.id} -> {args.out}")
        print(
            f"[stub] {len(checks)} checks enregistres. "
            "Implemente leur run(): src/amnesia/checks/"
        )
        for c in checks:
            print(f"  - {c.id}: {c.title}")
        return 0

    build_parser().print_help()
    return 2
