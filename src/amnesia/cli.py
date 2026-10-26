"""Interface en ligne de commande d'amnesia."""

from __future__ import annotations

import argparse
import codecs
import io
import sys

from . import __version__
from .checks import default_checks

# gestionnaires d'erreurs qui levent UnicodeEncodeError sur un caractere absent
# de la page de code ; les autres (backslashreplace de stderr...) sont gardes
_ERREURS_FATALES = frozenset({"strict", "surrogateescape", "surrogatepass"})


def _proteger_sorties() -> None:
    """Remplace par « ? » ce que stdout ou stderr ne savent pas encoder.

    Sous Windows avant Python 3.15, une sortie redirigée est encodée dans la page
    ANSI (cp1252) ou OEM (cp850) : « → » ou « ’ » y lèveraient UnicodeEncodeError.
    """
    for flux in (sys.stdout, sys.stderr):
        # None sous pythonw, ou flux remplace par un objet sans reconfigure()
        if (
            isinstance(flux, io.TextIOWrapper)
            and flux.errors in _ERREURS_FATALES
            and codecs.lookup(flux.encoding).name != "utf-8"
        ):
            flux.reconfigure(errors="replace")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="amnesia",
        description=(
            "Audit de forensic readiness : liste les questions d'enquête "
            "auxquelles ton SI ne pourra PAS répondre le jour de l'incident."
        ),
    )
    p.add_argument("--version", action="version", version=f"amnesia {__version__}")
    sub = p.add_subparsers(dest="cmd")

    a = sub.add_parser("audit", help="Lance les checks et liste les angles morts")
    a.add_argument("--target", default="localhost", help="hôte / tenant à auditer")
    a.add_argument("--out", default="amnesia-report.json", help="rapport de sortie")

    sub.add_parser("list-checks", help="Liste les checks disponibles")
    return p


def main(argv: list[str] | None = None) -> int:
    _proteger_sorties()
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    checks = default_checks()

    if args.cmd == "list-checks":
        for c in checks:
            print(f"{c.id:24} {c.title}")
        return 0

    if args.cmd == "audit":
        print(f"[stub] audit de {args.target} → {args.out}")
        print(
            f"[stub] {len(checks)} checks enregistrés. "
            "Implémente leur run() : src/amnesia/checks/"
        )
        for c in checks:
            print(f"  - {c.id}: {c.title}")
        return 0

    build_parser().print_help()
    return 2
