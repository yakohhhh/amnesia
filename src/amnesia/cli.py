"""Interface en ligne de commande d'amnesia."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import __version__
from .checks import default_checks
from .log import FORMATS, setup_logging

logger = logging.getLogger(__name__)


def _options_journal(defauts: bool) -> argparse.ArgumentParser:
    """Options de journalisation, acceptees avant comme apres la sous-commande.

    Dans la copie attachee aux sous-commandes (defauts=False), default=SUPPRESS :
    sinon la valeur par defaut de la sous-commande ecraserait celle passee avant,
    et « amnesia -v audit » donnerait une verbosite nulle.
    """

    def defaut(valeur: object) -> object:
        return valeur if defauts else argparse.SUPPRESS

    p = argparse.ArgumentParser(add_help=False)
    g = p.add_argument_group("journalisation (diagnostics sur stderr)")
    g.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=defaut(0),
        help="diagnostics INFO ; -vv : DEBUG (amnesia seulement)",
    )
    g.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=defaut(False),
        help="erreurs seulement (incompatible avec -v et --debug)",
    )
    g.add_argument(
        "--debug",
        action="store_true",
        default=defaut(False),
        help="DEBUG et tracebacks, jamais les variables locales",
    )
    g.add_argument(
        "--log-file",
        type=Path,
        default=defaut(None),
        metavar="PATH",
        help="copie du journal dans un fichier, cree en 0600",
    )
    g.add_argument(
        "--log-format",
        choices=FORMATS,
        default=defaut("text"),
        help="text (defaut) ou json : une ligne JSON par entree",
    )
    return p


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="amnesia",
        description=(
            "Audit de forensic readiness: liste les questions d'enquete "
            "auxquelles ton SI ne pourra PAS repondre le jour de l'incident."
        ),
        parents=[_options_journal(defauts=True)],
    )
    p.add_argument("--version", action="version", version=f"amnesia {__version__}")
    sub = p.add_subparsers(dest="cmd")
    journal = _options_journal(defauts=False)

    a = sub.add_parser(
        "audit", parents=[journal], help="Lance les checks et liste les angles morts"
    )
    a.add_argument("--target", default="localhost", help="hote / tenant a auditer")
    a.add_argument("--out", default="amnesia-report.json", help="rapport de sortie")

    sub.add_parser(
        "list-checks", parents=[journal], help="Liste les checks disponibles"
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    # verifie apres coup : -q et -v peuvent etre de part et d'autre de la sous-commande
    if args.quiet and (args.verbose or args.debug):
        parser.error("-q est incompatible avec -v et --debug")
    try:
        setup_logging(
            verbosity=-1 if args.quiet else args.verbose,
            debug=args.debug,
            log_file=args.log_file,
            log_format=args.log_format,
        )
    except OSError as exc:
        parser.error(f"--log-file {args.log_file} : {exc.strerror or exc}")
    logger.info("amnesia %s : commande %s", __version__, args.cmd)
    checks = default_checks()

    if args.cmd == "list-checks":
        for c in checks:
            print(f"{c.id:24} {c.title}")
        return 0

    if args.cmd == "audit":
        print(f"[stub] audit de {args.target} -> {args.out}")
        print(
            f"[stub] {len(checks)} checks enregistres. "
            "Implemente leur run(): src/amnesia/checks/"
        )
        for c in checks:
            print(f"  - {c.id}: {c.title}")
        return 0

    build_parser().print_help()
    return 2
