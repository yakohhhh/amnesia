"""Interface en ligne de commande d'amnesia."""

from __future__ import annotations

import argparse
import codecs
import io
import logging
import sys
from pathlib import Path

from . import __version__
from .checks import REGISTRY, CheckMeta, default_checks
from .log import FORMATS, setup_logging
from .report import schema_text
from .target import FORMES, Target, TargetError

logger = logging.getLogger(__name__)


def _options_journal(defauts: bool) -> argparse.ArgumentParser:
    """Options de journalisation, acceptées avant comme après la sous-commande.

    Dans la copie attachée aux sous-commandes (defauts=False), default=SUPPRESS :
    sinon la valeur par défaut de la sous-commande écraserait celle passée avant,
    et « amnesia -v audit » donnerait une verbosité nulle.
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
        help="copie du journal dans un fichier, créé en 0600",
    )
    g.add_argument(
        "--log-format",
        choices=FORMATS,
        default=defaut("text"),
        help="text (défaut) ou json : une ligne JSON par entrée",
    )
    return p


# gestionnaires d'erreurs qui levent UnicodeEncodeError sur un caractere absent
# de la page de code ou sur un surrogate isole (surrogateescape ne couvre que
# U+DC80..U+DCFF) ; les autres (backslashreplace de stderr...) sont gardes
_ERREURS_FATALES = frozenset({"strict", "surrogateescape", "surrogatepass"})


def _proteger_sorties() -> None:
    """Empêche stdout et stderr de planter sur un caractère impossible à encoder.

    Sous Windows avant Python 3.15, une sortie redirigée est encodée dans la page
    ANSI (cp1252) ou OEM (cp850) : « → » ou « ’ » y lèveraient UnicodeEncodeError
    et y deviennent « ? ». Même en UTF-8, un argument d'argv contenant un octet
    non UTF-8 (décodé en surrogate) ferait planter print() : il s'écrit « \\udcff ».
    """
    for flux in (sys.stdout, sys.stderr):
        # None sous pythonw, ou flux remplace par un objet sans reconfigure()
        if isinstance(flux, io.TextIOWrapper) and flux.errors in _ERREURS_FATALES:
            # en UTF-8 seuls les surrogates echouent : backslashreplace garde la
            # valeur de l'octet d'origine, utile a l'analyste
            utf8 = codecs.lookup(flux.encoding).name == "utf-8"
            flux.reconfigure(errors="backslashreplace" if utf8 else "replace")


def _cible(valeur: str) -> Target:
    """Type argparse de --target : un refus devient une erreur d'usage (code 2)."""
    try:
        return Target.parse(valeur)
    except TargetError as exc:
        # ArgumentTypeError : argparse affiche ce message et non la saisie brute
        raise argparse.ArgumentTypeError(str(exc)) from None


ETATS = {True: "implémenté", False: "à implémenter"}


def _lister_checks(metas: list[CheckMeta]) -> None:
    """Une ligne par check : id, domaine, état et titre, en colonnes alignées."""
    if not metas:
        return
    largeur_id = max(len(m.id) for m in metas)
    largeur_domaine = max(len(m.domain.value) for m in metas)
    largeur_etat = max(len(e) for e in ETATS.values())
    for m in metas:
        print(
            f"{m.id:<{largeur_id}}  {m.domain.value:<{largeur_domaine}}  "
            f"{ETATS[m.implemented]:<{largeur_etat}}  {m.title}"
        )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="amnesia",
        description=(
            "Audit de forensic readiness : liste les questions d'enquête "
            "auxquelles ton SI ne pourra PAS répondre le jour de l'incident."
        ),
        parents=[_options_journal(defauts=True)],
    )
    p.add_argument("--version", action="version", version=f"amnesia {__version__}")
    sub = p.add_subparsers(dest="cmd")
    journal = _options_journal(defauts=False)

    a = sub.add_parser(
        "audit", parents=[journal], help="Lance les checks et liste les angles morts"
    )
    a.add_argument(
        "--target", default="localhost", type=_cible, help=f"cible : {FORMES}"
    )
    a.add_argument("--out", default="amnesia-report.json", help="rapport de sortie")

    sub.add_parser(
        "list-checks", parents=[journal], help="Liste les checks disponibles"
    )
    sub.add_parser(
        "schema",
        parents=[journal],
        help="Affiche le JSON Schema du rapport (docs/format-rapport.md)",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    _proteger_sorties()
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

    if args.cmd == "list-checks":
        _lister_checks(REGISTRY.metas())
        return 0

    if args.cmd == "schema":
        # texte embarque tel quel : il finit deja par un saut de ligne
        print(schema_text(), end="")
        return 0

    if args.cmd == "audit":
        # instances neuves : aucun etat ne passe d'un audit a l'autre
        checks = default_checks()
        print(f"[stub] audit de {args.target.id} → {args.out}")
        print(
            f"[stub] {len(checks)} checks enregistrés. "
            "Implémente leur evaluate() : src/amnesia/checks/"
        )
        for c in checks:
            print(f"  - {c.id}: {c.title}")
        return 0

    build_parser().print_help()
    return 2
