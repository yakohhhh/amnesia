"""Interface en ligne de commande d'amnesia.

Codes de sortie : ``amnesia.exitcodes`` ; ``main()`` ne renvoie que ceux-là
(argparse sort lui-même en 2 sur une erreur d'usage).
"""

from __future__ import annotations

import argparse
import codecs
import io
import logging
import os
import sys
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .checks import REGISTRY, CheckMeta, default_checks
from .checks.base import ErrorInfo, assainir
from .exitcodes import (
    DEFAULT_FAIL_ON,
    FAIL_ON,
    FATAL,
    INTERRUPTED,
    OK,
    USAGE,
    exit_code,
    table_text,
)
from .facts import Collector, Fact, FactSet, LocalCollector, UnavailableReason
from .log import FORMATS, setup_logging
from .render import (
    GROUP_BY,
    RENDERERS,
    SEVERITIES,
    RenderOptions,
    ReportError,
    color_enabled,
    load_report,
    render_report,
)
from .report import build_report, dumps_report, schema_bytes, schema_text
from .runner import run_audit
from .target import FORMES, Target, TargetError, Transport

logger = logging.getLogger(__name__)

# rapport d'entree illisible ou refuse (amnesia render) : code fatal
CODE_RAPPORT_ILLISIBLE = FATAL

# --out - : le JSON va sur stdout, le rendu texte sur stderr
SORTIE_STANDARD = "-"

DEFAULT_OUT = "amnesia-report.json"
"""Rapport par défaut, relatif au répertoire courant (emplacement définitif : #25)."""

FORMATS_SORTIE = ("text", "json")
"""Ce que ``amnesia audit`` écrit sur stdout : rendu texte ou le rapport JSON."""


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


def _ecrire_utf8(octets: bytes, texte: str) -> None:
    """Écrit un document JSON sur stdout, octet pour octet, en UTF-8.

    JSON s'échange en UTF-8 (RFC 8259) : sous Windows avant Python 3.15, une
    sortie redirigée en mode texte serait encodée en cp1252 et ses fins de ligne
    en CRLF. Les octets passent donc par ``sys.stdout.buffer`` ; sans tampon
    (flux remplacé, pythonw), repli sur ``print()`` de ``texte``.
    """
    tampon = getattr(sys.stdout, "buffer", None)
    if tampon is None:
        # texte tel quel : il finit deja par un saut de ligne
        print(texte, end="")
        return
    sys.stdout.flush()
    tampon.write(octets)
    tampon.flush()


def _ecrire_schema() -> None:
    """Écrit le JSON Schema embarqué sur stdout, en UTF-8."""
    _ecrire_utf8(schema_bytes(), schema_text())


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


def _rendre(args: argparse.Namespace) -> int:
    """Commande render : rapport JSON vers stdout, en texte ou en Markdown.

    Sans ``--fail-on``, un rendu réussi vaut 0 : la commande affiche. Avec, elle
    applique la table de ``amnesia audit`` au rapport (1, 3), pour une CI qui
    travaille sur un JSON archivé.
    """
    # repli ASCII (-> pour →) d'apres l'encodage reel de stdout (cp1252...)
    encodage = getattr(sys.stdout, "encoding", None) or "utf-8"
    couleur = args.format == "text" and color_enabled(
        sys.stdout, os.environ, no_color=args.no_color
    )
    options = RenderOptions(
        group_by=args.group_by,
        min_severity=args.min_severity,
        color=couleur,
        encoding=encodage,
    )
    try:
        rapport = load_report(args.report)
        texte = render_report(rapport, args.format, options)
    except ReportError as exc:
        logger.error("rapport %s refusé : %s", args.report, exc)
        return CODE_RAPPORT_ILLISIBLE
    sys.stdout.write(texte)
    if args.fail_on is None:
        return OK
    # render_report() a valide le rapport : gaps[].severity et run.complete
    return exit_code(rapport, args.fail_on)


class _CollecteurAbsent:
    """Collecteur des transports dont la collecte n'existe pas encore.

    WinRM (#63) et bundle (#52) : chaque fait demandé est rendu
    ``unavailable`` / ``not_collected``, et les checks qui en dépendent sont
    ``skipped`` (audit incomplet, code 3). Aucune connexion n'est tentée.
    """

    def __init__(self, transport: Transport) -> None:
        self.source = f"collecteur {transport.value} non implémenté"

    def collect(
        self, target: Target, names: Iterable[str], *, timeout: float
    ) -> FactSet:
        instant = datetime.now(UTC)
        return FactSet(
            Fact.unavailable(
                nom,
                UnavailableReason.NOT_COLLECTED,
                source=self.source,
                collected_at=instant,
            )
            for nom in names
        )


def _collecteur(target: Target) -> Collector:
    if target.transport is Transport.LOCAL:
        return LocalCollector()
    return _CollecteurAbsent(target.transport)


def _ecrire_rapport(chemin: Path, octets: bytes, *, overwrite: bool) -> bool:
    """Écrit le rapport dans ``chemin`` ; faux (et journal) si c'est impossible.

    Le fichier est toujours créé en mode ``x`` (``O_EXCL``), qui ne suit jamais
    un lien, symbolique ou physique, planté à cet emplacement. Sans
    ``overwrite``, un fichier existant n'est donc jamais écrasé. Avec, l'entrée
    présente est d'abord retirée (un lien est retiré, sa cible reste intacte),
    puis le rapport est créé à sa place ; une entrée réapparue entre les deux
    fait échouer la création : rien n'est écrasé. Permissions, écriture
    atomique et emplacement par défaut : #25.
    """
    try:
        if overwrite:
            chemin.unlink(missing_ok=True)
        with chemin.open("xb") as fichier:
            fichier.write(octets)
    except OSError as exc:
        logger.error(
            "rapport %s : écriture impossible : %s", chemin, exc.strerror or exc
        )
        return False
    logger.info("rapport écrit : %s", chemin)
    return True


def _rendu_texte(rapport: dict[str, Any], flux: Any, *, no_color: bool) -> str:
    encodage = getattr(flux, "encoding", None) or "utf-8"
    options = RenderOptions(
        color=color_enabled(flux, os.environ, no_color=no_color), encoding=encodage
    )
    return render_report(rapport, "text", options)


def _auditer(
    args: argparse.Namespace, argv: Sequence[str], parser: argparse.ArgumentParser
) -> int:
    """Commande audit : checks du registre → rapport JSON → rendu texte.

    ``--out PATH`` : le JSON va dans le fichier et stdout reçoit ``--format``
    (rendu texte, ou le JSON). ``--out -`` : le JSON va sur stdout et le rendu
    texte sur stderr (rien d'autre avec ``--format json``).
    """
    vers_stdout = args.out == SORTIE_STANDARD
    chemin = None if vers_stdout else Path(args.out)
    # le chemin vient de la ligne de commande : neutralise avant tout echo
    chemin_affiche = assainir(str(chemin)) if chemin is not None else ""
    # avant l'audit : perdre un audit entier pour un fichier deja la serait pire
    if chemin is not None and not args.overwrite and chemin.exists():
        parser.error(
            f"--out {chemin_affiche} : existe déjà (--overwrite pour l'écraser)"
        )
    # instances neuves : aucun etat ne passe d'un audit a l'autre
    checks = default_checks()
    audit = run_audit(checks, args.target, _collecteur(args.target), debug=args.debug)
    rapport = build_report(audit, argv=argv)
    texte_json = dumps_report(rapport)
    octets = texte_json.encode("utf-8")
    if chemin is None:
        _ecrire_utf8(octets, texte_json)
        flux_texte = sys.stderr
    else:
        if not _ecrire_rapport(chemin, octets, overwrite=args.overwrite):
            return FATAL
        flux_texte = sys.stdout
        if args.format == "json":
            _ecrire_utf8(octets, texte_json)
    if args.format == "text":
        flux_texte.write(_rendu_texte(rapport, flux_texte, no_color=args.no_color))
        if chemin is not None:
            flux_texte.write(f"Rapport JSON : {chemin_affiche}\n")
        flux_texte.flush()
    if audit.interrupted:
        return INTERRUPTED
    return exit_code(rapport, args.fail_on)


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
        "audit",
        parents=[journal],
        help="Lance les checks et liste les angles morts",
        description=(
            "Lance les checks sur la cible, écrit le rapport JSON (--out) et "
            "affiche les questions d'enquête sans réponse."
        ),
        epilog=table_text(),
        # l'epilogue est une table : ses sauts de ligne sont conserves
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    a.add_argument(
        "--target", default="localhost", type=_cible, help=f"cible : {FORMES}"
    )
    a.add_argument(
        "--out",
        default=DEFAULT_OUT,
        metavar="PATH|-",
        help=(
            f"rapport JSON (défaut : {DEFAULT_OUT}) ; « - » : JSON sur stdout, "
            "rendu texte sur stderr"
        ),
    )
    a.add_argument(
        "--overwrite",
        action="store_true",
        help="écrase un rapport existant (refusé sinon)",
    )
    a.add_argument(
        "--format",
        choices=FORMATS_SORTIE,
        default="text",
        help="sortie sur stdout : text (défaut, rendu lisible) ou json (le rapport)",
    )
    a.add_argument(
        "--no-color",
        action="store_true",
        help="sans couleurs ANSI (aussi avec NO_COLOR ou hors terminal)",
    )
    a.add_argument(
        "--fail-on",
        choices=FAIL_ON,
        default=DEFAULT_FAIL_ON,
        help=(
            f"code 1 dès un angle mort de cette sévérité ou plus (défaut : "
            f"{DEFAULT_FAIL_ON}) ; never ne neutralise que le code 1"
        ),
    )

    sub.add_parser(
        "list-checks", parents=[journal], help="Liste les checks disponibles"
    )
    r = sub.add_parser(
        "render",
        parents=[journal],
        help="Rend un rapport JSON : les questions d'enquête sans réponse",
        description=(
            "Rend un rapport JSON produit par « amnesia audit », sans refaire "
            "l'audit. Rapport illisible ou de format non pris en charge : code "
            f"{CODE_RAPPORT_ILLISIBLE}."
        ),
    )
    r.add_argument("report", type=Path, metavar="RAPPORT", help="rapport JSON")
    r.add_argument(
        "--format",
        choices=tuple(RENDERERS),
        default="text",
        help="text (défaut, terminal) ou md (Markdown GFM)",
    )
    r.add_argument(
        "--group-by",
        choices=GROUP_BY,
        default="severity",
        help="regroupement des angles morts (défaut : severity)",
    )
    r.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        default="info",
        help="masque les angles morts moins graves (ils restent comptés)",
    )
    r.add_argument(
        "--no-color",
        action="store_true",
        help="sans couleurs ANSI (aussi avec NO_COLOR ou hors terminal)",
    )
    r.add_argument(
        "--fail-on",
        choices=FAIL_ON,
        default=None,
        help="applique les codes de sortie de « amnesia audit » au rapport (1, 3)",
    )

    sub.add_parser(
        "schema",
        parents=[journal],
        help="Affiche le JSON Schema du rapport (docs/format-rapport.md)",
    )
    return p


def _executer(
    args: argparse.Namespace, argv: Sequence[str], parser: argparse.ArgumentParser
) -> int:
    if args.cmd == "list-checks":
        _lister_checks(REGISTRY.metas())
        return OK

    if args.cmd == "render":
        return _rendre(args)

    if args.cmd == "schema":
        _ecrire_schema()
        return OK

    if args.cmd == "audit":
        return _auditer(args, argv, parser)

    # sans sous-commande : aide sur stderr, stdout reste vide (JSON avec --out -)
    parser.print_help(sys.stderr)
    return USAGE


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée de la commande ``amnesia`` ; rend un code de ``exitcodes``."""
    _proteger_sorties()
    parser = build_parser()
    arguments = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(arguments)
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

    try:
        return _executer(args, arguments, parser)
    except KeyboardInterrupt:
        # hors des checks (run_audit rend un audit partiel) : ecriture, rendu
        logger.warning("interrompu")
        return INTERRUPTED
    except Exception as exc:
        # jamais de traceback brut (code 1 de Python = angle mort) ; message
        # caviarde comme un resultat error, trace seulement avec --debug
        info = ErrorInfo.from_exception(exc)
        logger.error("erreur fatale : %s : %s", info.type, info.message)
        if args.debug:
            logger.debug("trace de l'erreur fatale", exc_info=exc)
        return FATAL
