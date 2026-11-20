# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Interface en ligne de commande d'amnesia.

Codes de sortie : ``amnesia.exitcodes`` ; ``main()`` ne renvoie que ceux-là
(argparse sort lui-même en 2 sur une erreur d'usage).
"""

from __future__ import annotations

import argparse
import codecs
import io
import json
import logging
import os
import sys
import traceback
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .catalog import (
    Catalog,
    CatalogError,
    Question,
    QuestionStatus,
    Source,
    SourceKind,
    Theme,
    UnknownIdError,
    load_catalog,
    verify_registry,
)
from .checks import REGISTRY, CheckMeta, default_checks
from .checks.base import ErrorInfo, assainir
from .config import (
    DEFAULT_FILE,
    LANGS,
    SOURCE_CWD,
    Config,
    ConfigError,
    example_toml,
    load_config,
)
from .exitcodes import (
    DEFAULT_FAIL_ON,
    FAIL_ON,
    FATAL,
    INTERRUPTED,
    OK,
    OUT_OF_SCOPE,
    USAGE,
    exit_code,
    table_text,
)
from .facts import Collector, Fact, FactSet, LocalCollector, UnavailableReason
from .log import FORMATS, redact, setup_logging
from .output import (
    UnsafeDestinationError,
    check_destination,
    default_report_path,
    prepare_default_dir,
    warn_if_not_ignored,
    write_private,
)
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
from .scope import (
    Authorization,
    Basis,
    Confirm,
    Scope,
    ScopeError,
    ScopeRefusal,
    authorize,
    parse_reference,
)
from .secrets import Secret, SecretError, resolve
from .target import FORMES, Target, TargetError, Transport

logger = logging.getLogger(__name__)

# rapport d'entree illisible ou refuse (amnesia render) : code fatal
CODE_RAPPORT_ILLISIBLE = FATAL
# catalogue embarque invalide (amnesia catalog) : code fatal, jamais 1
# (angle mort) ni 2 (usage)
CODE_CATALOGUE_INVALIDE = FATAL

# enabled_by_default d'une source, pour amnesia catalog show
PAR_DEFAUT = {
    True: "journalisé sur une installation par défaut",
    False: "absent d'une installation par défaut",
    None: "non établi",
}
# question « planned » : aucun check n'y contribue encore
SANS_CHECK = "aucun pour l'instant"

# --out - : le JSON va sur stdout, le rendu texte sur stderr
SORTIE_STANDARD = "-"

DEFAULT_OUT = default_report_path().as_posix()
"""Rapport sans ``--out`` : ``amnesia-out/amnesia-report.json``, relatif au
répertoire courant (``amnesia.output``)."""

# refus de --out, avant l'audit comme au moment d'ecrire
EXISTE_DEJA = "existe déjà (--overwrite pour l'écraser)"
MEME_AVEC_OVERWRITE = "même avec --overwrite"

FORMATS_SORTIE = ("text", "json")
"""Ce que ``amnesia audit`` écrit sur stdout : rendu texte ou le rapport JSON."""

ENV_MOT_DE_PASSE_WINRM = "AMNESIA_WINRM_PASSWORD"
"""Variable d'environnement du mot de passe WinRM, retirée dès sa lecture."""

ENTREE_WINRM = "winrm-password"
"""Nom du mot de passe WinRM (messages, entrée du trousseau)."""

TRANSPORTS_A_MOT_DE_PASSE: frozenset[Transport] = frozenset()
"""Transports dont le collecteur exige un mot de passe : s'il n'est désigné par
aucune source, il est demandé au terminal, et l'audit s'arrête sans terminal.
Vide tant qu'aucun collecteur distant n'existe : le collecteur WinRM (#63) y
ajoute son transport selon son mode d'authentification."""


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


def _options_mission() -> argparse.ArgumentParser:
    """Options du fichier de mission, communes à ``audit`` et ``config show``."""
    p = argparse.ArgumentParser(add_help=False)
    g = p.add_argument_group("fichier de mission (modèle : amnesia init)")
    g.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="FICHIER",
        help=(
            f"fichier de mission TOML (défaut : ./{DEFAULT_FILE} s'il existe) ; "
            "aucun secret dedans"
        ),
    )
    g.add_argument(
        "--scope",
        type=Path,
        default=None,
        metavar="FICHIER",
        help=(
            "fichier de périmètre autorisé (TOML, section [scope]), à la place "
            "de la section [scope] du fichier de mission ; une cible hors "
            f"périmètre ou hors période est refusée avant toute collecte (code "
            f"{OUT_OF_SCOPE}, docs/perimetre.md)"
        ),
    )
    g.add_argument(
        "--set",
        action="append",
        default=[],
        dest="surcharges",
        metavar="CLE=VALEUR",
        help=(
            "surcharge une clé du fichier de mission, par ex. "
            "thresholds.security_log_min_retention_days=180 ; répétable"
        ),
    )
    g.add_argument(
        "--lang",
        choices=LANGS,
        default=None,
        help=(
            "langue du livrable ; l'emporte sur report.lang du fichier (les "
            "rendus restent en français pour l'instant)"
        ),
    )
    return p


def _configuration(args: argparse.Namespace, parser: argparse.ArgumentParser) -> Config:
    """Configuration effective : ligne de commande, puis fichier, puis défauts.

    Un fichier illisible, une clé inconnue, une valeur refusée ou une clé au
    nom de secret sont des erreurs d'usage : code 2, sans lancer l'audit.
    """
    surcharges = list(args.surcharges)
    if args.lang is not None:
        # apres --set : l'option dediee l'emporte
        surcharges.append(f"report.lang={args.lang}")
    try:
        config = load_config(args.config, overrides=surcharges, scope_path=args.scope)
    except ConfigError as exc:
        # chemin et cles viennent de l'utilisateur : neutralises avant tout echo
        parser.error(f"configuration : {assainir(str(exc))}")
    if config.source_kind == SOURCE_CWD:
        # personne ne l'a designe : visible sans -v, et inscrit dans le rapport
        logger.warning(
            "fichier de mission %s trouvé dans le répertoire courant et appliqué "
            "sans avoir été désigné : vérifie son contenu (amnesia config show), "
            "ou désigne-le par --config %s",
            config.source,
            config.source,
        )
    elif config.source is not None:
        logger.info("fichier de mission : %s", config.source)
    return config


SANS_VALEUR = "(non renseigné)"
SANS_FICHIER = "aucun (valeurs par défaut)"


def _montrer_configuration(config: Config) -> None:
    """``amnesia config show`` : une ligne par clé, valeur et origine."""
    source = SANS_FICHIER if config.source is None else assainir(str(config.source))
    if config.source_kind == SOURCE_CWD:
        source += " (trouvé dans le répertoire courant, sans --config)"
    print(f"Fichier de mission : {source}")
    lignes = [
        (
            chemin,
            SANS_VALEUR if valeur is None else json.dumps(valeur, ensure_ascii=False),
            origine.value,
        )
        for chemin, valeur, origine in config.rows()
    ]
    largeur_cle = max(len(ligne[0]) for ligne in lignes)
    largeur_valeur = max(len(ligne[1]) for ligne in lignes)
    for chemin, valeur, origine in lignes:
        print(f"{chemin:<{largeur_cle}}  {valeur:<{largeur_valeur}}  {origine}")
    _montrer_perimetre(config.scope)
    # derniere ligne : le perimetre a son propre condensat, affiche avant
    print(f"config_hash : {config.config_hash()}")


SANS_PERIMETRE = (
    "aucun (hors terminal, --authorized-by est obligatoire ; docs/perimetre.md)"
)


def _montrer_perimetre(scope: Scope | None) -> None:
    """``amnesia config show`` : périmètre autorisé déclaré, et son condensat."""
    if scope is None:
        print(f"Périmètre autorisé : {SANS_PERIMETRE}")
        return
    print(f"Périmètre autorisé : {scope.source}")
    lignes = [
        ("scope.mission_id", scope.mission_id),
        ("scope.authorization.reference", scope.authorization_reference),
        ("scope.authorization.date", scope.authorization_date.isoformat()),
        ("scope.authorization.signatory", scope.signatory),
        ("scope.authorization.signatory_role", scope.signatory_role),
        ("scope.valid_from", scope.valid_from.isoformat()),
        ("scope.valid_until", scope.valid_until.isoformat()),
        ("scope.active_tests", scope.active_tests),
    ]
    for sens, regles in (("include", scope.include), ("exclude", scope.exclude)):
        lignes += [
            (f"scope.{sens}.{type_}", valeurs)
            for type_, valeurs in regles.to_dict().items()
            if valeurs
        ]
    largeur = max(len(cle) for cle, _ in lignes)
    for cle, valeur in lignes:
        # textes du fichier : neutralises comme toute valeur affichee
        print(f"{cle:<{largeur}}  {assainir(json.dumps(valeur, ensure_ascii=False))}")
    print(f"scope.sha256 : {scope.sha256()}")


def _reference(valeur: str) -> str:
    """Type argparse de --authorized-by : un refus devient une erreur d'usage."""
    try:
        return parse_reference(valeur)
    except ScopeError as exc:
        # ArgumentTypeError : argparse affiche ce message et non la saisie brute
        raise argparse.ArgumentTypeError(str(exc)) from None


def _terminal_interactif() -> bool:
    """Vrai si l'opérateur peut lire une question (stderr) et y répondre (stdin)."""
    for flux in (sys.stdin, sys.stderr):
        try:
            if flux is None or not flux.isatty():
                return False
        except (AttributeError, ValueError, OSError):
            # flux remplace ou ferme
            return False
    return True


def _saisir_confirmation(target: Target, attendu: str) -> str | None:
    """Fait ressaisir à l'opérateur le nom de la cible ; ``None`` sans saisie.

    La question va sur stderr : stdout peut porter le rapport (``--out -``).
    """
    sys.stderr.write(
        "Aucun périmètre déclaré (--scope FICHIER, ou section [scope] du "
        "fichier de mission).\n"
        f"Cible : {target.id}\n"
        "N'audite que ce qu'une autorisation écrite couvre. Pour confirmer, "
        f"saisis le nom exact de la cible ({attendu}) : "
    )
    sys.stderr.flush()
    try:
        saisie = sys.stdin.readline()
    except (OSError, ValueError):
        return None
    # fin de fichier : rien n'a ete saisi
    return saisie or None


def _confirmation_au_terminal() -> Confirm | None:
    """Saisie de confirmation, ou ``None`` hors terminal (CI, tâche planifiée)."""
    return _saisir_confirmation if _terminal_interactif() else None


def _autoriser(
    args: argparse.Namespace, config: Config, parser: argparse.ArgumentParser
) -> Authorization:
    """Base d'autorisation de l'audit, avant toute collecte ; ``ScopeRefusal`` sinon.

    Avec un périmètre déclaré (section ``[scope]`` ou ``--scope``) : cible et
    période vérifiées par ``amnesia.scope``. Sans périmètre : ``--authorized-by``,
    sinon confirmation au terminal. La décision est journalisée : périmètre,
    ``scope.sha256`` et identifiant de mission (journal d'exécution : #40).
    """
    target: Target = args.target
    reference: str | None = args.authorized_by
    scope = config.scope
    if scope is not None and reference is not None:
        parser.error(
            "--authorized-by : sans objet quand un périmètre est déclaré, dont "
            "la référence d'autorisation fait foi (retire l'option, ou le "
            "périmètre)"
        )
    confirmer = None
    if scope is None and reference is None and target.transport is not Transport.BUNDLE:
        confirmer = _confirmation_au_terminal()
    autorisation = authorize(
        target, scope=scope, authorized_by=reference, confirm=confirmer
    )
    if autorisation.basis is Basis.SCOPE and scope is not None:
        logger.info(
            "périmètre autorisé : mission %s, autorisation %s, scope.sha256 %s "
            "(%s) ; cible %s incluse",
            scope.mission_id,
            scope.authorization_reference,
            scope.sha256(),
            scope.source,
            target.id,
        )
    elif autorisation.basis is Basis.AUTHORIZED_BY:
        # la cible n'est comparee a rien : visible sans -v
        logger.warning(
            "aucun périmètre déclaré : la cible %s n'est comparée à aucune "
            "autorisation ; audit lancé sur la foi de --authorized-by (%s)",
            target.id,
            reference,
        )
    elif autorisation.basis is Basis.CONFIRMATION:
        logger.info(
            "aucun périmètre déclaré : cible %s confirmée au terminal", target.id
        )
    else:
        logger.info("cible %s : aucun système joint, périmètre non appliqué", target.id)
    return autorisation


def _initialiser(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """``amnesia init`` : écrit un fichier de mission d'exemple, sans rien écraser.

    Écriture par ``amnesia.output.write_private()`` : 0600 (le fichier nomme le
    client), atomique, jamais à travers un lien symbolique.
    """
    chemin: Path = args.fichier
    affiche = assainir(str(chemin))
    try:
        write_private(chemin, example_toml().encode("utf-8"), force=args.overwrite)
    except UnsafeDestinationError as exc:
        parser.error(f"{affiche} : {exc.strerror or exc}, {MEME_AVEC_OVERWRITE}")
    except FileExistsError:
        parser.error(f"{affiche} : {EXISTE_DEJA}")
    except OSError as exc:
        logger.error("%s : écriture impossible : %s", chemin, exc.strerror or exc)
        return FATAL
    # il nomme le client : meme avertissement que pour un rapport
    warn_if_not_ignored(chemin)
    print(f"Fichier de mission écrit : {affiche}")
    return OK


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

# colonne extra de list-checks pour un check qui n'en requiert aucun
SANS_EXTRA = "-"


def _extra(meta: CheckMeta) -> str:
    """Extra requis à la manière de pip (``[aws]``), ou ``-`` : socle seul."""
    return SANS_EXTRA if meta.requires_extra is None else f"[{meta.requires_extra}]"


def _lister_checks(metas: list[CheckMeta]) -> None:
    """Une ligne par check : id, domaine, extra requis, état et titre, alignés."""
    if not metas:
        return
    largeur_id = max(len(m.id) for m in metas)
    largeur_domaine = max(len(m.domain.value) for m in metas)
    largeur_extra = max(len(_extra(m)) for m in metas)
    largeur_etat = max(len(e) for e in ETATS.values())
    for m in metas:
        print(
            f"{m.id:<{largeur_id}}  {m.domain.value:<{largeur_domaine}}  "
            f"{_extra(m):<{largeur_extra}}  "
            f"{ETATS[m.implemented]:<{largeur_etat}}  {m.title}"
        )


def _lister_catalogue(catalogue: Catalog) -> None:
    """Questions groupées par thème, avec leur statut, alignées."""
    print(
        f"Catalogue {catalogue.version} : {len(catalogue)} questions, "
        f"{len(catalogue.sources)} sources de télémétrie"
    )
    largeur_id = max((len(q.id) for q in catalogue), default=0)
    largeur_statut = max(len(s.label) for s in QuestionStatus)
    for theme in Theme:
        questions = [q for q in catalogue if q.theme is theme]
        if not questions:
            continue
        print(f"\n{theme.label}")
        for q in questions:
            print(
                f"  {q.id:<{largeur_id}}  {q.status.label:<{largeur_statut}}  {q.text}"
            )


def _detail_source(source: Source, retrait: str = "") -> list[str]:
    """Lignes décrivant une source : résumé, titre, prérequis, état par défaut."""
    lignes = [f"{retrait}{source.id}  {source.summary()}", f"{retrait}  {source.title}"]
    if source.kind is SourceKind.EVENT:
        lignes.append(f"{retrait}  fournisseur : {source.provider}")
    lignes += [
        f"{retrait}  prérequis : {prerequis.describe()}"
        for prerequis in source.prerequisites
    ]
    lignes.append(f"{retrait}  par défaut : {PAR_DEFAUT[source.enabled_by_default]}")
    return lignes


def _montrer_question(catalogue: Catalog, question: Question) -> None:
    """Fiche d'une question : gabarit, raison d'être, checks, sources, références."""
    print(f"{question.id}  [{question.status.label}]")
    if question.replaced_by is not None:
        print(f"Remplacée par : {question.replaced_by}")
    print(f"Question : {question.text}")
    print(f"Pourquoi : {question.why}")
    print(f"Domaine : {question.domain.value}")
    print(f"Thème : {question.theme.label}")
    print(f"Rôles : {', '.join(r.label for r in question.roles)}")
    print(f"Sévérité par défaut : {question.severity_default.value}")
    print(f"Checks : {', '.join(question.checks) or SANS_CHECK}")
    print("Sources (une seule suffit) :")
    for source in catalogue.sources_of(question.id):
        print("\n".join(_detail_source(source, retrait="  ")))
    if question.references:
        print("Références :")
        for reference in question.references:
            version = "" if reference.version is None else f" v{reference.version}"
            url = "" if reference.url is None else f" : {reference.url}"
            print(f"  {reference.kind.value} {reference.id}{version}{url}")


def _cataloguer(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Commandes ``catalog list``, ``show`` et ``validate``.

    Un catalogue embarqué invalide vaut le code fatal, avec une ligne par
    erreur sur stderr : chacune nomme le fichier, l'entrée et le champ.
    """
    try:
        catalogue = load_catalog()
        if args.catalog_cmd == "validate":
            verify_registry(catalogue, REGISTRY.metas())
    except CatalogError as exc:
        for erreur in exc.errors:
            # texte du depot, mais rendu imprimable comme toute erreur fatale
            logger.error("catalogue invalide : %s", assainir(erreur))
        return CODE_CATALOGUE_INVALIDE
    if args.catalog_cmd == "validate":
        print(
            f"catalogue {catalogue.version} valide : {len(catalogue)} questions, "
            f"{len(catalogue.sources)} sources, "
            f"{sum(1 for q in catalogue if q.status is QuestionStatus.ACTIVE)} "
            "questions reliées à un check"
        )
        return OK
    if args.catalog_cmd == "list":
        _lister_catalogue(catalogue)
        return OK
    # show : argparse exige l'une des trois sous-commandes
    try:
        if args.id.startswith("SRC-"):
            print("\n".join(_detail_source(catalogue.source(args.id))))
        else:
            _montrer_question(catalogue, catalogue.question(args.id))
    except UnknownIdError:
        # erreur d'usage, sans echo de la saisie (sequences de terminal)
        parser.error(
            "catalog show : identifiant inconnu (liste : amnesia catalog list)"
        )
    return OK


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


OPTION_FICHIER_MOT_DE_PASSE = "--password-file"


# fragments de nom d'option qui annoncent une valeur secrete
_NOMS_SENSIBLES = ("pass", "pwd", "secret", "token", "cred", "key")


def _option_a_valeur_secrete(argv: Sequence[str]) -> str | None:
    """Désignation de la première option qui semble porter un secret, ou ``None``.

    Couvre ``-p``, toute abréviation de ``--password-file`` (argparse prendrait
    ``--password VALEUR`` pour un chemin) et toute option au nom sensible
    (``--passwd``, ``--token``, ``--client-secret``...), où qu'elle soit avant
    ``--``. Une option en ``-file`` désigne un fichier et reste admise. Le texte
    rendu ne reprend jamais la saisie : un nom collé à sa valeur
    (``--tokenVALEUR``) n'est cité que par son fragment sensible.
    """
    for argument in argv:
        if argument == "--":
            break
        option = argument.partition("=")[0]
        if not option.startswith("--"):
            # -p VALEUR ou -pVALEUR : la suite serait la valeur
            if option.startswith("-p"):
                return "-p"
            continue
        if option == OPTION_FICHIER_MOT_DE_PASSE:
            continue
        if len(option) > 2 and OPTION_FICHIER_MOT_DE_PASSE.startswith(option):
            return option
        nom = option[2:].lower()
        if nom.endswith("-file"):
            continue
        for fragment in _NOMS_SENSIBLES:
            if fragment in nom:
                return f"option en « {fragment} »"
    return None


def _mot_de_passe(
    args: argparse.Namespace, argv: Sequence[str], parser: argparse.ArgumentParser
) -> Secret | None:
    """Mot de passe de la cible, ou ``None`` si elle n'en demande pas.

    Sources (``amnesia.secrets``, docs/SECRETS.md) : ``--password-file``, puis
    ``AMNESIA_WINRM_PASSWORD``, puis une invite au terminal si le transport
    exige un mot de passe. Aucune option ne prend la valeur elle-même. Un refus
    (fichier trop ouvert, aucune source et pas de terminal) est une erreur
    d'usage : code 2, sans lancer l'audit ni attendre de saisie.
    """
    transport = args.target.transport
    fichier: Path | None = args.password_file
    if transport is not Transport.WINRM:
        if fichier is not None:
            parser.error(
                f"--password-file : sans objet pour une cible {transport.value}, "
                "qui ne s'authentifie pas (réservé à winrm://)"
            )
        # jamais heritee par les sous-processus de la collecte
        if os.environ.pop(ENV_MOT_DE_PASSE_WINRM, None) is not None:
            logger.warning(
                "%s ignorée et retirée de l'environnement : la cible %s ne "
                "s'authentifie pas",
                ENV_MOT_DE_PASSE_WINRM,
                transport.value,
            )
        return None
    requis = transport in TRANSPORTS_A_MOT_DE_PASSE
    designe = fichier is not None or ENV_MOT_DE_PASSE_WINRM in os.environ
    if not (requis or designe):
        return None
    try:
        return resolve(
            ENTREE_WINRM,
            file=fichier,
            env=ENV_MOT_DE_PASSE_WINRM,
            prompt="Mot de passe WinRM : " if requis else None,
        )
    except SecretError as exc:
        # le chemin vient de la ligne de commande : neutralise avant tout echo
        parser.error(
            f"mot de passe WinRM : {assainir(str(exc))} (sources admises : "
            f"--password-file, {ENV_MOT_DE_PASSE_WINRM}, saisie au terminal)"
        )


def _ecrire_rapport(chemin: Path, octets: bytes, *, overwrite: bool) -> int:
    """Écrit le rapport par ``amnesia.output.write_private()`` ; rend un code.

    0600 (ACL du seul compte courant sous Windows), écriture atomique, jamais
    à travers un lien symbolique. Une entrée apparue à ce chemin pendant
    l'audit, un lien symbolique ou une entrée qui n'est pas un fichier
    ordinaire donnent le code 2 sans rien modifier ; toute autre erreur, le
    code 4.
    """
    try:
        write_private(chemin, octets, force=overwrite)
    except UnsafeDestinationError as exc:
        logger.error(
            "rapport %s : %s, %s ; rapport non écrit",
            chemin,
            exc.strerror or exc,
            MEME_AVEC_OVERWRITE,
        )
        return USAGE
    except FileExistsError:
        logger.error("rapport %s : %s ; rapport non écrit", chemin, EXISTE_DEJA)
        return USAGE
    except OSError as exc:
        logger.error(
            "rapport %s : écriture impossible : %s", chemin, exc.strerror or exc
        )
        return FATAL
    logger.info("rapport écrit : %s", chemin)
    return OK


def _refus_out(chemin: Path, *, overwrite: bool) -> str | None:
    """Motif de refus de ``--out`` avant l'audit, ou ``None``.

    Perdre un audit entier pour un fichier déjà là serait pire : le test est
    fait avant. ``write_private()`` le refait de façon atomique au moment
    d'écrire. Un lien symbolique, ou une entrée qui n'est pas un fichier
    ordinaire (``/dev/null``, FIFO, dossier), n'est jamais remplacé.
    """
    try:
        check_destination(chemin, force=overwrite)
    except UnsafeDestinationError as exc:
        return f"{exc.strerror or exc}, {MEME_AVEC_OVERWRITE}"
    except FileExistsError:
        return EXISTE_DEJA
    return None


def _preparer_out(chemin: Path, *, par_defaut: bool) -> int:
    """Prépare ``amnesia-out/`` sans ``--out`` ; avertit si git peut voir le rapport.

    Rend 0, ou un code (et un journal) si le dossier par défaut est refusé
    (lien, autre propriétaire : 2) ou ne peut pas être créé (4).
    """
    if par_defaut:
        try:
            prepare_default_dir(chemin.parent)
        except UnsafeDestinationError as exc:
            logger.error(
                "dossier %s : %s ; audit non lancé (--out pour écrire ailleurs)",
                chemin.parent,
                exc.strerror or exc,
            )
            return USAGE
        except OSError as exc:
            logger.error(
                "dossier %s : création impossible : %s",
                chemin.parent,
                exc.strerror or exc,
            )
            return FATAL
    warn_if_not_ignored(chemin)
    return OK


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
    (rendu texte, ou le JSON). Sans ``--out``, le fichier est
    ``amnesia-out/amnesia-report.json``, dans un dossier créé en 0700 et ignoré
    par git. ``--out -`` : le JSON va sur stdout et le rendu texte sur stderr
    (rien d'autre avec ``--format json``). Écriture : ``amnesia.output``.
    """
    # avant tout le reste : un refus (codes 2 et 5) ne laisse rien sur le
    # disque, et la variable d'environnement a quitte le processus avant le
    # premier sous-processus (git check-ignore, collecte)
    config = _configuration(args, parser)
    try:
        # avant de lire un secret ou d'en demander un : une cible hors
        # perimetre n'est ni jointe ni authentifiee
        autorisation = _autoriser(args, config, parser)
    except ScopeRefusal as exc:
        # nom d'hote local, saisie : neutralises avant tout echo
        logger.error("audit refusé avant toute collecte : %s", assainir(exc.message))
        return OUT_OF_SCOPE
    mot_de_passe = _mot_de_passe(args, argv, parser)
    if mot_de_passe is not None:
        # le collecteur WinRM (#63) le recevra ici, et n'appellera reveal()
        # qu'au moment de s'authentifier
        logger.info(
            "mot de passe WinRM lu ; inutilisé : la collecte WinRM n'existe pas encore"
        )
    par_defaut = args.out is None
    chemin: Path | None
    if args.out == SORTIE_STANDARD:
        chemin = None
    elif par_defaut:
        chemin = default_report_path()
    else:
        chemin = Path(args.out)
    # le chemin vient de la ligne de commande : neutralise avant tout echo
    chemin_affiche = assainir(str(chemin)) if chemin is not None else ""
    if chemin is not None:
        try:
            refus = _refus_out(chemin, overwrite=args.overwrite)
        except OSError as exc:
            logger.error(
                "rapport %s : écriture impossible : %s", chemin, exc.strerror or exc
            )
            return FATAL
        if refus is not None:
            parser.error(f"--out {chemin_affiche} : {refus}")
        code = _preparer_out(chemin, par_defaut=par_defaut)
        if code != OK:
            return code
    # instances neuves : aucun etat ne passe d'un audit a l'autre
    checks = default_checks()
    audit = run_audit(
        checks,
        args.target,
        _collecteur(args.target),
        config=config.for_checks(),
        debug=args.debug,
    )
    rapport = build_report(audit, argv=argv, config=config, authorization=autorisation)
    texte_json = dumps_report(rapport)
    octets = texte_json.encode("utf-8")
    if chemin is None:
        _ecrire_utf8(octets, texte_json)
        flux_texte = sys.stderr
    else:
        code = _ecrire_rapport(chemin, octets, overwrite=args.overwrite)
        if code != OK:
            return code
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
    mission = _options_mission()

    a = sub.add_parser(
        "audit",
        parents=[journal, mission],
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
        "--authorized-by",
        type=_reference,
        default=None,
        metavar="REFERENCE",
        help=(
            "référence de l'autorisation écrite (lettre de mission) qui couvre "
            "la cible, recopiée dans le rapport ; obligatoire sans périmètre "
            "déclaré quand aucun terminal ne permet de confirmer la cible "
            f"(sinon code {OUT_OF_SCOPE}), refusée avec un périmètre"
        ),
    )
    a.add_argument(
        "--password-file",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "fichier d'une ligne qui contient le mot de passe WinRM, lisible de "
            "ton seul compte (0600) ; aucune option ne prend le mot de passe "
            f"lui-même (autres sources : {ENV_MOT_DE_PASSE_WINRM}, saisie au "
            "terminal ; docs/SECRETS.md)"
        ),
    )
    a.add_argument(
        "--out",
        default=None,
        metavar="PATH|-",
        help=(
            f"rapport JSON, créé en 0600 (défaut : {DEFAULT_OUT}, dossier en "
            "0700 ignoré par git) ; « - » : JSON sur stdout, rendu texte sur stderr"
        ),
    )
    a.add_argument(
        "--overwrite",
        action="store_true",
        help=(
            "remplace un rapport existant (refusé sinon) ; jamais un lien "
            "symbolique ni ce qui n'est pas un fichier ordinaire"
        ),
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
        "list-checks",
        parents=[journal],
        help="Liste les checks disponibles",
        description=(
            "Une ligne par check : id, domaine, extra optionnel requis ([nom] : "
            f"à installer en plus du paquet ; {SANS_EXTRA} : aucun), état et titre."
        ),
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

    i = sub.add_parser(
        "init",
        parents=[journal],
        help=f"Écrit un fichier de mission d'exemple ({DEFAULT_FILE})",
        description=(
            "Écrit un fichier de mission d'exemple, chaque clé commentée, créé "
            "en 0600. Un fichier existant n'est jamais écrasé sans --overwrite."
        ),
    )
    i.add_argument(
        "fichier",
        nargs="?",
        type=Path,
        default=Path(DEFAULT_FILE),
        metavar="FICHIER",
        help=f"fichier à écrire (défaut : {DEFAULT_FILE})",
    )
    i.add_argument(
        "--overwrite",
        action="store_true",
        help=(
            "remplace un fichier existant ; jamais un lien symbolique ni ce qui "
            "n'est pas un fichier ordinaire"
        ),
    )

    g = sub.add_parser(
        "config",
        parents=[journal],
        help="Configuration effective de l'audit (fichier de mission)",
    )
    gsub = g.add_subparsers(dest="config_cmd", required=True, metavar="COMMANDE")
    gsub.add_parser(
        "show",
        parents=[journal, mission],
        help="Affiche chaque valeur effective et son origine",
        description=(
            "Affiche la configuration effective, une ligne par clé : valeur et "
            "origine (défaut, fichier ou cli), puis config_hash, le SHA-256 que "
            "porte le rapport. Configuration refusée : code 2."
        ),
    )

    c = sub.add_parser(
        "catalog",
        parents=[journal],
        help="Catalogue des questions d'enquête (docs/catalogue.md)",
        description=(
            "Catalogue embarqué des questions d'enquête et de la télémétrie qui "
            "permet d'y répondre. Catalogue invalide : code "
            f"{CODE_CATALOGUE_INVALIDE}, une ligne par erreur."
        ),
    )
    csub = c.add_subparsers(dest="catalog_cmd", required=True, metavar="COMMANDE")
    csub.add_parser(
        "list",
        parents=[journal],
        help="Questions groupées par thème, avec leur statut",
    )
    s = csub.add_parser(
        "show",
        parents=[journal],
        help="Fiche d'une question (Q-...) ou d'une source (SRC-...)",
    )
    s.add_argument("id", metavar="ID", help="identifiant, ex. Q-WIN-RDP-LOGON")
    csub.add_parser(
        "validate",
        parents=[journal],
        help="Valide le catalogue et son lien avec le registre des checks",
        description=(
            "Valide les fichiers du catalogue (identifiants uniques, sources "
            "connues, GUID, statuts, ids.lock) et le lien réciproque avec le "
            "registre des checks. Code 0 si tout est cohérent, "
            f"{CODE_CATALOGUE_INVALIDE} sinon."
        ),
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

    if args.cmd == "catalog":
        return _cataloguer(args, parser)

    if args.cmd == "audit":
        return _auditer(args, argv, parser)

    if args.cmd == "init":
        return _initialiser(args, parser)

    if args.cmd == "config":
        _montrer_configuration(_configuration(args, parser))
        return OK

    # sans sous-commande : aide sur stderr, stdout reste vide (JSON avec --out -)
    parser.print_help(sys.stderr)
    return USAGE


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée de la commande ``amnesia`` ; rend un code de ``exitcodes``."""
    _proteger_sorties()
    parser = build_parser()
    arguments = list(sys.argv[1:] if argv is None else argv)
    option = _option_a_valeur_secrete(arguments)
    if option is not None:
        # avant argparse, qui recopierait la valeur (« unrecognized arguments »,
        # « invalid choice ») sur stderr, donc dans les journaux de CI
        parser.error(
            f"{option} : aucune option ne prend de valeur secrète ; le mot de "
            f"passe se lit d'un fichier ({OPTION_FICHIER_MOT_DE_PASSE}, "
            "docs/SECRETS.md)"
        )
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
            # trace caviardee AVANT le journal : un handler pose par l'hote sur
            # le logger racine ne recoit jamais l'exception brute
            trace = "".join(traceback.format_exception(exc))
            logger.debug("trace de l'erreur fatale :\n%s", redact(trace))
        return FATAL
