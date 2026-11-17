"""Socle des rendus : lecture du rapport JSON, options et textes communs.

Les rendus ne lisent que le rapport JSON (#22, ``docs/format-rapport.md``),
jamais les objets internes d'un audit : un rapport archivé se re-rend sans
refaire l'audit. ``read_report()`` valide les champs qu'ils affichent et refuse
une version MAJEURE de format inconnue.

Données hostiles : questions, raisons, cibles et messages viennent d'un hôte
audité, potentiellement compromis, ou d'un fichier modifiable. Avant affichage,
``neutralize()`` rend visibles les caractères capables d'agir sur un terminal
(séquences ANSI/OSC, C0, C1, bidi, séparateurs de ligne) et
``escape_markdown()`` échappe en plus ce qui formerait un lien, une image, du
HTML brut ou un tableau cassé. La neutralisation générique de toutes les sorties
relève de #45.
"""

from __future__ import annotations

import codecs
import json
import math
import re
import unicodedata
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, TypeVar

from ..checks.base import Reason, Severity, Status
from ..report import SCHEMA_VERSION

SUPPORTED_MAJOR = int(SCHEMA_VERSION.split(".", 1)[0])
"""Version MAJEURE du format lue par les rendus (``1`` : rapports ``1.x.y``)."""

GROUP_BY = ("severity", "domain", "target")
"""Regroupements des angles morts (``--group-by``)."""

SEVERITIES = tuple(s.value for s in sorted(Severity, reverse=True))
"""Sévérités, de ``critical`` à ``info``."""

TITLE = "amnesia — questions d'enquête sans réponse"

NIVEAUX = {
    "critical": "critique",
    "high": "élevée",
    "medium": "moyenne",
    "low": "faible",
    "info": "info",
}
"""Niveau en français de chaque sévérité (docs/severite.md)."""

STATUTS = {
    "pass": "conformes",
    "gap": "avec angle mort",
    "error": "en erreur",
    "skipped": "non exécutés",
    "not_applicable": "sans objet",
}
"""Libellé des compteurs par statut du résumé."""

STATUT_NON_VERIFIE = {"error": "erreur", "skipped": "non exécuté"}

MOTIFS = {
    "user_excluded": "exclu par l'utilisateur",
    "missing_privilege": "privilège insuffisant",
    "not_implemented": "check non implémenté",
    "not_collected": "fait non collecté",
    "access_denied": "accès refusé",
    "timeout": "délai dépassé",
    "unreachable": "cible injoignable",
    "internal_error": "erreur interne",
}
"""Libellé de chaque motif d'un check non vérifié (``Reason``)."""

DOMAINES = {
    "win": "Windows",
    "ad": "Active Directory",
    "m365": "Microsoft 365",
    "aws": "AWS",
    "siem": "SIEM",
}
"""Libellé de chaque domaine, désigné par le premier segment de ``check_id``."""

_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


class ReportError(ValueError):
    """Rapport illisible, invalide, ou d'une version de format non prise en charge."""


# --- options et protocole -----------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class RenderOptions:
    """Options d'un rendu.

    ``group_by`` : ``severity`` (défaut), ``domain`` ou ``target``.
    ``min_severity`` : sévérité minimale des angles morts affichés ; les autres
    restent comptés dans le résumé. ``color`` : couleurs ANSI (rendu texte
    seulement). ``encoding`` : encodage de la sortie ; un caractère qu'il ne sait
    pas représenter reçoit un repli ASCII (``→`` devient ``->``).
    """

    group_by: str = "severity"
    min_severity: str = "info"
    color: bool = False
    encoding: str = "utf-8"

    def __post_init__(self) -> None:
        if self.group_by not in GROUP_BY:
            raise ValueError(f"group_by inconnu : {self.group_by!r}")
        if self.min_severity not in SEVERITIES:
            raise ValueError(f"min_severity inconnue : {self.min_severity!r}")
        if not isinstance(self.color, bool):
            raise TypeError(f"color doit être un booléen : {self.color!r}")
        try:
            codecs.lookup(self.encoding)
        except LookupError:
            raise ValueError(f"encodage inconnu : {self.encoding!r}") from None


class Renderer(Protocol):
    """Rendu d'un rapport JSON v1 en texte (``text``, ``md``...)."""

    def render(self, report: Mapping[str, Any], options: RenderOptions) -> str:
        """Texte du rendu ; lève ``ReportError`` si le rapport est refusé."""
        ...


# --- lecture du rapport -------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GapView:
    """Angle mort tel que l'affichent les rendus."""

    check_id: str
    target: str
    question: str
    reason: str
    severity: Severity
    observed_window_days: int | float | None
    required_window_days: int | float | None

    @property
    def domain(self) -> str:
        """Premier segment de ``check_id`` (``win``, ``ad``...)."""
        return self.check_id.split(".", 1)[0]


@dataclass(frozen=True, slots=True)
class UnverifiedView:
    """Check en ``error`` ou ``skipped`` : jamais compté conforme."""

    check_id: str
    target: str
    status: Status
    reason: Reason | None
    message: str


@dataclass(frozen=True, slots=True)
class SummaryView:
    """Compteurs du rapport (``summary``)."""

    total: int
    by_status: Mapping[str, int]
    by_severity: Mapping[str, int]
    gaps: int
    excluded: int
    not_evaluated: int


@dataclass(frozen=True, slots=True)
class ReportView:
    """Champs du rapport affichés par les rendus, validés."""

    schema_version: str
    tool_version: str
    run_id: str
    started_at: str
    complete: bool
    interrupted: bool
    targets: tuple[str, ...]
    gaps: tuple[GapView, ...]
    unverified: tuple[UnverifiedView, ...]
    summary: SummaryView

    @property
    def unverified_count(self) -> int:
        """Checks non vérifiés, d'après ``results`` et ``summary`` (le plus grand)."""
        resume = self.summary
        return max(
            len(self.unverified),
            resume.excluded + resume.not_evaluated,
            resume.by_status["error"] + resume.by_status["skipped"],
        )

    @property
    def gap_count(self) -> int:
        """Angles morts, d'après ``gaps`` et ``summary`` (le plus grand)."""
        return max(len(self.gaps), self.summary.gaps, self.summary.by_status["gap"])

    @property
    def fully_verified(self) -> bool:
        """Vrai si chaque check a été évalué, sans interruption."""
        return self.complete and not self.interrupted and self.unverified_count == 0


_E = TypeVar("_E", bound=StrEnum)


def _valeur(objet: Mapping[str, Any], cle: str, parent: str) -> tuple[Any, str]:
    chemin = f"{parent}.{cle}" if parent else cle
    if cle not in objet:
        raise ReportError(f"{chemin} : champ manquant")
    return objet[cle], chemin


def _objet(objet: Mapping[str, Any], cle: str, parent: str = "") -> Mapping[str, Any]:
    valeur, chemin = _valeur(objet, cle, parent)
    if not isinstance(valeur, Mapping):
        raise ReportError(f"{chemin} : objet attendu")
    return valeur


def _liste(objet: Mapping[str, Any], cle: str, parent: str = "") -> list[Any]:
    valeur, chemin = _valeur(objet, cle, parent)
    if not isinstance(valeur, list):
        raise ReportError(f"{chemin} : liste attendue")
    return valeur


def _texte(objet: Mapping[str, Any], cle: str, parent: str = "") -> str:
    valeur, chemin = _valeur(objet, cle, parent)
    if not isinstance(valeur, str):
        raise ReportError(f"{chemin} : chaîne attendue")
    return valeur


def _booleen(objet: Mapping[str, Any], cle: str, parent: str = "") -> bool:
    valeur, chemin = _valeur(objet, cle, parent)
    if not isinstance(valeur, bool):
        raise ReportError(f"{chemin} : booléen attendu")
    return valeur


def _compte(objet: Mapping[str, Any], cle: str, parent: str = "") -> int:
    valeur, chemin = _valeur(objet, cle, parent)
    # bool est un int en Python : refuse explicitement
    if isinstance(valeur, bool) or not isinstance(valeur, int) or valeur < 0:
        raise ReportError(f"{chemin} : entier positif ou nul attendu")
    return valeur


def _jours(objet: Mapping[str, Any], cle: str, parent: str) -> int | float | None:
    valeur, chemin = _valeur(objet, cle, parent)
    if valeur is None:
        return None
    if (
        isinstance(valeur, bool)
        or not isinstance(valeur, int | float)
        or not math.isfinite(valeur)
        or valeur < 0
    ):
        raise ReportError(f"{chemin} : nombre de jours positif ou null attendu")
    return valeur


def _membre(enum: type[_E], objet: Mapping[str, Any], cle: str, parent: str = "") -> _E:
    valeur, chemin = _valeur(objet, cle, parent)
    if isinstance(valeur, str):
        try:
            return enum(valeur)
        except ValueError:
            pass
    # la valeur n'est pas citee : elle peut venir d'un fichier hostile
    valides = ", ".join(m.value for m in enum)
    raise ReportError(f"{chemin} : valeur inconnue ; valeurs valides : {valides}")


def check_schema_version(report: Mapping[str, Any]) -> str:
    """``schema_version`` du rapport, si sa version MAJEURE est prise en charge.

    Une version MINEURE plus récente est acceptée : elle ne fait qu'ajouter des
    champs, que les rendus ignorent (docs/format-rapport.md, « Compatibilité »).
    """
    valeur, _chemin = _valeur(report, "schema_version", "")
    if not isinstance(valeur, str) or _VERSION.fullmatch(valeur) is None:
        raise ReportError(
            "schema_version : version SemVer attendue (MAJEURE.MINEURE.CORRECTIF)"
        )
    majeure = int(valeur.split(".", 1)[0])
    if majeure != SUPPORTED_MAJOR:
        raise ReportError(
            f"format de rapport {valeur} non pris en charge : cette version "
            f"d'amnesia lit les rapports {SUPPORTED_MAJOR}.x.y"
        )
    return valeur


def _gap(donnees: Any, parent: str) -> GapView:
    if not isinstance(donnees, Mapping):
        raise ReportError(f"{parent} : objet attendu")
    preuve = _objet(donnees, "evidence", parent)
    chemin_preuve = f"{parent}.evidence"
    return GapView(
        check_id=_texte(donnees, "check_id", parent),
        target=_texte(donnees, "target", parent),
        question=_texte(donnees, "question", parent),
        reason=_texte(donnees, "reason", parent),
        severity=_membre(Severity, donnees, "severity", parent),
        observed_window_days=_jours(preuve, "observed_window_days", chemin_preuve),
        required_window_days=_jours(preuve, "required_window_days", chemin_preuve),
    )


def _non_verifie(donnees: Any, parent: str) -> UnverifiedView | None:
    if not isinstance(donnees, Mapping):
        raise ReportError(f"{parent} : objet attendu")
    statut = _membre(Status, donnees, "status", parent)
    if statut not in (Status.ERROR, Status.SKIPPED):
        return None
    motif_brut, _chemin = _valeur(donnees, "reason", parent)
    motif = None if motif_brut is None else _membre(Reason, donnees, "reason", parent)
    return UnverifiedView(
        check_id=_texte(donnees, "check_id", parent),
        target=_texte(donnees, "target", parent),
        status=statut,
        reason=motif,
        message=_texte(donnees, "message", parent),
    )


def _comptes(objet: Mapping[str, Any], cle: str, cles: Iterable[str]) -> dict[str, int]:
    comptes = _objet(objet, cle, "summary")
    return {c: _compte(comptes, c, f"summary.{cle}") for c in cles}


def read_report(report: Mapping[str, Any]) -> ReportView:
    """Vue validée d'un rapport JSON v1 ; lève ``ReportError`` sinon.

    Seuls les champs affichés sont vérifiés, avec leur chemin dans le message
    (``gaps[0].severity``) ; une valeur fautive n'y est jamais recopiée. Les
    angles morts sont triés de ``critical`` à ``info`` (tri stable : l'ordre du
    rapport départage une même sévérité).
    """
    if not isinstance(report, Mapping):
        raise ReportError("le rapport doit être un objet JSON")
    version = check_schema_version(report)
    outil = _objet(report, "tool")
    execution = _objet(report, "run")
    cibles = _liste(report, "targets")
    resultats = _liste(report, "results")
    gaps = [_gap(g, f"gaps[{i}]") for i, g in enumerate(_liste(report, "gaps"))]
    non_verifies = [
        nv
        for i, r in enumerate(resultats)
        if (nv := _non_verifie(r, f"results[{i}]")) is not None
    ]
    resume = _objet(report, "summary")
    for i, cible in enumerate(cibles):
        if not isinstance(cible, Mapping):
            raise ReportError(f"targets[{i}] : objet attendu")
    return ReportView(
        schema_version=version,
        tool_version=_texte(outil, "version", "tool"),
        run_id=_texte(execution, "id", "run"),
        started_at=_texte(execution, "started_at", "run"),
        complete=_booleen(execution, "complete", "run"),
        interrupted=_booleen(execution, "interrupted", "run"),
        targets=tuple(
            _texte(cible, "id", f"targets[{i}]") for i, cible in enumerate(cibles)
        ),
        gaps=tuple(sorted(gaps, key=lambda g: -g.severity.rank)),
        unverified=tuple(non_verifies),
        summary=SummaryView(
            total=_compte(resume, "total", "summary"),
            by_status=_comptes(resume, "by_status", (s.value for s in Status)),
            by_severity=_comptes(resume, "by_severity", SEVERITIES),
            gaps=_compte(resume, "gaps", "summary"),
            excluded=_compte(resume, "excluded", "summary"),
            not_evaluated=_compte(resume, "not_evaluated", "summary"),
        ),
    )


def _constante_refusee(nom: str) -> Any:
    raise ReportError(f"valeur non finie ({nom}) refusée")


def load_report(path: Path) -> dict[str, Any]:
    """Rapport JSON lu dans ``path`` ; lève ``ReportError`` s'il est illisible.

    Le contenu n'est pas encore validé : voir ``read_report()``.
    """
    try:
        # utf-8-sig : tolere le BOM qu'ajoutent certains editeurs Windows ; le
        # rapport est ecrit en UTF-8 sans BOM (docs/format-rapport.md)
        texte = path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        raise ReportError("le fichier n'est pas encodé en UTF-8") from None
    except OSError as exc:
        raise ReportError(f"lecture impossible : {exc.strerror or exc}") from None
    try:
        donnees = json.loads(texte, parse_constant=_constante_refusee)
    except json.JSONDecodeError as exc:
        raise ReportError(
            f"JSON invalide (ligne {exc.lineno}, colonne {exc.colno})"
        ) from None
    except RecursionError:
        raise ReportError("JSON trop profondément imbriqué") from None
    except ReportError:
        raise
    except ValueError:
        # entier de plus de 4300 chiffres (limite de conversion de Python)
        raise ReportError("JSON invalide : nombre hors limites") from None
    if not isinstance(donnees, dict):
        raise ReportError("le rapport doit être un objet JSON")
    return donnees


# --- textes : neutralisation, echappement, repli ASCII ------------------------


def _visible(caractere: str) -> str:
    # \x1b, \u202e, \n... : la valeur reste lisible par l'analyste
    return caractere.encode("unicode_escape").decode("ascii")


def neutralize(text: str) -> str:
    """Texte venu du rapport, sans caractère capable d'agir sur un terminal.

    Les caractères non imprimables (contrôles C0 et C1 dont ESC, DEL, formats
    bidi comme U+202E, séparateurs U+2028/U+2029, surrogates isolés, zones
    privées et non attribuées) sont remplacés par leur échappement visible
    (``\\x1b``, ``\\u202e``) ; les espaces Unicode (espace insécable...) restent.
    Le texte rendu tient donc sur une ligne et ne peut ni colorer, ni déplacer
    le curseur, ni retourner l'affichage.
    """
    return "".join(
        c if c.isprintable() or unicodedata.category(c) == "Zs" else _visible(c)
        for c in text
    )


# caracteres qui ouvrent un lien, une image, du HTML, une entite, du code, de
# l'emphase, une cellule de tableau, une mention, une reference ou des maths (GFM)
_MARKDOWN = re.compile(r"[\\`*_~\[\]()<>!|&#@$]")
# liens automatiques etendus de GFM : https://, mailto:, xmpp:..., et www.
_SCHEMA = re.compile(r"(?<=[A-Za-z]):")
_WWW = re.compile(r"(?i)(?<![A-Za-z0-9])(www)\.")


def escape_markdown(text: str, encoding: str | None = None) -> str:
    """Texte venu du rapport, neutralisé puis échappé pour Markdown (GFM).

    Aucun lien, image, HTML brut, entité, code ou emphase ne peut s'y former, et
    il ne casse pas une cellule de tableau : les caractères concernés sont
    précédés d'une barre oblique inverse, et les liens automatiques de GFM
    (``https://``, ``mailto:``, ``www.``, adresses électroniques) sont rompus.
    Le texte tient sur une ligne (``neutralize()``).

    Avec ``encoding``, le repli ASCII (``fallback()``) est appliqué avant
    l'échappement, qui voit donc les caractères finals : une lettre pleine
    chasse (U+FF48 pour ``h``) ou accentuée (``ẁẁẁ.``) ramenée à l'ASCII ne
    reforme pas, après coup, un lien automatique (``https:``, ``www.``). Le
    résultat est alors encodable dans ``encoding``.
    """
    texte = neutralize(text)
    if encoding is not None:
        texte = fallback(texte, encoding)
    texte = _MARKDOWN.sub(lambda m: "\\" + m.group(), texte.strip())
    texte = _SCHEMA.sub(r"\\:", texte)
    return _WWW.sub(r"\1\\.", texte)


_REPLIS = {
    "→": "->",
    "«": '"',
    "»": '"',
    "’": "'",
    "–": "-",
    "—": "-",
    "…": "...",
    "\u00a0": " ",
    "\u202f": " ",
}
"""Repli ASCII des caractères typographiques (docs/dev/encodage.md)."""


def _encodable(texte: str, encodage: str) -> bool:
    try:
        texte.encode(encodage)
    except UnicodeEncodeError:
        return False
    return True


def fallback(text: str, encoding: str) -> str:
    """``text`` encodable dans ``encoding``, avec un repli ASCII lisible.

    ``→`` devient ``->``, les guillemets « » des guillemets droits, une lettre
    accentuée sa lettre de base ; tout autre caractère non représentable, son
    échappement (``\\u4e2d``) : jamais un caractère spécial que le rendu
    aurait dû échapper. Sans effet si ``encoding`` sait tout représenter.
    """
    if _encodable(text, encoding):
        return text
    sortie: list[str] = []
    for caractere in text:
        if _encodable(caractere, encoding):
            sortie.append(caractere)
            continue
        repli = _REPLIS.get(caractere)
        if repli is None:
            base = "".join(
                c
                for c in unicodedata.normalize("NFKD", caractere)
                if not unicodedata.combining(c)
            )
            # lettres et chiffres seulement : la forme de compatibilite d'un
            # caractere pleine chasse (U+FF1C) serait un « < » ; les valeurs du
            # rapport sont repliees avant l'echappement (escape_markdown), mais
            # le repli final du document ne doit rien produire a echapper
            repli = base if base.isalnum() and _encodable(base, encoding) else ""
        if not repli or not _encodable(repli, encoding):
            repli = caractere.encode("ascii", "backslashreplace").decode("ascii")
        sortie.append(repli)
    return "".join(sortie)


# premiers mots d'une raison qui prennent une minuscule apres « Impossible : » ;
# liste fermee : un nom propre (Sysmon, Windows) garde sa majuscule
_MOTS_COURANTS = frozenset(
    {
        "le",
        "la",
        "les",
        "l",
        "un",
        "une",
        "des",
        "du",
        "de",
        "d",
        "aucun",
        "aucune",
        "ce",
        "cet",
        "cette",
        "ces",
        "cela",
        "il",
        "elle",
        "ils",
        "elles",
        "on",
        "son",
        "sa",
        "ses",
        "leur",
        "leurs",
        "seul",
        "seule",
        "seuls",
        "seules",
        "pas",
        "plus",
        "moins",
        "trop",
        "tout",
        "toute",
        "tous",
        "toutes",
        "en",
        "au",
        "aux",
        "depuis",
        "dans",
        "sans",
        "sur",
    }
)
_PREMIER_MOT = re.compile(r"[^\W\d_]+")


def lowercase_first(text: str) -> str:
    """``text`` avec une minuscule initiale si son premier mot est un mot courant.

    « Le journal Security... » devient « le journal Security... », mais
    « Sysmon n'est pas installé » et « RDP... » restent tels quels.
    """
    mot = _PREMIER_MOT.match(text)
    if mot is None or mot.group().casefold() not in _MOTS_COURANTS:
        return text
    # « Le », « L' » : seule l'initiale est en capitale ; « LE » reste tel quel
    premier = mot.group()
    if not premier[0].isupper() or (len(premier) > 1 and not premier[1:].islower()):
        return text
    return text[0].lower() + text[1:]


# --- contenu commun aux rendus ------------------------------------------------


def plural(nombre: int, singulier: str, pluriel: str | None = None) -> str:
    """« 0 angle mort », « 1 angle mort », « 2 angles morts »."""
    if nombre <= 1:
        return f"{nombre} {singulier}"
    return f"{nombre} {pluriel if pluriel is not None else singulier + 's'}"


def gaps_label(nombre: int) -> str:
    """Nombre d'angles morts, accordé."""
    return plural(nombre, "angle mort", "angles morts")


def _nombre(valeur: int | float) -> str:
    if isinstance(valeur, int):
        return str(valeur)
    if valeur.is_integer():
        return str(int(valeur))
    texte = f"{valeur:.2f}".rstrip("0").rstrip(".")
    return "< 0,01" if texte == "0" else texte.replace(".", ",")


def quantification(gap: GapView) -> str | None:
    """« Fenêtre observée 4 j / exigée 180 j », si le Gap porte ces durées."""
    observee, exigee = gap.observed_window_days, gap.required_window_days
    if observee is not None and exigee is not None:
        return f"Fenêtre observée {_nombre(observee)} j / exigée {_nombre(exigee)} j"
    if observee is not None:
        return f"Fenêtre observée {_nombre(observee)} j"
    if exigee is not None:
        return f"Fenêtre exigée {_nombre(exigee)} j"
    return None


def filter_gaps(
    gaps: Sequence[GapView], min_severity: str
) -> tuple[list[GapView], int]:
    """Angles morts de sévérité au moins ``min_severity``, et nombre de masqués."""
    seuil = Severity(min_severity).rank
    visibles = [g for g in gaps if g.severity.rank >= seuil]
    return visibles, len(gaps) - len(visibles)


_CLES_DE_GROUPE: dict[str, Callable[[GapView], str]] = {
    "severity": lambda g: g.severity.value,
    "domain": lambda g: g.domain,
    "target": lambda g: g.target,
}


def group_gaps(
    gaps: Sequence[GapView], group_by: str
) -> list[tuple[str, list[GapView]]]:
    """Groupes non vides d'angles morts, dans l'ordre d'affichage.

    Par sévérité : de ``critical`` à ``info`` ; par domaine ou par cible : ordre
    alphabétique. Dans un groupe, les angles morts gardent l'ordre de ``gaps``
    (de ``critical`` à ``info``).
    """
    try:
        cle = _CLES_DE_GROUPE[group_by]
    except KeyError:
        raise ValueError(f"group_by inconnu : {group_by!r}") from None
    ordre = SEVERITIES if group_by == "severity" else sorted({cle(g) for g in gaps})
    groupes: dict[str, list[GapView]] = {valeur: [] for valeur in ordre}
    for gap in gaps:
        groupes[cle(gap)].append(gap)
    return [(valeur, membres) for valeur, membres in groupes.items() if membres]


def group_title(
    group_by: str, valeur: str, nombre: int, affiche: Callable[[str], str]
) -> str:
    """Titre d'un groupe ; ``affiche`` neutralise ou échappe une valeur du rapport."""
    if group_by == "severity":
        sujet = f"Sévérité {NIVEAUX[valeur]} ({valeur})"
    elif group_by == "domain":
        libelle = DOMAINES.get(valeur)
        sujet = (
            f"Domaine {affiche(valeur)}"
            if libelle is None
            else f"Domaine {libelle} ({valeur})"
        )
    else:
        sujet = f"Cible {affiche(valeur)}"
    return f"{sujet} : {gaps_label(nombre)}"


def empty_line(rapport: ReportView, min_severity: str, masques: int) -> str:
    """Phrase affichée quand aucun angle mort n'est à lister.

    Ne dit jamais « aucun angle mort » si un check n'a pas été vérifié : ce qui
    n'a pas été évalué n'est jamais conforme.
    """
    if masques:
        return (
            f"0 angle mort de sévérité {NIVEAUX[min_severity]} ou plus "
            f"({gaps_label(masques)} sous ce seuil, masqués par --min-severity)."
        )
    if rapport.fully_verified and rapport.gap_count == 0:
        return "Aucun angle mort détecté : tous les checks ont été évalués."
    return "0 angle mort détecté parmi les checks évalués (voir « Non vérifié »)."


def synthesis(rapport: ReportView) -> str:
    """Synthèse du résumé final."""
    gaps = rapport.gap_count
    non_verifies = rapport.unverified_count
    if gaps == 0 and rapport.fully_verified:
        return "Synthèse : aucun angle mort détecté, tous les checks ont été évalués."
    phrase = f"Synthèse : {gaps_label(gaps)} détecté{'s' if gaps > 1 else ''}"
    if non_verifies:
        phrase += (
            f" ; {plural(non_verifies, 'check non vérifié', 'checks non vérifiés')}, "
            "au résultat inconnu"
        )
    if rapport.interrupted:
        phrase += " ; audit interrompu"
    if gaps == 0:
        phrase += " : la cible n'est pas pour autant conforme"
    return phrase + "."


def status_line(rapport: ReportView) -> str | None:
    """Avertissement d'en-tête : audit interrompu ou incomplet."""
    if rapport.interrupted:
        return "Audit interrompu : résultats partiels."
    if not rapport.complete or rapport.unverified_count:
        return "Audit incomplet : certains checks n'ont pas été vérifiés."
    return None


def unverified_detail(nv: UnverifiedView) -> tuple[str, str, str | None]:
    """Statut, motif et message (s'il apporte une information) d'un non vérifié.

    Le message est brut : à neutraliser ou échapper par le rendu.
    """
    statut = STATUT_NON_VERIFIE[nv.status.value]
    motif = "motif non précisé" if nv.reason is None else MOTIFS[nv.reason.value]
    message = nv.message.strip()
    if not message or message.casefold() == motif.casefold():
        return statut, motif, None
    return statut, motif, message


def summary_rows(
    rapport: ReportView, masques: int, min_severity: str
) -> list[tuple[str, int]]:
    """Lignes (libellé, nombre) du tableau récapitulatif, issues de ``summary``."""
    resume = rapport.summary
    lignes = [("Résultats", resume.total)]
    lignes += [
        (f"Résultats {STATUTS[s]} ({s})", resume.by_status[s])
        for s in (s.value for s in Status)
    ]
    lignes.append(("Angles morts", resume.gaps))
    lignes += [
        (f"Angles morts de sévérité {NIVEAUX[s]} ({s})", resume.by_severity[s])
        for s in SEVERITIES
    ]
    lignes.append(("Non évalués", resume.not_evaluated))
    lignes.append(("Exclus par l'utilisateur", resume.excluded))
    if masques:
        lignes.append((f"Masqués par --min-severity {min_severity}", masques))
    return lignes


def summary_lines(rapport: ReportView, masques: int, min_severity: str) -> list[str]:
    """Compteurs du résumé final, issus de ``summary`` (sans valeur hostile)."""
    resume = rapport.summary
    statuts = ", ".join(
        f"{STATUTS[s]} {resume.by_status[s]}" for s in (s.value for s in Status)
    )
    severites = ", ".join(f"{NIVEAUX[s]} {resume.by_severity[s]}" for s in SEVERITIES)
    lignes = [
        synthesis(rapport),
        f"Résultats : {resume.total} ; {statuts}",
        f"Angles morts : {resume.gaps} ; {severites}",
        f"Non évalués : {resume.not_evaluated} ; exclus par l'utilisateur : "
        f"{resume.excluded}",
    ]
    if masques:
        lignes.append(
            f"Masqués par --min-severity {min_severity} : {gaps_label(masques)}"
        )
    return lignes
