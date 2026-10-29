"""Modèle d'un check, de son résultat et d'un angle mort (Gap).

Un check rend un ``CheckResult`` dont le statut dit ce qu'il a pu établir. Une
liste de Gaps vide ne suffit pas : elle ne distingue pas « vérifié, rien à
signaler » de « rien n'a pu être vérifié » (accès refusé, timeout, check non
implémenté...). Les confondre donnerait exactement le faux sentiment de sécurité
qu'amnesia doit dissiper.

Règle : ce qui n'a pas été évalué n'est jamais conforme.

- ``verified`` n'est vrai que pour ``pass``, ``gap`` et ``not_applicable`` ;
- ``compliant`` n'est vrai que pour ``pass`` ;
- ``error`` et ``skipped`` sont comptés à part : ``excluded`` pour le motif
  ``user_excluded``, ``not_evaluated`` pour tous les autres motifs.

Statuts (``Status``)
--------------------
pass
    Le check a évalué la cible et n'a trouvé aucun angle mort.
    Ex. : le journal Security de dc01 fait 4 Go et couvre 120 jours.
gap
    Le check a évalué la cible et trouvé au moins un angle mort (Gap).
    Ex. : le journal Security de srv-file fait 20 Mo et a été écrasé il y a
    4 jours ; la question « qui s'est connecté en RDP ? » reste sans réponse.
error
    Le check a été lancé mais n'a pas pu conclure. Porte un motif d'erreur et
    une ``ErrorInfo``. Ex. : WinRM refuse la lecture du journal Security de dc01.
skipped
    Le check n'a pas été exécuté. Porte un motif de saut.
    Ex. : l'utilisateur a retiré win.sysmon du périmètre de l'audit.
not_applicable
    Le check a été évalué et ne concerne pas la cible : sans objet, ni conforme
    ni en défaut. Ex. : un check propre aux contrôleurs de domaine lancé sur un
    serveur de fichiers.

Motifs (``Reason``)
-------------------
Motifs de ``skipped`` (le check n'a pas été exécuté) :

user_excluded
    Exclu à la demande de l'utilisateur ; compté comme « exclu », pas comme
    « non évalué ». Ex. : win.sysmon retiré du périmètre par l'auditeur.
missing_privilege
    Privilège insuffisant détecté avant l'exécution (détection : #42).
    Ex. : lire le journal Security exige SeSecurityPrivilege, absent du jeton.
not_implemented
    Le check n'est pas encore écrit.
    Ex. : win.time_sync, dont evaluate() lève encore NotImplementedError.
not_collected
    Le fait nécessaire est absent des données disponibles.
    Ex. : bundle hors ligne collecté sans la configuration Sysmon.

Motifs de ``error`` (le check a échoué en cours d'exécution) :

access_denied
    La cible a refusé l'accès pendant l'exécution.
    Ex. : ``wevtutil gl Security`` renvoie « Accès refusé » sur dc01.
timeout
    Délai dépassé. Ex. : la requête WMI sur dc01 ne répond pas en 30 s.
unreachable
    Cible injoignable. Ex. : port WinRM 5986 fermé ou nom DNS introuvable.
internal_error
    Exception inattendue, bug d'amnesia ou du check.
    Ex. : ``KeyError`` sur une sortie de commande au format imprévu.

Exemple :

>>> r = CheckResult.skipped(
...     "win.sysmon", "dc01", Reason.USER_EXCLUDED, "retiré du périmètre"
... )
>>> r.verified, r.compliant, r.excluded, r.not_evaluated
(False, False, True, False)
>>> r.to_dict()["status"], r.to_dict()["reason"]
('skipped', 'user_excluded')
"""

from __future__ import annotations

import math
import os
import re
import subprocess
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import PurePath
from traceback import extract_tb
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..facts import FactSet
    from ..target import Kind
    from .context import Context
    from .registry import Domain


@dataclass
class Gap:
    """Une question d'enquête à laquelle on ne pourra PAS répondre, et pourquoi."""

    question: str
    reason: str
    severity: str = "medium"  # low | medium | high


class Check:
    """Un contrôle de forensic readiness. Les sous-classes implémentent evaluate().

    Un check ne joint jamais la cible : il déclare les faits qu'il lit
    (``requires_facts``), un collecteur les rassemble (``amnesia.facts``) et le
    moteur (#21) n'appelle ``evaluate()`` que si ``resolve()`` les trouve tous
    observés. Documentation : ``docs/dev/faits.md``.

    Métadonnées déclarées en attributs de classe, validées et figées en
    ``CheckMeta`` par ``@register`` (``amnesia.checks.registry``) :

    - obligatoires : ``id`` (``domaine.nom``), ``title``, ``description``,
      ``domain``, ``target_kinds``, ``version`` (incrémentée quand la logique
      change) et ``default_severity`` ;
    - vides par défaut : ``requires_facts`` (#20) et ``question_ids`` (#46).
    """

    id: str
    title: str
    description: str
    domain: Domain
    target_kinds: tuple[Kind, ...]
    version: int
    default_severity: str
    # cles des faits lus par evaluate() (windows.auditpol.backup...), sans doublon
    requires_facts: tuple[str, ...] = ()
    question_ids: tuple[str, ...] = ()

    def evaluate(self, facts: FactSet, ctx: Context) -> CheckResult:
        """Évalue les faits requis, sans aucune I/O ; rend pass ou gap.

        Fonction pure : ni processus, ni réseau, ni fichier, ni horloge système
        (``ctx.clock``). Les faits requis sont tous observés, mais leur valeur
        peut être ``None`` (clé ou option absente), qui peut produire un Gap.
        """
        raise NotImplementedError("check non implémenté — voir docs/ROADMAP.md")


# StrEnum (3.11+) : str() et format() rendent la valeur (« pass »), et non
# « Status.PASS » comme un (str, Enum) depuis 3.11. to_dict() passe malgre tout
# par .value, pour ne pas dependre de ce detail.
class Status(StrEnum):
    """Statut d'un résultat de check (définitions : docstring du module)."""

    PASS = "pass"  # noqa: S105 - statut, pas un mot de passe
    GAP = "gap"
    ERROR = "error"
    SKIPPED = "skipped"
    NOT_APPLICABLE = "not_applicable"


class Reason(StrEnum):
    """Motif d'un résultat skipped ou error (définitions : docstring du module)."""

    # skipped : le check n'a pas ete execute
    USER_EXCLUDED = "user_excluded"
    MISSING_PRIVILEGE = "missing_privilege"
    NOT_IMPLEMENTED = "not_implemented"
    NOT_COLLECTED = "not_collected"
    # error : le check a echoue en cours d'execution
    ACCESS_DENIED = "access_denied"
    TIMEOUT = "timeout"
    UNREACHABLE = "unreachable"
    INTERNAL_ERROR = "internal_error"

    @property
    def status(self) -> Status:
        """Le seul statut auquel ce motif peut être associé."""
        return _STATUT_DU_MOTIF[self]


_STATUT_DU_MOTIF: dict[Reason, Status] = {
    Reason.USER_EXCLUDED: Status.SKIPPED,
    Reason.MISSING_PRIVILEGE: Status.SKIPPED,
    Reason.NOT_IMPLEMENTED: Status.SKIPPED,
    Reason.NOT_COLLECTED: Status.SKIPPED,
    Reason.ACCESS_DENIED: Status.ERROR,
    Reason.TIMEOUT: Status.ERROR,
    Reason.UNREACHABLE: Status.ERROR,
    Reason.INTERNAL_ERROR: Status.ERROR,
}

# statuts pour lesquels la cible a effectivement ete evaluee
_STATUTS_VERIFIES = frozenset({Status.PASS, Status.GAP, Status.NOT_APPLICABLE})
# statuts qui exigent un motif (et un motif compatible)
_STATUTS_A_MOTIF = frozenset({Status.ERROR, Status.SKIPPED})


def _motifs(status: Status) -> str:
    return ", ".join(m.value for m in Reason if m.status is status)


# --- texte tire d'une exception ---------------------------------------------
# Message et trace finissent dans le rapport client. Ils viennent de la stdlib,
# d'une bibliotheque tierce ou de la sortie d'un hote audite (potentiellement
# compromis) : on les caviarde, puis on neutralise leurs caracteres de contrôle.

_MASQUE = "***"
_CAVIARDAGES: tuple[tuple[re.Pattern[str], str], ...] = (
    # identifiants dans une URL (winrm://audit:mdp@dc01) ; le mot de passe peut
    # contenir « @ » : on masque jusqu'au dernier
    (re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^\s:@/]*):\S*@"), rf"\1:{_MASQUE}@"),
    # /p:mdp, /password:mdp (wevtutil, schtasks...)
    (re.compile(r"(?i)(?<![\w/])(/p(?:assword)?:)\S+"), rf"\1{_MASQUE}"),
    # -p mdp, -Password mdp, --password=mdp
    (
        re.compile(r"(?i)(?<![\w-])(--?p(?:ass(?:word)?)?)(\s+|=)\S+"),
        rf"\1\2{_MASQUE}",
    ),
    # password=mdp, pwd: mdp, client_secret=..., access_token=..., api_key=...
    (
        re.compile(
            r"(?i)(?<![a-z0-9])(pass(?:word|wd|phrase)?|pwd|secret|token|"
            r"api[_-]?key)(\s*[=:]\s*)\S+"
        ),
        rf"\1\2{_MASQUE}",
    ),
    # Authorization: Bearer <jeton>
    (re.compile(r"(?i)(\bbearer\s+)\S+"), rf"\1{_MASQUE}"),
)


def _assainir(texte: str) -> str:
    for motif, remplacement in _CAVIARDAGES:
        texte = motif.sub(remplacement, texte)
    # sequences ANSI, retours chariot, bidi : rendus visibles (\x1b, \r, \u202e)
    return "".join(
        c if c.isprintable() else c.encode("unicode_escape").decode("ascii")
        for c in texte
    )


def _executable(cmd: Any) -> str:
    # executable seul : les arguments peuvent porter un mot de passe (/p:...)
    if isinstance(cmd, list | tuple):
        return PurePath(os.fsdecode(cmd[0])).name if cmd else ""
    # chaine passee au shell : premier mot
    mots = os.fsdecode(cmd).split(maxsplit=1)
    return PurePath(mots[0]).name if mots else ""


def _message_de(exc: BaseException) -> str:
    """Message caviardé de l'exception ; ne lève jamais."""
    try:
        # str() de ces deux exceptions recopie toute la ligne de commande
        if isinstance(exc, subprocess.CalledProcessError):
            texte = f"commande {_executable(exc.cmd)!r} : code {exc.returncode}"
        elif isinstance(exc, subprocess.TimeoutExpired):
            texte = f"commande {_executable(exc.cmd)!r} : délai de {exc.timeout} s"
        else:
            texte = str(exc)
        return _assainir(texte)
    except Exception:
        # __str__ defaillant : le resultat error doit exister quand meme
        return "<message illisible>"


def _trace_de(exc: BaseException) -> str:
    """Frames de l'exception seules ; ne lève jamais.

    Ni message, ni exceptions chaînées (__cause__, __context__), ni notes : ils
    peuvent porter le secret qu'un check a justement écarté de son exception.
    Nom de fichier sans son chemin, qui révélerait la machine de l'auditeur.
    """
    try:
        lignes = ["Traceback (most recent call last):"]
        for f in extract_tb(exc.__traceback__):
            fichier = PurePath(f.filename).name
            lignes.append(f'  File "{fichier}", line {f.lineno}, in {f.name}')
            if f.line:
                lignes.append(f"    {f.line}")
        return "".join(_assainir(ligne) + "\n" for ligne in lignes)
    except Exception:
        return "<trace illisible>"


@dataclass(frozen=True, slots=True)
class ErrorInfo:
    """Exception à l'origine d'un statut error.

    ``message`` et ``traceback`` finissent dans le rapport client.
    ``from_exception`` reprend donc ``str(exc)`` caviardé (identifiants dans une
    URL, /p:, -p, password=...) et sans caractères de contrôle ; pour une erreur
    de subprocess, seul l'exécutable est gardé. Ce caviardage est un filet de
    sécurité : un check ne met toujours aucun secret dans ses exceptions. La
    trace n'est conservée que sur demande explicite (``with_traceback=True``),
    réduite aux frames.
    """

    type: str
    message: str
    traceback: str | None = None

    @classmethod
    def from_exception(
        cls, exc: BaseException, *, with_traceback: bool = False
    ) -> ErrorInfo:
        t = type(exc)
        nom = t.__qualname__
        if t.__module__ != "builtins":
            nom = f"{t.__module__}.{nom}"
        trace = _trace_de(exc) if with_traceback else None
        return cls(type=nom, message=_message_de(exc), traceback=trace)

    def to_dict(self) -> dict[str, str | None]:
        return {"type": self.type, "message": self.message, "traceback": self.traceback}


@dataclass(frozen=True, slots=True)
class CheckResult:
    """Résultat d'un check sur une cible : un statut, et ses Gaps s'il y en a.

    Les invariants sont vérifiés à la construction (ValueError, TypeError) ;
    passer de préférence par les constructeurs ``passed``, ``with_gaps``,
    ``skipped``, ``not_applicable`` et ``failed``. ``message`` reste du texte
    libre : son rendu en terminal (#22) neutralise les caractères de contrôle.
    """

    check_id: str
    target: str  # identifiant normalise de la cible (type dedie : #18)
    status: Status
    gaps: tuple[Gap, ...] = ()
    reason: Reason | None = None
    message: str = ""
    error: ErrorInfo | None = None
    duration_s: float | None = None

    def __post_init__(self) -> None:
        self._verifier_types()
        self._verifier_invariants()

    def _verifier_types(self) -> None:
        for champ in ("check_id", "target"):
            valeur = getattr(self, champ)
            if not isinstance(valeur, str) or not valeur:
                raise ValueError(f"{champ} doit être une chaîne non vide : {valeur!r}")
            # identifiant normalise : ni sequence ANSI, ni retour chariot, ni bidi
            if not valeur.isprintable():
                raise ValueError(f"{champ} non imprimable : {valeur!r}")
        if not isinstance(self.status, Status):
            raise TypeError(f"status doit être un Status : {self.status!r}")
        if not isinstance(self.gaps, tuple) or not all(
            isinstance(g, Gap) for g in self.gaps
        ):
            raise TypeError(f"gaps doit être un tuple de Gap : {self.gaps!r}")
        if self.reason is not None and not isinstance(self.reason, Reason):
            raise TypeError(f"reason doit être un Reason ou None : {self.reason!r}")
        if not isinstance(self.message, str):
            raise TypeError(f"message doit être une chaîne : {self.message!r}")
        if self.error is not None and not isinstance(self.error, ErrorInfo):
            raise TypeError(f"error doit être un ErrorInfo ou None : {self.error!r}")
        if self.duration_s is not None and (
            isinstance(self.duration_s, bool)
            or not isinstance(self.duration_s, int | float)
        ):
            raise TypeError(f"duration_s doit être un nombre : {self.duration_s!r}")

    def _verifier_invariants(self) -> None:
        statut = self.status.value
        # gap <=> au moins un Gap
        if self.status is Status.GAP and not self.gaps:
            raise ValueError("statut gap sans aucun Gap")
        if self.status is not Status.GAP and self.gaps:
            raise ValueError(f"statut {statut} avec {len(self.gaps)} Gap(s)")
        # error et skipped exigent un motif compatible ; les autres n'en ont pas
        if self.status in _STATUTS_A_MOTIF:
            if self.reason is None:
                raise ValueError(
                    f"statut {statut} sans motif (attendu : {_motifs(self.status)})"
                )
            if self.reason.status is not self.status:
                raise ValueError(
                    f"motif {self.reason.value} incompatible avec le statut "
                    f"{statut} (attendu : {_motifs(self.status)})"
                )
        elif self.reason is not None:
            raise ValueError(
                f"statut {statut} : aucun motif attendu, reçu {self.reason.value}"
            )
        # error <=> ErrorInfo renseignee
        if self.status is Status.ERROR and self.error is None:
            raise ValueError("statut error sans ErrorInfo")
        if self.status is not Status.ERROR and self.error is not None:
            raise ValueError(f"statut {statut} avec une ErrorInfo")
        if self.duration_s is not None and not (
            math.isfinite(self.duration_s) and self.duration_s >= 0
        ):
            raise ValueError(f"duration_s invalide : {self.duration_s!r}")

    @property
    def verified(self) -> bool:
        """Vrai si la cible a été évaluée : pass, gap ou not_applicable."""
        return self.status in _STATUTS_VERIFIES

    @property
    def compliant(self) -> bool:
        """Vrai pour pass uniquement : ce qui n'est pas évalué n'est pas conforme."""
        return self.status is Status.PASS

    @property
    def excluded(self) -> bool:
        """Exclu par l'utilisateur (skipped / user_excluded), compté à part."""
        return self.reason is Reason.USER_EXCLUDED

    @property
    def not_evaluated(self) -> bool:
        """error, ou skipped pour un autre motif que user_excluded."""
        return not self.verified and not self.excluded

    @classmethod
    def passed(
        cls,
        check_id: str,
        target: str,
        *,
        message: str = "",
        duration_s: float | None = None,
    ) -> CheckResult:
        return cls(
            check_id, target, Status.PASS, message=message, duration_s=duration_s
        )

    @classmethod
    def with_gaps(
        cls,
        check_id: str,
        target: str,
        gaps: Iterable[Gap],
        *,
        message: str = "",
        duration_s: float | None = None,
    ) -> CheckResult:
        # un iterable vide leve ValueError : il ne devient jamais un pass
        return cls(
            check_id,
            target,
            Status.GAP,
            gaps=tuple(gaps),
            message=message,
            duration_s=duration_s,
        )

    @classmethod
    def skipped(
        cls,
        check_id: str,
        target: str,
        reason: Reason,
        message: str,
        *,
        duration_s: float | None = None,
    ) -> CheckResult:
        return cls(
            check_id,
            target,
            Status.SKIPPED,
            reason=reason,
            message=message,
            duration_s=duration_s,
        )

    @classmethod
    def not_applicable(
        cls,
        check_id: str,
        target: str,
        message: str,
        *,
        duration_s: float | None = None,
    ) -> CheckResult:
        return cls(
            check_id,
            target,
            Status.NOT_APPLICABLE,
            message=message,
            duration_s=duration_s,
        )

    @classmethod
    def failed(
        cls,
        check_id: str,
        target: str,
        reason: Reason,
        exc: BaseException,
        *,
        message: str | None = None,
        with_traceback: bool = False,
        duration_s: float | None = None,
    ) -> CheckResult:
        info = ErrorInfo.from_exception(exc, with_traceback=with_traceback)
        return cls(
            check_id,
            target,
            Status.ERROR,
            reason=reason,
            message=(info.message or info.type) if message is None else message,
            error=info,
            duration_s=duration_s,
        )

    def to_dict(self) -> dict[str, Any]:
        """Forme sérialisable à clés stables ; enums rendus par leur .value.

        Le schéma du rapport relève de #22.
        """
        return {
            "check_id": self.check_id,
            "target": self.target,
            "status": self.status.value,
            "reason": None if self.reason is None else self.reason.value,
            "message": self.message,
            # Gap.to_dict() arrive avec le modèle Gap v1 (#16)
            "gaps": [asdict(g) for g in self.gaps],
            "error": None if self.error is None else self.error.to_dict(),
            "duration_s": self.duration_s,
        }


class CheckSkipped(Exception):
    """Levée par un check qui ne peut pas s'exécuter (motif de skipped).

    Le moteur (#21) la convertit en résultat skipped. Un motif d'erreur
    (timeout, access_denied...) est refusé : c'est une exception ordinaire.
    """

    def __init__(self, reason: Reason, message: str) -> None:
        if not isinstance(reason, Reason):
            raise TypeError(f"reason doit être un Reason : {reason!r}")
        if reason.status is not Status.SKIPPED:
            raise ValueError(
                f"motif {reason.value} invalide pour CheckSkipped "
                f"(attendu : {_motifs(Status.SKIPPED)})"
            )
        # tous les arguments dans args : copy et pickle reconstruisent l'exception
        super().__init__(reason, message)
        self.reason = reason
        self.message = message

    def __str__(self) -> str:
        return f"{self.reason.value}: {self.message}"


class NotApplicable(Exception):
    """Levée par un check sans objet sur la cible ; convertie en not_applicable."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message
