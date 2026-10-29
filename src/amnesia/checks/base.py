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

import hashlib
import json
import math
import os
import re
import subprocess
import unicodedata
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, fields
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePath
from traceback import extract_tb
from typing import TYPE_CHECKING, Any, TypeAlias, TypeVar

if TYPE_CHECKING:
    from ..facts import FactSet
    from ..target import Kind
    from .context import Context
    from .registry import Domain


# --- angle mort (Gap) : severite, preuve, references -------------------------

_E = TypeVar("_E", bound=StrEnum)


def _apercu(valeur: str, limite: int = 64) -> str:
    """Forme affichable d'une saisie : repr tronquée."""
    return repr(valeur if len(valeur) <= limite else valeur[:limite] + "...")


def _membre(enum: type[_E], valeur: object, champ: str) -> _E:
    """Membre de ``enum`` désigné par ``valeur`` (membre ou chaîne de sa valeur)."""
    if isinstance(valeur, enum):
        return valeur
    if not isinstance(valeur, str):
        raise TypeError(f"{champ} doit être une chaîne : {valeur!r}")
    try:
        return enum(valeur)
    except ValueError:
        valides = ", ".join(m.value for m in enum)
        raise ValueError(
            f"valeur inconnue pour {champ} : {_apercu(valeur)} ; "
            f"valeurs valides : {valides}"
        ) from None


class Severity(StrEnum):
    """Gravité d'un angle mort, de ``critical`` (la plus grave) à ``info``.

    Grille, définitions et exemples : docs/severite.md.

    Les comparaisons suivent ``rank`` (0 pour info, 4 pour critical), et non
    l'ordre alphabétique que le mixin ``str`` donnerait sinon (``critical`` <
    ``high`` < ``info`` < ``low`` < ``medium``) : ``Severity.MEDIUM <
    Severity.HIGH`` est vrai. Une Severity ne se compare qu'à une Severity
    (TypeError sinon) : une chaîne passe d'abord par ``Severity.parse()``.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Rang de gravité : 0 pour info, 4 pour critical."""
        return _RANG_DE_SEVERITE[self]

    @classmethod
    def parse(cls, valeur: str) -> Severity:
        """Severity de valeur ``valeur`` ; ValueError listant les 5 valeurs sinon."""
        return _membre(cls, valeur, "severity")

    def __lt__(self, other: object) -> bool:
        return self.rank < _rang(other)

    def __le__(self, other: object) -> bool:
        return self.rank <= _rang(other)

    def __gt__(self, other: object) -> bool:
        return self.rank > _rang(other)

    def __ge__(self, other: object) -> bool:
        return self.rank >= _rang(other)


_RANG_DE_SEVERITE: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _rang(autre: object) -> int:
    # jamais de repli sur la comparaison de str : elle serait alphabetique
    if not isinstance(autre, Severity):
        raise TypeError(
            f"une Severity ne se compare qu'à une Severity, pas à "
            f"{type(autre).__name__} (convertir avec Severity.parse())"
        )
    return autre.rank


class Confidence(StrEnum):
    """Degré de certitude d'une preuve.

    measured
        Valeur lue sur la cible. Ex. : taille maximale du journal Security.
    estimated
        Valeur extrapolée. Ex. : rétention déduite du débit d'événements.
    assumed
        Valeur supposée, faute de pouvoir la lire. Ex. : configuration par
        défaut de Windows.
    """

    MEASURED = "measured"
    ESTIMATED = "estimated"
    ASSUMED = "assumed"


# valeur JSON d'une preuve ; un datetime y est converti en ISO 8601 UTC
JSON: TypeAlias = (
    "bool | int | float | str | datetime | Sequence[JSON] | Mapping[str, JSON] | None"
)

# au-dela, une preuve est refusee : une sortie hostile ne doit pas epuiser la pile
_PROFONDEUR_MAX = 64
# entiers sur 64 bits (tailles en octets, compteurs) : au-dela, json.dumps leve
# (plus de 4300 chiffres) ou un lecteur JSON perd la valeur
_ENTIER_MIN = -(2**63)
_ENTIER_MAX = 2**64 - 1

# chemin d'une valeur dans la preuve : racine, puis cles et indices ; formate
# seulement en cas d'erreur, sans quoi son cout croitrait avec la taille des cles
_Chemin: TypeAlias = tuple[str | int, ...]


class _DictFige(Mapping[str, JSON]):
    """Dictionnaire en lecture seule d'une preuve.

    Picklable, contrairement à MappingProxyType : le moteur peut exécuter les
    checks dans d'autres processus.
    """

    __slots__ = ("_valeurs",)

    def __init__(self, valeurs: dict[str, JSON]) -> None:
        self._valeurs = valeurs

    def __getitem__(self, cle: str) -> JSON:
        return self._valeurs[cle]

    def __iter__(self) -> Iterator[str]:
        return iter(self._valeurs)

    def __len__(self) -> int:
        return len(self._valeurs)

    def __repr__(self) -> str:
        return repr(self._valeurs)


def _lisible(chemin: _Chemin) -> str:
    """Forme affichable d'un chemin : ``details['canaux'][1]``, clés tronquées."""
    racine, *suite = chemin
    return f"{racine}" + "".join(
        f"[{c}]" if isinstance(c, int) else f"[{_apercu(c)}]" for c in suite
    )


def _texte_utf8(valeur: str, chemin: _Chemin) -> str:
    """``valeur`` en ``str`` de base ; ValueError si l'UTF-8 strict la refuse."""
    # surrogate isole (nom de fichier non UTF-8 decode en surrogateescape) : le
    # rapport, ecrit en UTF-8, ne pourrait plus etre serialise
    try:
        valeur.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(
            f"{_lisible(chemin)} : surrogate isolé, non encodable en UTF-8 "
            "(le neutraliser avant, par exemple avec backslashreplace)"
        ) from None
    return str.__str__(valeur)


def _figer(valeur: object, chemin: _Chemin, profondeur: int = 0) -> JSON:
    """Copie figée et sérialisable en JSON de ``valeur`` ; lève sinon.

    Dictionnaires en ``_DictFige`` à clés ``str``, listes et tuples en tuples,
    datetime en ISO 8601 UTC ; les sous-classes (enums...) deviennent le type
    de base. Tout autre objet est refusé (TypeError), comme un flottant non
    fini, un entier hors de 64 bits, un texte non encodable en UTF-8 (surrogate
    isolé) ou un datetime sans fuseau (ValueError).
    """
    if profondeur > _PROFONDEUR_MAX:
        raise ValueError(
            f"{_lisible(chemin)} : preuve trop imbriquée "
            f"(plus de {_PROFONDEUR_MAX} niveaux)"
        )
    if valeur is None or isinstance(valeur, bool):
        return valeur
    if isinstance(valeur, int):
        if not _ENTIER_MIN <= valeur <= _ENTIER_MAX:
            raise ValueError(
                f"{_lisible(chemin)} : entier hors des bornes JSON (64 bits) : "
                f"{valeur.bit_length()} bits"
            )
        return int(valeur)
    if isinstance(valeur, float):
        if not math.isfinite(valeur):
            raise ValueError(
                f"{_lisible(chemin)} : flottant non fini, hors JSON : {valeur!r}"
            )
        return float(valeur)
    if isinstance(valeur, str):
        return _texte_utf8(valeur, chemin)
    if isinstance(valeur, datetime):
        if valeur.utcoffset() is None:
            raise ValueError(f"{_lisible(chemin)} : datetime sans fuseau horaire")
        return valeur.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(valeur, Mapping):
        copie: dict[str, JSON] = {}
        for cle, sous_valeur in valeur.items():
            if not isinstance(cle, str):
                raise TypeError(f"{_lisible(chemin)} : clé non textuelle {cle!r}")
            sous_chemin = (*chemin, cle)
            copie[_texte_utf8(cle, sous_chemin)] = _figer(
                sous_valeur, sous_chemin, profondeur + 1
            )
        return _DictFige(copie)
    if isinstance(valeur, list | tuple):
        return tuple(
            _figer(v, (*chemin, i), profondeur + 1) for i, v in enumerate(valeur)
        )
    raise TypeError(
        f"{_lisible(chemin)} : valeur non sérialisable en JSON "
        f"({type(valeur).__name__})"
    )


def _degeler(valeur: JSON) -> Any:
    """Forme JSON native (dict, list) d'une valeur figée par ``_figer``."""
    if isinstance(valeur, Mapping):
        return {cle: _degeler(v) for cle, v in valeur.items()}
    if isinstance(valeur, tuple):
        return [_degeler(v) for v in valeur]
    return valeur


def _verifier_identifiant(valeur: object, champ: str) -> None:
    # identifiant : ni sequence ANSI, ni retour chariot, ni bidi
    if not isinstance(valeur, str):
        raise TypeError(f"{champ} doit être une chaîne : {valeur!r}")
    if not valeur.strip():
        raise ValueError(f"{champ} doit être une chaîne non vide")
    if not valeur.isprintable():
        raise ValueError(f"{champ} non imprimable : {valeur!r}")


def _verifier_texte(valeur: object, champ: str) -> None:
    # texte libre : son rendu en terminal (#22) neutralise les caracteres de controle
    if not isinstance(valeur, str):
        raise TypeError(f"{champ} doit être une chaîne : {valeur!r}")
    if not valeur.strip():
        raise ValueError(f"{champ} doit être une chaîne non vide")
    _texte_utf8(valeur, (champ,))


def _verifier_jours(valeur: object, champ: str) -> None:
    if valeur is None:
        return
    if isinstance(valeur, bool) or not isinstance(valeur, int | float):
        raise TypeError(f"{champ} doit être un nombre de jours : {valeur!r}")
    if not (math.isfinite(valeur) and valeur >= 0):
        raise ValueError(f"{champ} invalide : {valeur!r}")


def _champs_du_dict(
    cls: type[Any], donnees: object, extras: frozenset[str] = frozenset()
) -> dict[str, Any]:
    """Champs de ``cls`` lus dans ``donnees`` : clé inconnue ou manquante refusée.

    Toutes les clés qu'écrit ``to_dict()`` sont exigées, celles des champs à
    valeur par défaut comprises : un rapport tronqué ou retouché ne doit pas
    perdre en silence un ``compromise_indicator`` ou des références. Seules les
    clés de ``extras`` (dérivées et revérifiées) sont facultatives.
    """
    nom = cls.__name__
    if not isinstance(donnees, Mapping):
        raise TypeError(f"{nom} : dictionnaire attendu, reçu {type(donnees).__name__}")
    champs = [f.name for f in fields(cls)]
    inconnues = [c for c in donnees if c not in champs and c not in extras]
    if inconnues:
        raise ValueError(
            f"{nom} : clé(s) inconnue(s) : {', '.join(map(repr, inconnues))}"
        )
    manquantes = [c for c in champs if c not in donnees]
    if manquantes:
        raise ValueError(f"{nom} : clé(s) manquante(s) : {', '.join(manquantes)}")
    return {c: v for c, v in donnees.items() if c in champs}


@dataclass(frozen=True, slots=True, kw_only=True)
class Evidence:
    """Preuve chiffrée d'un angle mort : ce qui a été observé, ce qui était attendu.

    - ``observed``, ``expected`` : valeurs JSON (nombre, booléen, texte...),
      exprimées dans ``unit`` (``bytes``, ``days``, ``bool``...) ;
    - ``observed_window_days``, ``required_window_days`` : fenêtre couverte et
      fenêtre exigée, en jours, quand la question porte sur une durée ;
    - ``confidence`` : valeur lue, extrapolée ou supposée (``Confidence``) ;
    - ``source`` : commande ou API lue, sans identifiants ; caviardée comme le
      message d'une ``ErrorInfo`` (identifiants dans une URL, /p:, -Password,
      password=...), en filet de sécurité ;
    - ``details`` : valeurs brutes (``max_size_bytes``, ``log_mode``,
      ``oldest_event_utc``...).

    Le contenu est validé et figé à la construction : tout doit être
    sérialisable en JSON, un datetime (avec fuseau) devient une chaîne ISO 8601
    UTC, et tout autre objet est refusé. Dictionnaires et listes sont copiés en
    lecture seule (listes en tuples) : la preuve ne change plus après coup.
    """

    observed: JSON = field(hash=False)
    expected: JSON = field(hash=False)
    unit: str | None = None
    observed_window_days: float | None = None
    required_window_days: float | None = None
    confidence: Confidence
    source: str
    details: Mapping[str, JSON] = field(default_factory=dict, hash=False)

    def __post_init__(self) -> None:
        for champ in ("observed", "expected"):
            object.__setattr__(self, champ, _figer(getattr(self, champ), (champ,)))
        if not isinstance(self.details, Mapping):
            raise TypeError(
                f"details doit être un dictionnaire : {type(self.details).__name__}"
            )
        object.__setattr__(self, "details", _figer(self.details, ("details",)))
        if self.unit is not None:
            _verifier_identifiant(self.unit, "unit")
        _verifier_jours(self.observed_window_days, "observed_window_days")
        _verifier_jours(self.required_window_days, "required_window_days")
        object.__setattr__(
            self, "confidence", _membre(Confidence, self.confidence, "confidence")
        )
        _verifier_identifiant(self.source, "source")
        # filet de securite : une ligne de commande recopiee telle quelle peut
        # porter le mot de passe d'audit (/p:, -Password, winrm://u:mdp@h) ;
        # caviardage idempotent, from_dict(to_dict()) reste symetrique
        object.__setattr__(self, "source", assainir(self.source))

    def to_dict(self) -> dict[str, Any]:
        """Forme sérialisable en JSON, à clés stables ; inverse de ``from_dict``."""
        return {
            "observed": _degeler(self.observed),
            "expected": _degeler(self.expected),
            "unit": self.unit,
            "observed_window_days": self.observed_window_days,
            "required_window_days": self.required_window_days,
            "confidence": self.confidence.value,
            "source": self.source,
            "details": _degeler(self.details),
        }

    @classmethod
    def from_dict(cls, donnees: Mapping[str, Any]) -> Evidence:
        """Evidence relue depuis ``to_dict()`` ; clé inconnue ou manquante refusée."""
        return cls(**_champs_du_dict(cls, donnees))


class ReferenceKind(StrEnum):
    """Référentiel d'une ``Reference``."""

    ATTACK = "attack"
    ANSSI = "anssi"
    MICROSOFT = "microsoft"
    CIS = "cis"
    OTHER = "other"


# technique (T1021, T1021.001) ou composant de donnees (DC0067)
_ID_ATTACK = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?|DC[0-9]{4}")
# Data Source, depreciee depuis ATT&CK v18
_DATA_SOURCE_ATTACK = re.compile(r"DS[0-9]{4}")
# https uniquement, sans identifiants (user@) : l'URL finit en lien dans le rapport.
# Hote en ASCII strict (re.ASCII : sans lui, IGNORECASE accepte le signe kelvin,
# le s long ou le i sans point dans [a-z], homographes d'un autre domaine).
# Chemin, requete et fragment limites aux caracteres de la RFC 3986, apostrophe
# exclue : " < > ` { } | \ ^ ' et le non-ASCII arrivent deja encodes en %XX.
# L'echappement au rendu HTML/PDF (#22) reste obligatoire.
_URL = re.compile(
    r"https://[a-z0-9.-]+(?::[0-9]{1,5})?"
    r"(?:[/?#][a-z0-9\-._~:/?#\[\]@!$&()*+,;=%]*)?",
    re.IGNORECASE | re.ASCII,
)


@dataclass(frozen=True, slots=True)
class Reference:
    """Référence externe d'un Gap : ATT&CK, ANSSI, Microsoft, CIS ou autre.

    Pour ATT&CK (``kind="attack"``), ``id`` désigne une technique
    (``T1021.001``) ou un composant de données (``DC0067``), et ``version`` est
    obligatoire (``v20``). Les Data Sources ``DSxxxx``, dépréciées depuis
    ATT&CK v18 (octobre 2025), sont refusées. ``url``, facultative, commence par
    ``https://``, a un hôte ASCII, ne porte pas d'identifiants et se limite aux
    caractères de la RFC 3986 (le reste s'encode en %XX) : elle devient un lien
    dans le rapport client, dont le rendu l'échappe malgré tout (#22).
    """

    kind: ReferenceKind
    id: str
    url: str | None = None
    version: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", _membre(ReferenceKind, self.kind, "kind"))
        _verifier_identifiant(self.id, "id")
        if self.version is not None:
            _verifier_identifiant(self.version, "version")
        if self.kind is ReferenceKind.ATTACK:
            if _DATA_SOURCE_ATTACK.fullmatch(self.id):
                raise ValueError(
                    f"{self.id} : les Data Sources ATT&CK (DSxxxx) sont dépréciées "
                    "depuis la v18 ; référencer un composant de données (DCxxxx)"
                )
            if not _ID_ATTACK.fullmatch(self.id):
                raise ValueError(
                    f"identifiant ATT&CK invalide {_apercu(self.id)} : attendu une "
                    "technique (T1021, T1021.001) ou un composant de données (DC0067)"
                )
            if self.version is None:
                raise ValueError(f"{self.id} : version ATT&CK obligatoire (ex. v20)")
        if self.url is not None:
            if not isinstance(self.url, str):
                raise TypeError(f"url doit être une chaîne : {self.url!r}")
            if not (_URL.fullmatch(self.url) and self.url.isprintable()):
                raise ValueError(
                    f"url invalide {_apercu(self.url)} : https://<hôte>/..., "
                    "sans identifiants"
                )

    def to_dict(self) -> dict[str, str | None]:
        """Forme sérialisable en JSON, à clés stables ; inverse de ``from_dict``."""
        return {
            "kind": self.kind.value,
            "id": self.id,
            "version": self.version,
            "url": self.url,
        }

    @classmethod
    def from_dict(cls, donnees: Mapping[str, Any]) -> Reference:
        """Reference relue depuis ``to_dict()`` ; clé inconnue ou manquante refusée."""
        return cls(**_champs_du_dict(cls, donnees))


def _cle_alphabetique(texte: str) -> str:
    # ordre alphabetique sans accents ni casse : « Était » avant « Qui »
    decompose = unicodedata.normalize("NFKD", texte)
    return "".join(c for c in decompose if not unicodedata.combining(c)).casefold()


@dataclass(frozen=True, slots=True, kw_only=True)
class Gap:
    """Une question d'enquête à laquelle on ne pourra PAS répondre, et pourquoi.

    Identification : le check qui l'a produit (``check_id``), la cible
    (``target``, forme normalisée ``Target.id``), la ressource en défaut
    (``resource`` : journal, GPO, objet AD, trail...) et, facultative tant que le
    catalogue (#46) n'existe pas, la question de référence (``question_id``).

    Contenu : la question (``question``), la raison (``reason``), la sévérité
    (``severity``, grille dans docs/severite.md) et la preuve chiffrée
    (``evidence``). Puis une remédiation courte, avec un chemin de GPO ou une
    commande (``remediation`` ; ``remediation_id`` servira à #76), des
    références (``references``) et ``compromise_indicator`` : le constat peut
    traduire une compromission (journal effacé...) et s'investigue avant de se
    corriger.

    Tous les champs se passent par mot-clé et sont validés à la construction
    (ValueError, TypeError) ; une sévérité donnée en chaîne est convertie par
    ``Severity.parse()``. ``sorted()`` applique le tri canonique : sévérité
    décroissante, puis question (ordre alphabétique, sans accents ni casse),
    puis cible. ``fingerprint`` identifie le constat indépendamment de son
    texte : dédoublonnage entre hôtes (#67) et comparaison d'audits (#142).

    Exemple du README : qui s'est connecté en RDP sur SRV-FILE il y a trois
    semaines ? Impossible : le journal Security fait 20 Mo et a été écrasé il y
    a 4 jours.

    >>> gap = Gap(
    ...     check_id="win.event_log_retention",
    ...     target="winrm://srv-file",
    ...     resource="Security",
    ...     question="Qui s'est connecté en RDP sur SRV-FILE il y a trois semaines ?",
    ...     reason="Le journal Security fait 20 Mo et a été écrasé il y a 4 jours.",
    ...     severity=Severity.HIGH,
    ...     evidence=Evidence(
    ...         observed=4,
    ...         expected=90,
    ...         unit="days",
    ...         observed_window_days=4,
    ...         required_window_days=90,
    ...         confidence=Confidence.MEASURED,
    ...         source="Get-WinEvent -LogName Security -Oldest -MaxEvents 1",
    ...         details={
    ...             "max_size_bytes": 20971520,
    ...             "log_mode": "Circular",
    ...             "oldest_event_utc": datetime(2026, 10, 17, 9, 30, tzinfo=UTC),
    ...         },
    ...     ),
    ...     remediation=(
    ...         "Porter le journal Security à 4 Go au moins par GPO : Configuration "
    ...         "ordinateur > Stratégies > Modèles d'administration > Composants "
    ...         "Windows > Service Journal des événements > Sécurité."
    ...     ),
    ...     references=(
    ...         Reference(
    ...             ReferenceKind.ATTACK,
    ...             "T1021.001",
    ...             url="https://attack.mitre.org/techniques/T1021/001/",
    ...             version="v20",
    ...         ),
    ...         Reference(ReferenceKind.ATTACK, "DC0067", version="v20"),
    ...     ),
    ... )
    >>> gap.severity.value, gap.severity.rank
    ('high', 3)
    >>> gap.evidence.details["oldest_event_utc"]
    '2026-10-17T09:30:00Z'
    >>> Gap.from_dict(gap.to_dict()) == gap
    True
    """

    check_id: str
    target: str
    resource: str
    question_id: str | None = None
    question: str
    reason: str
    severity: Severity
    evidence: Evidence
    remediation: str
    remediation_id: str | None = None
    references: tuple[Reference, ...] = ()
    compromise_indicator: bool = False

    def __post_init__(self) -> None:
        for champ in ("check_id", "target", "resource"):
            _verifier_identifiant(getattr(self, champ), champ)
        for champ in ("question_id", "remediation_id"):
            if getattr(self, champ) is not None:
                _verifier_identifiant(getattr(self, champ), champ)
        for champ in ("question", "reason", "remediation"):
            _verifier_texte(getattr(self, champ), champ)
        object.__setattr__(
            self, "severity", _membre(Severity, self.severity, "severity")
        )
        if not isinstance(self.evidence, Evidence):
            raise TypeError(f"evidence doit être une Evidence : {self.evidence!r}")
        if not isinstance(self.references, tuple) or not all(
            isinstance(r, Reference) for r in self.references
        ):
            raise TypeError(
                f"references doit être un tuple de Reference : {self.references!r}"
            )
        if not isinstance(self.compromise_indicator, bool):
            raise TypeError(
                f"compromise_indicator doit être un booléen : "
                f"{self.compromise_indicator!r}"
            )

    @property
    def fingerprint(self) -> str:
        """SHA-256 hexadécimal de check_id, question_id, target et resource.

        Indépendant de ``reason``, de la sévérité et de la preuve : le même
        constat garde la même empreinte d'un audit à l'autre. Les champs sont
        encodés en tableau JSON, sans ambiguïté de séparateur. Un
        ``CheckResult`` refuse deux Gaps de même empreinte : tant que
        ``question_id`` manque (#46), deux questions sur la même ressource
        exigent un ``question_id`` ou une ``resource`` distincte.
        """
        identite = json.dumps(
            [self.check_id, self.question_id, self.target, self.resource],
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return hashlib.sha256(identite.encode("utf-8")).hexdigest()

    def sort_key(self) -> tuple[int, str, str, str, str, str]:
        """Clé du tri canonique : sévérité décroissante, question, cible.

        Ressource et empreinte départagent les ex aequo : l'ordre est
        déterministe, d'un audit à l'autre.
        """
        return (
            -self.severity.rank,
            _cle_alphabetique(self.question),
            self.question,
            self.target,
            self.resource,
            self.fingerprint,
        )

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Gap):
            return NotImplemented
        return self.sort_key() < other.sort_key()

    def to_dict(self) -> dict[str, Any]:
        """Forme sérialisable en JSON, à clés stables ; inverse de ``from_dict``.

        Le schéma du rapport relève de #22.
        """
        return {
            "fingerprint": self.fingerprint,
            "check_id": self.check_id,
            "target": self.target,
            "resource": self.resource,
            "question_id": self.question_id,
            "question": self.question,
            "reason": self.reason,
            "severity": self.severity.value,
            "evidence": self.evidence.to_dict(),
            "remediation": self.remediation,
            "remediation_id": self.remediation_id,
            "references": [r.to_dict() for r in self.references],
            "compromise_indicator": self.compromise_indicator,
        }

    @classmethod
    def from_dict(cls, donnees: Mapping[str, Any]) -> Gap:
        """Gap relu depuis ``to_dict()``.

        Clé inconnue ou manquante refusée, valeurs par défaut comprises
        (``compromise_indicator``, ``references``...) ; ``fingerprint``,
        facultative car recalculée, doit correspondre aux champs relus
        (ValueError sinon).
        """
        champs = _champs_du_dict(cls, donnees, extras=frozenset({"fingerprint"}))
        champs["evidence"] = Evidence.from_dict(champs["evidence"])
        references = champs["references"]
        if not isinstance(references, list | tuple):
            raise TypeError(f"references doit être une liste : {references!r}")
        champs["references"] = tuple(Reference.from_dict(r) for r in references)
        gap = cls(**champs)
        empreinte = donnees.get("fingerprint")
        if empreinte is not None and empreinte != gap.fingerprint:
            raise ValueError(
                "fingerprint ne correspond pas à check_id, question_id, target "
                "et resource"
            )
        return gap


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


def assainir(texte: str) -> str:
    """Texte caviardé (secrets) et imprimable, prêt pour un message de résultat.

    Même traitement que le message d'``ErrorInfo`` : à appliquer à tout texte
    venu de la cible ou d'un collecteur (source d'un fait...) avant le rapport.
    """
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
        return assainir(texte)
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
        return "".join(assainir(ligne) + "\n" for ligne in lignes)
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
        # chaque Gap est rattache au check et a la cible du resultat
        empreintes: set[str] = set()
        for g in self.gaps:
            if (g.check_id, g.target) != (self.check_id, self.target):
                raise ValueError(
                    f"Gap de {g.check_id} sur {g.target} dans le résultat de "
                    f"{self.check_id} sur {self.target}"
                )
            # deux Gaps de meme empreinte : un dedoublonnage (#67, #142) en
            # perdrait un sans bruit ; on echoue des maintenant
            if g.fingerprint in empreintes:
                raise ValueError(
                    f"deux Gaps de {self.check_id} sur {self.target} ont la même "
                    f"empreinte (ressource {_apercu(g.resource)}) : renseigner "
                    "question_id ou distinguer resource"
                )
            empreintes.add(g.fingerprint)
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
            "gaps": [g.to_dict() for g in self.gaps],
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
