# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Modèle des faits : ``Fact``, ``FactSet`` et leur forme JSON versionnée.

Un fait est une donnée brute observée sur une cible (``windows.auditpol.backup``,
``windows.eventlog.config:Security``...), collectée une fois et lue par un ou
plusieurs checks. Il est soit observé (``ok``), soit indisponible
(``unavailable``) avec un motif :

- une clé de registre ou une option absente est une valeur observée (``None``),
  pas une indisponibilité : elle peut produire un Gap ;
- un fait indisponible (accès refusé, délai dépassé...) ne doit jamais en
  produire : ``resolve()`` le traduit en ``error``, ``skipped`` ou
  ``not_applicable``.

Clés : ``domaine.nom[.nom...][:qualificatif]``, domaine parmi ``FACT_DOMAINS``
(``windows``, ``ad``, ``m365``, ``aws``, ``siem``) ; le qualificatif désigne une
instance (``:Security``, ``:Microsoft-Windows-Sysmon/Operational``).

Minimisation (#41) : la valeur d'un fait observé suit le schéma fermé déclaré
pour son nom (``amnesia.privacy.FACT_SCHEMAS``) : clés admises, nature et
longueur de chaque valeur, listes bornées. Un fait sans schéma déclaré, une
clé inconnue ou une valeur d'une autre nature sont refusés
(``FactsFormatError``) ; un collecteur déclare ses schémas par
``amnesia.privacy.declare_fact_schema()``.

Forme JSON (enveloppe ``amnesia.facts/1``, JSON Schema
``amnesia/schemas/facts-1.schema.json``, documentation ``docs/dev/faits.md``) :

>>> from datetime import UTC, datetime
>>> instant = datetime(2026, 10, 21, 9, 30, tzinfo=UTC)
>>> faits = FactSet(
...     [
...         Fact.ok(
...             "windows.eventlog.config:Security",
...             {"max_size_bytes": 20971520, "log_mode": "Circular"},
...             source="Get-WinEvent -ListLog Security",
...             collected_at=instant,
...         ),
...         Fact.unavailable(
...             "windows.auditpol.backup",
...             UnavailableReason.ACCESS_DENIED,
...             source="auditpol /backup",
...             collected_at=instant,
...         ),
...     ]
... )
>>> faits.value("windows.eventlog.config:Security")["max_size_bytes"]
20971520
>>> faits.to_dict()["facts"]["windows.auditpol.backup"]["unavailable_reason"]
'access_denied'
>>> FactSet.from_dict(faits.to_dict()) == faits
True
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, TypeAlias

from ..inputs import UnsafeInputError, load_json
from ..privacy import check_fact_value, check_source, event_content_field

SCHEMA = "amnesia.facts/1"
FACT_DOMAINS = ("windows", "ad", "m365", "aws", "siem")

# qualificatif : nom de journal, de service... ; espaces simples permis
# (« Windows PowerShell »), jamais en tete ni en fin
_QUALIFICATIF = r"[A-Za-z0-9_./-]+(?: [A-Za-z0-9_./-]+)*"
# fullmatch et non match : « $ » accepterait un saut de ligne final. Recopie
# dans le JSON Schema (propertyNames) ; un test verifie la concordance.
FACT_NAME_PATTERN = (
    rf"(?:{'|'.join(FACT_DOMAINS)})(?:\.[a-z0-9_]+)+(?::{_QUALIFICATIF})?"
)
_FORMAT_NOM = re.compile(FACT_NAME_PATTERN)
_LONGUEUR_NOM_MAX = 256
# profondeur maximale d'une valeur : borne la recursion sur un JSON hostile
_PROFONDEUR_MAX = 32

# valeur d'un fait, figee : tuple pour une liste, mapping en lecture seule pour
# un objet JSON ; to_dict() rend des list et des dict
JSONValue: TypeAlias = (
    "bool | int | float | str | tuple[JSONValue, ...] | Mapping[str, JSONValue] | None"
)


class FactsFormatError(ValueError):
    """Faits refusés : enveloppe, version de schéma ou fait invalide."""


class FactStatus(StrEnum):
    """Statut d'un fait : observé (``ok``) ou indisponible (``unavailable``)."""

    OK = "ok"
    UNAVAILABLE = "unavailable"


class UnavailableReason(StrEnum):
    """Motif d'indisponibilité d'un fait (traduction : ``resolve()``)."""

    ACCESS_DENIED = "access_denied"
    TIMEOUT = "timeout"
    UNREACHABLE = "unreachable"
    UNSUPPORTED = "unsupported"
    NOT_COLLECTED = "not_collected"


def validate_fact_name(nom: object) -> str:
    """Rend ``nom`` s'il est une clé de fait valide ; lève FactsFormatError."""
    if not isinstance(nom, str):
        raise FactsFormatError(f"nom de fait : chaîne attendue, reçu {nom!r}")
    if len(nom) > _LONGUEUR_NOM_MAX or not _FORMAT_NOM.fullmatch(nom):
        raise FactsFormatError(
            f"nom de fait invalide : {nom[:80]!a} (attendu : "
            f"domaine.nom[:qualificatif], domaine parmi {', '.join(FACT_DOMAINS)})"
        )
    return nom


def _figer(valeur: object, nom: str, profondeur: int = 0) -> JSONValue:
    """Copie figée d'une valeur JSON ; lève FactsFormatError sinon.

    Un message ne cite que ``nom`` (le nom du fait) et une profondeur, jamais
    une clé de la valeur : dans un fait indexé par compte ou par poste, la clé
    est elle-même la donnée à ne pas faire sortir.
    """
    ou = f"{nom} (profondeur {profondeur})"
    if profondeur > _PROFONDEUR_MAX:
        raise FactsFormatError(f"{nom} : valeur trop imbriquée")
    if valeur is None or isinstance(valeur, bool | int | str):
        return valeur
    if isinstance(valeur, float):
        if not math.isfinite(valeur):
            raise FactsFormatError(f"{ou} : flottant non fini, hors JSON")
        return valeur
    if isinstance(valeur, list | tuple):
        return tuple(_figer(v, nom, profondeur + 1) for v in valeur)
    if isinstance(valeur, Mapping):
        copie: dict[str, JSONValue] = {}
        for cle, v in valeur.items():
            if not isinstance(cle, str):
                raise FactsFormatError(f"{ou} : clé non textuelle")
            # minimisation (#41) : le contenu d'un evenement ne devient jamais
            # un fait ; le nom cite est celui du module, pas la cle recue. Ce
            # filet nomme le refus ; la garantie est le schema ferme du fait
            # (_verifier_schema)
            refuse = event_content_field(cle)
            if refuse is not None:
                raise FactsFormatError(
                    f"{ou} : champ de contenu d'événement refusé ({refuse}) ; "
                    "seules des configurations et des métadonnées de journaux "
                    "sont collectées (docs/DONNEES.md)"
                )
            copie[cle] = _figer(v, nom, profondeur + 1)
        return MappingProxyType(copie)
    raise FactsFormatError(f"{ou} : type non JSON {type(valeur).__name__}")


def _verifier_schema(nom: str, valeur: JSONValue) -> None:
    """Refuse la valeur d'un fait observé qui sort de son schéma fermé (#41).

    Schéma par nom de fait (``amnesia.privacy.FACT_SCHEMAS``) : clés admises,
    nature et longueur des valeurs, listes bornées. Un fait sans schéma
    déclaré est refusé. Le message cite le nom du fait sans son qualificatif,
    un champ du schéma et une profondeur, jamais ce qui a été reçu.
    """
    try:
        check_fact_value(nom, valeur)
    except ValueError as exc:
        raise FactsFormatError(f"{nom.partition(':')[0]} : {exc}") from None


def _degeler(valeur: JSONValue) -> Any:
    if isinstance(valeur, tuple):
        return [_degeler(v) for v in valeur]
    if isinstance(valeur, Mapping):
        return {cle: _degeler(v) for cle, v in valeur.items()}
    return valeur


def _horodatage(valeur: datetime) -> str:
    texte = valeur.astimezone(UTC).isoformat()
    return texte.removesuffix("+00:00") + "Z"


@dataclass(frozen=True, slots=True)
class Fact:
    """Un fait collecté sur une cible ; validé à la construction.

    ``value`` est figée (tuples, mappings en lecture seule) : un même fait est
    lu par plusieurs checks, aucun ne doit pouvoir le modifier pour les autres.
    ``collected_at`` est ramené en UTC ; un horodatage sans fuseau est refusé.
    Construire de préférence par ``Fact.ok`` et ``Fact.unavailable``.
    """

    name: str
    status: FactStatus
    value: JSONValue
    unavailable_reason: UnavailableReason | None
    source: str
    collected_at: datetime

    def __post_init__(self) -> None:
        validate_fact_name(self.name)
        if not isinstance(self.status, FactStatus):
            raise FactsFormatError(f"{self.name} : status invalide {self.status!r}")
        raison = self.unavailable_reason
        if raison is not None and not isinstance(raison, UnavailableReason):
            raise FactsFormatError(
                f"{self.name} : unavailable_reason invalide {raison!r}"
            )
        if self.status is FactStatus.OK and raison is not None:
            raise FactsFormatError(
                f"{self.name} : fait ok avec un motif d'indisponibilité"
            )
        if self.status is FactStatus.UNAVAILABLE:
            if raison is None:
                raise FactsFormatError(f"{self.name} : fait indisponible sans motif")
            if self.value is not None:
                raise FactsFormatError(f"{self.name} : fait indisponible avec valeur")
        if not isinstance(self.source, str) or not self.source.strip():
            raise FactsFormatError(f"{self.name} : source vide")
        # rendu tel quel dans les journaux et le rapport : ni ANSI ni saut de ligne
        if not self.source.isprintable():
            raise FactsFormatError(f"{self.name} : source non imprimable")
        # minimisation (#41) : une source est une commande ou une API, bornee
        # en longueur ; le refus ne reprend pas la valeur
        try:
            check_source(self.source)
        except ValueError as exc:
            raise FactsFormatError(f"{self.name} : {exc}") from None
        if not isinstance(self.collected_at, datetime):
            raise FactsFormatError(f"{self.name} : collected_at doit être un datetime")
        decalage = self.collected_at.utcoffset()
        if decalage is None:
            raise FactsFormatError(f"{self.name} : collected_at sans fuseau horaire")
        if decalage != timedelta(0) or self.collected_at.tzinfo is not UTC:
            try:
                instant = self.collected_at.astimezone(UTC)
            except OverflowError:
                # 0001-01-01T00:00:00+01:00 : avant datetime.min une fois en UTC
                raise FactsFormatError(
                    f"{self.name} : collected_at hors limites"
                ) from None
            object.__setattr__(self, "collected_at", instant)
        object.__setattr__(self, "value", _figer(self.value, self.name))
        if self.status is FactStatus.OK:
            _verifier_schema(self.name, self.value)

    @property
    def available(self) -> bool:
        """Vrai si le fait a été observé (``ok``), même avec une valeur ``None``."""
        return self.status is FactStatus.OK

    @classmethod
    def ok(
        cls, name: str, value: object, *, source: str, collected_at: datetime
    ) -> Fact:
        """Fait observé ; ``None`` est une observation (clé ou option absente)."""
        return cls(name, FactStatus.OK, _figer(value, name), None, source, collected_at)

    @classmethod
    def unavailable(
        cls,
        name: str,
        reason: UnavailableReason,
        *,
        source: str,
        collected_at: datetime,
    ) -> Fact:
        """Fait qui n'a pas pu être observé, pour le motif ``reason``."""
        return cls(name, FactStatus.UNAVAILABLE, None, reason, source, collected_at)

    def to_dict(self) -> dict[str, Any]:
        """Forme JSON du fait, sans son nom (clé de l'enveloppe)."""
        raison = self.unavailable_reason
        return {
            "status": self.status.value,
            "value": _degeler(self.value),
            "unavailable_reason": None if raison is None else raison.value,
            "source": self.source,
            "collected_at": _horodatage(self.collected_at),
        }

    @classmethod
    def from_dict(cls, name: str, donnees: object) -> Fact:
        """Fait lu depuis sa forme JSON ; lève FactsFormatError."""
        validate_fact_name(name)
        if not isinstance(donnees, Mapping):
            raise FactsFormatError(f"{name} : objet JSON attendu")
        inconnus = sorted(set(donnees) - _CHAMPS_DU_FAIT)
        if inconnus:
            raise FactsFormatError(f"{name} : champ(s) inconnu(s) {inconnus}")
        manquants = sorted(_CHAMPS_REQUIS - set(donnees))
        if manquants:
            raise FactsFormatError(f"{name} : champ(s) manquant(s) {manquants}")
        try:
            statut = FactStatus(donnees["status"])
            brut = donnees.get("unavailable_reason")
            raison = None if brut is None else UnavailableReason(brut)
        except ValueError as exc:
            raise FactsFormatError(f"{name} : {exc}") from None
        horodatage = donnees["collected_at"]
        if not isinstance(horodatage, str):
            raise FactsFormatError(f"{name} : collected_at doit être une chaîne")
        try:
            instant = datetime.fromisoformat(horodatage)
        except ValueError:
            raise FactsFormatError(
                f"{name} : collected_at invalide {horodatage!r} (ISO 8601 attendu)"
            ) from None
        return cls(name, statut, donnees["value"], raison, donnees["source"], instant)


_CHAMPS_REQUIS = frozenset({"status", "value", "source", "collected_at"})
_CHAMPS_DU_FAIT = _CHAMPS_REQUIS | {"unavailable_reason"}


class FactSet(Mapping[str, Fact]):
    """Ensemble de faits d'une collecte, indexé par nom ; non modifiable.

    Un fait absent du ``FactSet`` n'a pas été collecté : ``resolve()`` le traite
    comme ``not_collected``.
    """

    __slots__ = ("_faits",)

    schema = SCHEMA

    def __init__(self, facts: Iterable[Fact] = ()) -> None:
        faits: dict[str, Fact] = {}
        for fait in facts:
            if not isinstance(fait, Fact):
                raise TypeError(f"FactSet : Fact attendu, reçu {fait!r}")
            if fait.name in faits:
                raise FactsFormatError(f"fait en double : {fait.name}")
            faits[fait.name] = fait
        self._faits = MappingProxyType(faits)

    def __getitem__(self, name: str) -> Fact:
        return self._faits[name]

    def __iter__(self) -> Iterator[str]:
        return iter(self._faits)

    def __len__(self) -> int:
        return len(self._faits)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FactSet):
            return NotImplemented
        return dict(self._faits) == dict(other._faits)

    def __repr__(self) -> str:
        return f"FactSet({sorted(self._faits)!r})"

    def value(self, name: str) -> JSONValue:
        """Valeur d'un fait observé ; KeyError s'il est absent ou indisponible.

        ``evaluate()`` n'est appelé qu'après ``resolve()`` : ses faits requis
        sont alors tous observés.
        """
        fait = self._faits.get(name)
        if fait is None or not fait.available:
            raise KeyError(f"fait {name} absent ou indisponible")
        return fait.value

    def subset(self, names: Iterable[str]) -> FactSet:
        """Faits de ``names`` présents dans cet ensemble (les autres sont omis)."""
        return FactSet(self._faits[n] for n in dict.fromkeys(names) if n in self)

    def to_dict(self) -> dict[str, Any]:
        """Enveloppe JSON versionnée, faits triés par nom."""
        return {
            "schema": self.schema,
            "facts": {n: self._faits[n].to_dict() for n in sorted(self._faits)},
        }

    @classmethod
    def from_dict(cls, donnees: object) -> FactSet:
        """Lit une enveloppe JSON ; rejette une version de schéma inconnue."""
        if not isinstance(donnees, Mapping):
            raise FactsFormatError("enveloppe de faits : objet JSON attendu")
        if "schema" not in donnees:
            raise FactsFormatError(f"enveloppe de faits sans champ schema ({SCHEMA})")
        version = donnees["schema"]
        if version != SCHEMA:
            raise FactsFormatError(
                f"version de schéma de faits inconnue : {ascii(version)[:80]} "
                f"(version prise en charge : {SCHEMA})"
            )
        inconnus = sorted(set(donnees) - {"schema", "facts"})
        if inconnus:
            raise FactsFormatError(
                f"enveloppe de faits : champ(s) inconnu(s) {inconnus}"
            )
        faits = donnees.get("facts")
        if not isinstance(faits, Mapping):
            raise FactsFormatError("enveloppe de faits : champ facts (objet) manquant")
        return cls(Fact.from_dict(nom, corps) for nom, corps in faits.items())


def load_facts(path: Path) -> FactSet:
    """Lit un fichier de faits JSON ; lève FactsFormatError.

    Le fichier peut venir d'un client (import de bundle, #52) : il se lit par
    ``amnesia.inputs``, qui plafonne sa taille et son imbrication et refuse les
    clés en double et les valeurs non finies. UTF-8, avec ou sans BOM (Windows
    PowerShell 5.1, ``Out-File -Encoding utf8``), ou UTF-16 avec BOM. Tout
    fichier illisible ou invalide lève FactsFormatError, jamais une autre
    exception.
    """
    try:
        donnees = load_json(path)
    except UnsafeInputError as exc:
        # message ecrit par amnesia.inputs : aucun contenu du fichier
        raise FactsFormatError(f"{path.name} : {exc}") from None
    try:
        return FactSet.from_dict(donnees)
    except FactsFormatError as exc:
        raise FactsFormatError(f"{path.name} : {exc}") from None
