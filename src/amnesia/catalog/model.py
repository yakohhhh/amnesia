# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Modèle du catalogue : questions d'enquête, sources de télémétrie, rendu.

Une **question** est ce que l'enquêteur demandera le jour de l'incident (« Qui
s'est connecté en RDP sur SRV-FILE il y a trois semaines ? »). Une **source**
est la télémétrie qui permet d'y répondre : un événement (canal, fournisseur,
Event IDs, filtres) ou un réglage (synchronisation horaire), avec ses
prérequis (sous-catégorie d'audit, valeur de registre, canal activé, SACL).
Les sources d'une question sont des alternatives : une seule suffit.

Ce module ne fait aucune I/O : il décrit les objets, rend le texte d'une
question et humanise une durée. La lecture des fichiers TOML et leur validation
sont dans ``amnesia.catalog.loader`` ; le format est documenté dans
docs/catalogue.md.

Exemple :

>>> humanize_days(21), humanize_days(4), humanize_days(60)
('trois semaines', '4 jours', 'deux mois')
"""

from __future__ import annotations

import string
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from enum import StrEnum

from ..checks.base import FORMAT_QUESTION_ID, Reference, Severity, assainir
from ..checks.registry import Domain

# variables d'un gabarit de question ; {lookback} vient de lookback_days
PLACEHOLDERS = ("host", "lookback", "account", "share")
# longueur maximale d'une valeur rendue dans une question : un nom DNS complet
# fait 255 caracteres au plus. Au-dela, la valeur est tronquee avant
# assainir(), dont le caviardage est quadratique sur certaines entrees
# (« a.a.a. ») : un hote hostile ne bloque pas l'audit par un nom demesure
_LONGUEUR_VALEUR_MAX = 256
_TRONCATURE = "..."


class CatalogError(ValueError):
    """Catalogue invalide : ``errors`` porte une ligne par erreur, localisée.

    Chaque ligne nomme le fichier, l'entrée et le champ en cause
    (``questions/windows.toml : question n° 3 (Q-WIN-RDP-LOGON) : sources :
    source inconnue 'SRC-X'``).
    """

    def __init__(self, *errors: str) -> None:
        # toutes les erreurs dans args : copy et pickle reconstruisent l'exception
        super().__init__(*errors)
        self.errors: tuple[str, ...] = errors

    def __str__(self) -> str:
        return "\n".join(self.errors)


class UnknownIdError(LookupError):
    """Identifiant de question ou de source absent du catalogue."""


class QuestionStatus(StrEnum):
    """État d'une question dans le catalogue.

    active
        Au moins un check du registre y contribue.
    planned
        Aucun check n'y contribue encore : la question est décrite, pas évaluée.
    deprecated
        Remplacée par ``replaced_by`` ; elle reste dans le catalogue, car son
        identifiant figure dans des rapports déjà remis.
    """

    ACTIVE = "active"
    PLANNED = "planned"
    DEPRECATED = "deprecated"

    @property
    def label(self) -> str:
        """Libellé français, pour l'affichage."""
        return _LIBELLE_DU_STATUT[self]


_LIBELLE_DU_STATUT: dict[QuestionStatus, str] = {
    QuestionStatus.ACTIVE: "active",
    QuestionStatus.PLANNED: "prévue",
    QuestionStatus.DEPRECATED: "dépréciée",
}


class Theme(StrEnum):
    """Thème d'enquête d'une question ; l'ordre est celui de l'affichage."""

    AUTHENTICATION = "authentication"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"
    ANTI_FORENSICS = "anti_forensics"

    @property
    def label(self) -> str:
        """Libellé français, pour l'affichage."""
        return _LIBELLE_DU_THEME[self]


_LIBELLE_DU_THEME: dict[Theme, str] = {
    Theme.AUTHENTICATION: "Authentification",
    Theme.EXECUTION: "Exécution",
    Theme.PERSISTENCE: "Persistance",
    Theme.LATERAL_MOVEMENT: "Mouvement latéral",
    Theme.EXFILTRATION: "Exfiltration",
    Theme.ANTI_FORENSICS: "Anti-forensic",
}


class Role(StrEnum):
    """Rôle d'hôte auquel une question s'applique."""

    DC = "dc"
    SERVER = "server"
    WORKSTATION = "workstation"

    @property
    def label(self) -> str:
        """Libellé français, pour l'affichage."""
        return _LIBELLE_DU_ROLE[self]


_LIBELLE_DU_ROLE: dict[Role, str] = {
    Role.DC: "contrôleur de domaine",
    Role.SERVER: "serveur",
    Role.WORKSTATION: "poste",
}


class SourceKind(StrEnum):
    """Nature d'une source : événement journalisé ou réglage de l'hôte."""

    EVENT = "event"
    SETTING = "setting"


class PrerequisiteKind(StrEnum):
    """Ce qui doit être en place pour qu'une source produise sa télémétrie.

    audit_subcategory
        Sous-catégorie de la stratégie d'audit avancée (``guid``, ``name``),
        en succès (``success``), en échec (``failure``) ou les deux.
    registry_value
        Valeur de registre (``key``, ``name``, ``value``).
    channel_enabled
        Canal de journal d'événements activé (``channel``).
    sacl
        Entrée d'audit sur un objet (``object`` ; ``guids`` : droits étendus
        à auditer, s'il y en a).
    """

    AUDIT_SUBCATEGORY = "audit_subcategory"
    REGISTRY_VALUE = "registry_value"
    CHANNEL_ENABLED = "channel_enabled"
    SACL = "sacl"


@dataclass(frozen=True, slots=True, kw_only=True)
class Prerequisite:
    """Prérequis d'une source ; les champs renseignés dépendent de ``kind``."""

    kind: PrerequisiteKind
    guid: str | None = None
    name: str | None = None
    success: bool = False
    failure: bool = False
    key: str | None = None
    value: str | int | None = None
    channel: str | None = None
    object: str | None = None
    guids: tuple[str, ...] = ()

    def describe(self) -> str:
        """Prérequis en une ligne, pour ``amnesia catalog show``."""
        if self.kind is PrerequisiteKind.AUDIT_SUBCATEGORY:
            modes = [
                libelle
                for actif, libelle in (
                    (self.success, "succès"),
                    (self.failure, "échec"),
                )
                if actif
            ]
            return (
                f"sous-catégorie d'audit « {self.name} » {self.guid} "
                f"({' et '.join(modes)})"
            )
        if self.kind is PrerequisiteKind.REGISTRY_VALUE:
            return f"registre {self.key}\\{self.name} = {self.value}"
        if self.kind is PrerequisiteKind.CHANNEL_ENABLED:
            return f"canal {self.channel} activé"
        droits = f" ({', '.join(self.guids)})" if self.guids else ""
        return f"entrée d'audit (SACL) sur {self.object}{droits}"


# valeur d'un filtre d'evenement : LogonType = 10, Properties = [guid, guid]
FilterValue = str | int | tuple[str | int, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class Source:
    """Source de télémétrie : ce qu'il faut journaliser pour répondre.

    ``event`` : ``channel``, ``provider``, ``event_ids`` et, s'il y en a,
    ``filters`` (champ de l'événement et valeur attendue : ``LogonType = 10``).
    ``setting`` : ``setting`` nomme le réglage. ``enabled_by_default`` vaut
    ``None`` tant que le comportement d'une installation par défaut n'est pas
    établi (à confirmer sur des hôtes de référence, #50).
    """

    id: str
    kind: SourceKind
    domain: Domain
    title: str
    channel: str | None = None
    provider: str | None = None
    event_ids: tuple[int, ...] = ()
    filters: tuple[tuple[str, FilterValue], ...] = ()
    setting: str | None = None
    prerequisites: tuple[Prerequisite, ...] = ()
    enabled_by_default: bool | None = None

    def summary(self) -> str:
        """Canal, Event IDs et filtres en une ligne (ou le réglage)."""
        if self.kind is SourceKind.SETTING:
            return f"réglage : {self.setting}"
        ids = ", ".join(str(i) for i in self.event_ids)
        resume = f"{self.channel} {ids}"
        if self.filters:
            filtres = ", ".join(f"{c} = {_valeur(v)}" for c, v in self.filters)
            resume += f" ({filtres})"
        return resume


def _valeur(valeur: FilterValue) -> str:
    if isinstance(valeur, tuple):
        return " ou ".join(str(v) for v in valeur)
    return str(valeur)


def placeholders_of(template: str) -> tuple[str, ...]:
    """Variables d'un gabarit, dans l'ordre ; ValueError hors du vocabulaire.

    Un gabarit n'emploie que ``{host}``, ``{lookback}``, ``{account}`` et
    ``{share}``, sans conversion, format ni accès à un attribut (``{host!r}``,
    ``{host:>9}``, ``{host.x}``) : il est rendu sans ``str.format``.
    """
    return tuple(champ for _, champ in _segments(template) if champ is not None)


def _segments(gabarit: str) -> list[tuple[str, str | None]]:
    """Paires (texte littéral, variable qui le suit ou None)."""
    try:
        analyse = list(string.Formatter().parse(gabarit))
    except ValueError as exc:
        raise ValueError(f"gabarit mal formé ({exc})") from None
    segments: list[tuple[str, str | None]] = []
    for litteral, champ, format_, conversion in analyse:
        if champ is not None and (
            champ not in PLACEHOLDERS or format_ or conversion is not None
        ):
            permis = ", ".join(f"{{{p}}}" for p in PLACEHOLDERS)
            raise ValueError(
                f"variable de gabarit inconnue ou mise en forme : "
                f"{{{champ}}} (variables permises : {permis})"
            )
        segments.append((litteral, champ))
    return segments


@dataclass(frozen=True, slots=True, kw_only=True)
class Question:
    """Question d'enquête du catalogue.

    ``id`` est immuable et jamais réutilisé (docs/RELEASING.md) ; ``text`` est
    le gabarit français (``text_en`` reste vide jusqu'à #138) et ``why`` ce que
    l'enquête perd sans réponse. ``sources`` et ``checks`` sont des
    identifiants : sources du catalogue (une seule suffit) et checks du
    registre. ``scenarios`` est réservé à #75.
    """

    id: str
    status: QuestionStatus
    domain: Domain
    theme: Theme
    roles: tuple[Role, ...]
    text: str
    why: str
    severity_default: Severity
    sources: tuple[str, ...]
    checks: tuple[str, ...] = ()
    scenarios: tuple[str, ...] = ()
    references: tuple[Reference, ...] = ()
    replaced_by: str | None = None
    text_en: str = ""
    why_en: str = ""

    def __post_init__(self) -> None:
        if not FORMAT_QUESTION_ID.fullmatch(self.id):
            raise ValueError(f"identifiant de question invalide : {self.id!r}")
        # un gabarit hors vocabulaire est refuse ici : render() ne leve plus
        placeholders_of(self.text)

    @property
    def placeholders(self) -> tuple[str, ...]:
        """Variables du gabarit, dans l'ordre et sans doublon."""
        return tuple(dict.fromkeys(placeholders_of(self.text)))

    def render(
        self,
        *,
        host: str | None = None,
        lookback_days: int | None = None,
        account: str | None = None,
        share: str | None = None,
    ) -> str:
        """Texte de la question pour un contexte donné.

        ``lookback_days`` (entier >= 1) alimente ``{lookback}``, rendu par
        ``humanize_days()``. Une variable du gabarit sans valeur lève
        ``ValueError`` ; une valeur que le gabarit n'emploie pas est ignorée,
        pour qu'une reformulation du catalogue ne casse aucun check. Les
        valeurs viennent de la cible : elles sont caviardées et rendues
        imprimables (``assainir``), après troncature à 256 caractères (suivis
        de « ... »). Une valeur démesurée est tronquée, jamais refusée : une
        exception ferait du Gap une erreur interne, et un hôte hostile
        masquerait ainsi l'angle mort.
        """
        employees = self.placeholders
        valeurs: dict[str, str] = {}
        for nom, valeur in (("host", host), ("account", account), ("share", share)):
            if valeur is None:
                continue
            if not isinstance(valeur, str):
                raise TypeError(f"{nom} doit être une chaîne : {valeur!r}")
            if not valeur.strip():
                raise ValueError(f"{nom} doit être une chaîne non vide")
            if nom not in employees:
                # ignoree sans etre caviardee : aucun cout pour une valeur inutile
                continue
            if len(valeur) > _LONGUEUR_VALEUR_MAX:
                valeur = valeur[:_LONGUEUR_VALEUR_MAX] + _TRONCATURE
            valeurs[nom] = assainir(valeur)
        if lookback_days is not None:
            valeurs["lookback"] = humanize_days(lookback_days)
        manquantes = [p for p in self.placeholders if p not in valeurs]
        if manquantes:
            attendus = ", ".join(
                "lookback_days" if p == "lookback" else p for p in manquantes
            )
            raise ValueError(
                f"question {self.id} : valeur manquante pour {attendus} "
                f"(gabarit : {self.text!r})"
            )
        return "".join(
            litteral + (valeurs[champ] if champ is not None else "")
            for litteral, champ in _segments(self.text)
        )


class Catalog:
    """Catalogue validé : questions et sources, par identifiant.

    Construit par ``amnesia.catalog.loader`` (``load_catalog()`` pour le
    catalogue embarqué). ``version`` est la version CalVer du fichier
    ``VERSION``, recopiée dans ``tool.catalog_version`` du rapport.
    """

    __slots__ = ("_questions", "_sources", "_version")

    def __init__(
        self, version: str, questions: Iterable[Question], sources: Iterable[Source]
    ) -> None:
        self._version = version
        self._questions = {q.id: q for q in sorted(questions, key=lambda q: q.id)}
        self._sources = {s.id: s for s in sorted(sources, key=lambda s: s.id)}

    @property
    def version(self) -> str:
        """Version CalVer du catalogue (``2026.11.0``)."""
        return self._version

    @property
    def questions(self) -> tuple[Question, ...]:
        """Questions, triées par identifiant."""
        return tuple(self._questions.values())

    @property
    def sources(self) -> tuple[Source, ...]:
        """Sources, triées par identifiant."""
        return tuple(self._sources.values())

    def __contains__(self, question_id: object) -> bool:
        # une valeur non hachable (liste...) n'est simplement pas une question
        return isinstance(question_id, str) and question_id in self._questions

    def __iter__(self) -> Iterator[Question]:
        return iter(self._questions.values())

    def __len__(self) -> int:
        return len(self._questions)

    def __repr__(self) -> str:
        return (
            f"Catalog(version={self._version!r}, questions={len(self._questions)}, "
            f"sources={len(self._sources)})"
        )

    def question(self, question_id: str) -> Question:
        """Question d'identifiant ``question_id`` ; ``UnknownIdError`` sinon."""
        try:
            return self._questions[question_id]
        except (KeyError, TypeError):
            raise UnknownIdError(
                f"question inconnue du catalogue {self._version} : {question_id!r}"
            ) from None

    def source(self, source_id: str) -> Source:
        """Source d'identifiant ``source_id`` ; ``UnknownIdError`` sinon."""
        try:
            return self._sources[source_id]
        except (KeyError, TypeError):
            raise UnknownIdError(
                f"source inconnue du catalogue {self._version} : {source_id!r}"
            ) from None

    def sources_of(self, question_id: str) -> tuple[Source, ...]:
        """Sources alternatives d'une question, dans l'ordre du catalogue."""
        return tuple(self.source(s) for s in self.question(question_id).sources)

    def questions_of_check(self, check_id: str) -> tuple[Question, ...]:
        """Questions auxquelles le check ``check_id`` contribue, triées par id."""
        return tuple(q for q in self if check_id in q.checks)

    def render(
        self,
        question_id: str,
        *,
        host: str | None = None,
        lookback_days: int | None = None,
        account: str | None = None,
        share: str | None = None,
    ) -> str:
        """Texte de la question ``question_id`` (``Question.render``)."""
        return self.question(question_id).render(
            host=host, lookback_days=lookback_days, account=account, share=share
        )


# nombres ecrits en lettres jusqu'a douze ; au-dela, en chiffres (« 13 mois »)
_EN_LETTRES = (
    "zéro",
    "un",
    "deux",
    "trois",
    "quatre",
    "cinq",
    "six",
    "sept",
    "huit",
    "neuf",
    "dix",
    "onze",
    "douze",
)
# unites essayees de la plus longue a la plus courte : (jours, singulier,
# pluriel, feminin)
_UNITES = (
    (365, "an", "ans", False),
    (30, "mois", "mois", False),
    (7, "semaine", "semaines", True),
)


def humanize_days(days: int) -> str:
    """Durée en français : « 4 jours », « deux semaines », « deux mois ».

    Un multiple exact de 365, de 30 ou de 7 jours se dit en années, en mois ou
    en semaines, le nombre en lettres jusqu'à douze ; toute autre durée reste
    en jours, en chiffres. ``days`` est un entier >= 1.

    >>> [humanize_days(n) for n in (1, 4, 7, 14, 21, 30, 60, 90, 365)]
    ... # doctest: +NORMALIZE_WHITESPACE
    ['1 jour', '4 jours', 'une semaine', 'deux semaines', 'trois semaines',
     'un mois', 'deux mois', 'trois mois', 'un an']
    """
    if isinstance(days, bool) or not isinstance(days, int):
        raise TypeError(f"lookback_days doit être un entier de jours : {days!r}")
    if days < 1:
        raise ValueError(f"lookback_days doit être >= 1 : {days!r}")
    for jours, singulier, pluriel, feminin in _UNITES:
        nombre, reste = divmod(days, jours)
        if reste:
            continue
        if nombre == 1:
            return f"{'une' if feminin else 'un'} {singulier}"
        quantite = _EN_LETTRES[nombre] if nombre < len(_EN_LETTRES) else str(nombre)
        return f"{quantite} {pluriel}"
    return f"{days} jour" if days == 1 else f"{days} jours"
