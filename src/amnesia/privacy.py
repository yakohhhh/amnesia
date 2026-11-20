# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Minimisation des données collectées (RGPD, art. 5.1.c et 25).

Règle : seules des configurations et des métadonnées de journaux sortent de la
cible, jamais le contenu d'un événement. Un 4624 porte un compte, un domaine,
une adresse IP et un nom de poste : des données personnelles (art. 4), qu'un
audit de configuration n'a aucune raison de traiter. Ce module est la source
unique de ce qui est admis ; ``docs/DONNEES.md`` en est l'inventaire lisible.

- ``PERSONAL_FIELDS`` : les seules données personnelles admises, chacune avec
  sa finalité et l'endroit où elle est écrite. Trois viennent de la collecte
  ou de son exécution ; la quatrième, le nom que l'auditeur déclare lui-même
  dans le fichier de mission, n'est jamais lue sur la cible ;
- ``FACT_SCHEMAS`` et ``check_fact_value()`` : schéma fermé de la valeur de
  chaque fait, par nom de fait. Clés admises, nature et longueur de chaque
  valeur, listes bornées ; un fait sans schéma déclaré est refusé. Un
  collecteur déclare les siens par ``declare_fact_schema()`` ;
- ``event_content_field()`` : nom d'un champ de contenu d'événement
  (``Message``, ``Properties``, ``UserId``, ``MachineName``, champs
  d'``EventData``), reconnu quelle que soit sa graphie. ``amnesia.facts.model``
  refuse tout fait qui en porte un ; ce second filet nomme ce qui est refusé,
  le schéma fermé reste la garantie ;
- ``EVIDENCE_FIELDS`` et ``check_evidence()`` : schéma fermé de la preuve d'un
  Gap (nombres, durées, horodatages, noms de paramètres). Une clé hors schéma
  est refusée à la construction de l'``Evidence``, avant toute copie
  (``check_evidence_keys()``) ;
- ``TextFormat`` : les seules formes qu'un texte peut prendre dans un fait ou
  une preuve (énumération, ou motif borné : nom de journal, nom de
  paramètre, GUID...). Aucune nature n'admet un texte libre ;
- ``REPORT_TEXT_FIELDS`` et ``report_text_violations()`` : champs texte admis
  dans le rapport JSON, contrôlés par ``amnesia.report`` avant toute écriture ;
- ``check_script_privacy()`` : verdict sur l'inventaire de l'AST d'un script
  PowerShell (``scripts/inventaire_ps.ps1``), en complément de
  ``amnesia.readonly.check_script_inventory``. Une propriété de contenu
  d'événement, ou un résultat de ``Get-WinEvent`` qui n'est pas projeté
  aussitôt sur des métadonnées de ``EVENT_METADATA``, est un écart.

Aucun message de ce module ne reprend une valeur reçue, ni une clé qu'il ne
connaît pas : un refus ne doit pas faire sortir ce qu'il refuse.
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final

# --- donnees personnelles admises -------------------------------------------------


@dataclass(frozen=True, slots=True)
class PersonalField:
    """Donnée personnelle admise : ce qu'elle est, pourquoi, où elle est écrite."""

    name: str
    description: str
    purpose: str
    location: str


PERSONAL_FIELDS: Final[tuple[PersonalField, ...]] = (
    PersonalField(
        "host_name",
        "noms d'hôtes et FQDN des cibles auditées",
        "rattacher chaque constat à la machine concernée",
        "rapport (targets[].id, results[].target, gaps[].target), journal d'exécution",
    ),
    PersonalField(
        "admin_account",
        "UPN ou noms des comptes d'administration utilisés ou cités par une "
        "configuration",
        "tracer le compte qui a servi à la collecte et désigner le compte "
        "qu'une remédiation concerne",
        "journal d'exécution ; rapport seulement si une configuration le cite",
    ),
    PersonalField(
        "operator_account",
        "compte local de l'auditeur qui a lancé l'audit",
        "imputer l'exécution dans le journal d'exécution (#40)",
        "journal d'exécution seulement, jamais le rapport remis au client",
    ),
    PersonalField(
        "declared_auditor",
        "nom de l'auditeur ou de l'équipe, tel que l'auditeur le déclare dans le "
        "fichier de mission (amnesia.toml)",
        "identifier l'auteur du livrable auprès du client",
        "rapport (mission.auditor), seulement si le fichier de mission le renseigne",
    ),
)
"""Seules données personnelles admises ; tout autre champ personnel est refusé."""


# --- contenu d'evenement : jamais hors de la cible --------------------------------

EVENT_PROPERTIES: Final = ("Message", "Properties", "UserId", "MachineName")
"""Propriétés d'un événement qu'aucun script de collecte ne lit ni ne nomme."""

EVENT_METADATA: Final = (
    "TimeCreated",
    "RecordId",
    "Id",
    "LogName",
    "ProviderName",
    "Level",
)
"""Seules propriétés d'un événement qu'un script de collecte peut lire.

Liste fermée : horodatage, rang dans le journal, identifiant du type
d'événement, journal, fournisseur et niveau. Aucune ne désigne une personne,
un poste ou une adresse. Toute autre propriété est refusée, ``PSObject`` et
``BaseObject`` comprises, qui rendraient l'événement entier.
"""

EVENT_METHODS: Final = ("ToXml", "FormatDescription")
"""Méthodes d'un événement qui en rendent le contenu entier."""

EVENT_DATA_FIELDS: Final = (
    "EventData",
    "UserData",
    "TargetUserName",
    "TargetDomainName",
    "TargetUserSid",
    "TargetLogonId",
    "SubjectUserName",
    "SubjectDomainName",
    "SubjectUserSid",
    "SubjectLogonId",
    "IpAddress",
    "IpPort",
    "WorkstationName",
    "Xml",
    "User",
    "UserName",
    "AccountName",
    "AccountDomain",
    "Computer",
    "ComputerName",
    "LogonId",
    "TargetSid",
    "ProcessName",
    "CommandLine",
    "ParentCommandLine",
)
"""Champs d'``EventData`` et de l'enveloppe d'un événement (4624, 4625, 4688...).

Liste noire, donc incomplète par nature : elle sert à nommer ce qui est refusé.
La garantie est le schéma fermé des faits (``FACT_SCHEMAS``), qui refuse toute
clé qu'il ne déclare pas.
"""

_HORS_CLE: Final = re.compile(r"[^a-z0-9]")


def normalize_key(key: str) -> str:
    """Forme de comparaison d'une clé : NFKC, ``casefold``, puis ``[a-z0-9]`` seuls.

    ``Message``, ``MESSAGE``, ``message`` suivi d'espaces ou d'une espace sans
    chasse (U+200B), sa forme en pleine chasse (U+FF2D...), ``Msg-`` ou
    ``target_user_name`` contre ``TargetUserName`` : aucune de ces graphies ne
    distingue deux clés. Un homoglyphe d'un autre alphabet n'est pas ramené à
    sa lettre latine : il est refusé par le schéma fermé des faits, qui ne
    connaît que ses propres clés.
    """
    return _HORS_CLE.sub("", unicodedata.normalize("NFKC", key).casefold())


_CONTENU_D_EVENEMENT: Final[Mapping[str, str]] = MappingProxyType(
    {normalize_key(nom): nom for nom in (*EVENT_PROPERTIES, *EVENT_DATA_FIELDS)}
)
_PROPRIETES: Final[Mapping[str, str]] = MappingProxyType(
    {nom.casefold(): nom for nom in EVENT_PROPERTIES}
)
_METADONNEES: Final = frozenset(nom.casefold() for nom in EVENT_METADATA)
_METHODES: Final[Mapping[str, str]] = MappingProxyType(
    {nom.casefold(): nom for nom in EVENT_METHODS}
)


def event_content_field(key: object) -> str | None:
    """Nom canonique du champ de contenu d'événement que désigne ``key``.

    La comparaison porte sur ``normalize_key()`` : ni la casse, ni les
    espaces, ni la ponctuation, ni les formes de compatibilité Unicode ne
    distinguent deux clés. Rend ``None`` pour toute autre clé. Le nom rendu
    vient de ce module, jamais de l'entrée : il peut figurer dans un message
    d'erreur.
    """
    if not isinstance(key, str):
        return None
    return _CONTENU_D_EVENEMENT.get(normalize_key(key))


# --- natures et formes de texte ---------------------------------------------------


class Nature(StrEnum):
    """Nature d'une valeur de preuve ou de fait."""

    NUMBER = "number"
    DURATION = "duration"
    TIMESTAMP = "timestamp"
    BOOLEAN = "boolean"
    SETTING = "setting"
    RECORD = "record"
    """Objet aux champs déclarés ; dans un fait seulement, jamais une preuve."""


class TextFormat(StrEnum):
    """Forme d'un texte de nature ``SETTING`` qui n'est pas une énumération.

    Vocabulaire fermé : un schéma choisit une de ces formes, il n'écrit pas
    son propre motif. Aucune n'admet un saut de ligne, une ponctuation de
    phrase ou un texte de longueur libre.
    """

    CHANNEL = "channel"
    PARAMETER = "parameter"
    IDENTIFIER = "identifier"
    GUID = "guid"
    HASH = "hash"
    VERSION = "version"


@dataclass(frozen=True, slots=True)
class _Forme:
    motif: re.Pattern[str]
    longueur: int
    description: str


_JETON_DE_JOURNAL: Final = r"[A-Za-z0-9_./-]+"

_FORMES: Final[Mapping[TextFormat, _Forme]] = MappingProxyType(
    {
        TextFormat.CHANNEL: _Forme(
            # espaces simples permis (« Windows PowerShell »), jamais en tete
            # ni en fin : meme forme que le qualificatif d'un nom de fait
            re.compile(rf"{_JETON_DE_JOURNAL}(?: {_JETON_DE_JOURNAL})*", re.ASCII),
            128,
            "nom de journal d'événements",
        ),
        TextFormat.PARAMETER: _Forme(
            # sans espace : une valeur de registre, un chemin de cle, un GUID
            # de sous-categorie, jamais une phrase
            re.compile(r"[A-Za-z0-9_.:\\/{}*-]+", re.ASCII),
            256,
            "nom ou valeur de paramètre, sans espace",
        ),
        TextFormat.IDENTIFIER: _Forme(
            re.compile(r"[A-Za-z0-9_.*-]+", re.ASCII),
            128,
            "nom de service ou de module",
        ),
        TextFormat.GUID: _Forme(
            re.compile(
                r"\{?[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}?", re.ASCII
            ),
            38,
            "GUID",
        ),
        TextFormat.HASH: _Forme(
            re.compile(r"[0-9A-Fa-f]{32,128}", re.ASCII), 128, "empreinte hexadécimale"
        ),
        TextFormat.VERSION: _Forme(
            re.compile(r"[0-9]{1,5}(?:\.[0-9]{1,5}){0,3}", re.ASCII),
            23,
            "numéro de version",
        ),
    }
)

SETTING_MAX_LENGTH: Final = 256
"""Longueur maximale d'un nom ou d'une valeur de paramètre, toutes formes."""

LIST_MAX_LENGTH: Final = 256
"""Nombre maximal d'éléments d'une liste dans un fait ou une preuve."""

NUMBER_MAX: Final = 2**63
"""Valeur absolue maximale d'un nombre dans un fait : au-delà, ce n'est plus
une mesure."""

SOURCE_MAX_LENGTH: Final = 256
"""Longueur maximale de la ``source`` d'un fait ou d'une preuve."""

# 2026-10-21T09:30:00.123456+00:00 : 32 caracteres
_HORODATAGE_MAX: Final = 40


def text_matches(value: object, form: TextFormat) -> bool:
    """Vrai si ``value`` est un texte de la forme ``form``, longueur comprise."""
    if not isinstance(value, str):
        return False
    forme = _FORMES[form]
    # la longueur d'abord : le motif ne parcourt jamais un texte demesure
    return len(value) <= forme.longueur and forme.motif.fullmatch(value) is not None


def check_source(value: object, field: str = "source") -> None:
    """Vérifie la ``source`` d'un fait ou d'une preuve ; lève ``ValueError`` sinon.

    Une source est une commande ou une API, pas un contenu : texte
    imprimable d'une ligne (ni saut de ligne, ni caractère de contrôle), de
    ``SOURCE_MAX_LENGTH`` caractères au plus. Le message ne reprend pas la
    valeur.
    """
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > SOURCE_MAX_LENGTH
        or not value.isprintable()
    ):
        raise ValueError(
            f"{field} hors schéma : commande ou API, sur une ligne imprimable de "
            f"{SOURCE_MAX_LENGTH} caractères au plus"
        )


def _scalaire_conforme(
    valeur: object,
    nature: Nature,
    choices: tuple[str, ...] = (),
    form: TextFormat | None = None,
    *,
    borne: bool = False,
) -> bool:
    """Vrai si ``valeur`` est de la nature déclarée ; ``None`` est toujours admis.

    ``borne`` (faits) : un nombre est fini et de valeur absolue ``NUMBER_MAX``
    au plus.
    """
    if valeur is None:
        return True
    if nature is Nature.BOOLEAN:
        return isinstance(valeur, bool)
    if nature in (Nature.NUMBER, Nature.DURATION):
        if isinstance(valeur, bool) or not isinstance(valeur, int | float):
            return False
        if borne:
            # un entier demesure ne passe pas par math.isfinite (OverflowError)
            if isinstance(valeur, float) and not math.isfinite(valeur):
                return False
            if abs(valeur) > NUMBER_MAX:
                return False
        return nature is Nature.NUMBER or valeur >= 0
    if nature is Nature.TIMESTAMP:
        if isinstance(valeur, datetime):
            return valeur.utcoffset() is not None
        if not isinstance(valeur, str) or len(valeur) > _HORODATAGE_MAX:
            return False
        try:
            return datetime.fromisoformat(valeur).utcoffset() is not None
        except ValueError:
            return False
    if nature is Nature.SETTING:
        # jamais un texte libre : une enumeration, sinon une forme bornee
        if choices:
            return isinstance(valeur, str) and valeur in choices
        return form is not None and text_matches(valeur, form)
    return False


def _verifier_texte_declare(
    nom: str, nature: Nature, choices: tuple[str, ...], form: TextFormat | None
) -> None:
    """Refuse un champ ``SETTING`` sans énumération ni forme, ou avec les deux."""
    if nature is Nature.SETTING:
        if bool(choices) == (form is not None):
            raise ValueError(
                f"champ {nom!r} : un paramètre déclare une énumération (choices) "
                "ou une forme (format), l'une des deux seulement"
            )
    elif choices or form is not None:
        raise ValueError(f"champ {nom!r} : choices et format réservés aux paramètres")
    if any(
        not isinstance(c, str) or not c or len(c) > SETTING_MAX_LENGTH for c in choices
    ):
        raise ValueError(f"champ {nom!r} : énumération invalide")


# --- schema de la preuve d'un Gap -------------------------------------------------


@dataclass(frozen=True, slots=True)
class EvidenceField:
    """Clé admise dans la preuve d'un Gap, avec la nature de sa valeur.

    ``repeated`` : la valeur est une liste de valeurs de cette nature, de
    ``LIST_MAX_LENGTH`` éléments au plus. Un paramètre (``Nature.SETTING``)
    déclare son énumération (``choices``) ou sa forme (``format``).
    """

    name: str
    nature: Nature
    description: str
    repeated: bool = False
    choices: tuple[str, ...] = ()
    format: TextFormat | None = None

    def __post_init__(self) -> None:
        if self.nature is Nature.RECORD:
            raise ValueError(f"champ {self.name!r} : une preuve ne porte aucun objet")
        _verifier_texte_declare(self.name, self.nature, self.choices, self.format)


LOG_MODES: Final = ("Circular", "AutoBackup", "Retain")
"""Modes de rétention d'un journal d'événements (``LogMode``)."""

_CHAMPS_DE_PREUVE: Final = (
    EvidenceField(
        "max_size_bytes",
        Nature.NUMBER,
        "taille maximale du journal (MaximumSizeInBytes)",
    ),
    EvidenceField(
        "file_size_bytes", Nature.NUMBER, "taille du fichier du journal (FileSize)"
    ),
    EvidenceField(
        "record_count", Nature.NUMBER, "nombre d'enregistrements (RecordCount)"
    ),
    EvidenceField(
        "log_mode",
        Nature.SETTING,
        "mode de rétention du journal (LogMode : Circular, AutoBackup, Retain)",
        choices=LOG_MODES,
    ),
    EvidenceField(
        "oldest_event_utc", Nature.TIMESTAMP, "horodatage du plus ancien événement"
    ),
    EvidenceField(
        "newest_event_utc", Nature.TIMESTAMP, "horodatage du plus récent événement"
    ),
    EvidenceField(
        "events_per_day",
        Nature.NUMBER,
        "débit estimé : RecordCount / (plus récent - plus ancien)",
    ),
    EvidenceField(
        "retention_days", Nature.DURATION, "durée de conservation configurée, en jours"
    ),
    EvidenceField(
        "enabled", Nature.BOOLEAN, "journal, stratégie ou service activé ou non"
    ),
    EvidenceField(
        "setting",
        Nature.SETTING,
        "nom du paramètre en défaut (valeur de registre, GUID de sous-catégorie "
        "d'audit), sans espace",
        format=TextFormat.PARAMETER,
    ),
    EvidenceField(
        "settings",
        Nature.SETTING,
        "noms des paramètres en défaut, sans espace",
        repeated=True,
        format=TextFormat.PARAMETER,
    ),
    EvidenceField(
        "channels",
        Nature.SETTING,
        "noms des journaux concernés",
        repeated=True,
        format=TextFormat.CHANNEL,
    ),
)

EVIDENCE_FIELDS: Final[Mapping[str, EvidenceField]] = MappingProxyType(
    {champ.name: champ for champ in _CHAMPS_DE_PREUVE}
)
"""Schéma fermé de ``Evidence.details`` : une clé absente d'ici est refusée.

Un check qui a besoin d'une nouvelle valeur l'ajoute ici, avec sa nature, et
dans ``docs/DONNEES.md`` : la revue voit passer chaque donnée nouvelle.
"""

_HORS_SCHEMA: Final = (
    "clé hors du schéma des preuves (amnesia.privacy.EVIDENCE_FIELDS, docs/DONNEES.md)"
)


def check_evidence_keys(value: object, field: str = "details") -> None:
    """Refuse d'emblée une clé textuelle hors de ``EVIDENCE_FIELDS``.

    Ne lit que les clés d'un dictionnaire, jamais ses valeurs : appelé avant de
    figer une preuve, il évite de copier une valeur volumineuse pour la refuser
    ensuite. Tout autre objet, et une clé non textuelle, sont laissés au
    contrôle de type qui suit.
    """
    if isinstance(value, Mapping) and any(
        isinstance(cle, str) and cle not in EVIDENCE_FIELDS for cle in value
    ):
        raise ValueError(f"{field} : {_HORS_SCHEMA}")


def _valeur_de_preuve_conforme(valeur: object, champ: EvidenceField) -> bool:
    if not champ.repeated:
        return _scalaire_conforme(valeur, champ.nature, champ.choices, champ.format)
    if not isinstance(valeur, list | tuple) or len(valeur) > LIST_MAX_LENGTH:
        return False
    return all(
        v is not None
        and _scalaire_conforme(v, champ.nature, champ.choices, champ.format)
        for v in valeur
    )


def check_evidence(details: object, field: str = "details") -> None:
    """Vérifie un dictionnaire de preuve contre ``EVIDENCE_FIELDS`` ; lève sinon.

    ``ValueError`` pour une clé hors schéma ou une valeur d'une autre nature que
    celle déclarée (énumération, forme et longueur comprises ; une liste a
    ``LIST_MAX_LENGTH`` éléments au plus), ``TypeError`` si ``details`` n'est
    pas un dictionnaire. ``None`` est admis partout : la valeur est absente de
    la cible. Le message nomme une clé du schéma, jamais une clé inconnue ni
    une valeur.
    """
    if not isinstance(details, Mapping):
        raise TypeError(f"{field} doit être un dictionnaire")
    for cle, valeur in details.items():
        champ = EVIDENCE_FIELDS.get(cle) if isinstance(cle, str) else None
        if champ is None:
            raise ValueError(f"{field} : {_HORS_SCHEMA}")
        if not _valeur_de_preuve_conforme(valeur, champ):
            attendu = f"liste de {champ.nature.value}" if champ.repeated else ""
            raise ValueError(
                f"{field}[{champ.name!r}] : valeur hors schéma, "
                f"{attendu or champ.nature.value} attendu"
            )


def evidence_text_conforms(value: object) -> bool:
    """Vrai si ``value`` est un texte admis dans ``observed`` ou ``expected``.

    Un nom ou une valeur de paramètre (``TextFormat.PARAMETER`` : sans espace,
    donc jamais une phrase) ou un horodatage avec fuseau. Un nom de journal,
    qui peut porter des espaces, va dans ``details["channels"]`` ou dans la
    ressource du Gap.
    """
    if not isinstance(value, str):
        return False
    return text_matches(value, TextFormat.PARAMETER) or _scalaire_conforme(
        value, Nature.TIMESTAMP
    )


def check_evidence_value(value: object, field: str) -> None:
    """Vérifie ``observed`` ou ``expected`` : scalaire, liste plate ou dictionnaire.

    Un texte suit ``evidence_text_conforms()`` ; une liste a
    ``LIST_MAX_LENGTH`` éléments au plus ; un dictionnaire suit
    ``EVIDENCE_FIELDS``.
    """
    if isinstance(value, Mapping):
        check_evidence(value, field)
        return
    if isinstance(value, list | tuple):
        if len(value) > LIST_MAX_LENGTH:
            raise ValueError(
                f"{field} : valeur hors schéma, liste de {LIST_MAX_LENGTH} "
                "éléments au plus attendue"
            )
        elements: tuple[object, ...] = tuple(value)
    else:
        elements = (value,)
    for element in elements:
        if element is None or isinstance(element, bool | int | float | datetime):
            continue
        if evidence_text_conforms(element):
            continue
        raise ValueError(
            f"{field} : valeur hors schéma, nombre, booléen, horodatage ou "
            "paramètre sans espace attendu"
        )


# --- schema ferme des faits -------------------------------------------------------

_NOM_DE_CHAMP: Final = re.compile(r"[a-z][a-z0-9_]{0,63}", re.ASCII)
# nom de fait sans qualificatif ; les domaines admis sont ceux de amnesia.facts
_NOM_DE_FAIT: Final = re.compile(r"[a-z0-9_]+(?:\.[a-z0-9_]+)+", re.ASCII)
_NATURES_SCALAIRES: Final = (
    Nature.NUMBER,
    Nature.DURATION,
    Nature.TIMESTAMP,
    Nature.BOOLEAN,
)
# imbrication maximale des champs d'un schema : objet, liste d'objets, champs
_IMBRICATION_MAX: Final = 4


@dataclass(frozen=True, slots=True)
class FactField:
    """Champ admis dans la valeur d'un fait, avec la nature de sa valeur.

    Comme ``EvidenceField``, avec en plus ``Nature.RECORD`` : la valeur est un
    objet dont ``fields`` déclare les champs. ``repeated`` : une liste (de
    ``LIST_MAX_LENGTH`` éléments au plus) de valeurs de cette nature.
    """

    name: str
    nature: Nature
    description: str
    repeated: bool = False
    choices: tuple[str, ...] = ()
    format: TextFormat | None = None
    fields: tuple[FactField, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _NOM_DE_CHAMP.fullmatch(self.name):
            raise ValueError("champ de fait : nom en minuscules [a-z0-9_] attendu")
        if normalize_key(self.name) in _CONTENU_D_EVENEMENT:
            raise ValueError(
                f"champ {self.name!r} : nom d'un champ de contenu d'événement"
            )
        _verifier_texte_declare(self.name, self.nature, self.choices, self.format)
        if (self.nature is Nature.RECORD) != bool(self.fields):
            raise ValueError(
                f"champ {self.name!r} : fields est réservé aux objets (record), "
                "qui en déclarent au moins un"
            )
        _verifier_champs_declares(self.fields)


def _verifier_champs_declares(champs: tuple[FactField, ...]) -> None:
    if any(not isinstance(champ, FactField) for champ in champs):
        raise TypeError("fields : FactField attendus")
    noms = [champ.name for champ in champs]
    if len(set(noms)) != len(noms):
        raise ValueError("fields : nom de champ en double")


def _imbrication(champs: tuple[FactField, ...]) -> int:
    return 1 + max((_imbrication(c.fields) for c in champs if c.fields), default=0)


@dataclass(frozen=True, slots=True)
class FactSchema:
    """Schéma fermé de la valeur d'un fait, désigné par son nom sans qualificatif.

    - ``fields`` : la valeur est un objet, dont voici les seules clés admises ;
    - ``scalar`` : la valeur est un nombre, une durée, un horodatage ou un
      booléen. Un fait n'est jamais un texte seul ;
    - ``qualifier`` : forme du qualificatif (``:Security``) ; sans elle, un
      nom qualifié est refusé.

    ``None`` est toujours admis : la clé ou l'option est absente de la cible.
    """

    name: str
    description: str
    fields: tuple[FactField, ...] = ()
    scalar: Nature | None = None
    qualifier: TextFormat | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _NOM_DE_FAIT.fullmatch(self.name):
            raise ValueError(
                "schéma de fait : nom domaine.nom attendu, sans qualificatif"
            )
        if bool(self.fields) == (self.scalar is not None):
            raise ValueError(
                f"schéma de {self.name} : fields ou scalar, l'un des deux seulement"
            )
        if self.scalar is not None and self.scalar not in _NATURES_SCALAIRES:
            raise ValueError(
                f"schéma de {self.name} : un fait scalaire est un nombre, une "
                "durée, un horodatage ou un booléen, jamais un texte"
            )
        _verifier_champs_declares(self.fields)
        if self.fields and _imbrication(self.fields) > _IMBRICATION_MAX:
            raise ValueError(f"schéma de {self.name} : champs trop imbriqués")


def _repris(nom: str) -> FactField:
    """Champ de fait de même nom, nature et forme qu'une clé de preuve."""
    champ = EVIDENCE_FIELDS[nom]
    return FactField(
        champ.name,
        champ.nature,
        champ.description,
        repeated=champ.repeated,
        choices=champ.choices,
        format=champ.format,
    )


SERVICE_STATES: Final = (
    "Running",
    "Stopped",
    "Paused",
    "StartPending",
    "StopPending",
    "ContinuePending",
    "PausePending",
)
"""États d'un service Windows (``ServiceControllerStatus``)."""

SERVICE_START_MODES: Final = ("Boot", "System", "Automatic", "Manual", "Disabled")
"""Modes de démarrage d'un service Windows (``ServiceStartMode``)."""

_FAITS_WINDOWS: Final = (
    FactSchema(
        "windows.auditpol.backup",
        "politique d'audit avancée : valeur numérique de chaque sous-catégorie, "
        "désignée par son GUID",
        fields=(
            FactField(
                "subcategories",
                Nature.RECORD,
                "sous-catégories d'audit",
                repeated=True,
                fields=(
                    FactField(
                        "guid",
                        Nature.SETTING,
                        "GUID de la sous-catégorie",
                        format=TextFormat.GUID,
                    ),
                    FactField(
                        "setting_value",
                        Nature.NUMBER,
                        "valeur numérique (0 : aucun audit, 1 : succès, 2 : échecs, "
                        "3 : les deux)",
                    ),
                ),
            ),
        ),
    ),
    FactSchema(
        "windows.eventlog.config",
        "configuration et métadonnées d'un journal d'événements, désigné par "
        "le qualificatif",
        fields=(
            _repris("max_size_bytes"),
            _repris("file_size_bytes"),
            _repris("record_count"),
            _repris("log_mode"),
            _repris("enabled"),
            _repris("oldest_event_utc"),
            _repris("newest_event_utc"),
        ),
        qualifier=TextFormat.CHANNEL,
    ),
    FactSchema(
        "windows.powershell.logging_policy",
        "stratégies de journalisation de PowerShell (registre)",
        fields=(
            FactField(
                "script_block_logging",
                Nature.BOOLEAN,
                "journalisation des blocs de script (EnableScriptBlockLogging)",
            ),
            FactField(
                "script_block_invocation_logging",
                Nature.BOOLEAN,
                "journalisation des appels de blocs de script "
                "(EnableScriptBlockInvocationLogging)",
            ),
            FactField(
                "module_logging",
                Nature.BOOLEAN,
                "journalisation des modules (EnableModuleLogging)",
            ),
            FactField(
                "module_names",
                Nature.SETTING,
                "modules journalisés (ModuleNames, jokers compris)",
                repeated=True,
                format=TextFormat.IDENTIFIER,
            ),
            FactField(
                "transcription", Nature.BOOLEAN, "transcription (EnableTranscripting)"
            ),
        ),
    ),
    FactSchema(
        "windows.sysmon.service",
        "service Sysmon : présence, état et mode de démarrage",
        fields=(
            FactField("installed", Nature.BOOLEAN, "service présent ou non"),
            FactField(
                "service_name",
                Nature.SETTING,
                "nom du service (Sysmon, Sysmon64, ou renommé)",
                format=TextFormat.IDENTIFIER,
            ),
            FactField(
                "state", Nature.SETTING, "état du service", choices=SERVICE_STATES
            ),
            FactField(
                "start_mode",
                Nature.SETTING,
                "mode de démarrage du service",
                choices=SERVICE_START_MODES,
            ),
            FactField(
                "version",
                Nature.SETTING,
                "version du binaire",
                format=TextFormat.VERSION,
            ),
        ),
    ),
    FactSchema(
        "windows.sysmon.config",
        "configuration chargée par Sysmon",
        fields=(
            FactField("loaded", Nature.BOOLEAN, "configuration chargée ou non"),
            FactField(
                "schema_version",
                Nature.SETTING,
                "version du schéma de configuration",
                format=TextFormat.VERSION,
            ),
            FactField(
                "config_hash",
                Nature.SETTING,
                "empreinte de la configuration chargée",
                format=TextFormat.HASH,
            ),
            FactField(
                "hash_algorithms",
                Nature.SETTING,
                "algorithmes d'empreinte configurés",
                repeated=True,
                choices=("MD5", "SHA1", "SHA256", "IMPHASH"),
            ),
            FactField("rule_count", Nature.NUMBER, "nombre de règles chargées"),
        ),
    ),
    FactSchema(
        "windows.w32time.config",
        "configuration du service de temps Windows (registre)",
        fields=(
            FactField(
                "type",
                Nature.SETTING,
                "mode de synchronisation (Parameters\\Type)",
                choices=("NTP", "NT5DS", "NoSync", "AllSync"),
            ),
            FactField(
                "ntp_server_count",
                Nature.NUMBER,
                "nombre de serveurs NTP configurés ; leurs noms ne sont pas collectés",
            ),
            FactField(
                "service_state",
                Nature.SETTING,
                "état du service w32time",
                choices=SERVICE_STATES,
            ),
            FactField(
                "service_start_mode",
                Nature.SETTING,
                "mode de démarrage du service w32time",
                choices=SERVICE_START_MODES,
            ),
            FactField(
                "poll_interval_seconds",
                Nature.DURATION,
                "intervalle d'interrogation (SpecialPollInterval), en secondes",
            ),
        ),
    ),
    FactSchema(
        "windows.w32time.status",
        "état de la synchronisation horaire",
        fields=(
            FactField("synchronized", Nature.BOOLEAN, "horloge synchronisée ou non"),
            FactField("stratum", Nature.NUMBER, "strate de l'horloge"),
            FactField(
                "last_sync_utc",
                Nature.TIMESTAMP,
                "horodatage de la dernière synchronisation réussie",
            ),
            FactField(
                "offset_seconds", Nature.NUMBER, "écart à la source, en secondes"
            ),
            FactField(
                "leap_indicator", Nature.NUMBER, "indicateur de seconde intercalaire"
            ),
        ),
    ),
)

_schemas_de_faits: dict[str, FactSchema] = {}

FACT_SCHEMAS: Final[Mapping[str, FactSchema]] = MappingProxyType(_schemas_de_faits)
"""Schémas déclarés, par nom de fait sans qualificatif ; vue en lecture seule.

Un fait observé dont le nom n'a pas de schéma ici est refusé : ce qui sort
d'une cible est une liste fermée, pas « tout sauf ce qu'on a pensé à
interdire ».
"""


def declare_fact_schema(schema: FactSchema) -> None:
    """Déclare le schéma fermé de la valeur d'un fait.

    Point d'extension des collecteurs : chacun déclare, à l'import de son
    module, le schéma des faits qu'il rend (collecteur PowerShell : #48), et
    l'inscrit dans ``docs/DONNEES.md`` et ``docs/dev/faits.md``, pour que la
    revue voie passer chaque donnée nouvelle. Les schémas des faits Windows
    lus par les checks livrés sont déclarés ici même.

    Un schéma ne se remplace pas : redéclarer un nom avec un autre schéma lève
    ``ValueError`` (la même déclaration, rejouée, est sans effet). Aucun
    schéma ne peut admettre un texte libre : ``FactSchema`` et ``FactField``
    n'en offrent pas la nature.
    """
    if not isinstance(schema, FactSchema):
        raise TypeError("declare_fact_schema : FactSchema attendu")
    existant = _schemas_de_faits.get(schema.name)
    if existant is not None and existant != schema:
        raise ValueError(f"schéma de {schema.name} déjà déclaré, et différent")
    _schemas_de_faits[schema.name] = schema


for _schema in _FAITS_WINDOWS:
    declare_fact_schema(_schema)

_SANS_SCHEMA: Final = (
    "aucun schéma déclaré pour ce fait (amnesia.privacy.FACT_SCHEMAS, "
    "docs/DONNEES.md) : fait refusé"
)


def _refus(champ: FactField, profondeur: int) -> ValueError:
    # champ.name vient du schema, jamais de la valeur recue
    if champ.nature is Nature.RECORD:
        attendu = "objet"
    elif champ.choices:
        attendu = "valeur de l'énumération"
    elif champ.format is not None:
        attendu = _FORMES[champ.format].description
    else:
        attendu = champ.nature.value
    if champ.repeated:
        attendu = f"liste de {LIST_MAX_LENGTH} éléments au plus ({attendu})"
    return ValueError(
        f"valeur hors schéma pour le champ {champ.name!r} à la profondeur "
        f"{profondeur}, {attendu} attendu"
    )


def _verifier_objet(
    valeur: object, champs: tuple[FactField, ...], profondeur: int
) -> None:
    if not isinstance(valeur, Mapping):
        raise ValueError(
            f"valeur hors schéma à la profondeur {profondeur}, objet attendu"
        )
    admis = {champ.name: champ for champ in champs}
    for cle, element in valeur.items():
        champ = admis.get(cle) if isinstance(cle, str) else None
        if champ is None:
            # la cle recue n'est jamais reprise : elle peut etre une donnee
            raise ValueError(
                f"clé hors du schéma du fait à la profondeur {profondeur} "
                "(amnesia.privacy.FACT_SCHEMAS, docs/DONNEES.md)"
            )
        _verifier_champ(element, champ, profondeur + 1)


def _verifier_element(valeur: object, champ: FactField, profondeur: int) -> None:
    if champ.nature is Nature.RECORD:
        if not isinstance(valeur, Mapping):
            raise _refus(champ, profondeur)
        _verifier_objet(valeur, champ.fields, profondeur)
    elif not _scalaire_conforme(
        valeur, champ.nature, champ.choices, champ.format, borne=True
    ):
        raise _refus(champ, profondeur)


def _verifier_champ(valeur: object, champ: FactField, profondeur: int) -> None:
    if valeur is None:
        return
    if not champ.repeated:
        _verifier_element(valeur, champ, profondeur)
        return
    if not isinstance(valeur, list | tuple) or len(valeur) > LIST_MAX_LENGTH:
        raise _refus(champ, profondeur)
    for element in valeur:
        if element is None:
            raise _refus(champ, profondeur)
        _verifier_element(element, champ, profondeur + 1)


def check_fact_value(name: str, value: object) -> None:
    """Vérifie la valeur d'un fait observé contre son schéma ; lève ``ValueError``.

    ``name`` est un nom de fait déjà validé (``domaine.nom[:qualificatif]``).
    Sont refusés : un fait sans schéma déclaré, un qualificatif que le schéma
    n'admet pas, une clé absente du schéma à n'importe quelle profondeur, une
    valeur d'une autre nature que celle déclarée (énumération, forme et
    longueur comprises) et une liste de plus de ``LIST_MAX_LENGTH`` éléments.
    ``None`` est admis partout, sauf dans une liste.

    Le message ne reprend ni la valeur, ni une clé reçue, ni le nom du fait :
    seulement un nom de champ du schéma et une profondeur.
    """
    base, separateur, qualificatif = name.partition(":")
    schema = _schemas_de_faits.get(base)
    if schema is None:
        raise ValueError(_SANS_SCHEMA)
    if separateur and (
        schema.qualifier is None or not text_matches(qualificatif, schema.qualifier)
    ):
        raise ValueError("qualificatif hors du schéma du fait")
    if value is None:
        return
    if schema.scalar is not None:
        if not _scalaire_conforme(value, schema.scalar, borne=True):
            raise ValueError(f"valeur hors schéma, {schema.scalar.value} attendu")
        return
    _verifier_objet(value, schema.fields, 0)


# --- champs texte admis dans le rapport -------------------------------------------

_BLOCS_DE_PREUVE: Final = ("observed", "expected", "details")
_RACINE_DES_PREUVES: Final = "gaps[].evidence"
_NATURES_TEXTUELLES: Final = (Nature.TIMESTAMP, Nature.SETTING)

_STRUCTURE = "vocabulaire, identifiant ou horodatage écrit par amnesia"
_CATALOGUE = "texte du catalogue ou du check, écrit par amnesia"
_HOTE = "nom d'hôte de la cible (donnée personnelle admise : host_name)"
_DIAGNOSTIC = "diagnostic d'un check non conclu, caviardé"
_CONFIGURATION = "nom ou valeur d'un paramètre de configuration lu sur la cible"
# saisie par l'auditeur dans amnesia.toml, jamais lue sur la cible
_MISSION = "donnée de mission déclarée par l'auditeur (fichier de mission)"
_AUDITEUR = (
    "auditeur ou équipe déclaré dans le fichier de mission "
    "(donnée personnelle admise : declared_auditor)"
)


def _champs_texte() -> dict[str, str]:
    champs = {
        "schema_version": _STRUCTURE,
        "tool.name": _STRUCTURE,
        "tool.version": _STRUCTURE,
        "tool.catalog_version": _STRUCTURE,
        "run.id": _STRUCTURE,
        "run.started_at": _STRUCTURE,
        "run.finished_at": _STRUCTURE,
        "run.profile": _MISSION,
        "run.config_source": _STRUCTURE,
        "config_hash": _STRUCTURE,
        "mission.client": _MISSION,
        "mission.reference": _MISSION,
        "mission.auditor": _AUDITEUR,
        "mission.start": _MISSION,
        "mission.end": _MISSION,
        "mission.tlp": _MISSION,
        "run.argv[]": "ligne de commande, secrets et chemins masqués",
        "targets[].id": _HOTE,
        "targets[].kind": _STRUCTURE,
        "targets[].transport": _STRUCTURE,
        "results[].check_id": _STRUCTURE,
        "results[].target": _HOTE,
        "results[].status": _STRUCTURE,
        "results[].reason": _STRUCTURE,
        "results[].message": _DIAGNOSTIC,
        "results[].error.type": _DIAGNOSTIC,
        "results[].error.message": _DIAGNOSTIC,
        "results[].error.traceback": _DIAGNOSTIC,
        "gaps[].fingerprint": _STRUCTURE,
        "gaps[].check_id": _STRUCTURE,
        "gaps[].target": _HOTE,
        "gaps[].resource": _CONFIGURATION,
        "gaps[].question_id": _STRUCTURE,
        "gaps[].question": _CATALOGUE,
        "gaps[].reason": _CATALOGUE,
        "gaps[].severity": _STRUCTURE,
        "gaps[].remediation": _CATALOGUE,
        "gaps[].remediation_id": _STRUCTURE,
        "gaps[].references[].kind": _STRUCTURE,
        "gaps[].references[].id": _STRUCTURE,
        "gaps[].references[].version": _STRUCTURE,
        "gaps[].references[].url": _STRUCTURE,
        f"{_RACINE_DES_PREUVES}.unit": _STRUCTURE,
        f"{_RACINE_DES_PREUVES}.confidence": _STRUCTURE,
        f"{_RACINE_DES_PREUVES}.source": "commande ou API lue, sans identifiants",
        f"{_RACINE_DES_PREUVES}.observed": _CONFIGURATION,
        f"{_RACINE_DES_PREUVES}.observed[]": _CONFIGURATION,
        f"{_RACINE_DES_PREUVES}.expected": _CONFIGURATION,
        f"{_RACINE_DES_PREUVES}.expected[]": _CONFIGURATION,
    }
    for bloc in _BLOCS_DE_PREUVE:
        for champ in _CHAMPS_DE_PREUVE:
            if champ.nature in _NATURES_TEXTUELLES:
                suffixe = "[]" if champ.repeated else ""
                chemin = f"{_RACINE_DES_PREUVES}.{bloc}.{champ.name}{suffixe}"
                champs[chemin] = champ.description
    return champs


REPORT_TEXT_FIELDS: Final[Mapping[str, str]] = MappingProxyType(_champs_texte())
"""Champs texte admis dans le rapport JSON : chemin, puis ce qu'il porte.

``[]`` désigne chaque élément d'une liste. Les clés d'une preuve (``observed``,
``expected``, ``details``) suivent ``EVIDENCE_FIELDS``.
"""


def _tout_admis(valeur: str) -> bool:
    return True


def _source_conforme(valeur: str) -> bool:
    try:
        check_source(valeur)
    except ValueError:
        return False
    return True


def _controle(champ: EvidenceField) -> Callable[[str], bool]:
    def conforme(valeur: str) -> bool:
        return _scalaire_conforme(valeur, champ.nature, champ.choices, champ.format)

    return conforme


def _controles_de_texte() -> dict[str, Callable[[str], bool]]:
    controles: dict[str, Callable[[str], bool]] = {
        f"{_RACINE_DES_PREUVES}.source": _source_conforme,
    }
    for bloc in ("observed", "expected"):
        for suffixe in ("", "[]"):
            chemin = f"{_RACINE_DES_PREUVES}.{bloc}{suffixe}"
            controles[chemin] = evidence_text_conforms
    for bloc in _BLOCS_DE_PREUVE:
        for champ in _CHAMPS_DE_PREUVE:
            if champ.nature in _NATURES_TEXTUELLES:
                suffixe = "[]" if champ.repeated else ""
                chemin = f"{_RACINE_DES_PREUVES}.{bloc}.{champ.name}{suffixe}"
                controles[chemin] = _controle(champ)
    return controles


# forme exigee des textes venus de la cible : ceux d'une preuve. Les autres
# champs texte sont ecrits par amnesia ou saisis par l'auditeur
_CONTROLES_DE_TEXTE: Final[Mapping[str, Callable[[str], bool]]] = MappingProxyType(
    _controles_de_texte()
)


def _violations(valeur: Any, chemin: str, ecarts: list[str]) -> None:
    if isinstance(valeur, str):
        if chemin not in REPORT_TEXT_FIELDS:
            ecarts.append(f"{chemin} : champ texte hors schéma")
        elif not _CONTROLES_DE_TEXTE.get(chemin, _tout_admis)(valeur):
            ecarts.append(f"{chemin} : texte hors de la forme admise par le schéma")
    elif isinstance(valeur, list | tuple):
        if chemin.startswith(_RACINE_DES_PREUVES) and len(valeur) > LIST_MAX_LENGTH:
            ecarts.append(
                f"{chemin} : liste de plus de {LIST_MAX_LENGTH} éléments, hors schéma"
            )
        for element in valeur:
            _violations(element, f"{chemin}[]", ecarts)
    elif isinstance(valeur, Mapping):
        preuve = chemin in {f"{_RACINE_DES_PREUVES}.{b}" for b in _BLOCS_DE_PREUVE}
        for rang, (cle, element) in enumerate(valeur.items()):
            if preuve and cle not in EVIDENCE_FIELDS:
                # la cle elle-meme est du texte libre : jamais reprise
                ecarts.append(f"{chemin} : {_HORS_SCHEMA} (rang {rang})")
                continue
            if not isinstance(cle, str):
                ecarts.append(f"{chemin} : clé non textuelle (rang {rang})")
                continue
            sous_chemin = f"{chemin}.{cle}" if chemin else cle
            _violations(element, sous_chemin, ecarts)


def report_text_violations(report: Mapping[str, Any]) -> list[str]:
    """Écarts d'un rapport JSON au schéma des champs texte admis.

    Parcourt tout le rapport ; rend un message par écart, liste vide si chaque
    chaîne est à un chemin de ``REPORT_TEXT_FIELDS``, chaque clé de preuve dans
    ``EVIDENCE_FIELDS``, et chaque texte d'une preuve (``source``,
    ``observed``, ``expected``, ``details``) de la forme que son schéma
    déclare, listes bornées comprises. Un message donne le chemin, jamais la
    valeur. ``amnesia.report.build_report()`` refuse de rendre un rapport qui
    en présente un (``amnesia.report.ReportPrivacyError``).
    """
    ecarts: list[str] = []
    _violations(report, "", ecarts)
    return ecarts


# --- scripts PowerShell : rien que des metadonnees --------------------------------

PS_EVENT_READER: Final = "Get-WinEvent"
"""Cmdlet qui lit des événements : son résultat exige une projection explicite."""

PS_METADATA_PARAMETERS: Final = ("ListLog", "ListProvider")
"""Paramètres de ``Get-WinEvent`` qui rendent une configuration, pas un événement."""

PS_PROJECTION: Final = "Select-Object"
PS_PROJECTION_PARAMETER: Final = "Property"

_SANS_PROJECTION: Final = (
    f"résultat de {PS_EVENT_READER} émis sans projection explicite "
    f"(propriété unique ou {PS_PROJECTION} -{PS_PROJECTION_PARAMETER})"
)
_HORS_METADONNEES: Final = (
    f"résultat de {PS_EVENT_READER} projeté sur autre chose que les "
    f"métadonnées admises ({', '.join(EVENT_METADATA)})"
)
_INCONNU: Final = "élément d'inventaire inconnu"
# abreviation la plus courte qui distingue -ListLog de -ListProvider
_PREFIXE_MIN: Final = len("ListL")
_JOKERS: Final = frozenset("*?[]")


def _textes(valeur: object) -> list[str] | None:
    if isinstance(valeur, list) and all(isinstance(v, str) for v in valeur):
        return valeur
    return None


def _lit_des_metadonnees(parametres: list[str]) -> bool:
    # PowerShell admet tout debut non ambigu d'un nom de parametre
    return any(
        len(parametre) >= _PREFIXE_MIN and complet.casefold().startswith(p)
        for parametre in parametres
        for p in (parametre.casefold(),)
        for complet in PS_METADATA_PARAMETERS
    )


def _selection(suivant: object) -> list[str] | None:
    """Noms projetés par ``Select-Object -Property``, constants et sans joker.

    ``None`` si ``suivant`` n'est pas cette projection explicite.
    """
    if not isinstance(suivant, Mapping):
        return None
    nom, parametres = suivant.get("name"), _textes(suivant.get("parameters"))
    arguments = _textes(suivant.get("arguments"))
    if not isinstance(nom, str) or parametres is None or arguments is None:
        return None
    explicite = (
        nom.casefold() == PS_PROJECTION.casefold()
        and [p.casefold() for p in parametres] == [PS_PROJECTION_PARAMETER.casefold()]
        and suivant.get("dynamic") is False
        and suivant.get("splat") is False
        and bool(arguments)
        and not any(_JOKERS & set(argument) for argument in arguments)
    )
    return arguments if explicite else None


def _projection(element: Mapping[str, Any]) -> str | None:
    """Motif du refus de ce que devient un événement lu, ``None`` s'il est admis.

    Liste fermée, pas liste noire : une projection ne vaut que si chaque
    propriété lue est une métadonnée de ``EVENT_METADATA``. ``(Get-WinEvent
    ...).PSObject.BaseObject`` ne nomme aucune propriété interdite et rendrait
    pourtant l'événement entier.
    """
    projection = element.get("projection")
    if projection == "member":
        noms = [element.get("member")]
    elif projection == "pipeline":
        selection = _selection(element.get("next"))
        if selection is None:
            return _SANS_PROJECTION
        noms = list(selection)
    else:
        return _SANS_PROJECTION
    if all(isinstance(nom, str) and nom.casefold() in _METADONNEES for nom in noms):
        return None
    return _HORS_METADONNEES


def _commande(element: Mapping[str, Any]) -> list[str]:
    parametres = _textes(element.get("parameters"))
    arguments = _textes(element.get("arguments"))
    if parametres is None or arguments is None:
        return [_INCONNU]
    motifs = [
        f"propriété de contenu d'événement nommée en argument : {_PROPRIETES[a]}"
        for a in (argument.casefold() for argument in arguments)
        if a in _PROPRIETES
    ]
    nom = element.get("name")
    if not isinstance(nom, str) or nom.casefold() != PS_EVENT_READER.casefold():
        return motifs
    if _lit_des_metadonnees(parametres):
        return motifs
    refus = _projection(element)
    return motifs if refus is None else [*motifs, refus]


def _element(element: Mapping[str, Any]) -> list[str]:
    genre = element.get("kind")
    if genre == "command":
        return _commande(element)
    if genre == "property":
        nom = element.get("name")
        if not isinstance(nom, str) or not nom:
            return ["propriété au nom calculé à l'exécution"]
        if nom.casefold() in _PROPRIETES:
            return [
                f"propriété de contenu d'événement : .{_PROPRIETES[nom.casefold()]}"
            ]
        return []
    if genre == "method":
        nom = element.get("name")
        if isinstance(nom, str) and nom.casefold() in _METHODES:
            return [
                "méthode qui rend le contenu d'un événement : "
                f".{_METHODES[nom.casefold()]}()"
            ]
    return []


def check_script_privacy(inventory: Mapping[str, Any]) -> list[str]:
    """Écarts d'un script PowerShell à la minimisation, d'après son inventaire.

    ``inventory`` est une entrée de la sortie de ``scripts/inventaire_ps.ps1``.
    Sont des écarts : toute référence à une propriété de ``EVENT_PROPERTIES``
    (accès ``.Message``, nom passé en argument d'une commande), une propriété
    au nom calculé, une méthode de ``EVENT_METHODS``, et tout résultat de
    ``Get-WinEvent`` qui n'est pas projeté aussitôt : ``(Get-WinEvent
    ...).TimeCreated`` ou ``Get-WinEvent ... | Select-Object -Property <noms>``.
    La projection ne porte que sur des métadonnées de ``EVENT_METADATA`` :
    toute autre propriété est refusée, connue ou non.
    Un événement rangé dans une variable est donc refusé, faute de pouvoir
    suivre ce qu'elle devient. ``Get-WinEvent -ListLog`` et ``-ListProvider``,
    qui rendent une configuration, ne sont pas concernés.

    Ce verdict complète ``amnesia.readonly.check_script_inventory`` (lecture
    seule) : un script de ``src/amnesia/ps/`` passe les deux.
    """
    elements = inventory.get("items")
    if not isinstance(elements, list):
        return ["inventaire illisible"]
    ecarts: list[str] = []
    for element in elements:
        if not isinstance(element, Mapping):
            ecarts.append(_INCONNU)
            continue
        ecarts.extend(f"ligne {element.get('line')} : {m}" for m in _element(element))
    return ecarts
