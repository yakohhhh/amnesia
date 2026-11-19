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
- ``event_content_field()`` : nom d'un champ de contenu d'événement
  (``Message``, ``Properties``, ``UserId``, ``MachineName``, champs
  d'``EventData``). ``amnesia.facts.model`` refuse tout fait qui en porte un ;
- ``EVIDENCE_FIELDS`` et ``check_evidence()`` : schéma fermé de la preuve d'un
  Gap (nombres, durées, horodatages, noms de paramètres). Une clé hors schéma
  est refusée à la construction de l'``Evidence``, avant toute copie
  (``check_evidence_keys()``) ;
- ``REPORT_TEXT_FIELDS`` et ``report_text_violations()`` : champs texte admis
  dans le rapport JSON ;
- ``check_script_privacy()`` : verdict sur l'inventaire de l'AST d'un script
  PowerShell (``scripts/inventaire_ps.ps1``), en complément de
  ``amnesia.readonly.check_script_inventory``. Une propriété de contenu
  d'événement, ou un résultat de ``Get-WinEvent`` qui n'est pas projeté
  aussitôt sur des métadonnées de ``EVENT_METADATA``, est un écart.

Aucun message de ce module ne reprend une valeur reçue, ni une clé qu'il ne
connaît pas : un refus ne doit pas faire sortir ce qu'il refuse.
"""

from __future__ import annotations

from collections.abc import Mapping
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
)
"""Champs d'``EventData`` des événements d'ouverture de session (4624, 4625...)."""

_CONTENU_D_EVENEMENT: Final[Mapping[str, str]] = MappingProxyType(
    {nom.casefold(): nom for nom in (*EVENT_PROPERTIES, *EVENT_DATA_FIELDS)}
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

    La comparaison ignore la casse. Rend ``None`` pour toute autre clé. Le nom
    rendu vient de ce module, jamais de l'entrée : il peut figurer dans un
    message d'erreur.
    """
    if not isinstance(key, str):
        return None
    return _CONTENU_D_EVENEMENT.get(key.casefold())


# --- schema de la preuve d'un Gap -------------------------------------------------


class Nature(StrEnum):
    """Nature d'une valeur de preuve."""

    NUMBER = "number"
    DURATION = "duration"
    TIMESTAMP = "timestamp"
    BOOLEAN = "boolean"
    SETTING = "setting"


@dataclass(frozen=True, slots=True)
class EvidenceField:
    """Clé admise dans la preuve d'un Gap, avec la nature de sa valeur.

    ``repeated`` : la valeur est une liste de valeurs de cette nature.
    """

    name: str
    nature: Nature
    description: str
    repeated: bool = False


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
        "nom du paramètre en défaut (valeur de registre, sous-catégorie d'audit)",
    ),
    EvidenceField(
        "settings", Nature.SETTING, "noms des paramètres en défaut", repeated=True
    ),
    EvidenceField(
        "channels", Nature.SETTING, "noms des journaux concernés", repeated=True
    ),
)

EVIDENCE_FIELDS: Final[Mapping[str, EvidenceField]] = MappingProxyType(
    {champ.name: champ for champ in _CHAMPS_DE_PREUVE}
)
"""Schéma fermé de ``Evidence.details`` : une clé absente d'ici est refusée.

Un check qui a besoin d'une nouvelle valeur l'ajoute ici, avec sa nature, et
dans ``docs/DONNEES.md`` : la revue voit passer chaque donnée nouvelle.
"""

SETTING_MAX_LENGTH: Final = 256
"""Longueur maximale d'un nom ou d'une valeur de paramètre dans une preuve."""

_HORS_SCHEMA: Final = (
    "clé hors du schéma des preuves (amnesia.privacy.EVIDENCE_FIELDS, docs/DONNEES.md)"
)


def _scalaire_conforme(valeur: object, nature: Nature) -> bool:
    if valeur is None:
        return True
    if nature is Nature.BOOLEAN:
        return isinstance(valeur, bool)
    if nature in (Nature.NUMBER, Nature.DURATION):
        if isinstance(valeur, bool) or not isinstance(valeur, int | float):
            return False
        return nature is Nature.NUMBER or valeur >= 0
    if nature is Nature.TIMESTAMP:
        if isinstance(valeur, datetime):
            return valeur.utcoffset() is not None
        if not isinstance(valeur, str):
            return False
        try:
            return datetime.fromisoformat(valeur).utcoffset() is not None
        except ValueError:
            return False
    return isinstance(valeur, str) and len(valeur) <= SETTING_MAX_LENGTH


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


def check_evidence(details: object, field: str = "details") -> None:
    """Vérifie un dictionnaire de preuve contre ``EVIDENCE_FIELDS`` ; lève sinon.

    ``ValueError`` pour une clé hors schéma ou une valeur d'une autre nature que
    celle déclarée, ``TypeError`` si ``details`` n'est pas un dictionnaire.
    ``None`` est admis partout : la valeur est absente de la cible. Le message
    nomme une clé du schéma, jamais une clé inconnue ni une valeur.
    """
    if not isinstance(details, Mapping):
        raise TypeError(f"{field} doit être un dictionnaire")
    for cle, valeur in details.items():
        champ = EVIDENCE_FIELDS.get(cle) if isinstance(cle, str) else None
        if champ is None:
            raise ValueError(f"{field} : {_HORS_SCHEMA}")
        if champ.repeated:
            conforme = isinstance(valeur, list | tuple) and all(
                v is not None and _scalaire_conforme(v, champ.nature) for v in valeur
            )
        else:
            conforme = _scalaire_conforme(valeur, champ.nature)
        if not conforme:
            attendu = f"liste de {champ.nature.value}" if champ.repeated else ""
            raise ValueError(
                f"{field}[{champ.name!r}] : valeur hors schéma, "
                f"{attendu or champ.nature.value} attendu"
            )


def check_evidence_value(value: object, field: str) -> None:
    """Vérifie ``observed`` ou ``expected`` : scalaire, liste plate ou dictionnaire.

    Un texte est un nom ou une valeur de paramètre, borné à
    ``SETTING_MAX_LENGTH`` caractères ; un dictionnaire suit ``EVIDENCE_FIELDS``.
    """
    if isinstance(value, Mapping):
        check_evidence(value, field)
        return
    elements = value if isinstance(value, list | tuple) else (value,)
    for element in elements:
        if element is None or isinstance(element, bool | int | float | datetime):
            continue
        if isinstance(element, str) and len(element) <= SETTING_MAX_LENGTH:
            continue
        raise ValueError(
            f"{field} : valeur hors schéma, nombre, booléen, horodatage ou "
            f"paramètre de {SETTING_MAX_LENGTH} caractères au plus attendu"
        )


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


def _violations(valeur: Any, chemin: str, ecarts: list[str]) -> None:
    if isinstance(valeur, str):
        if chemin not in REPORT_TEXT_FIELDS:
            ecarts.append(f"{chemin} : champ texte hors schéma")
    elif isinstance(valeur, list | tuple):
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
    """Champs texte d'un rapport JSON absents de ``REPORT_TEXT_FIELDS``.

    Parcourt tout le rapport ; rend un message par écart, liste vide si chaque
    chaîne est à un chemin admis et chaque clé de preuve dans
    ``EVIDENCE_FIELDS``. Un message donne le chemin, jamais la valeur.
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
