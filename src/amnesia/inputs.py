# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Analyse sûre des fichiers importés : la seule porte d'entrée (#35).

amnesia lit des fichiers produits ailleurs : configurations Sysmon (XML),
exports et sauvegardes de GPO (``gpreport.xml``, ``Backup.xml``,
``Registry.pol``, ``audit.csv``), bundles de collecte hors ligne, fichiers de
mission. Ils peuvent venir d'un SI compromis (hypothèse H4 du modèle de menace) :
ce sont des entrées hostiles. Tout format importé passe donc par ce module, et
par lui seul : aucun autre module de ``amnesia`` n'importe ``xml.*``,
``zipfile`` ni ``tarfile`` (``tests/test_architecture.py`` le vérifie).

Garanties communes (menaces M03 et M04 de ``docs/threat-model.md``) :

- **octets réellement lus** : seul un fichier ordinaire est lu (ni FIFO, ni
  périphérique, ni dossier), et la lecture est plafonnée en flux par
  ``Limits.max_bytes`` ; la taille annoncée par ``stat()`` ne sert qu'à refuser
  plus tôt ;
- **structures bornées** : nombre d'enregistrements, profondeur d'imbrication,
  colonnes, entrées d'archive, octets décompressés et ratio de compression ;
- **aucune désérialisation de code** : ni pickle, ni marshal, ni shelve, ni
  ``eval`` ou ``exec`` ;
- **erreur typée** : tout refus lève ``UnsafeInputError``, dont le message ne
  reproduit jamais le contenu du fichier (ni texte, ni nom d'entrée d'archive,
  ni message d'un analyseur), seulement un motif, des positions et des
  plafonds. L'exception ne chaîne aucune autre exception : celle d'un
  analyseur peut porter le document entier.

Formats :

``load_xml``, ``loads_xml``
    DTD, entités et références externes refusées dès la déclaration
    ``DOCTYPE``, avant toute expansion (XXE, *billion laughs*) ; UTF-8 ou
    UTF-16 avec BOM, décodé explicitement. L'analyseur est expat, celui de la
    bibliothèque standard, avec les gestionnaires qui refusent ces
    constructions : le socle n'a aucune dépendance tierce
    (``docs/dev/dependances.md``).
``extract_zip``
    Chemins absolus, ``..``, liens symboliques, fichiers spéciaux, noms en
    double, entrées chiffrées et ZIP64 refusés avant toute écriture ;
    extraction dans un dossier temporaire en 0700, supprimé en sortie ;
    plafonds appliqués aux octets réellement décompressés.
``load_json``, ``loads_json``, ``load_toml``, ``loads_toml``
    Taille plafonnée avant l'analyse, profondeur bornée, erreur contrôlée
    plutôt qu'un ``RecursionError``.
``load_csv``, ``loads_csv``
    ``csv.field_size_limit`` explicite, nombre de colonnes vérifié.
``load_registry_pol``, ``loads_registry_pol``
    Signature ``PReg``, version 1, longueurs vérifiées avant toute lecture.

TAR n'est pas pris en charge : il ne le sera que si le format de bundle (#52)
l'exige, avec ``tarfile`` et ``filter="data"`` (PEP 706), ici et nulle part
ailleurs.

Contrat de l'appelant : un collecteur qui importe un fichier rend le fait
correspondant indisponible (``UnavailableReason.NOT_COLLECTED``) quand ce
module lève ``UnsafeInputError`` ; le moteur traduit de la même façon une
``UnsafeInputError`` qui lui parviendrait (``skipped`` / ``not_collected``) :
« non évalué », jamais conforme, sans trace d'exécution.

Ce module n'importe rien d'amnesia : tout module peut s'en servir sans créer de
cycle.
"""

from __future__ import annotations

import codecs
import contextlib
import csv
import functools
import io
import json
import math
import os
import re
import shutil
import stat
import struct
import tempfile
import threading
import tomllib
import unicodedata
import zipfile
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field, fields, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, BinaryIO, ParamSpec, TypeAlias, TypeVar
from xml.etree import ElementTree
from xml.parsers import expat

__all__ = [
    "DEFAULT_LIMITS",
    "Limits",
    "PolEntry",
    "Rejection",
    "UnsafeInputError",
    "XmlElement",
    "extract_zip",
    "load_csv",
    "load_json",
    "load_registry_pol",
    "load_toml",
    "load_xml",
    "loads_csv",
    "loads_json",
    "loads_registry_pol",
    "loads_toml",
    "loads_xml",
    "read_bytes",
]

_P = ParamSpec("_P")
_T = TypeVar("_T")

Chemin: TypeAlias = "str | os.PathLike[str]"

XmlElement: TypeAlias = ElementTree.Element
"""Élément XML rendu par ``load_xml`` : à annoter sans importer ``xml.etree``."""

_MIO = 1024 * 1024
_BLOC = 64 * 1024


@dataclass(frozen=True, slots=True, kw_only=True)
class Limits:
    """Plafonds appliqués à un fichier importé ; tous strictement positifs.

    Les valeurs par défaut conviennent aux formats attendus (configuration
    Sysmon, sauvegarde de GPO, bundle de collecte) ; l'appelant en passe
    d'autres pour un format plus petit ou plus gros.
    """

    max_bytes: int = 200 * _MIO
    """Octets lus par fichier, et écrits par entrée d'archive (200 Mio)."""

    max_records: int = 1_000_000
    """Enregistrements : éléments et attributs XML, objets et tableaux JSON ou
    TOML, lignes CSV, entrées de Registry.pol."""

    max_depth: int = 64
    """Profondeur d'imbrication : XML, JSON, TOML, et nombre de composants du
    chemin d'une entrée d'archive."""

    max_columns: int = 256
    """Colonnes d'une ligne CSV."""

    max_field_chars: int = 131_072
    """Caractères d'un champ CSV (``csv.field_size_limit``)."""

    max_entries: int = 10_000
    """Fichiers et dossiers créés par une archive : entrées déclarées et
    dossiers intermédiaires que leurs chemins impliquent."""

    max_total_bytes: int = 1024 * _MIO
    """Octets décompressés par archive, toutes entrées confondues (1 Gio)."""

    max_ratio: int = 100
    """Octets décompressés par octet d'archive, au-delà de 1 Mio décompressé."""

    max_toml_bytes: int = _MIO
    """Octets d'un document TOML (1 Mio), en plus de ``max_bytes`` : ``tomllib``
    construit tout le document avant qu'un seul conteneur puisse être compté,
    et occupe de l'ordre de cent fois la taille du texte."""

    def __post_init__(self) -> None:
        for champ in fields(self):
            valeur = getattr(self, champ.name)
            if isinstance(valeur, bool) or not isinstance(valeur, int) or valeur < 1:
                raise ValueError(f"{champ.name} : entier strictement positif attendu")


DEFAULT_LIMITS = Limits()
"""Plafonds par défaut, dont 200 Mio par fichier."""


class Rejection(StrEnum):
    """Motif d'un refus : valeur stable, lisible par l'appelant et les tests."""

    UNREADABLE = "unreadable"
    """Fichier illisible, ou extraction impossible (erreur du système)."""

    NOT_REGULAR_FILE = "not_regular_file"
    """FIFO, périphérique, socket ou dossier."""

    TOO_LARGE = "too_large"
    """Trop d'octets : fichier, entrée ou total décompressé, champ."""

    TOO_MANY = "too_many"
    """Trop d'enregistrements, de colonnes ou d'entrées d'archive."""

    TOO_DEEP = "too_deep"
    """Imbrication au-delà de ``Limits.max_depth``."""

    COMPRESSION_RATIO = "compression_ratio"
    """Ratio de compression d'une bombe de décompression."""

    ENCODING = "encoding"
    """Encodage invalide ou non pris en charge."""

    MALFORMED = "malformed"
    """Syntaxe invalide, signature inconnue, fichier tronqué."""

    FORBIDDEN = "forbidden"
    """Construction interdite : DTD, entité ou référence externe XML."""

    UNSAFE_PATH = "unsafe_path"
    """Entrée d'archive au chemin absolu, à ``..``, ou au nom piégé."""

    LINK = "link"
    """Entrée d'archive qui est un lien symbolique ou un fichier spécial."""

    DUPLICATE = "duplicate"
    """Nom en double : entrée d'archive ou clé JSON."""

    UNSUPPORTED = "unsupported"
    """Variante refusée : chiffrement, méthode de compression, ZIP64."""


class UnsafeInputError(ValueError):
    """Fichier importé refusé : hostile, démesuré, mal formé ou illisible.

    ``code`` est le motif (``Rejection``) et ``message`` un texte français
    affichable. Le message est écrit par ce module : il ne reprend jamais un
    octet du fichier, un nom d'entrée d'archive ni le message d'un analyseur.
    """

    def __init__(self, code: Rejection, message: str) -> None:
        # tous les arguments dans args : copy et pickle reconstruisent l'exception
        super().__init__(code, message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return self.message


def _sans_chainage(fonction: Callable[_P, _T]) -> Callable[_P, _T]:
    """Relève tout refus hors du bloc ``except`` : ni cause, ni contexte.

    ``raise ... from None`` masque le contexte à l'affichage mais le garde dans
    ``__context__`` ; or l'exception d'un analyseur peut porter le document
    (``json.JSONDecodeError.doc``) ou un nom d'entrée (``zipfile.BadZipFile``).
    """

    @functools.wraps(fonction)
    def enveloppe(*args: _P.args, **kwargs: _P.kwargs) -> _T:
        try:
            return fonction(*args, **kwargs)
        except UnsafeInputError as exc:
            refus = UnsafeInputError(exc.code, exc.message)
        raise refus

    return enveloppe


# --- lecture plafonnee --------------------------------------------------------

# O_NONBLOCK : ouvrir une FIFO sans ecrivain ne bloque pas ; O_NOCTTY : un
# terminal ne devient pas le terminal de controle ; O_BINARY : octets bruts
# sous Windows. Chaque drapeau vaut 0 la ou il n'existe pas.
_DRAPEAUX_LECTURE = (
    os.O_RDONLY
    | getattr(os, "O_BINARY", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_NOCTTY", 0)
)
_DRAPEAUX_CREATION = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_BINARY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


def _trop_gros(plafond: int) -> UnsafeInputError:
    return UnsafeInputError(
        Rejection.TOO_LARGE, f"fichier de plus de {plafond} octets refusé"
    )


def _illisible(exc: OSError, action: str = "lecture") -> UnsafeInputError:
    # strerror : message du systeme, sans le chemin ni le contenu
    detail = exc.strerror or type(exc).__name__
    return UnsafeInputError(Rejection.UNREADABLE, f"{action} impossible : {detail}")


def _lire_flux(lire: Callable[[int], bytes], plafond: int) -> bytes:
    """Lit jusqu'à la fin du flux, et refuse au premier octet au-delà de ``plafond``.

    Jamais plus d'un octet de trop n'est demandé : un flux sans fin (FIFO,
    périphérique, fichier qui grossit) ne remplit pas la mémoire.
    """
    morceaux: list[bytes] = []
    total = 0
    while True:
        bloc = lire(min(_BLOC, plafond - total + 1))
        if not bloc:
            return b"".join(morceaux)
        total += len(bloc)
        if total > plafond:
            raise _trop_gros(plafond)
        morceaux.append(bloc)


def _pas_ordinaire() -> UnsafeInputError:
    return UnsafeInputError(
        Rejection.NOT_REGULAR_FILE,
        "seul un fichier ordinaire est lu (ni FIFO, ni périphérique, ni dossier)",
    )


@contextlib.contextmanager
def _ouvrir_ordinaire(path: Chemin, plafond: int) -> Iterator[tuple[BinaryIO, int]]:
    """Fichier ordinaire ouvert en lecture et sa taille annoncée, sous ``plafond``.

    Le type et la taille sont lus sur le descripteur ouvert (``fstat``), pas sur
    le chemin : le fichier contrôlé est celui qui sera lu. Le contrôle du
    chemin qui précède ne sert qu'à ne pas ouvrir un périphérique, ce qui peut
    déjà agir sur lui.
    """
    fd = -1
    try:
        ordinaire = stat.S_ISREG(Path(path).stat().st_mode)
        if ordinaire:
            fd = os.open(path, _DRAPEAUX_LECTURE)
    except OSError as exc:
        raise _illisible(exc) from None
    except ValueError:
        # octet NUL dans le chemin : ValueError de l'interpreteur, pas OSError
        raise UnsafeInputError(
            Rejection.UNREADABLE, "lecture impossible : chemin invalide"
        ) from None
    if not ordinaire:
        raise _pas_ordinaire()
    try:
        # avant os.fdopen, qui leve sa propre erreur sur un dossier
        etat = os.fstat(fd)
        if not stat.S_ISREG(etat.st_mode):
            raise _pas_ordinaire()
        if etat.st_size > plafond:
            raise _trop_gros(plafond)
        flux = os.fdopen(fd, "rb")
    except BaseException as exc:
        with contextlib.suppress(OSError):
            os.close(fd)
        if isinstance(exc, OSError):
            raise _illisible(exc) from None
        raise
    with flux:
        yield flux, etat.st_size


@_sans_chainage
def read_bytes(path: Chemin, *, limits: Limits = DEFAULT_LIMITS) -> bytes:
    """Contenu d'un fichier ordinaire, au plus ``limits.max_bytes`` octets.

    Un fichier plus gros est refusé sans être lu quand sa taille est annoncée,
    et au premier octet de trop sinon. Lève ``UnsafeInputError``, y compris
    pour un fichier absent ou illisible.
    """
    with _ouvrir_ordinaire(path, limits.max_bytes) as (flux, _):
        try:
            return _lire_flux(flux.read, limits.max_bytes)
        except OSError as exc:
            raise _illisible(exc) from None


def _plafonner(data: bytes, limits: Limits) -> bytes:
    if not isinstance(data, bytes):
        raise TypeError(f"octets attendus, reçu {type(data).__name__}")
    if len(data) > limits.max_bytes:
        raise _trop_gros(limits.max_bytes)
    return data


# --- texte --------------------------------------------------------------------

_BOM_UTF32 = (codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)
_BOM_UTF16 = (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)
_NOMS_DE_CODECS = {"utf-8": "UTF-8", "utf-8-sig": "UTF-8", "utf-16": "UTF-16"}


def _decoder(donnees: bytes, defaut: str = "utf-8") -> str:
    """Texte décodé strictement : UTF-8 ou UTF-16 selon le BOM, sinon ``defaut``.

    Windows PowerShell 5.1 écrit par défaut en UTF-16 avec BOM, et certains
    éditeurs ajoutent un BOM à l'UTF-8 : les deux sont acceptés, quel que soit
    le format.
    """
    # FF FE 00 00 commence comme le BOM UTF-16 : UTF-32 se teste d'abord
    if donnees.startswith(_BOM_UTF32):
        raise UnsafeInputError(Rejection.ENCODING, "encodage UTF-32 non pris en charge")
    if donnees.startswith(codecs.BOM_UTF8):
        codec = "utf-8-sig"
    elif donnees.startswith(_BOM_UTF16):
        codec = "utf-16"
    else:
        codec = defaut
    try:
        return donnees.decode(codec)
    except UnicodeDecodeError:
        # le nom du codec vient du code appelant ou du BOM, jamais du contenu
        attendu = _NOMS_DE_CODECS.get(codec, codec)
        raise UnsafeInputError(
            Rejection.ENCODING, f"encodage invalide : {attendu} attendu"
        ) from None


# --- XML ----------------------------------------------------------------------

# encodage declare par <?xml ... encoding="..."?>, lu sur un fichier sans BOM
_DECLARATION_XML = re.compile(
    rb"""<\?xml[^>]{0,200}?encoding\s*=\s*["']([A-Za-z][A-Za-z0-9._-]{0,39})["']"""
)
# encodages sur un octet admis sans BOM ; UTF-16 exige son BOM
_CODECS_XML = {
    "utf-8": "utf-8",
    "utf8": "utf-8",
    "us-ascii": "ascii",
    "ascii": "ascii",
    "iso-8859-1": "latin-1",
    "windows-1252": "cp1252",
}


def _decoder_xml(donnees: bytes) -> str:
    if donnees.startswith((codecs.BOM_UTF8, *_BOM_UTF16, *_BOM_UTF32)):
        return _decoder(donnees)
    if donnees[:2] in (b"<\x00", b"\x00<"):
        raise UnsafeInputError(Rejection.ENCODING, "XML en UTF-16 sans BOM refusé")
    declaration = _DECLARATION_XML.match(donnees)
    if declaration is None:
        return _decoder(donnees)
    codec = _CODECS_XML.get(declaration[1].decode("ascii").lower())
    if codec is None:
        raise UnsafeInputError(
            Rejection.ENCODING, "encodage déclaré par le XML non pris en charge"
        )
    return _decoder(donnees, codec)


def _dtd_refusee(*_: object) -> None:
    raise UnsafeInputError(
        Rejection.FORBIDDEN, "XML refusé : déclaration DOCTYPE (DTD) interdite"
    )


def _entite_refusee(*_: object) -> None:
    raise UnsafeInputError(
        Rejection.FORBIDDEN, "XML refusé : déclaration d'entité interdite"
    )


def _reference_externe_refusee(*_: object) -> int:
    raise UnsafeInputError(
        Rejection.FORBIDDEN, "XML refusé : référence externe interdite"
    )


def _nom_qualifie(nom: str) -> str:
    # expat rend « uri}local » ; ElementTree note « {uri}local »
    return "{" + nom if "}" in nom else nom


class _ConstructeurXml:
    """Gestionnaires expat : construit l'arbre et compte éléments et niveaux."""

    def __init__(self, limits: Limits) -> None:
        self._limits = limits
        self._arbre = ElementTree.TreeBuilder()
        self._elements = 0
        self._profondeur = 0

    def debut(self, nom: str, attributs: list[str]) -> None:
        # un attribut coute autant qu'un element : meme budget, sinon un seul
        # element en porterait des millions
        self._elements += 1 + len(attributs) // 2
        self._profondeur += 1
        if self._elements > self._limits.max_records:
            raise UnsafeInputError(
                Rejection.TOO_MANY,
                f"XML de plus de {self._limits.max_records} éléments et attributs "
                "refusé",
            )
        if self._profondeur > self._limits.max_depth:
            raise UnsafeInputError(
                Rejection.TOO_DEEP,
                f"XML trop imbriqué (plus de {self._limits.max_depth} niveaux)",
            )
        # ordered_attributes : liste plate nom, valeur, nom, valeur...
        paires = zip(attributs[::2], attributs[1::2], strict=True)
        self._arbre.start(
            _nom_qualifie(nom), {_nom_qualifie(cle): valeur for cle, valeur in paires}
        )

    def fin(self, nom: str) -> None:
        self._profondeur -= 1
        self._arbre.end(_nom_qualifie(nom))

    def texte(self, donnees: str) -> None:
        self._arbre.data(donnees)

    def racine(self) -> XmlElement:
        return self._arbre.close()


@_sans_chainage
def loads_xml(data: bytes, *, limits: Limits = DEFAULT_LIMITS) -> XmlElement:
    """Élément racine d'un document XML hostile ; lève ``UnsafeInputError``.

    Toute déclaration ``DOCTYPE`` est refusée, donc toute DTD, interne ou
    externe, et toute entité déclarée : ni XXE, ni *billion laughs*. Rien n'est
    lu hors de ``data`` : ni fichier, ni réseau. Commentaires et instructions
    de traitement sont ignorés ; les noms qualifiés suivent la notation
    ``{uri}local`` d'ElementTree.
    """
    texte = _decoder_xml(_plafonner(data, limits))
    constructeur = _ConstructeurXml(limits)
    analyseur = expat.ParserCreate(namespace_separator="}")
    analyseur.buffer_text = True
    analyseur.ordered_attributes = True
    # refus des la declaration DOCTYPE : rien d'une DTD n'est lu ni expanse ;
    # les trois gestionnaires suivants sont une defense en profondeur
    analyseur.StartDoctypeDeclHandler = _dtd_refusee
    analyseur.EntityDeclHandler = _entite_refusee
    analyseur.UnparsedEntityDeclHandler = _entite_refusee
    analyseur.ExternalEntityRefHandler = _reference_externe_refusee
    analyseur.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    analyseur.StartElementHandler = constructeur.debut
    analyseur.EndElementHandler = constructeur.fin
    analyseur.CharacterDataHandler = constructeur.texte
    try:
        # texte deja decode : expat le lit en UTF-8, quelle que soit la
        # declaration d'encodage du document
        analyseur.Parse(texte, True)
        return constructeur.racine()
    except expat.ExpatError as exc:
        raise UnsafeInputError(
            Rejection.MALFORMED,
            f"XML mal formé (ligne {exc.lineno}, colonne {exc.offset + 1})",
        ) from None


@_sans_chainage
def load_xml(path: Chemin, *, limits: Limits = DEFAULT_LIMITS) -> XmlElement:
    """Élément racine du fichier XML ``path`` : voir ``loads_xml``."""
    return loads_xml(read_bytes(path, limits=limits), limits=limits)


# --- JSON et TOML -------------------------------------------------------------

# chaine JSON, fermee ou non : le quantificateur possessif et la fin de texte
# admise gardent le balayage lineaire, meme sur des guillemets jamais fermes
_CHAINE_JSON = re.compile(r'"(?:[^"\\]|\\.)*+(?:"|\\?\Z)', re.DOTALL)
_HORS_STRUCTURE = re.compile(r"[^\[\]{}]+")


def _trop_imbrique(format_: str, limits: Limits) -> UnsafeInputError:
    return UnsafeInputError(
        Rejection.TOO_DEEP,
        f"{format_} trop imbriqué (plus de {limits.max_depth} niveaux)",
    )


def _trop_de_conteneurs(format_: str, limits: Limits) -> UnsafeInputError:
    return UnsafeInputError(
        Rejection.TOO_MANY,
        f"{format_} de plus de {limits.max_records} objets et tableaux refusé",
    )


def _verifier_imbrication_json(texte: str, limits: Limits) -> None:
    """Profondeur et nombre de conteneurs, comptés avant l'analyse.

    L'analyseur JSON est récursif : la profondeur se vérifie sur le texte,
    chaînes retirées, sans jamais approcher la limite de récursion de
    l'interpréteur (ni la pile d'un thread de travail).
    """
    structure = _HORS_STRUCTURE.sub("", _CHAINE_JSON.sub("", texte))
    if structure.count("[") + structure.count("{") > limits.max_records:
        raise _trop_de_conteneurs("JSON", limits)
    profondeur = 0
    for caractere in structure:
        if caractere in "[{":
            profondeur += 1
            if profondeur > limits.max_depth:
                raise _trop_imbrique("JSON", limits)
        elif profondeur:
            profondeur -= 1


def _constante_refusee(nom: str) -> Any:
    # nom : NaN, Infinity ou -Infinity, fixe par l'analyseur, pas par le fichier
    raise UnsafeInputError(
        Rejection.MALFORMED, f"JSON invalide : valeur non finie ({nom}) refusée"
    )


def _flottant_fini(format_: str) -> Callable[[str], float]:
    """Conversion des nombres à virgule d'un format, valeurs non finies refusées.

    ``parse_constant`` ne voit que les littéraux ``NaN`` et ``Infinity`` : un
    nombre qui déborde (``1e999``) devient ``inf`` sans passer par lui.
    """

    def convertir(texte: str) -> float:
        valeur = float(texte)
        if not math.isfinite(valeur):
            raise UnsafeInputError(
                Rejection.MALFORMED, f"{format_} invalide : valeur non finie refusée"
            )
        return valeur

    return convertir


def _sans_doublon(paires: list[tuple[str, Any]]) -> dict[str, Any]:
    # json.loads garde silencieusement la derniere de deux cles identiques :
    # deux lecteurs du meme fichier n'y verraient pas la meme valeur
    objet = dict(paires)
    if len(objet) != len(paires):
        raise UnsafeInputError(Rejection.DUPLICATE, "JSON refusé : clé en double")
    return objet


@_sans_chainage
def loads_json(data: bytes, *, limits: Limits = DEFAULT_LIMITS) -> Any:
    """Valeur d'un document JSON hostile ; lève ``UnsafeInputError``.

    UTF-8 (BOM toléré) ou UTF-16 avec BOM. Refusés : imbrication au-delà de
    ``limits.max_depth``, clés en double, ``NaN``, ``Infinity`` et tout nombre
    qui déborde en valeur non finie (``1e999``).
    """
    texte = _decoder(_plafonner(data, limits))
    _verifier_imbrication_json(texte, limits)
    try:
        return json.loads(
            texte,
            object_pairs_hook=_sans_doublon,
            parse_constant=_constante_refusee,
            parse_float=_flottant_fini("JSON"),
        )
    except json.JSONDecodeError as exc:
        raise UnsafeInputError(
            Rejection.MALFORMED,
            f"JSON invalide (ligne {exc.lineno}, colonne {exc.colno})",
        ) from None
    except RecursionError:
        # jamais atteint sous max_depth par defaut : filet si l'appelant le releve
        raise _trop_imbrique("JSON", limits) from None
    except UnsafeInputError:
        raise
    except ValueError:
        # entier au-dela de sys.get_int_max_str_digits() (4300 chiffres)
        raise UnsafeInputError(
            Rejection.MALFORMED, "JSON invalide : nombre hors limites"
        ) from None


@_sans_chainage
def load_json(path: Chemin, *, limits: Limits = DEFAULT_LIMITS) -> Any:
    """Valeur du fichier JSON ``path`` : voir ``loads_json``."""
    return loads_json(read_bytes(path, limits=limits), limits=limits)


def _verifier_structure(valeur: object, format_: str, limits: Limits) -> None:
    """Profondeur et nombre de conteneurs d'une valeur analysée, sans récursion."""
    pile: list[tuple[object, int]] = [(valeur, 1)]
    conteneurs = 0
    while pile:
        courant, profondeur = pile.pop()
        if isinstance(courant, dict):
            enfants: Iterator[object] = iter(courant.values())
        elif isinstance(courant, list):
            enfants = iter(courant)
        else:
            continue
        conteneurs += 1
        if profondeur > limits.max_depth:
            raise _trop_imbrique(format_, limits)
        if conteneurs > limits.max_records:
            raise _trop_de_conteneurs(format_, limits)
        pile.extend((enfant, profondeur + 1) for enfant in enfants)


def _limites_toml(limits: Limits) -> Limits:
    return replace(limits, max_bytes=min(limits.max_bytes, limits.max_toml_bytes))


@_sans_chainage
def loads_toml(data: bytes, *, limits: Limits = DEFAULT_LIMITS) -> dict[str, Any]:
    """Table d'un document TOML hostile ; lève ``UnsafeInputError``.

    UTF-8 (BOM toléré) ou UTF-16 avec BOM, comme les autres formats de texte.

    ``tomllib`` est écrit en Python : une imbrication qui épuise sa récursion
    lève un ``RecursionError`` propre, traduit ici ; la profondeur du résultat
    est ensuite bornée par ``limits.max_depth``. Il construit aussi tout le
    document avant qu'un conteneur puisse être compté : le texte est donc borné
    à ``limits.max_toml_bytes`` avant l'analyse. ``inf`` et ``nan``, que la
    syntaxe admet, sont refusés comme en JSON.
    """
    texte = _decoder(_plafonner(data, _limites_toml(limits)))
    try:
        document = tomllib.loads(texte, parse_float=_flottant_fini("TOML"))
    except RecursionError:
        raise _trop_imbrique("TOML", limits) from None
    except UnsafeInputError:
        raise
    except ValueError:
        # TOMLDecodeError : son message peut citer une cle ou un caractere
        raise UnsafeInputError(Rejection.MALFORMED, "TOML invalide") from None
    _verifier_structure(document, "TOML", limits)
    return document


@_sans_chainage
def load_toml(path: Chemin, *, limits: Limits = DEFAULT_LIMITS) -> dict[str, Any]:
    """Table du fichier TOML ``path`` : voir ``loads_toml``."""
    # plafond du format des la lecture : un fichier trop gros n'est pas lu
    return loads_toml(read_bytes(path, limits=_limites_toml(limits)), limits=limits)


# --- CSV ----------------------------------------------------------------------

# csv.field_size_limit est un reglage du processus : pose, lecture et remise en
# place se font sous verrou (le moteur evalue les checks dans des threads)
_VERROU_CSV = threading.Lock()


@_sans_chainage
def loads_csv(
    data: bytes,
    *,
    limits: Limits = DEFAULT_LIMITS,
    columns: int | None = None,
    encoding: str = "utf-8",
    delimiter: str = ",",
) -> list[list[str]]:
    """Lignes d'un CSV hostile, en-tête comprise ; lève ``UnsafeInputError``.

    Toutes les lignes ont le même nombre de colonnes : ``columns`` s'il est
    donné, sinon celui de la première ligne ; les lignes vides sont ignorées.
    ``encoding`` est le codec d'un fichier sans BOM (``audit.csv`` d'une GPO
    peut être en page de code ANSI) ; un BOM UTF-8 ou UTF-16 l'emporte.
    """
    texte = _decoder(_plafonner(data, limits), encoding)
    attendu = columns
    lignes: list[list[str]] = []
    with _VERROU_CSV:
        ancien = csv.field_size_limit(limits.max_field_chars)
        try:
            lecteur = csv.reader(
                io.StringIO(texte, newline=""), delimiter=delimiter, strict=True
            )
            for ligne in lecteur:
                if not ligne:
                    continue
                if len(ligne) > limits.max_columns:
                    raise UnsafeInputError(
                        Rejection.TOO_MANY,
                        f"CSV de plus de {limits.max_columns} colonnes refusé "
                        f"(ligne {lecteur.line_num})",
                    )
                if attendu is None:
                    attendu = len(ligne)
                if len(ligne) != attendu:
                    raise UnsafeInputError(
                        Rejection.MALFORMED,
                        f"CSV invalide : {len(ligne)} colonnes au lieu de "
                        f"{attendu} (ligne {lecteur.line_num})",
                    )
                if len(lignes) >= limits.max_records:
                    raise UnsafeInputError(
                        Rejection.TOO_MANY,
                        f"CSV de plus de {limits.max_records} lignes refusé",
                    )
                lignes.append(ligne)
        except csv.Error:
            raise UnsafeInputError(
                Rejection.MALFORMED,
                "CSV invalide, ou champ de plus de "
                f"{limits.max_field_chars} caractères",
            ) from None
        finally:
            csv.field_size_limit(ancien)
    return lignes


@_sans_chainage
def load_csv(
    path: Chemin,
    *,
    limits: Limits = DEFAULT_LIMITS,
    columns: int | None = None,
    encoding: str = "utf-8",
    delimiter: str = ",",
) -> list[list[str]]:
    """Lignes du fichier CSV ``path`` : voir ``loads_csv``."""
    return loads_csv(
        read_bytes(path, limits=limits),
        limits=limits,
        columns=columns,
        encoding=encoding,
        delimiter=delimiter,
    )


# --- Registry.pol -------------------------------------------------------------

# en-tete : REGFILE_SIGNATURE 0x67655250 (« PReg ») puis REGISTRY_FILE_VERSION 1,
# deux DWORD petit-boutistes ; corps : suite de [cle;valeur;type;taille;donnees]
# en UTF-16LE, cle et valeur terminees par NUL
_POL_SIGNATURE = b"PReg"
_POL_VERSION = 1
_POL_ENTETE = struct.Struct("<4sI")
_POL_DWORD = struct.Struct("<I")
_POL_OUVRANT = "[".encode("utf-16-le")
_POL_SEPARATEUR = ";".encode("utf-16-le")
_POL_FERMANT = "]".encode("utf-16-le")
_POL_NUL = b"\x00\x00"
# un nom de valeur du registre compte au plus 16 383 caracteres ; un chemin de
# cle, 255 par niveau : la borne couvre les deux sans laisser lire sans fin
_POL_NOM_MAX = 16_384


@dataclass(frozen=True, slots=True)
class PolEntry:
    """Entrée d'un Registry.pol : clé, valeur, type ``REG_*`` et données brutes.

    ``data`` n'est pas interprété : l'appelant le décode selon ``type``
    (``REG_SZ`` = 1 en UTF-16LE, ``REG_DWORD`` = 4...).
    """

    key: str
    value: str
    type: int
    data: bytes


def _pol_tronque() -> UnsafeInputError:
    return UnsafeInputError(Rejection.MALFORMED, "Registry.pol tronqué")


def _pol_attendre(donnees: bytes, position: int, delimiteur: bytes) -> int:
    fin = position + len(delimiteur)
    if fin > len(donnees):
        raise _pol_tronque()
    if donnees[position:fin] != delimiteur:
        raise UnsafeInputError(
            Rejection.MALFORMED,
            f"Registry.pol invalide : délimiteur attendu à l'octet {position}",
        )
    return fin


def _pol_chaine(donnees: bytes, position: int) -> tuple[str, int]:
    """Chaîne UTF-16LE terminée par NUL ; rend le texte et la position suivante."""
    limite = min(len(donnees), position + 2 * (_POL_NOM_MAX + 1))
    fin = position
    while True:
        fin = donnees.find(_POL_NUL, fin, limite)
        if fin < 0:
            if limite == len(donnees):
                raise _pol_tronque()
            raise UnsafeInputError(
                Rejection.TOO_LARGE,
                f"Registry.pol : nom de plus de {_POL_NOM_MAX} caractères refusé",
            )
        # le terminateur est une unite UTF-16 : il commence a un octet pair
        if (fin - position) % 2 == 0:
            break
        fin += 1
    try:
        texte = donnees[position:fin].decode("utf-16-le")
    except UnicodeDecodeError:
        raise UnsafeInputError(
            Rejection.ENCODING, "Registry.pol : nom qui n'est pas de l'UTF-16"
        ) from None
    return texte, fin + len(_POL_NUL)


def _pol_dword(donnees: bytes, position: int) -> tuple[int, int]:
    fin = position + _POL_DWORD.size
    if fin > len(donnees):
        raise _pol_tronque()
    (valeur,) = _POL_DWORD.unpack_from(donnees, position)
    return valeur, fin


@_sans_chainage
def loads_registry_pol(
    data: bytes, *, limits: Limits = DEFAULT_LIMITS
) -> tuple[PolEntry, ...]:
    """Entrées d'un Registry.pol hostile ; lève ``UnsafeInputError``.

    Analyse bornée : signature ``PReg`` et version 1 exigées, chaque longueur
    comparée aux octets restants avant d'être suivie, nombre d'entrées plafonné
    par ``limits.max_records``.
    """
    donnees = _plafonner(data, limits)
    if len(donnees) < _POL_ENTETE.size:
        raise _pol_tronque()
    signature, version = _POL_ENTETE.unpack_from(donnees)
    if signature != _POL_SIGNATURE:
        raise UnsafeInputError(
            Rejection.MALFORMED, "Registry.pol invalide : signature PReg absente"
        )
    if version != _POL_VERSION:
        raise UnsafeInputError(
            Rejection.UNSUPPORTED,
            f"Registry.pol en version {version} : seule la version 1 est lue",
        )
    entrees: list[PolEntry] = []
    position = _POL_ENTETE.size
    while position < len(donnees):
        if len(entrees) >= limits.max_records:
            raise UnsafeInputError(
                Rejection.TOO_MANY,
                f"Registry.pol de plus de {limits.max_records} entrées refusé",
            )
        position = _pol_attendre(donnees, position, _POL_OUVRANT)
        cle, position = _pol_chaine(donnees, position)
        position = _pol_attendre(donnees, position, _POL_SEPARATEUR)
        valeur, position = _pol_chaine(donnees, position)
        position = _pol_attendre(donnees, position, _POL_SEPARATEUR)
        type_, position = _pol_dword(donnees, position)
        position = _pol_attendre(donnees, position, _POL_SEPARATEUR)
        taille, position = _pol_dword(donnees, position)
        position = _pol_attendre(donnees, position, _POL_SEPARATEUR)
        # la taille annoncee se compare aux octets restants avant toute lecture
        if taille > len(donnees) - position:
            raise _pol_tronque()
        contenu = donnees[position : position + taille]
        position = _pol_attendre(donnees, position + taille, _POL_FERMANT)
        entrees.append(PolEntry(cle, valeur, type_, contenu))
    return tuple(entrees)


@_sans_chainage
def load_registry_pol(
    path: Chemin, *, limits: Limits = DEFAULT_LIMITS
) -> tuple[PolEntry, ...]:
    """Entrées du fichier Registry.pol ``path`` : voir ``loads_registry_pol``."""
    return loads_registry_pol(read_bytes(path, limits=limits), limits=limits)


# --- ZIP ----------------------------------------------------------------------

# fin de repertoire central (EOCD) : signature, disques, nombres d'entrees,
# taille et position du repertoire central, longueur du commentaire
_ZIP_FIN = struct.Struct("<4s4H2LH")
_ZIP_SIGNATURE_FIN = b"PK\x05\x06"
_ZIP_LOCALISATEUR_64 = b"PK\x06\x07"
_ZIP_TAILLE_LOCALISATEUR_64 = 20
# zipfile cherche la fin de repertoire sur 65 535 octets de commentaire, et
# sur 65 536 sous Python 3.11 : la fenetre lue couvre le plus large des deux
_ZIP_RECHERCHE_FIN = 1 << 16
# octets du repertoire central admis par entree, en moyenne : 46 d'en-tete, le
# nom et les champs supplementaires ; au-dela, le catalogue est demesure
_ZIP_CATALOGUE_PAR_ENTREE = 1024
# sous ce volume decompresse, le ratio n'est pas evalue : un petit fichier tres
# repetitif n'est pas une bombe
_ZIP_SEUIL_RATIO = _MIO
_ZIP_METHODES = frozenset({zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED})
_ZIP_CHIFFRE = 0x1
# attribut MS-DOS « dossier », pose par les outils Windows
_ZIP_DOSSIER_DOS = 0x10
_ZIP_NOM_MAX = 4096
_ZIP_COMPOSANT_MAX = 255
# noms de peripheriques que Windows ouvre quel que soit le dossier
# (meme regle que ntpath.isreserved : chiffres en exposant compris)
_PERIPHERIQUES_WINDOWS = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"{port}{n}" for port in ("COM", "LPT") for n in "123456789\xb9\xb2\xb3"}
)
_ERREURS_ZIP = (
    zipfile.BadZipFile,
    zipfile.LargeZipFile,
    zlib.error,
    EOFError,
    # methode de compression, chiffrement, RecursionError
    RuntimeError,
    struct.error,
    # avertissement de zipfile (3.12+) converti en erreur par -W error : son
    # message peut citer un nom d'entree
    Warning,
    # noms non decodables, positions negatives
    ValueError,
    OverflowError,
)


def _chemin_refuse(numero: int, motif: str) -> UnsafeInputError:
    # le numero d'ordre de l'entree, jamais son nom : il vient de l'archive
    return UnsafeInputError(
        Rejection.UNSAFE_PATH, f"archive ZIP refusée : entrée n° {numero}, {motif}"
    )


def _zip_verifier_fin(flux: BinaryIO, taille: int, limits: Limits) -> None:
    """Contrôle la fin de répertoire central avant que ``zipfile`` ne la suive.

    ``zipfile`` charge tout le répertoire central en mémoire avant qu'une seule
    entrée puisse être comptée : son volume est donc borné ici, sur les octets
    lus en queue de fichier. ZIP64 est refusé : les plafonds tiennent dans le
    format classique (65 535 entrées, 4 Gio).

    La fin de répertoire et son commentaire doivent terminer le fichier, à
    l'octet près : la fin retenue ici est alors celle que ``zipfile`` retient,
    quelle que soit sa fenêtre de recherche, et les 20 octets qui la précèdent,
    où se loge le localisateur ZIP64, sont toujours parmi ceux lus ici.
    """
    fenetre = min(
        taille, _ZIP_FIN.size + _ZIP_RECHERCHE_FIN + _ZIP_TAILLE_LOCALISATEUR_64
    )
    flux.seek(taille - fenetre)
    queue = flux.read(fenetre)
    flux.seek(0)
    # meme recherche que zipfile : la fin sans commentaire, sinon la derniere
    # signature de la queue
    position = len(queue) - _ZIP_FIN.size
    if not (
        position >= 0
        and queue.startswith(_ZIP_SIGNATURE_FIN, position)
        and queue.endswith(b"\x00\x00")
    ):
        position = queue.rfind(_ZIP_SIGNATURE_FIN)
    if position < 0 or position + _ZIP_FIN.size > len(queue):
        raise UnsafeInputError(
            Rejection.MALFORMED, "archive ZIP invalide : fin de répertoire absente"
        )
    (
        _,
        disque,
        disque_central,
        sur_disque,
        entrees,
        taille_centrale,
        debut,
        commentaire,
    ) = _ZIP_FIN.unpack_from(queue, position)
    if position + _ZIP_FIN.size + commentaire != len(queue):
        # octets apres le commentaire, ou commentaire tronque : zipfile et ce
        # controle pourraient ne pas lire la meme fin de repertoire
        raise UnsafeInputError(
            Rejection.MALFORMED,
            "archive ZIP invalide : octets après la fin de répertoire",
        )
    localisateur = position - _ZIP_TAILLE_LOCALISATEUR_64
    if localisateur < 0 and taille > len(queue):
        # jamais atteint : la fin termine le fichier, donc position >= 21 dans
        # une fenetre pleine ; filet si la fenetre venait a retrecir
        raise UnsafeInputError(Rejection.UNSUPPORTED, "archive ZIP64 refusée")
    if (
        0xFFFF in (sur_disque, entrees)
        or 0xFFFFFFFF in (taille_centrale, debut)
        or (localisateur >= 0 and queue.startswith(_ZIP_LOCALISATEUR_64, localisateur))
    ):
        raise UnsafeInputError(Rejection.UNSUPPORTED, "archive ZIP64 refusée")
    if disque or disque_central:
        raise UnsafeInputError(
            Rejection.UNSUPPORTED, "archive ZIP en plusieurs volumes refusée"
        )
    if (
        entrees > limits.max_entries
        or taille_centrale > limits.max_entries * _ZIP_CATALOGUE_PAR_ENTREE
    ):
        raise _trop_d_entrees(limits)


def _trop_d_entrees(limits: Limits) -> UnsafeInputError:
    return UnsafeInputError(
        Rejection.TOO_MANY,
        f"archive ZIP de plus de {limits.max_entries} entrées refusée "
        "(fichiers et dossiers, dossiers intermédiaires compris)",
    )


def _zip_parties(
    numero: int, info: zipfile.ZipInfo, limits: Limits
) -> tuple[tuple[str, ...], bool]:
    """Composants sûrs du chemin d'une entrée, et s'il s'agit d'un dossier.

    Le nom d'origine est contrôlé, pas celui que ``zipfile`` a déjà nettoyé.
    ``\\`` vaut séparateur sur toutes les plateformes : une archive piégée pour
    Windows est refusée aussi sous Linux.
    """
    brut = info.orig_filename
    if not brut or len(brut) > _ZIP_NOM_MAX:
        raise _chemin_refuse(numero, "nom vide ou trop long")
    if any(ord(caractere) < 0x20 or caractere == "\x7f" for caractere in brut):
        raise _chemin_refuse(numero, "caractère de contrôle dans le nom")
    nom = brut.replace("\\", "/")
    if nom.startswith("/"):
        raise _chemin_refuse(numero, "chemin absolu")
    mode = info.external_attr >> 16
    dossier = (
        nom.endswith("/")
        or stat.S_ISDIR(mode)
        or bool(info.external_attr & _ZIP_DOSSIER_DOS)
    )
    parties = tuple(nom.rstrip("/").split("/"))
    if len(parties) > limits.max_depth:
        # chaque composant est un dossier a creer : sans plafond, quelques
        # entrees vides creent des millions de dossiers
        raise _chemin_refuse(numero, f"chemin de plus de {limits.max_depth} composants")
    for partie in parties:
        if partie == "..":
            raise _chemin_refuse(numero, "chemin qui remonte par « .. »")
        if partie in ("", "."):
            raise _chemin_refuse(numero, "chemin non canonique")
        if ":" in partie:
            # C:, \\?\, flux de donnees alternatif NTFS (fichier:flux)
            raise _chemin_refuse(numero, "lecteur ou flux Windows dans le chemin")
        if partie.endswith((" ", ".")):
            # Windows retire ces fins de nom : deux entrees se confondraient
            raise _chemin_refuse(numero, "nom terminé par un point ou une espace")
        if partie.split(".", 1)[0].rstrip(" ").upper() in _PERIPHERIQUES_WINDOWS:
            raise _chemin_refuse(numero, "nom de périphérique Windows")
        if len(partie.encode("utf-8", "surrogatepass")) > _ZIP_COMPOSANT_MAX:
            raise _chemin_refuse(numero, "nom vide ou trop long")
    type_fichier = stat.S_IFMT(mode)
    if type_fichier == stat.S_IFLNK:
        raise UnsafeInputError(
            Rejection.LINK,
            f"archive ZIP refusée : entrée n° {numero}, lien symbolique",
        )
    if type_fichier not in (0, stat.S_IFREG, stat.S_IFDIR):
        raise UnsafeInputError(
            Rejection.LINK,
            f"archive ZIP refusée : entrée n° {numero}, fichier spécial",
        )
    if info.flag_bits & _ZIP_CHIFFRE:
        raise UnsafeInputError(
            Rejection.UNSUPPORTED,
            f"archive ZIP refusée : entrée n° {numero} chiffrée",
        )
    if info.compress_type not in _ZIP_METHODES:
        raise UnsafeInputError(
            Rejection.UNSUPPORTED,
            f"archive ZIP refusée : entrée n° {numero}, méthode de compression "
            "non prise en charge",
        )
    return parties, dossier


def _cle_de_nom(partie: str) -> str:
    # NTFS, APFS et HFS+ confondent la casse et les formes Unicode
    return unicodedata.normalize("NFC", partie).casefold()


@dataclass(slots=True)
class _NoeudZip:
    """Fichier ou dossier du plan d'extraction, rangé par composant de chemin."""

    fichier: bool
    declare: bool = False
    """Dossier déclaré par une entrée, et non seulement impliqué par un chemin."""
    enfants: dict[str, _NoeudZip] = field(default_factory=dict)


def _zip_doublon(numero: int, motif: str) -> UnsafeInputError:
    return UnsafeInputError(
        Rejection.DUPLICATE, f"archive ZIP refusée : entrée n° {numero}, {motif}"
    )


def _zip_plan(
    archive: zipfile.ZipFile, limits: Limits
) -> list[tuple[tuple[str, ...], bool, zipfile.ZipInfo]]:
    """Entrées contrôlées, toutes, avant la première écriture.

    Les noms sont rangés dans un arbre de composants : sa taille est celle de
    ce qui sera créé, fichiers et dossiers, et elle est bornée par
    ``limits.max_entries``, dossiers intermédiaires compris.
    """
    infos = archive.infolist()
    if len(infos) > limits.max_entries:
        raise _trop_d_entrees(limits)
    plan: list[tuple[tuple[str, ...], bool, zipfile.ZipInfo]] = []
    racine = _NoeudZip(fichier=False)
    noeuds = 0
    positions: set[int] = set()
    annonce = 0
    for numero, info in enumerate(infos, start=1):
        parties, dossier = _zip_parties(numero, info, limits)
        if info.header_offset in positions:
            # deux entrees sur les memes octets : zipfile (3.12+) n'emet alors
            # qu'un avertissement, qui cite le nom de l'entree
            raise UnsafeInputError(
                Rejection.MALFORMED,
                f"archive ZIP invalide : entrée n° {numero} superposée à une autre",
            )
        positions.add(info.header_offset)
        noeud = racine
        for rang, partie in enumerate(parties, start=1):
            derniere = rang == len(parties)
            cle = _cle_de_nom(partie)
            enfant = noeud.enfants.get(cle)
            if enfant is None:
                noeuds += 1
                if noeuds > limits.max_entries:
                    raise _trop_d_entrees(limits)
                enfant = _NoeudZip(fichier=derniere and not dossier)
                noeud.enfants[cle] = enfant
            elif derniere and (enfant.declare or (enfant.fichier and not dossier)):
                raise _zip_doublon(numero, "nom en double")
            elif enfant.fichier or (derniere and not dossier):
                raise _zip_doublon(numero, "un nom désigne un fichier et un dossier")
            noeud = enfant
        if dossier:
            noeud.declare = True
        # refus precoce sur les tailles annoncees ; elles peuvent mentir, les
        # plafonds sont donc tenus sur les octets decompresses, a l'extraction
        annonce += info.file_size
        if info.file_size > limits.max_bytes or annonce > limits.max_total_bytes:
            raise _zip_trop_gros(limits)
        plan.append((parties, dossier, info))
    return plan


def _zip_trop_gros(limits: Limits) -> UnsafeInputError:
    return UnsafeInputError(
        Rejection.TOO_LARGE,
        f"archive ZIP refusée : plus de {limits.max_bytes} octets décompressés "
        f"par entrée, ou de {limits.max_total_bytes} au total",
    )


def _creer_dossiers(racine: Path, parties: tuple[str, ...]) -> None:
    chemin = racine
    for partie in parties:
        chemin = chemin / partie
        # 0700 a chaque niveau, comme la racine
        with contextlib.suppress(FileExistsError):
            chemin.mkdir(mode=0o700)


@_sans_chainage
def _extraire_zip(path: Chemin, racine: Path, limits: Limits) -> None:
    with _ouvrir_ordinaire(path, limits.max_bytes) as (flux, taille_archive):
        try:
            _zip_verifier_fin(flux, taille_archive, limits)
            with zipfile.ZipFile(flux) as archive:
                plan = _zip_plan(archive, limits)
                plafond_ratio = max(_ZIP_SEUIL_RATIO, limits.max_ratio * taille_archive)
                total = 0
                for parties, dossier, info in plan:
                    if dossier:
                        _creer_dossiers(racine, parties)
                        continue
                    _creer_dossiers(racine, parties[:-1])
                    destination = racine.joinpath(*parties)
                    # O_EXCL : jamais par-dessus un fichier ni a travers un lien
                    fd = os.open(destination, _DRAPEAUX_CREATION, 0o600)
                    with os.fdopen(fd, "wb") as sortie, archive.open(info) as source:
                        ecrits = 0
                        while bloc := source.read(_BLOC):
                            ecrits += len(bloc)
                            total += len(bloc)
                            # avant d'ecrire : le disque ne recoit jamais un
                            # octet au-dela des plafonds
                            if ecrits > limits.max_bytes:
                                raise _zip_trop_gros(limits)
                            if total > limits.max_total_bytes:
                                raise _zip_trop_gros(limits)
                            if total > plafond_ratio:
                                raise UnsafeInputError(
                                    Rejection.COMPRESSION_RATIO,
                                    "archive ZIP refusée : ratio de compression "
                                    f"supérieur à {limits.max_ratio}",
                                )
                            sortie.write(bloc)
        except UnsafeInputError:
            raise
        except _ERREURS_ZIP:
            # le message de zipfile peut citer un nom d'entree : jamais repris
            raise UnsafeInputError(
                Rejection.MALFORMED, "archive ZIP invalide ou corrompue"
            ) from None
        except OSError as exc:
            raise _illisible(exc, "extraction") from None


@contextlib.contextmanager
def extract_zip(path: Chemin, *, limits: Limits = DEFAULT_LIMITS) -> Iterator[Path]:
    """Extrait une archive ZIP hostile dans un dossier temporaire privé.

    Gestionnaire de contexte : rend le dossier d'extraction (créé en 0700,
    fichiers en 0600) et le supprime en sortie, extraction réussie ou non.

    Toutes les entrées sont contrôlées avant la première écriture : chemin
    absolu, ``..``, chemin trop profond, lien symbolique, fichier spécial, nom
    en double, entrée chiffrée ou ZIP64 font refuser l'archive entière. Le
    plafond d'entrées compte tout ce qui serait créé, dossiers intermédiaires
    compris. Les plafonds d'octets (par entrée et au total, ratio de
    compression) portent sur les octets réellement décompressés : les tailles
    annoncées par les en-têtes ne servent qu'à refuser plus tôt. Lève
    ``UnsafeInputError``.
    """
    try:
        racine = Path(tempfile.mkdtemp(prefix="amnesia-"))
    except OSError as exc:
        raise _illisible(exc, "extraction") from None
    try:
        _extraire_zip(path, racine, limits)
        yield racine
    finally:
        shutil.rmtree(racine, ignore_errors=True)
