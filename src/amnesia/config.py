# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Fichier de mission ``amnesia.toml`` : configuration effective d'un audit.

``load_config()`` lit le fichier désigné (``--config``), sinon ``amnesia.toml``
du répertoire courant s'il existe, par la couche sûre ``amnesia.inputs``, puis
applique les surcharges de la ligne de commande. Priorité, de la plus forte à
la plus faible : ligne de commande, fichier, valeurs par défaut. Le profil
(#47) s'intercalera entre les valeurs par défaut et le fichier : ``Origin`` et
``_Etat.poser()`` sont les points d'extension.

Un fichier trouvé dans le répertoire courant n'a pas été désigné : il est
refusé s'il est un lien symbolique, s'il appartient à un autre compte ou si le
groupe ou les autres comptes peuvent l'écrire (hors Windows, où ces droits ne
se lisent pas dans ``st_mode``), et ``Config.source_kind`` retient d'où vient
le fichier (``cwd`` ou ``--config``) pour l'appelant et pour le rapport.

Validation stricte : une clé inconnue, un type inattendu, une date qui n'est
pas ISO 8601, un marquage hors TLP 2.0 ou un seuil hors bornes lèvent
``ConfigError``, dont le message cite le chemin de la clé. Aucun secret : une
clé au nom de secret (``password``, ``secret``, ``token``, ``*_key``) est
refusée où qu'elle soit, sauf si elle est une clé connue, et sa valeur n'est
jamais reprise dans le message ; un texte libre qui ressemble à un secret
(``password=...``, identifiants dans une URL) est refusé de même.

Clés : ``KEYS`` (mission, profil, rapport) et ``THRESHOLDS`` (seuils). Format
et exemple commenté : ``example_toml()``, écrit par ``amnesia init``.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import stat
import sys
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from enum import StrEnum
from pathlib import Path, PureWindowsPath
from types import MappingProxyType
from typing import Any

from .checks.base import assainir
from .inputs import UnsafeInputError, load_toml
from .output import DEFAULT_DIR

__all__ = [
    "DEFAULT_FILE",
    "KEYS",
    "LANGS",
    "REPORT_FORMATS",
    "SOURCE_CWD",
    "SOURCE_OPTION",
    "THRESHOLDS",
    "TLP",
    "Config",
    "ConfigError",
    "Origin",
    "Threshold",
    "example_toml",
    "load_config",
]

DEFAULT_FILE = "amnesia.toml"
"""Fichier de mission lu sans ``--config``, s'il existe dans le répertoire courant."""

SOURCE_CWD = "cwd"
"""``Config.source_kind`` : fichier trouvé dans le répertoire courant, sans
avoir été désigné."""

SOURCE_OPTION = "--config"
"""``Config.source_kind`` : fichier désigné par ``--config``."""

TLP = ("TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED")
"""Marquages TLP 2.0 (FIRST, 2022), du moins au plus restrictif."""

LANGS = ("fr", "en")
"""Langues du livrable."""

REPORT_FORMATS = ("json", "md", "text")
"""Formats de livrable."""

SOURCES_DE_SECRETS = (
    "--password-file, variable d'environnement AMNESIA_WINRM_PASSWORD ou saisie "
    "au terminal ; docs/SECRETS.md"
)
"""Où fournir un secret, puisque le fichier de mission n'en porte aucun."""

_TEXTE_MAX = 200
_CHEMIN_MAX = 1024
_PROFIL = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
# nom de cle qui annonce un secret : password, passwd, pwd, secret, token, *_key
_CLE_SECRETE = re.compile(r"passw|passphrase|pwd|secret|token|(?:^|[_.-]|api)key$")
# cle citee telle quelle dans un message ; toute autre passe par ascii()
_CLE_SURE = re.compile(r"[A-Za-z0-9_.-]{1,80}")
# nombre passe par --set : chiffres ASCII seuls, la ou int() et float()
# admettent aussi « 5_0 », «  50  », « 1e3 » ou « nan »
_ENTIER = re.compile(r"-?[0-9]+")
_DECIMAL = re.compile(r"-?[0-9]+(?:\.[0-9]+)?")
# categories Unicode refusees dans un texte libre : controles (dont ANSI),
# formats (dont bidi), surrogates, usage prive, non assignes, separateurs de
# ligne et de paragraphe ; les espaces (Zs, dont l'insecable) sont admises
_CATEGORIES_REFUSEES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})
# bit « substitut de nom » d'une balise de reanalyse Windows (lien symbolique,
# jonction), comme amnesia.output
_SUBSTITUT_DE_NOM = 0x20000000


class ConfigError(ValueError):
    """Configuration refusée ; le message, en français, est affichable tel quel.

    Il cite le chemin de la clé, jamais la valeur d'une clé au nom de secret.
    """


class Origin(StrEnum):
    """D'où vient une valeur effective ; affiché par ``amnesia config show``."""

    DEFAULT = "défaut"
    FILE = "fichier"
    CLI = "cli"


@dataclass(frozen=True, slots=True)
class Threshold:
    """Seuil d'un check, surchargeable dans ``[thresholds]``.

    ``minimum`` et ``maximum`` sont inclus. ``integer`` : la valeur est un
    entier ; sinon tout nombre fini, rendu en flottant.
    """

    name: str
    default: int | float
    minimum: int | float
    maximum: int | float
    unit: str
    description: str
    integer: bool = True


THRESHOLDS: tuple[Threshold, ...] = (
    Threshold(
        name="security_log_min_retention_days",
        default=90,
        minimum=1,
        maximum=3650,
        unit="jours",
        description=(
            "profondeur minimale du journal Security avant écrasement, en jours"
        ),
    ),
    Threshold(
        name="ntp_max_offset_seconds",
        default=5.0,
        minimum=0.001,
        maximum=3600,
        unit="secondes",
        description="écart d'horloge maximal toléré avec la source de temps",
        integer=False,
    ),
)
"""Seuils connus. Les checks Windows ne sont pas encore évalués : quand un
check déclarera ses seuils dans ses métadonnées (``CheckMeta``), cette table
en sera dérivée ; ``load_config(thresholds=...)`` accepte déjà une autre table."""


def _montrer(valeur: object, limite: int = 60) -> str:
    """Valeur citée dans un message : échappée par ``ascii()`` et tronquée."""
    try:
        texte = ascii(valeur)
    except ValueError:
        # entier de plus de 4300 chiffres (0xFFFF... en TOML) : repr() le refuse
        return "<entier trop grand>"
    return texte if len(texte) <= limite else texte[: limite - 1] + "…"


def _cle(chemin: str) -> str:
    return chemin if _CLE_SURE.fullmatch(chemin) else _montrer(chemin)


def _est_secrete(cle: str) -> bool:
    return _CLE_SECRETE.search(cle.lower()) is not None


def _refus_secret(chemin: str) -> ConfigError:
    return ConfigError(
        f"clé « {_cle(chemin)} » : aucun secret dans le fichier de mission ni "
        "sur la ligne de commande ; retire cette clé et fournis le secret par "
        f"une source admise ({SOURCES_DE_SECRETS})"
    )


def _refuser_secrets(
    valeur: object, connues: Mapping[str, object], chemin: str = ""
) -> None:
    """Refuse toute clé au nom de secret, à n'importe quelle profondeur.

    Une clé connue n'est jamais un secret, quel que soit son nom : un seuil
    ``krbtgt_password_max_age_days`` doit pouvoir être déclaré.
    """
    if isinstance(valeur, Mapping):
        for cle, contenu in valeur.items():
            sous_chemin = f"{chemin}.{cle}" if chemin else str(cle)
            if sous_chemin not in connues and _est_secrete(str(cle)):
                raise _refus_secret(sous_chemin)
            _refuser_secrets(contenu, connues, sous_chemin)
    elif isinstance(valeur, list):
        for element in valeur:
            _refuser_secrets(element, connues, chemin)


def _echapper(texte: str) -> str:
    # meme echappement que la fin d'assainir() : seul le caviardage les distingue
    return "".join(
        c if c.isprintable() else c.encode("unicode_escape").decode("ascii")
        for c in texte
    )


def _texte(limite: int = _TEXTE_MAX) -> Callable[[str, object, bool], str]:
    def analyser(chemin: str, valeur: object, _cli: bool) -> str:
        if not isinstance(valeur, str):
            raise ConfigError(f"{chemin} : chaîne attendue")
        if not valeur.strip():
            raise ConfigError(f"{chemin} : chaîne vide")
        if len(valeur) > limite:
            raise ConfigError(f"{chemin} : {limite} caractères au plus")
        if any(unicodedata.category(c) in _CATEGORIES_REFUSEES for c in valeur):
            raise ConfigError(
                f"{chemin} : caractère de contrôle ou non imprimable refusé"
            )
        # ce texte est recopie dans le rapport et par « config show » : ce que
        # assainir() y caviarderait (password=..., identifiants d'une URL,
        # secret deja lu) n'a pas sa place ici ; la valeur n'est pas reprise
        if assainir(valeur) != _echapper(valeur):
            raise ConfigError(
                f"{chemin} : la valeur ressemble à un secret (« password=... », "
                "« token: ... », identifiants dans une URL) ; aucun secret dans "
                f"la configuration ({SOURCES_DE_SECRETS})"
            )
        return valeur

    return analyser


def _dossier(chemin: str, valeur: object, cli: bool) -> str:
    texte = _texte(_CHEMIN_MAX)(chemin, valeur, cli)
    if cli:
        # choix explicite de l'operateur : un chemin absolu est admis
        return texte
    # formes Windows et POSIX refusees sur tout systeme : le fichier voyage
    windows = PureWindowsPath(texte)
    if windows.drive or windows.root or ".." in re.split(r"[/\\]", texte):
        raise ConfigError(
            f"{chemin} : chemin relatif sans « .. » attendu dans le fichier de "
            "mission (ni chemin absolu, ni lecteur, ni partage UNC) ; un autre "
            f"dossier se désigne par --set {chemin}=CHEMIN"
        )
    return texte


def _date(chemin: str, valeur: object, _cli: bool) -> date:
    # une date TOML (2026-01-12) arrive deja typee ; datetime herite de date
    if isinstance(valeur, date) and not isinstance(valeur, datetime):
        return valeur
    if isinstance(valeur, str) and _DATE.fullmatch(valeur):
        try:
            return date.fromisoformat(valeur)
        except ValueError:
            pass
    raise ConfigError(
        f"{chemin} : date ISO 8601 attendue (AAAA-MM-JJ, par ex. 2026-01-12)"
    )


def _choix(
    chemin: str, valeur: object, permis: Sequence[str], nature: str = "valeur"
) -> str:
    if isinstance(valeur, str) and valeur in permis:
        return valeur
    proche = (
        difflib.get_close_matches(valeur, permis, n=1)
        if isinstance(valeur, str)
        else []
    )
    suggestion = f" ; voulais-tu dire « {proche[0]} » ?" if proche else ""
    raise ConfigError(
        f"{chemin} : {nature} {_montrer(valeur)} refusée (attendu : "
        f"{', '.join(permis)}){suggestion}"
    )


def _tlp(chemin: str, valeur: object, _cli: bool) -> str:
    if valeur == "TLP:WHITE":
        raise ConfigError(
            f"{chemin} : TLP:WHITE appartient à TLP 1.0 ; il est devenu "
            "TLP:CLEAR en TLP 2.0 (https://www.first.org/tlp/) : écris "
            '"TLP:CLEAR"'
        )
    return _choix(chemin, valeur, TLP, "marquage")


def _profil(chemin: str, valeur: object, _cli: bool) -> str:
    if isinstance(valeur, str) and _PROFIL.fullmatch(valeur):
        return valeur
    raise ConfigError(
        f"{chemin} : nom de profil attendu (minuscules, chiffres, « - » et "
        "« _ », 64 caractères au plus)"
    )


def _langue(chemin: str, valeur: object, _cli: bool) -> str:
    return _choix(chemin, valeur, LANGS, "langue")


def _formats(chemin: str, valeur: object, cli: bool) -> tuple[str, ...]:
    if cli and isinstance(valeur, str):
        # --set report.formats=json,md
        valeur = [morceau.strip() for morceau in valeur.split(",")]
    if not isinstance(valeur, list) or not valeur:
        raise ConfigError(
            f'{chemin} : tableau non vide attendu, par ex. ["json", "md"] '
            f"(formats : {', '.join(REPORT_FORMATS)})"
        )
    formats = tuple(_choix(chemin, v, REPORT_FORMATS, "format") for v in valeur)
    if len(set(formats)) != len(formats):
        raise ConfigError(f"{chemin} : format en double")
    return formats


def _seuil(seuil: Threshold) -> Callable[[str, object, bool], int | float]:
    nature = "entier" if seuil.integer else "nombre"
    bornes = f"{nature} de {seuil.minimum} à {seuil.maximum} {seuil.unit}"

    def analyser(chemin: str, valeur: object, cli: bool) -> int | float:
        nombre: object = valeur
        if cli and isinstance(valeur, str):
            nombre = None
            if (_ENTIER if seuil.integer else _DECIMAL).fullmatch(valeur):
                try:
                    nombre = int(valeur) if seuil.integer else float(valeur)
                except ValueError:
                    # plus de 4300 chiffres : int() refuse
                    nombre = None
        # bool herite de int : true n'est pas un seuil
        if isinstance(nombre, bool) or not isinstance(nombre, int | float):
            raise ConfigError(f"{chemin} : {bornes} attendu")
        if seuil.integer and not isinstance(nombre, int):
            raise ConfigError(f"{chemin} : {bornes} attendu")
        # nan echoue a toute comparaison, inf depasse le maximum : refuses ici
        if not seuil.minimum <= nombre <= seuil.maximum:
            raise ConfigError(
                f"{chemin} : {_montrer(nombre)} hors bornes ({bornes} attendu)"
            )
        return nombre if seuil.integer else float(nombre)

    return analyser


@dataclass(frozen=True, slots=True)
class _Cle:
    """Clé connue : chemin pointé, valeur par défaut et validation."""

    path: str
    default: Any
    parse: Callable[[str, object, bool], Any]


KEYS: tuple[_Cle, ...] = (
    _Cle("mission.client", None, _texte()),
    _Cle("mission.reference", None, _texte()),
    _Cle("mission.auditor", None, _texte()),
    _Cle("mission.start", None, _date),
    _Cle("mission.end", None, _date),
    _Cle("mission.tlp", None, _tlp),
    _Cle("profile", None, _profil),
    _Cle("report.lang", "fr", _langue),
    _Cle("report.formats", ("json",), _formats),
    _Cle("report.output_dir", DEFAULT_DIR, _dossier),
)
"""Clés hors seuils, dans l'ordre d'affichage. Une clé absente du fichier
garde sa valeur par défaut ; ``None`` : non renseignée."""

_SECTION_SEUILS = "thresholds"


def _cles(seuils: Sequence[Threshold]) -> dict[str, _Cle]:
    cles = {cle.path: cle for cle in KEYS}
    for seuil in seuils:
        chemin = f"{_SECTION_SEUILS}.{seuil.name}"
        cles[chemin] = _Cle(chemin, seuil.default, _seuil(seuil))
    return cles


def _inconnue(chemin: str, connues: Sequence[str]) -> ConfigError:
    proche = difflib.get_close_matches(chemin, connues, n=1)
    suggestion = f" ; voulais-tu dire « {proche[0]} » ?" if proche else ""
    return ConfigError(f"clé inconnue « {_cle(chemin)} »{suggestion}")


def _json(valeur: Any) -> Any:
    if isinstance(valeur, date):
        return valeur.isoformat()
    if isinstance(valeur, tuple):
        return list(valeur)
    return valeur


@dataclass(frozen=True)
class Config:
    """Configuration effective : valeur et origine de chaque clé connue.

    ``values`` et ``origins`` ont les mêmes clés (chemins pointés), dans
    l'ordre d'affichage. ``source`` : fichier de mission lu, ou ``None`` ;
    ``source_kind`` : ``SOURCE_OPTION`` s'il a été désigné par ``--config``,
    ``SOURCE_CWD`` s'il a été trouvé dans le répertoire courant, ``None`` sans
    fichier.
    """

    values: Mapping[str, Any]
    origins: Mapping[str, Origin]
    source: Path | None = None
    source_kind: str | None = None

    @classmethod
    def defaults(cls, thresholds: Sequence[Threshold] = THRESHOLDS) -> Config:
        """Configuration sans fichier ni surcharge."""
        return _Etat(_cles(thresholds)).figer(None, None)

    @property
    def profile(self) -> str | None:
        """Nom du profil retenu (#47), ou ``None``."""
        profil: str | None = self.values["profile"]
        return profil

    def section(self, name: str) -> dict[str, Any]:
        """Valeurs JSON d'une section (``mission``, ``report``, ``thresholds``)."""
        prefixe = f"{name}."
        return {
            chemin[len(prefixe) :]: _json(valeur)
            for chemin, valeur in self.values.items()
            if chemin.startswith(prefixe)
        }

    def thresholds(self) -> Mapping[str, int | float]:
        """Seuils effectifs, en lecture seule : ``Context.config["thresholds"]``."""
        return MappingProxyType(self.section(_SECTION_SEUILS))

    def for_checks(self) -> Mapping[str, Any]:
        """Réglages remis aux checks (``Context.config``), en lecture seule."""
        return MappingProxyType({_SECTION_SEUILS: self.thresholds()})

    def rows(self) -> list[tuple[str, Any, Origin]]:
        """Chaque clé, sa valeur JSON et son origine, dans l'ordre d'affichage."""
        return [
            (chemin, _json(valeur), self.origins[chemin])
            for chemin, valeur in self.values.items()
        ]

    def to_dict(self) -> dict[str, Any]:
        """Configuration effective en JSON : tables imbriquées, dates ISO 8601."""
        document: dict[str, Any] = {}
        for chemin, valeur in self.values.items():
            table = document
            *sections, nom = chemin.split(".")
            for section in sections:
                table = table.setdefault(section, {})
            table[nom] = _json(valeur)
        return document

    def canonical_json(self) -> str:
        """JSON canonique : clés triées, sans espace, UTF-8 non échappé."""
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )

    def config_hash(self) -> str:
        """SHA-256 (hexadécimal) du JSON canonique de la configuration effective.

        Les origines n'y entrent pas : deux audits de même configuration
        effective ont le même condensat, qu'elle vienne du fichier ou de la
        ligne de commande.
        """
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()


class _Etat:
    """Valeurs en cours de construction ; chaque couche écrase la précédente."""

    def __init__(self, cles: Mapping[str, _Cle]) -> None:
        self._cles = cles
        self._valeurs: dict[str, Any] = {c: cle.default for c, cle in cles.items()}
        self._origines = dict.fromkeys(cles, Origin.DEFAULT)

    def poser(self, chemin: str, valeur: object, origine: Origin) -> None:
        """Valide ``valeur`` et la pose ; lève ``ConfigError``."""
        cle = self._cles.get(chemin)
        if cle is None:
            raise _inconnue(chemin, list(self._cles))
        self._valeurs[chemin] = cle.parse(chemin, valeur, origine is Origin.CLI)
        self._origines[chemin] = origine

    def table(self, document: Mapping[str, Any], origine: Origin) -> None:
        """Pose chaque clé d'un document TOML : sections puis clés."""
        sections = {c.split(".")[0] for c in self._cles if "." in c}
        feuilles = {c for c in self._cles if "." not in c}
        racine = sorted(sections | feuilles)
        for nom, contenu in document.items():
            if nom not in racine:
                raise _inconnue(nom, racine)
            if nom not in sections:
                self.poser(nom, contenu, origine)
                continue
            if not isinstance(contenu, Mapping):
                raise ConfigError(f"{nom} : table attendue ([{nom}])")
            for cle, valeur in contenu.items():
                if cle in feuilles and f"{nom}.{cle}" not in self._cles:
                    # en TOML, tout ce qui suit un en-tete [section] lui appartient
                    raise ConfigError(
                        f"clé « {cle} » lue dans la section [{nom}] : c'est une "
                        "clé de premier niveau, à écrire avant la première "
                        "section du fichier"
                    )
                self.poser(f"{nom}.{cle}", valeur, origine)

    def figer(self, source: Path | None, source_kind: str | None) -> Config:
        """Contrôles entre clés, puis configuration immuable."""
        debut, fin = self._valeurs["mission.start"], self._valeurs["mission.end"]
        if debut is not None and fin is not None and fin < debut:
            raise ConfigError(
                f"mission.end ({fin.isoformat()}) précède mission.start "
                f"({debut.isoformat()})"
            )
        return Config(
            values=MappingProxyType(dict(self._valeurs)),
            origins=MappingProxyType(dict(self._origines)),
            source=source,
            source_kind=source_kind,
        )


def _surcharge(brut: str, connues: Mapping[str, object]) -> tuple[str, str]:
    chemin, egal, valeur = brut.partition("=")
    chemin = chemin.strip()
    if chemin not in connues and any(
        _est_secrete(partie) for partie in chemin.split(".")
    ):
        raise _refus_secret(chemin)
    if not egal or not chemin:
        raise ConfigError(
            "--set : forme CLÉ=VALEUR attendue, par ex. "
            "thresholds.security_log_min_retention_days=180"
        )
    return chemin, valeur


def _verifier_fichier_implicite(chemin: Path) -> None:
    """Refuse un fichier de mission non désigné qu'un tiers a pu poser ou écrire.

    Lien symbolique (ou jonction Windows), fichier d'un autre compte, fichier
    inscriptible par le groupe ou les autres comptes. Sous Windows, ``st_mode``
    ne dit rien de l'ACL : seul le lien y est refusé.
    """
    conseil = f"désigne-le par --config {DEFAULT_FILE} si tu lui fais confiance"
    try:
        st = os.lstat(chemin)
    except OSError:
        raise ConfigError(f"{chemin} : illisible") from None
    if stat.S_ISLNK(st.st_mode) or getattr(st, "st_reparse_tag", 0) & _SUBSTITUT_DE_NOM:
        raise ConfigError(
            f"{chemin} : lien symbolique refusé pour un fichier de mission "
            f"trouvé dans le répertoire courant ; {conseil}"
        )
    if sys.platform != "win32":
        if st.st_uid != os.geteuid():
            raise ConfigError(
                f"{chemin} : appartient à un autre compte, refusé pour un "
                f"fichier de mission trouvé dans le répertoire courant ; {conseil}"
            )
        droits = stat.S_IMODE(st.st_mode)
        if droits & 0o022:
            raise ConfigError(
                f"{chemin} : droits {droits:04o}, le groupe ou les autres "
                "comptes peuvent l'écrire ; refusé pour un fichier de mission "
                "trouvé dans le répertoire courant (« chmod go-w », ou "
                f"{conseil})"
            )


def load_config(
    path: Path | None = None,
    *,
    overrides: Sequence[str] = (),
    directory: Path | None = None,
    thresholds: Sequence[Threshold] = THRESHOLDS,
) -> Config:
    """Configuration effective ; lève ``ConfigError``.

    ``path`` : fichier de mission (``--config``) ; ``None`` : ``amnesia.toml``
    de ``directory`` (défaut : répertoire courant) s'il existe, sinon aucun
    fichier. Ce fichier non désigné est refusé s'il est un lien symbolique,
    s'il appartient à un autre compte ou si d'autres comptes peuvent l'écrire ;
    ``Config.source_kind`` dit lequel des deux cas s'applique. ``overrides`` :
    surcharges ``CLÉ=VALEUR`` de la ligne de commande, dans l'ordre ; la
    dernière l'emporte. ``thresholds`` : seuils admis.
    """
    cles = _cles(thresholds)
    etat = _Etat(cles)
    source = path
    source_kind = None if path is None else SOURCE_OPTION
    if source is None:
        candidat = (directory or Path()) / DEFAULT_FILE
        if os.path.lexists(candidat):
            _verifier_fichier_implicite(candidat)
            source, source_kind = candidat, SOURCE_CWD
    if source is not None:
        try:
            document = load_toml(source)
            _refuser_secrets(document, cles)
            etat.table(document, Origin.FILE)
        except UnsafeInputError as exc:
            raise ConfigError(f"{source} : {exc.message}") from None
        except ConfigError as exc:
            # le fichier fautif d'abord : il peut avoir ete trouve sans --config
            raise ConfigError(f"{source} : {exc}") from None
    for brut in overrides:
        chemin, valeur = _surcharge(brut, cles)
        etat.poser(chemin, valeur, Origin.CLI)
    return etat.figer(source, source_kind)


_EXEMPLE = f"""\
# Fichier de mission amnesia : qui audite quoi, pour qui, avec quels seuils.
# Lu par « amnesia audit » (--config FICHIER, sinon ./{DEFAULT_FILE}).
# Priorité : ligne de commande (--lang, --set CLÉ=VALEUR), puis ce fichier,
# puis les valeurs par défaut. « amnesia config show » affiche le résultat et
# l'origine de chaque valeur. Une clé inconnue est une erreur.
#
# AUCUN SECRET ICI : pas de mot de passe, de jeton ni de clé. Les secrets
# passent par {SOURCES_DE_SECRETS}.

# Profil d'audit retenu (nom seulement). Décommente pour en choisir un.
# profile = "exemple"

[mission]
# Client audité, tel qu'il figurera dans le rapport.
client = "Client Exemple"
# Référence de la mission (bon de commande, numéro de dossier).
reference = "MISSION-0001"
# Auditeur ou équipe qui mène l'audit.
auditor = "Équipe d'audit"
# Début de la mission, date ISO 8601 (AAAA-MM-JJ).
start = 2026-01-12
# Fin de la mission ; jamais avant le début.
end = 2026-01-16
# Marquage TLP 2.0 du livrable : {", ".join(TLP)}.
tlp = "TLP:AMBER"

[report]
# Langue du livrable : {" ou ".join(LANGS)}.
lang = "fr"
# Formats du livrable : {", ".join(REPORT_FORMATS)}.
formats = ["json"]
# Dossier des livrables, relatif au répertoire courant.
output_dir = "{DEFAULT_DIR}"

[thresholds]
"""


def example_toml(thresholds: Sequence[Threshold] = THRESHOLDS) -> str:
    """Fichier de mission d'exemple : chaque clé commentée, valeurs par défaut.

    Le texte se charge sans erreur par ``load_config()`` ; ses seuils sont les
    valeurs par défaut, bornes en commentaire.
    """
    lignes = [_EXEMPLE]
    for seuil in thresholds:
        nature = "entier" if seuil.integer else "nombre"
        lignes.append(
            f"# {seuil.description[0].upper()}{seuil.description[1:]} "
            f"({nature} de {seuil.minimum} à {seuil.maximum}).\n"
            f"{seuil.name} = {seuil.default}\n"
        )
    return "".join(lignes)
