# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Lecture et validation du catalogue (TOML, sans dépendance tierce).

Un catalogue est un répertoire :

- ``VERSION`` : version CalVer (``2026.11.0``) ;
- ``questions/<domaine>.toml`` : tables ``[[question]]`` ;
- ``sources/<domaine>.toml`` : tables ``[[source]]`` ;
- ``ids.lock`` : identifiants de questions déjà publiés, un par ligne.

``read_catalog()`` valide tout ce qu'il lit et rend un ``Catalog``, ou lève
``CatalogError`` avec une ligne par erreur, chacune localisée (fichier, entrée,
champ). La validation se fait en deux temps : la forme de chaque entrée, puis,
si elle est saine, les liens (source inconnue, ``replaced_by``, ``ids.lock``).
``load_catalog()`` lit une fois le catalogue embarqué dans le paquet.

Le lien avec le registre des checks se vérifie à part (``verify_registry()``) :
le catalogue ne charge aucun check. ``amnesia catalog validate`` enchaîne les
deux. Format des fichiers : docs/catalogue.md.
"""

from __future__ import annotations

import functools
import re
import tomllib
from collections.abc import Callable, Iterable, Mapping
from importlib import resources
from importlib.resources.abc import Traversable
from typing import Any, NoReturn, TypeVar

from ..checks.base import FORMAT_QUESTION_ID, Reference, Severity
from ..checks.registry import CheckMeta, Domain
from .model import (
    Catalog,
    CatalogError,
    FilterValue,
    Prerequisite,
    PrerequisiteKind,
    Question,
    QuestionStatus,
    Role,
    Source,
    SourceKind,
    Theme,
    placeholders_of,
)

QUESTIONS = "questions"
SOURCES = "sources"
VERSION = "VERSION"
IDS_LOCK = "ids.lock"

# fullmatch et non match : « $ » accepterait un saut de ligne final
FORMAT_SOURCE_ID = re.compile(r"SRC-[A-Z0-9]+(?:-[A-Z0-9]+)+", re.ASCII)
# CalVer AAAA.M.N : annee, mois sans zero initial, numero d'ordre dans le mois
FORMAT_VERSION = re.compile(
    r"20[0-9]{2}\.(?:[1-9]|1[0-2])\.(?:0|[1-9][0-9]*)", re.ASCII
)
_GUID = r"[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}"
# sous-categorie d'audit : notation de MS-GPAC, entre accolades
_GUID_SOUS_CATEGORIE = re.compile(r"\{" + _GUID + r"\}", re.ASCII)
# droit etendu ou classe d'objet AD : notation du schema, sans accolades
_GUID_NU = re.compile(_GUID, re.ASCII)
_ETIQUETTE = re.compile(r"[a-z][a-z0-9_]*", re.ASCII)
# id de check : meme forme que le registre (amnesia.checks.registry)
_FORMAT_CHECK_ID = re.compile(r"[a-z][a-z0-9]*(?:\.[a-z0-9_]+)+", re.ASCII)
# champ d'evenement d'un filtre : LogonType, Properties, EventData.TargetUserName
_CHAMP_DE_FILTRE = re.compile(r"[A-Za-z][A-Za-z0-9_.]*", re.ASCII)
_EVENT_ID_MAX = 65535

_E = TypeVar("_E")


class _Invalide(Exception):
    """Champ refusé ; convertie en ligne d'erreur localisée."""

    def __init__(self, champ: str | None, motif: str) -> None:
        super().__init__(champ, motif)
        self.champ = champ
        self.motif = motif


def _apercu(valeur: object, limite: int = 64) -> str:
    texte = valeur if isinstance(valeur, str) else repr(valeur)
    return repr(texte if len(texte) <= limite else texte[:limite] + "...")


def _lisible(texte: str, limite: int = 64) -> str:
    """Clé TOML, identifiant ou nom de fichier, sûr dans un message d'erreur.

    Un texte imprimable et court passe tel quel ; sinon sa forme ``repr``
    bornée : ni séquence ANSI, ni saut de ligne, ni bidi dans ``CatalogError``.
    """
    if texte.isprintable() and len(texte) <= limite:
        return texte
    return _apercu(texte, limite)


def _non_imprimable(valeur: object, chemin: str = "") -> tuple[str, str] | None:
    """Première clé ou chaîne non imprimable de ``valeur``, avec son chemin."""
    if isinstance(valeur, str):
        return None if valeur.isprintable() else (chemin, valeur)
    if isinstance(valeur, dict):
        for cle, contenu in valeur.items():
            if not cle.isprintable():
                return chemin, cle
            trouve = _non_imprimable(contenu, f"{chemin}.{cle}" if chemin else cle)
            if trouve is not None:
                return trouve
    elif isinstance(valeur, list):
        for position, contenu in enumerate(valeur):
            trouve = _non_imprimable(contenu, f"{chemin}[{position}]")
            if trouve is not None:
                return trouve
    return None


class _Entree:
    """Lecture typée d'une table TOML ; toute clé non lue est une erreur."""

    def __init__(self, donnees: Mapping[str, Any], prefixe: str = "") -> None:
        self._donnees = donnees
        self._prefixe = prefixe
        self._lues: set[str] = set()

    def _nom(self, champ: str) -> str:
        return f"{self._prefixe}{champ}"

    def refuser(self, champ: str | None, motif: str) -> NoReturn:
        # sans champ, l'erreur porte sur la table elle-meme (prerequisites[0])
        lieu = self._prefixe.rstrip(".") or None if champ is None else self._nom(champ)
        raise _Invalide(lieu, motif)

    def present(self, champ: str) -> bool:
        return champ in self._donnees

    def brut(self, champ: str, attendu: type[_E], libelle: str) -> _E:
        self._lues.add(champ)
        if champ not in self._donnees:
            self.refuser(champ, "champ obligatoire manquant")
        valeur = self._donnees[champ]
        # bool est un int : true n'est jamais un Event ID ni une valeur de registre
        if not isinstance(valeur, attendu) or (
            isinstance(valeur, bool) and attendu is not bool
        ):
            self.refuser(champ, f"{libelle} attendu(e), reçu {_apercu(valeur)}")
        return valeur

    def texte(self, champ: str) -> str:
        valeur = self.brut(champ, str, "chaîne")
        # rendu tel quel dans le terminal et le rapport : ni ANSI, ni saut de ligne
        if not valeur.strip() or not valeur.isprintable():
            self.refuser(champ, f"texte vide ou non imprimable : {_apercu(valeur)}")
        return valeur

    def texte_facultatif(self, champ: str) -> str | None:
        return self.texte(champ) if self.present(champ) else None

    def booleen(self, champ: str, defaut: bool) -> bool:
        return self.brut(champ, bool, "booléen") if self.present(champ) else defaut

    def membre(
        self, champ: str, enum: Callable[[str], _E], valides: Iterable[str]
    ) -> _E:
        valeur = self.brut(champ, str, "chaîne")
        try:
            return enum(valeur)
        except ValueError:
            self.refuser(
                champ,
                f"valeur inconnue {_apercu(valeur)} (valeurs : {', '.join(valides)})",
            )

    def liste(self, champ: str, *, vide_permis: bool = True) -> list[Any]:
        if not self.present(champ):
            self._lues.add(champ)
            if not vide_permis:
                self.refuser(champ, "champ obligatoire manquant")
            return []
        valeur: list[Any] = self.brut(champ, list, "liste")
        if not valeur and not vide_permis:
            self.refuser(champ, "liste vide")
        return valeur

    def textes(
        self,
        champ: str,
        *,
        vide_permis: bool = True,
        forme: re.Pattern[str] | None = None,
        libelle: str = "identifiant",
    ) -> tuple[str, ...]:
        elements = self.liste(champ, vide_permis=vide_permis)
        for element in elements:
            if not isinstance(element, str) or not element.strip():
                self.refuser(
                    champ, f"chaîne non vide attendue, reçu {_apercu(element)}"
                )
            if forme is not None and not forme.fullmatch(element):
                self.refuser(champ, f"{libelle} mal formé {_apercu(element)}")
            # affiche tel quel par « catalog show », meme sans forme imposee
            if not element.isprintable():
                self.refuser(champ, f"texte non imprimable : {_apercu(element)}")
        if len(set(elements)) != len(elements):
            self.refuser(champ, f"doublon dans {elements!r}")
        return tuple(elements)

    def table(self, champ: str) -> _Entree:
        valeur = self.brut(champ, dict, "table")
        return _Entree(valeur, prefixe=f"{self._nom(champ)}.")

    def terminer(self) -> None:
        inconnues = sorted(c for c in self._donnees if c not in self._lues)
        if inconnues:
            cles = ", ".join(_lisible(c) for c in inconnues)
            self.refuser(None, f"clé(s) inconnue(s) : {cles}")


def _valeurs(enum: Iterable[Any]) -> list[str]:
    return [str(m.value) for m in enum]


# --- sources -----------------------------------------------------------------


def _prerequis(donnees: object, position: int) -> Prerequisite:
    prefixe = f"prerequisites[{position}]."
    if not isinstance(donnees, dict):
        raise _Invalide(prefixe.rstrip("."), f"table attendue, reçu {_apercu(donnees)}")
    e = _Entree(donnees, prefixe=prefixe)
    genre = e.membre("kind", PrerequisiteKind, _valeurs(PrerequisiteKind))
    if genre is PrerequisiteKind.AUDIT_SUBCATEGORY:
        guid = e.texte("guid")
        if not _GUID_SOUS_CATEGORIE.fullmatch(guid):
            e.refuser(
                "guid",
                f"GUID mal formé {_apercu(guid)} "
                "(attendu : {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX})",
            )
        prerequis = Prerequisite(
            kind=genre,
            guid=guid,
            name=e.texte("name"),
            success=e.booleen("success", False),
            failure=e.booleen("failure", False),
        )
        if not (prerequis.success or prerequis.failure):
            e.refuser("success", "success ou failure doit valoir true")
    elif genre is PrerequisiteKind.REGISTRY_VALUE:
        cle = e.texte("key")
        nom = e.texte("name")
        valeur = e.brut("value", object, "chaîne ou entier")
        if not isinstance(valeur, str | int):
            e.refuser("value", f"chaîne ou entier attendu(e), reçu {_apercu(valeur)}")
        # affichee telle quelle par « catalog show » (Prerequisite.describe)
        if isinstance(valeur, str) and not (valeur.strip() and valeur.isprintable()):
            e.refuser("value", f"texte vide ou non imprimable : {_apercu(valeur)}")
        prerequis = Prerequisite(kind=genre, key=cle, name=nom, value=valeur)
    elif genre is PrerequisiteKind.CHANNEL_ENABLED:
        prerequis = Prerequisite(kind=genre, channel=e.texte("channel"))
    else:
        objet = e.texte("object")
        guids = e.textes("guids", forme=_GUID_NU, libelle="GUID")
        prerequis = Prerequisite(kind=genre, object=objet, guids=guids)
    e.terminer()
    return prerequis


def _filtres(e: _Entree) -> tuple[tuple[str, FilterValue], ...]:
    if not e.present("filters"):
        return ()
    table = e.brut("filters", dict, "table")
    filtres: list[tuple[str, FilterValue]] = []
    for champ, valeur in table.items():
        # cle et valeurs affichees telles quelles par « catalog show »
        # (Source.summary) : ni ANSI, ni saut de ligne, ni bidi
        if not _CHAMP_DE_FILTRE.fullmatch(champ):
            e.refuser(
                "filters",
                f"nom de champ mal formé {_apercu(champ)} (lettres, chiffres, "
                "« _ » et « . », en commençant par une lettre)",
            )
        nom = f"filters.{champ}"
        elements = valeur if isinstance(valeur, list) else [valeur]
        if not elements or not all(
            isinstance(v, str | int) and not isinstance(v, bool) and v != ""
            for v in elements
        ):
            e.refuser(
                nom,
                f"chaîne, entier ou liste des deux attendu, reçu {_apercu(valeur)}",
            )
        for v in elements:
            if isinstance(v, str) and not (v.strip() and v.isprintable()):
                e.refuser(nom, f"texte vide ou non imprimable : {_apercu(v)}")
        filtres.append((champ, tuple(elements) if isinstance(valeur, list) else valeur))
    return tuple(filtres)


def _source(donnees: Mapping[str, Any], domaine: Domain) -> Source:
    e = _Entree(donnees)
    identifiant = e.texte("id")
    if not FORMAT_SOURCE_ID.fullmatch(identifiant):
        e.refuser(
            "id", f"identifiant mal formé {_apercu(identifiant)} (ex. SRC-SEC-4624)"
        )
    genre = e.membre("kind", SourceKind, _valeurs(SourceKind))
    titre = e.texte("title")
    canal = fournisseur = reglage = None
    event_ids: tuple[int, ...] = ()
    filtres: tuple[tuple[str, FilterValue], ...] = ()
    if genre is SourceKind.EVENT:
        canal = e.texte("channel")
        fournisseur = e.texte("provider")
        ids = e.liste("event_ids", vide_permis=False)
        for i in ids:
            if (
                isinstance(i, bool)
                or not isinstance(i, int)
                or not 0 < i <= _EVENT_ID_MAX
            ):
                e.refuser("event_ids", f"Event ID invalide : {i!r}")
        if len(set(ids)) != len(ids):
            e.refuser("event_ids", f"doublon dans {ids!r}")
        event_ids = tuple(ids)
        filtres = _filtres(e)
    else:
        reglage = e.texte("setting")
    prerequis = tuple(
        _prerequis(p, position) for position, p in enumerate(e.liste("prerequisites"))
    )
    par_defaut = (
        e.booleen("enabled_by_default", False)
        if e.present("enabled_by_default")
        else None
    )
    # channel, event_ids... sur une source setting (et inversement) : cle inconnue
    e.terminer()
    return Source(
        id=identifiant,
        kind=genre,
        domain=domaine,
        title=titre,
        channel=canal,
        provider=fournisseur,
        event_ids=event_ids,
        filters=filtres,
        setting=reglage,
        prerequisites=prerequis,
        enabled_by_default=par_defaut,
    )


# --- questions ---------------------------------------------------------------


def _references(e: _Entree) -> tuple[Reference, ...]:
    references: list[Reference] = []
    for position, donnees in enumerate(e.liste("references")):
        nom = f"references[{position}]"
        if not isinstance(donnees, dict):
            e.refuser(nom, f"table attendue, reçu {_apercu(donnees)}")
        try:
            # url et version facultatives ; cle inconnue ou manquante refusee
            references.append(
                Reference.from_dict({"url": None, "version": None, **donnees})
            )
        except (TypeError, ValueError) as exc:
            e.refuser(nom, str(exc))
    return tuple(references)


def _textes_localises(e: _Entree, champ: str) -> tuple[str, str]:
    """Texte ``fr`` (obligatoire) et ``en`` (vide jusqu'à #138) d'un champ."""
    table = e.table(champ)
    francais = table.texte("fr")
    anglais = table.brut("en", str, "chaîne") if table.present("en") else ""
    if not anglais.isprintable():
        table.refuser("en", f"texte non imprimable : {_apercu(anglais)}")
    table.terminer()
    return francais, anglais


def _question(donnees: Mapping[str, Any], domaine: Domain) -> Question:
    e = _Entree(donnees)
    identifiant = e.texte("id")
    prefixe = f"Q-{domaine.prefix.upper()}-"
    if not FORMAT_QUESTION_ID.fullmatch(identifiant) or not identifiant.startswith(
        prefixe
    ):
        e.refuser(
            "id",
            f"identifiant mal formé {_apercu(identifiant)} (attendu : {prefixe}<SUJET> "
            "en majuscules, chiffres et tirets)",
        )
    statut = e.membre("status", QuestionStatus, _valeurs(QuestionStatus))
    declare = e.membre("domain", Domain, _valeurs(Domain))
    if declare is not domaine:
        e.refuser(
            "domain",
            f"{declare.value!r} dans le fichier du domaine {domaine.value!r}",
        )
    theme = e.membre("theme", Theme, _valeurs(Theme))
    roles: list[Role] = []
    for nom in e.textes("roles", vide_permis=False):
        try:
            roles.append(Role(nom))
        except ValueError:
            valides = ", ".join(_valeurs(Role))
            e.refuser("roles", f"valeur inconnue {_apercu(nom)} (valeurs : {valides})")
    texte, texte_en = _textes_localises(e, "text")
    try:
        placeholders_of(texte)
        placeholders_of(texte_en)
    except ValueError as exc:
        e.refuser("text", str(exc))
    pourquoi, pourquoi_en = _textes_localises(e, "why")
    severite = e.membre("severity_default", Severity, _valeurs(Severity))
    sources = e.textes(
        "sources", vide_permis=False, forme=FORMAT_SOURCE_ID, libelle="identifiant"
    )
    checks = e.textes("checks", forme=_FORMAT_CHECK_ID, libelle="id de check")
    scenarios = e.textes("scenarios", forme=_ETIQUETTE, libelle="étiquette")
    references = _references(e)
    if e.liste("attack"):
        e.refuser("attack", "champ réservé à #147 : le laisser vide")
    remplace_par = e.texte_facultatif("replaced_by")
    if statut is QuestionStatus.ACTIVE and not checks:
        e.refuser(
            "checks",
            'question active sans check (status = "planned" tant qu\'aucun check '
            "n'y contribue)",
        )
    if statut is not QuestionStatus.ACTIVE and checks:
        e.refuser(
            "checks",
            f'question {statut.value} avec des checks (status = "active" attendu)',
        )
    if statut is QuestionStatus.DEPRECATED and remplace_par is None:
        e.refuser("replaced_by", "champ obligatoire pour une question deprecated")
    if statut is not QuestionStatus.DEPRECATED and remplace_par is not None:
        e.refuser("replaced_by", 'réservé à status = "deprecated"')
    e.terminer()
    return Question(
        id=identifiant,
        status=statut,
        domain=domaine,
        theme=theme,
        roles=tuple(roles),
        text=texte,
        why=pourquoi,
        severity_default=severite,
        sources=sources,
        checks=checks,
        scenarios=scenarios,
        references=references,
        replaced_by=remplace_par,
        text_en=texte_en,
        why_en=pourquoi_en,
    )


# --- fichiers ----------------------------------------------------------------


def _lire(racine: Traversable, *chemin: str) -> str:
    """Texte UTF-8 d'un fichier du catalogue ; ``_Invalide`` s'il est illisible."""
    fichier = racine
    # un segment a la fois : toutes les ressources de paquet (zip compris)
    # n'acceptent pas plusieurs segments par appel avant Python 3.12
    for segment in chemin:
        fichier = fichier.joinpath(segment)
    try:
        return fichier.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise _Invalide(None, "fichier absent") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise _Invalide(None, f"fichier illisible ({type(exc).__name__})") from None


def _fichiers(racine: Traversable, dossier: str, erreurs: list[str]) -> list[Domain]:
    """Domaines des fichiers ``<domaine>.toml`` de ``dossier``, triés."""
    repertoire = racine.joinpath(dossier)
    if not repertoire.is_dir():
        erreurs.append(f"{dossier}/ : répertoire absent")
        return []
    domaines: list[Domain] = []
    for nom in sorted(f.name for f in repertoire.iterdir() if f.name.endswith(".toml")):
        try:
            domaines.append(Domain(nom.removesuffix(".toml")))
        except ValueError:
            erreurs.append(
                f"{dossier}/{_lisible(nom)} : nom de fichier inconnu (attendu : "
                f"<domaine>.toml ; domaines : {', '.join(_valeurs(Domain))})"
            )
    return domaines


def _entrees(
    racine: Traversable,
    dossier: str,
    cle: str,
    genre: str,
    lire: Callable[[Mapping[str, Any], Domain], _E],
    identifiant: Callable[[_E], str],
    erreurs: list[str],
) -> dict[str, tuple[_E, str]]:
    """Entrées valides de ``dossier``, par identifiant, avec leur emplacement."""
    lues: dict[str, tuple[_E, str]] = {}
    for domaine in _fichiers(racine, dossier, erreurs):
        fichier = f"{dossier}/{domaine.value}.toml"
        try:
            document = tomllib.loads(_lire(racine, dossier, f"{domaine.value}.toml"))
        except _Invalide as exc:
            erreurs.append(f"{fichier} : {exc.motif}")
            continue
        except tomllib.TOMLDecodeError as exc:
            erreurs.append(f"{fichier} : TOML invalide : {exc}")
            continue
        tables = document.get(cle)
        inconnues = sorted(set(document) - {cle})
        if inconnues or not isinstance(tables, list) or not tables:
            erreurs.append(
                f"{fichier} : seules des tables [[{cle}]] sont attendues, au moins une"
                + (
                    " (clé(s) inconnue(s) : "
                    f"{', '.join(_lisible(c) for c in inconnues)})"
                    if inconnues
                    else ""
                )
            )
            continue
        for numero, donnees in enumerate(tables, start=1):
            lieu = f"{fichier} : {genre} n° {numero}"
            if isinstance(donnees, dict) and isinstance(donnees.get("id"), str):
                lieu += f" ({_lisible(donnees['id'])})"
            try:
                if not isinstance(donnees, dict):
                    raise _Invalide(None, "table attendue")
                entree = lire(donnees, domaine)
                # filet pour les champs a venir : aucune cle ni chaine non
                # imprimable n'entre au catalogue, meme d'un champ lu sans controle
                trouve = _non_imprimable(donnees)
                if trouve is not None:
                    raise _Invalide(
                        trouve[0] or None,
                        f"texte non imprimable : {_apercu(trouve[1])}",
                    )
            except _Invalide as exc:
                champ = "" if exc.champ is None else f"{exc.champ} : "
                erreurs.append(f"{lieu} : {champ}{exc.motif}")
                continue
            cle_entree = identifiant(entree)
            if cle_entree in lues:
                erreurs.append(
                    f"{lieu} : id : identifiant dupliqué {cle_entree!r}, déjà défini "
                    f"par {lues[cle_entree][1]}"
                )
                continue
            lues[cle_entree] = (entree, lieu)
    return lues


def _version(racine: Traversable, erreurs: list[str]) -> str:
    try:
        version = _lire(racine, VERSION).strip()
    except _Invalide as exc:
        erreurs.append(f"{VERSION} : {exc.motif}")
        return ""
    if not FORMAT_VERSION.fullmatch(version):
        erreurs.append(
            f"{VERSION} : version CalVer attendue (AAAA.M.N, ex. 2026.11.0), "
            f"lu {_apercu(version)}"
        )
    return version


def _ids_publies(racine: Traversable, erreurs: list[str]) -> list[str]:
    """Identifiants de ``ids.lock`` : un par ligne, triés, ``#`` en commentaire."""
    try:
        lignes = _lire(racine, IDS_LOCK).splitlines()
    except _Invalide as exc:
        erreurs.append(f"{IDS_LOCK} : {exc.motif}")
        return []
    ids: list[str] = []
    for numero, ligne in enumerate(lignes, start=1):
        identifiant = ligne.strip()
        if not identifiant or identifiant.startswith("#"):
            continue
        if not FORMAT_QUESTION_ID.fullmatch(identifiant):
            erreurs.append(
                f"{IDS_LOCK} : ligne {numero} : identifiant de question mal formé "
                f"{_apercu(identifiant)}"
            )
            continue
        ids.append(identifiant)
    if ids != sorted(set(ids)):
        erreurs.append(f"{IDS_LOCK} : identifiants attendus triés et sans doublon")
    return ids


def _verifier_liens(
    questions: Mapping[str, tuple[Question, str]],
    sources: Mapping[str, tuple[Source, str]],
    publies: Iterable[str],
    erreurs: list[str],
) -> None:
    for question, lieu in questions.values():
        for source in question.sources:
            if source not in sources:
                erreurs.append(f"{lieu} : sources : source inconnue {source!r}")
        cible = question.replaced_by
        if cible is None:
            continue
        if cible == question.id or cible not in questions:
            erreurs.append(f"{lieu} : replaced_by : question inconnue {cible!r}")
        elif questions[cible][0].status is QuestionStatus.DEPRECATED:
            erreurs.append(
                f"{lieu} : replaced_by : {cible} est elle-même dépréciée "
                "(désigner la question qui la remplace)"
            )
    publies = set(publies)
    for identifiant in sorted(publies - set(questions)):
        erreurs.append(
            f"{IDS_LOCK} : {identifiant} : identifiant publié absent du catalogue "
            '(un identifiant ne se retire jamais : status = "deprecated" et '
            "replaced_by)"
        )
    for identifiant in sorted(set(questions) - publies):
        erreurs.append(
            f"{questions[identifiant][1]} : id : identifiant absent de {IDS_LOCK} "
            "(l'y ajouter : il devient immuable)"
        )


def read_catalog(root: Traversable) -> Catalog:
    """Catalogue du répertoire ``root``, validé ; ``CatalogError`` sinon.

    ``root`` est un ``pathlib.Path`` ou une ressource de paquet
    (``importlib.resources.files``). Rien n'est mis en cache : pour le
    catalogue embarqué, préférer ``load_catalog()``.
    """
    erreurs: list[str] = []
    version = _version(root, erreurs)
    sources = _entrees(
        root, SOURCES, "source", "source", _source, lambda s: s.id, erreurs
    )
    questions = _entrees(
        root, QUESTIONS, "question", "question", _question, lambda q: q.id, erreurs
    )
    publies = _ids_publies(root, erreurs)
    # liens verifies sur des entrees saines seulement : une entree refusee
    # ferait sinon signaler a tort chaque question qui la cite
    if not erreurs:
        _verifier_liens(questions, sources, publies, erreurs)
    if erreurs:
        raise CatalogError(*erreurs)
    return Catalog(
        version,
        (question for question, _ in questions.values()),
        (source for source, _ in sources.values()),
    )


@functools.cache
def load_catalog() -> Catalog:
    """Catalogue embarqué dans le paquet, lu et validé une seule fois.

    Lève ``CatalogError`` si les fichiers embarqués sont invalides (paquet
    altéré). ``load_catalog.cache_clear()`` force une relecture.
    """
    return read_catalog(resources.files(__package__ or "amnesia.catalog"))


def render_question(
    question_id: str,
    *,
    host: str | None = None,
    lookback_days: int | None = None,
    account: str | None = None,
    share: str | None = None,
) -> str:
    """Texte d'une question du catalogue embarqué, pour un contexte donné.

    C'est la seule origine du champ ``question`` d'un ``Gap``. ``UnknownIdError``
    si l'identifiant est inconnu, ``ValueError`` si une variable du gabarit n'a
    pas de valeur ; détail dans ``Question.render()``.
    """
    return load_catalog().render(
        question_id,
        host=host,
        lookback_days=lookback_days,
        account=account,
        share=share,
    )


# --- lien avec le registre des checks ------------------------------------------


def registry_errors(catalog: Catalog, metas: Iterable[CheckMeta]) -> list[str]:
    """Incohérences entre le catalogue et le registre des checks, localisées.

    Le lien est déclaré des deux côtés et doit être réciproque : ``checks``
    d'une question cite des ids du registre, et ``question_ids`` d'un check
    cite exactement les questions qui le listent.
    """
    erreurs: list[str] = []
    par_id = {m.id: m for m in metas}
    for question in catalog:
        lieu = f"{QUESTIONS}/{question.domain.value}.toml : question {question.id}"
        for check in question.checks:
            if check not in par_id:
                erreurs.append(f"{lieu} : checks : check inconnu du registre {check!r}")
            elif question.id not in par_id[check].question_ids:
                erreurs.append(
                    f"{lieu} : checks : {check} ne cite pas cette question dans "
                    f"question_ids (module {par_id[check].module})"
                )
    for meta in sorted(par_id.values(), key=lambda m: m.id):
        lieu = f"check {meta.id} (module {meta.module})"
        for identifiant in meta.question_ids:
            if identifiant not in catalog:
                erreurs.append(
                    f"{lieu} : question_ids : question inconnue du catalogue "
                    f"{identifiant!r}"
                )
            elif meta.id not in catalog.question(identifiant).checks:
                erreurs.append(
                    f"{lieu} : question_ids : {identifiant} ne liste pas ce check "
                    "dans son champ checks"
                )
    return erreurs


def verify_registry(catalog: Catalog, metas: Iterable[CheckMeta]) -> None:
    """Lève ``CatalogError`` si ``registry_errors()`` trouve une incohérence."""
    erreurs = registry_errors(catalog, metas)
    if erreurs:
        raise CatalogError(*erreurs)
