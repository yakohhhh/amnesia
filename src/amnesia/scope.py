# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Périmètre autorisé d'un audit : déclaration, contrôle, trace.

Un audit ne joint une cible que si une autorisation écrite la couvre. Le
périmètre se déclare dans la section ``[scope]`` du fichier de mission
(``amnesia.config``) ou dans un fichier séparé de même schéma (``--scope``,
``load_scope()``) : identifiant de mission, autorisation écrite (référence,
date, signataire), période de validité, inclusions typées et exclusions.
``authorize()`` rend la base d'autorisation d'un audit, recopiée dans le
rapport, ou lève ``ScopeRefusal`` : l'appelant s'arrête alors avant toute
collecte, avec le code de sortie ``exitcodes.OUT_OF_SCOPE``.

Règle : en cas de doute, refuser.

- la cible est comparée sur sa forme normalisée (``Target.address``,
  ``target.normalize_host()``) ; la machine locale est désignée par son nom
  (``platform.node()``) ;
- une exclusion l'emporte sur toute inclusion ;
- en inclusion, ``*.corp.example`` couvre exactement un label, comme dans un
  certificat : ``srv01.corp.example``, ni ``corp.example`` ni
  ``srv01.filiale.corp.example`` ; en exclusion, il couvre toute la profondeur ;
- une cible désignée par un nom que seule une plage d'adresses peut couvrir,
  ou exclure, est résolue : **toutes** ses adresses doivent être incluses,
  aucune exclue. Ce module n'ouvre aucune connexion et ne résout rien
  lui-même : la résolution est fournie par l'appelant (``resolver``), et sans
  elle la cible est refusée ;
- la période de validité est tenue à la fois dans le fuseau du poste et en
  UTC : aux bornes, les deux dates doivent être dans la période ;
- sans périmètre, l'audit exige une confirmation saisie au terminal ou une
  référence d'autorisation déclarée (``--authorized-by``).

Un bundle (``bundle:<chemin>``) est une collecte déjà faite : aucun système
n'est joint, aucun contrôle n'est appliqué (``Basis.OFFLINE``). Son hôte
d'origine sera comparé au périmètre à l'import (#52).

Schéma et exemples : ``docs/perimetre.md``.
"""

from __future__ import annotations

import difflib
import hashlib
import ipaddress
import json
import platform
import re
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from .checks.base import assainir
from .inputs import UnsafeInputError, load_toml
from .target import Kind, Target, TargetError, Transport, normalize_host

__all__ = [
    "SECTION",
    "SOURCE_MISSION",
    "SOURCE_OPTION",
    "TYPES",
    "Authorization",
    "Basis",
    "Confirm",
    "Refusal",
    "Resolver",
    "Rules",
    "Scope",
    "ScopeError",
    "ScopeRefusal",
    "authorize",
    "confirmation_name",
    "load_scope",
    "parse_reference",
    "parse_scope",
]

SECTION = "scope"
"""Section du fichier de mission, et seule table d'un fichier de périmètre."""

SOURCE_MISSION = "mission"
"""``Scope.source`` : section ``[scope]`` du fichier de mission."""

SOURCE_OPTION = "--scope"
"""``Scope.source`` : fichier de périmètre désigné par ``--scope``."""

TYPES = ("hosts", "dns", "ad_domains", "cidrs", "entra_tenants", "aws_accounts")
"""Types d'inclusion et d'exclusion, dans l'ordre d'affichage."""

Resolver = Callable[[str], Sequence[str]]
"""Résolution d'un nom d'hôte : ses adresses IP, en texte. Fournie par le
collecteur du transport, seul autorisé à joindre le réseau ; une erreur
(``OSError``) ou une liste vide valent refus."""

Confirm = Callable[[Target, str], str | None]
"""Saisie de confirmation : reçoit la cible et le nom attendu, rend le texte
saisi par l'opérateur, ou ``None`` s'il n'a rien saisi (fin de fichier)."""

_Adresse = ipaddress.IPv4Address | ipaddress.IPv6Address
_Reseau = ipaddress.IPv4Network | ipaddress.IPv6Network

_TEXTE_MAX = 200
_CLES = (
    "mission_id",
    "valid_from",
    "valid_until",
    "active_tests",
    "authorization",
    "include",
    "exclude",
)
_CLES_AUTORISATION = ("reference", "date", "signatory", "signatory_role")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_COMPTE_AWS = re.compile(r"[0-9]{12}")
# categories Unicode refusees dans un texte libre, comme amnesia.config :
# controles (dont ANSI), formats (dont bidi), surrogates, usage prive, non
# assignes, separateurs de ligne et de paragraphe
_CATEGORIES_REFUSEES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


class ScopeError(ValueError):
    """Périmètre mal déclaré ; le message, en français, cite le chemin de la clé.

    Fichier illisible, clé inconnue ou absente, valeur refusée : une erreur de
    configuration, pas un refus d'audit (``ScopeRefusal``).
    """


class Refusal(StrEnum):
    """Motif d'un refus d'audit."""

    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    EXCLUDED = "excluded"
    OUT_OF_SCOPE = "out_of_scope"
    UNRESOLVED = "unresolved"
    UNSUPPORTED = "unsupported"
    NO_AUTHORIZATION = "no_authorization"
    NOT_CONFIRMED = "not_confirmed"


class ScopeRefusal(Exception):
    """Audit refusé avant toute collecte ; ``message`` est affichable tel quel."""

    def __init__(self, code: Refusal, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class Basis(StrEnum):
    """Sur quoi repose l'autorisation d'un audit (``scope.basis`` du rapport)."""

    SCOPE = "scope"
    """Cible comparée au périmètre déclaré, et incluse."""

    AUTHORIZED_BY = "authorized-by"
    """Aucun périmètre : référence déclarée par ``--authorized-by``, cible non
    vérifiée."""

    CONFIRMATION = "confirmation"
    """Aucun périmètre : nom de la cible ressaisi au terminal par l'opérateur."""

    OFFLINE = "offline"
    """Bundle : aucun système joint, aucun contrôle appliqué."""


def _montrer(valeur: object, limite: int = 60) -> str:
    """Valeur citée dans un message : échappée par ``ascii()`` et tronquée."""
    try:
        texte = ascii(valeur)
    except ValueError:
        # entier de plus de 4300 chiffres : repr() le refuse
        return "<entier trop grand>"
    return texte if len(texte) <= limite else texte[: limite - 1] + "…"


def _adresse(texte: str) -> _Adresse | None:
    try:
        return ipaddress.ip_address(texte)
    except ValueError:
        return None


def _identite(target: Target) -> str:
    """Forme normalisée de la cible, pour un message ; jamais d'exception."""
    try:
        return target.id
    except TargetError:
        # type de cible reserve, sans forme normalisee (cloud, SIEM : #95)
        return f"{target.kind.value}/{target.transport.value}"


def _texte(chemin: str, valeur: object) -> str:
    """Texte libre recopié dans le rapport : mêmes refus que ``amnesia.config``."""
    if not isinstance(valeur, str):
        raise ScopeError(f"{chemin} : chaîne attendue")
    if not valeur.strip():
        raise ScopeError(f"{chemin} : chaîne vide")
    if len(valeur) > _TEXTE_MAX:
        raise ScopeError(f"{chemin} : {_TEXTE_MAX} caractères au plus")
    if any(unicodedata.category(c) in _CATEGORIES_REFUSEES for c in valeur):
        raise ScopeError(f"{chemin} : caractère de contrôle ou non imprimable refusé")
    # ce que assainir() caviarderait (password=..., identifiants d'une URL,
    # secret deja lu) n'a pas sa place dans un rapport ; valeur non reprise.
    # Meme echappement que la fin d'assainir() : l'espace insecable est admise
    echappe = "".join(
        c if c.isprintable() else c.encode("unicode_escape").decode("ascii")
        for c in valeur
    )
    if assainir(valeur) != echappe:
        raise ScopeError(
            f"{chemin} : la valeur ressemble à un secret (« password=... », "
            "« token: ... », identifiants dans une URL) ; aucun secret dans un "
            "périmètre"
        )
    return valeur


def _date(chemin: str, valeur: object) -> date:
    # une date TOML (2026-01-12) arrive deja typee ; datetime herite de date
    if isinstance(valeur, date) and not isinstance(valeur, datetime):
        return valeur
    if isinstance(valeur, str) and _DATE.fullmatch(valeur):
        try:
            return date.fromisoformat(valeur)
        except ValueError:
            pass
    raise ScopeError(
        f"{chemin} : date ISO 8601 attendue (AAAA-MM-JJ, par ex. 2026-01-12)"
    )


def _table(chemin: str, valeur: object, cles: Sequence[str]) -> Mapping[str, Any]:
    if not isinstance(valeur, Mapping):
        raise ScopeError(f"{chemin} : table attendue ([{chemin}])")
    for cle in valeur:
        if cle not in cles:
            proche = difflib.get_close_matches(str(cle), cles, n=1)
            suggestion = (
                f" ; voulais-tu dire « {chemin}.{proche[0]} » ?" if proche else ""
            )
            raise ScopeError(f"clé inconnue {_montrer(f'{chemin}.{cle}')}{suggestion}")
    return valeur


def _requise(table: Mapping[str, Any], chemin: str, cle: str) -> Any:
    if cle not in table:
        raise ScopeError(f"{chemin}.{cle} : clé obligatoire absente")
    return table[cle]


def _hote(ou: str, brut: str) -> str:
    if "*" in brut:
        raise ScopeError(
            f"{ou} : nom d'hôte ou adresse IP exacts attendus ; un motif "
            "« *.domaine » se déclare dans dns"
        )
    try:
        return normalize_host(brut)
    except TargetError as exc:
        raise ScopeError(f"{ou} : {_montrer(brut)} refusé ({exc})") from None


def _nom(ou: str, brut: str) -> str:
    hote = _hote(ou, brut)
    if _adresse(hote) is not None:
        raise ScopeError(
            f"{ou} : nom de domaine attendu ; une adresse IP se déclare dans "
            "hosts ou cidrs"
        )
    return hote


def _motif(ou: str, brut: str) -> str:
    if not brut.startswith("*."):
        raise ScopeError(
            f"{ou} : motif « *.domaine » attendu (par ex. *.corp.example) ; un "
            "nom exact se déclare dans hosts"
        )
    return f"*.{_nom(ou, brut[2:])}"


def _cidr(ou: str, brut: str) -> str:
    try:
        reseau = ipaddress.ip_network(brut, strict=True)
    except ValueError:
        raise ScopeError(
            f"{ou} : plage CIDR attendue, sans bit d'hôte (par ex. 192.0.2.0/24 "
            f"ou 2001:db8::/32) ; {_montrer(brut)} refusé"
        ) from None
    if reseau.prefixlen == 0:
        raise ScopeError(
            f"{ou} : une plage qui couvre toutes les adresses n'est pas un périmètre"
        )
    return str(reseau)


def _tenant(ou: str, brut: str) -> str:
    guid = brut.lower()
    if not _GUID.fullmatch(guid):
        raise ScopeError(
            f"{ou} : GUID de tenant Entra attendu "
            "(xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)"
        )
    return guid


def _compte_aws(ou: str, brut: str) -> str:
    if not _COMPTE_AWS.fullmatch(brut):
        raise ScopeError(
            f"{ou} : identifiant de compte AWS attendu (12 chiffres, entre guillemets)"
        )
    return brut


_ANALYSEURS: Mapping[str, Callable[[str, str], str]] = {
    "hosts": _hote,
    "dns": _motif,
    "ad_domains": _nom,
    "cidrs": _cidr,
    "entra_tenants": _tenant,
    "aws_accounts": _compte_aws,
}


@dataclass(frozen=True, slots=True)
class Rules:
    """Inclusions ou exclusions typées, normalisées, triées et sans doublon.

    ``hosts`` : noms d'hôte ou adresses IP exacts ; ``dns`` : motifs
    ``*.domaine`` (un seul label en inclusion, toute profondeur en exclusion) ;
    ``ad_domains`` : domaines Active Directory (le domaine lui-même et ses
    hôtes directs, ses sous-domaines aussi en exclusion) ; ``cidrs`` : plages
    d'adresses ;
    ``entra_tenants`` : GUID de tenants Entra ; ``aws_accounts`` : identifiants
    de comptes AWS.
    """

    hosts: tuple[str, ...] = ()
    dns: tuple[str, ...] = ()
    ad_domains: tuple[str, ...] = ()
    cidrs: tuple[str, ...] = ()
    entra_tenants: tuple[str, ...] = ()
    aws_accounts: tuple[str, ...] = ()

    @property
    def empty(self) -> bool:
        """Vrai si aucune règle n'est déclarée."""
        return not any(getattr(self, nom) for nom in TYPES)

    def networks(self) -> tuple[_Reseau, ...]:
        """Plages d'adresses : ``cidrs``, et chaque adresse IP de ``hosts``."""
        plages = [ipaddress.ip_network(cidr) for cidr in self.cidrs]
        plages += [
            ipaddress.ip_network(hote)
            for hote in self.hosts
            if _adresse(hote) is not None
        ]
        return tuple(plages)

    def match_name(self, name: str, *, deep: bool = False) -> str | None:
        """Règle qui couvre le nom d'hôte normalisé ``name``, ou ``None``.

        Un motif ``*.domaine`` et un domaine AD couvrent leurs hôtes directs :
        un seul label. ``deep=True`` (exclusions) : à toute profondeur, pour
        qu'une exclusion couvre aussi les sous-domaines de ce qu'elle nomme.
        """
        if name in self.hosts or name in self.ad_domains:
            return name
        _, point, parent = name.partition(".")
        while point:
            if f"*.{parent}" in self.dns:
                return f"*.{parent}"
            if parent in self.ad_domains:
                return parent
            if not deep:
                break
            _, point, parent = parent.partition(".")
        return None

    def match_address(self, address: _Adresse) -> str | None:
        """Plage qui contient ``address``, ou ``None``."""
        for plage in self.networks():
            if address.version == plage.version and address in plage:
                return str(plage)
        return None

    def to_dict(self) -> dict[str, list[str]]:
        """Règles en JSON : une liste triée par type, vide si rien n'est déclaré."""
        return {nom: list(getattr(self, nom)) for nom in TYPES}


def _regles(chemin: str, valeur: object) -> Rules:
    table = _table(chemin, valeur, TYPES)
    champs: dict[str, tuple[str, ...]] = {}
    for nom, analyser in _ANALYSEURS.items():
        entrees = table.get(nom, [])
        if not isinstance(entrees, list):
            raise ScopeError(f"{chemin}.{nom} : tableau de chaînes attendu")
        valeurs: set[str] = set()
        for rang, entree in enumerate(entrees):
            ou = f"{chemin}.{nom}[{rang}]"
            if not isinstance(entree, str):
                raise ScopeError(f"{ou} : chaîne attendue, entre guillemets")
            valeurs.add(analyser(ou, entree))
        champs[nom] = tuple(sorted(valeurs))
    return Rules(**champs)


def _adresses(resolues: Sequence[str]) -> list[_Adresse]:
    """Adresses rendues par la résolution ; ``ValueError`` si l'une est illisible."""
    adresses: list[_Adresse] = []
    for brut in resolues:
        # fe80::1%eth0 : la zone ne change pas l'appartenance a une plage
        adresse = ipaddress.ip_address(str(brut).partition("%")[0])
        if isinstance(adresse, ipaddress.IPv6Address):
            # ::ffff:a.b.c.d designe une IPv4 : comparee aux plages IPv4
            adresse = adresse.ipv4_mapped or adresse
        if adresse not in adresses:
            adresses.append(adresse)
    return adresses


@dataclass(frozen=True, slots=True)
class Scope:
    """Périmètre autorisé, validé : à construire par ``parse_scope()``.

    ``source`` : ``SOURCE_MISSION`` ou ``SOURCE_OPTION``. ``active_tests`` :
    verrou des tests actifs (#155), fermé par défaut.
    """

    mission_id: str
    authorization_reference: str
    authorization_date: date
    signatory: str
    signatory_role: str
    valid_from: date
    valid_until: date
    include: Rules
    exclude: Rules = Rules()
    active_tests: bool = False
    source: str = SOURCE_OPTION

    def declaration(self) -> dict[str, Any]:
        """Déclaration complète, normalisée, en JSON : ce que couvre ``sha256()``."""
        return {
            "mission_id": self.mission_id,
            "authorization": {
                "reference": self.authorization_reference,
                "date": self.authorization_date.isoformat(),
                "signatory": self.signatory,
                "signatory_role": self.signatory_role,
            },
            "valid_from": self.valid_from.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "active_tests": self.active_tests,
            "include": self.include.to_dict(),
            "exclude": self.exclude.to_dict(),
        }

    def sha256(self) -> str:
        """SHA-256 (hexadécimal) du JSON canonique de ``declaration()``.

        Clés triées, sans espace, UTF-8 non échappé, comme ``config_hash`` :
        le même périmètre a le même condensat qu'il soit déclaré dans le
        fichier de mission ou dans un fichier séparé, quels que soient l'ordre
        des entrées et les commentaires.
        """
        canonique = json.dumps(
            self.declaration(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        return hashlib.sha256(canonique.encode("utf-8")).hexdigest()

    def verify(
        self,
        target: Target,
        *,
        now: datetime | None = None,
        resolver: Resolver | None = None,
        local_name: Callable[[], str] | None = None,
    ) -> tuple[str, ...]:
        """Vérifie que ``target`` peut être auditée ; lève ``ScopeRefusal`` sinon.

        Rend les adresses IP vérifiées quand la cible a dû être résolue : le
        collecteur se connecte à l'une d'elles, pas à une nouvelle résolution
        du nom. ``now`` : instant avec fuseau (défaut : maintenant) ;
        ``resolver`` : résolution des noms, sans laquelle une cible qui en a
        besoin est refusée ; ``local_name`` : nom de la machine locale (défaut :
        ``platform.node``).
        """
        self._verifier_periode(now)
        if target.kind is Kind.M365_TENANT:
            return self._verifier_identifiant(target, "entra_tenants", "tenant Entra")
        if target.kind is Kind.AWS_ACCOUNT:
            return self._verifier_identifiant(target, "aws_accounts", "compte AWS")
        if target.transport is Transport.LOCAL:
            brut = (platform.node if local_name is None else local_name)()
            designation = f"machine locale {_montrer(brut)}"
        elif target.transport is not Transport.BUNDLE and target.address is not None:
            brut = target.address
            designation = f"cible {_identite(target)}"
        else:
            raise ScopeRefusal(
                Refusal.UNSUPPORTED,
                f"cible {_identite(target)} : ce type de cible ne peut pas être "
                "comparé au périmètre",
            )
        try:
            hote = normalize_host(brut)
        except TargetError:
            raise ScopeRefusal(
                Refusal.OUT_OF_SCOPE,
                f"{designation} : nom hors de la grammaire des noms d'hôte, "
                "impossible à comparer au périmètre",
            ) from None
        return self._verifier_hote(hote, designation, resolver)

    def _verifier_periode(self, now: datetime | None) -> None:
        instant = datetime.now(UTC).astimezone() if now is None else now
        if instant.utcoffset() is None:
            raise ValueError("instant sans fuseau horaire")
        # aux bornes, la date du poste et la date UTC different : les deux
        # doivent etre dans la periode
        jours = (instant.date(), instant.astimezone(UTC).date())
        periode = (
            f"l'autorisation {self.authorization_reference} couvre la période du "
            f"{self.valid_from.isoformat()} au {self.valid_until.isoformat()}"
        )
        if min(jours) < self.valid_from:
            raise ScopeRefusal(
                Refusal.NOT_YET_VALID,
                f"périmètre pas encore valide le {min(jours).isoformat()} : {periode}",
            )
        if max(jours) > self.valid_until:
            raise ScopeRefusal(
                Refusal.EXPIRED,
                f"périmètre expiré le {max(jours).isoformat()} : {periode}",
            )

    def _verifier_identifiant(
        self, target: Target, type_: str, nature: str
    ) -> tuple[str, ...]:
        identifiant = (target.address or "").lower()
        if identifiant in getattr(self.exclude, type_):
            raise ScopeRefusal(
                Refusal.EXCLUDED,
                f"{nature} {_montrer(identifiant)} exclu du périmètre "
                f"(exclude.{type_})",
            )
        if not identifiant or identifiant not in getattr(self.include, type_):
            raise ScopeRefusal(
                Refusal.OUT_OF_SCOPE,
                f"{nature} {_montrer(identifiant)} hors du périmètre autorisé "
                f"(include.{type_})",
            )
        return ()

    def _verifier_hote(
        self, hote: str, designation: str, resolver: Resolver | None
    ) -> tuple[str, ...]:
        adresse = _adresse(hote)
        if adresse is not None:
            self._refuser_adresse_exclue(adresse, designation)
            if self.include.match_address(adresse) is None:
                raise ScopeRefusal(
                    Refusal.OUT_OF_SCOPE,
                    f"{designation} : adresse hors du périmètre autorisé "
                    "(include.cidrs, include.hosts)",
                )
            return ()
        regle = self.exclude.match_name(hote, deep=True)
        if regle is not None:
            raise ScopeRefusal(
                Refusal.EXCLUDED,
                f"{designation} : exclue du périmètre par {regle}",
            )
        par_nom = self.include.match_name(hote) is not None
        if not par_nom and not self.include.networks():
            raise ScopeRefusal(
                Refusal.OUT_OF_SCOPE,
                f"{designation} : hors du périmètre autorisé (include.hosts, "
                "include.dns, include.ad_domains)",
            )
        if par_nom and not self.exclude.networks():
            return ()
        # une plage peut couvrir ou exclure ce nom : seules ses adresses le disent
        adresses = self._resoudre(hote, designation, resolver)
        for resolue in adresses:
            self._refuser_adresse_exclue(resolue, designation)
        if not par_nom:
            dehors = [a for a in adresses if self.include.match_address(a) is None]
            if dehors:
                raise ScopeRefusal(
                    Refusal.OUT_OF_SCOPE,
                    f"{designation} : résolue vers {dehors[0]}, hors des plages "
                    "autorisées (include.cidrs) ; toutes les adresses d'une "
                    "cible désignée par un nom doivent être incluses",
                )
        return tuple(str(a) for a in adresses)

    def _refuser_adresse_exclue(self, adresse: _Adresse, designation: str) -> None:
        plage = self.exclude.match_address(adresse)
        if plage is not None:
            raise ScopeRefusal(
                Refusal.EXCLUDED,
                f"{designation} : adresse {adresse} exclue du périmètre par {plage}",
            )

    def _resoudre(
        self, hote: str, designation: str, resolver: Resolver | None
    ) -> list[_Adresse]:
        if resolver is None:
            raise ScopeRefusal(
                Refusal.UNRESOLVED,
                f"{designation} : seule une plage d'adresses du périmètre peut "
                "couvrir ou exclure ce nom, et aucune résolution de nom n'est "
                "disponible avant le collecteur réseau (#63) ; désigne la cible "
                "par son adresse IP, ou déclare son nom dans include.hosts et "
                "des exclusions par nom",
            )
        try:
            adresses = _adresses(resolver(hote))
        except (OSError, ValueError):
            adresses = []
        if not adresses:
            raise ScopeRefusal(
                Refusal.UNRESOLVED,
                f"{designation} : nom non résolu, impossible de le comparer aux "
                "plages d'adresses du périmètre",
            )
        return adresses


def parse_scope(table: object, *, source: str = SOURCE_OPTION) -> Scope:
    """Périmètre validé d'une table ``[scope]`` déjà lue ; lève ``ScopeError``."""
    racine = _table(SECTION, table, _CLES)
    autorisation = _table(
        f"{SECTION}.authorization",
        _requise(racine, SECTION, "authorization"),
        _CLES_AUTORISATION,
    )
    chemin = f"{SECTION}.authorization"
    actifs = racine.get("active_tests", False)
    if not isinstance(actifs, bool):
        raise ScopeError(f"{SECTION}.active_tests : booléen attendu (true ou false)")
    scope = Scope(
        mission_id=_texte(
            f"{SECTION}.mission_id", _requise(racine, SECTION, "mission_id")
        ),
        authorization_reference=_texte(
            f"{chemin}.reference", _requise(autorisation, chemin, "reference")
        ),
        authorization_date=_date(
            f"{chemin}.date", _requise(autorisation, chemin, "date")
        ),
        signatory=_texte(
            f"{chemin}.signatory", _requise(autorisation, chemin, "signatory")
        ),
        signatory_role=_texte(
            f"{chemin}.signatory_role",
            _requise(autorisation, chemin, "signatory_role"),
        ),
        valid_from=_date(
            f"{SECTION}.valid_from", _requise(racine, SECTION, "valid_from")
        ),
        valid_until=_date(
            f"{SECTION}.valid_until", _requise(racine, SECTION, "valid_until")
        ),
        include=_regles(f"{SECTION}.include", _requise(racine, SECTION, "include")),
        exclude=_regles(f"{SECTION}.exclude", racine.get("exclude", {})),
        active_tests=actifs,
        source=source,
    )
    if scope.valid_until < scope.valid_from:
        raise ScopeError(
            f"{SECTION}.valid_until ({scope.valid_until.isoformat()}) précède "
            f"{SECTION}.valid_from ({scope.valid_from.isoformat()})"
        )
    if scope.authorization_date > scope.valid_from:
        raise ScopeError(
            f"{chemin}.date ({scope.authorization_date.isoformat()}) suit "
            f"{SECTION}.valid_from ({scope.valid_from.isoformat()}) : une "
            "autorisation écrite précède la période qu'elle couvre"
        )
    if scope.include.empty:
        raise ScopeError(
            f"{SECTION}.include : au moins une inclusion attendue ({', '.join(TYPES)})"
        )
    return scope


def load_scope(path: Path) -> Scope:
    """Périmètre du fichier ``path`` (``--scope``) ; lève ``ScopeError``.

    Le fichier, lu par ``amnesia.inputs``, ne contient que la table
    ``[scope]``, de même schéma que dans le fichier de mission. Le message ne
    cite pas ``path`` : l'appelant le préfixe.
    """
    try:
        document = load_toml(path)
    except UnsafeInputError as exc:
        raise ScopeError(exc.message) from None
    if SECTION not in document:
        raise ScopeError(f"section [{SECTION}] absente")
    autres = sorted(cle for cle in document if cle != SECTION)
    if autres:
        raise ScopeError(
            f"clé {_montrer(autres[0])} hors de la section [{SECTION}] : un "
            f"fichier de périmètre ne contient que [{SECTION}]"
        )
    return parse_scope(document[SECTION], source=SOURCE_OPTION)


def parse_reference(text: object) -> str:
    """Référence d'autorisation de ``--authorized-by`` ; lève ``ScopeError``."""
    return _texte("--authorized-by", text)


def confirmation_name(target: Target) -> str:
    """Nom que l'opérateur doit ressaisir pour confirmer ``target``.

    L'hôte d'une cible distante, sans schéma ni port ; ``local`` pour la
    machine locale.
    """
    if target.transport is Transport.LOCAL:
        return "local"
    return _identite(target) if target.address is None else target.address


def _saisie(texte: str) -> str:
    saisie = texte.strip().lower()
    if saisie.startswith("[") and saisie.endswith("]"):
        # IPv6 ressaisie entre crochets, comme dans winrm://[...]
        saisie = saisie[1:-1]
    return saisie


@dataclass(frozen=True, slots=True)
class Authorization:
    """Base d'autorisation d'un audit, recopiée dans le rapport (``scope``).

    ``reference`` : valeur de ``--authorized-by``, sans périmètre.
    ``addresses`` : adresses IP vérifiées d'une cible qu'il a fallu résoudre.
    """

    basis: Basis
    scope: Scope | None = None
    reference: str | None = None
    addresses: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Bloc ``scope`` du rapport (docs/format-rapport.md).

        Le signataire n'y figure pas : son nom reste dans le fichier de
        périmètre, que ``sha256`` identifie.
        """
        scope = self.scope
        if scope is None:
            return {
                "basis": self.basis.value,
                "source": None,
                "mission_id": None,
                "sha256": None,
                "authorization": {"reference": self.reference, "date": None},
                "valid_from": None,
                "valid_until": None,
                "active_tests": False,
                "include": None,
                "exclude": None,
            }
        return {
            "basis": self.basis.value,
            "source": scope.source,
            "mission_id": scope.mission_id,
            "sha256": scope.sha256(),
            "authorization": {
                "reference": scope.authorization_reference,
                "date": scope.authorization_date.isoformat(),
            },
            "valid_from": scope.valid_from.isoformat(),
            "valid_until": scope.valid_until.isoformat(),
            "active_tests": scope.active_tests,
            "include": scope.include.to_dict(),
            "exclude": scope.exclude.to_dict(),
        }


def authorize(
    target: Target,
    *,
    scope: Scope | None = None,
    authorized_by: str | None = None,
    confirm: Confirm | None = None,
    now: datetime | None = None,
    resolver: Resolver | None = None,
    local_name: Callable[[], str] | None = None,
) -> Authorization:
    """Base d'autorisation de l'audit de ``target`` ; lève ``ScopeRefusal`` sinon.

    À appeler avant toute collecte. Avec un périmètre : ``Scope.verify()``.
    Sans périmètre : ``authorized_by`` (référence déjà validée par
    ``parse_reference()``), sinon ``confirm``, qui fait ressaisir à l'opérateur
    le nom exact de la cible ; ``confirm=None`` : aucun terminal, refus. Un
    bundle ne joint aucun système : aucun contrôle.

    Lève ``ValueError`` si ``scope`` et ``authorized_by`` sont donnés ensemble :
    la référence d'un périmètre déclaré fait foi.
    """
    if scope is not None and authorized_by is not None:
        raise ValueError("authorized_by : sans objet quand un périmètre est déclaré")
    if target.transport is Transport.BUNDLE:
        return Authorization(Basis.OFFLINE, scope=scope, reference=authorized_by)
    if scope is not None:
        adresses = scope.verify(
            target, now=now, resolver=resolver, local_name=local_name
        )
        return Authorization(Basis.SCOPE, scope=scope, addresses=adresses)
    if authorized_by is not None:
        return Authorization(Basis.AUTHORIZED_BY, reference=authorized_by)
    if confirm is None:
        raise ScopeRefusal(
            Refusal.NO_AUTHORIZATION,
            f"cible {_identite(target)} : aucun périmètre déclaré (--scope FICHIER, ou "
            f"section [{SECTION}] du fichier de mission) et aucun terminal pour "
            "confirmer la cible ; hors terminal, --authorized-by "
            '"<référence de la lettre de mission>" est obligatoire',
        )
    attendu = confirmation_name(target)
    saisie = confirm(target, attendu)
    if saisie is None or _saisie(saisie) != attendu:
        raise ScopeRefusal(
            Refusal.NOT_CONFIRMED,
            f"cible {_identite(target)} : confirmation refusée, le nom saisi n'est pas "
            f"« {attendu} »",
        )
    return Authorization(Basis.CONFIRMATION)
