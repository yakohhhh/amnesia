"""Cible d'un audit : modele Target et validation stricte de --target.

Grammaire, extensible par schema :

- ``local`` ou ``localhost`` : la machine courante (windows_host / local) ;
- ``winrm://<hote>[:port]`` : un hote distant (windows_host / winrm). L'hote est
  une IPv4, une IPv6 entre crochets ou un nom d'hote (RFC 1123, longueurs
  RFC 1035) ; un IDN s'ecrit en punycode ``xn--`` ;
- ``bundle:<chemin>`` : une collecte hors ligne, fichier ou dossier existant
  (windows_host / bundle).

Un nom nu (``dc01``) est refuse : le transport doit etre explicite.

Regle : une cible n'est jamais interpolee dans du PowerShell, du LDAP ou une
URL ; elle passe toujours par des parametres. La validation ci-dessous est une
defense en profondeur, pas une autorisation d'interpoler.
"""

from __future__ import annotations

import ipaddress
import re
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class TargetError(ValueError):
    """Cible refusee. Le message, en francais, ne reprend jamais d'identifiants."""


class Kind(StrEnum):
    WINDOWS_HOST = "windows_host"
    # reserves : aucun schema ne les produit encore (cibles cloud : #95)
    M365_TENANT = "m365_tenant"
    AWS_ACCOUNT = "aws_account"
    SIEM = "siem"


class Transport(StrEnum):
    LOCAL = "local"
    WINRM = "winrm"
    BUNDLE = "bundle"
    API = "api"  # reserve aux cibles cloud (#95)


FORMES = "local, winrm://<hote>[:port] ou bundle:<chemin>"

# borne grossiere, avant toute analyse : aucune cible legitime n'en approche
_LONGUEUR_MAX = 4096
# metacaracteres shell, cmd et PowerShell (dont l'accent grave, echappement
# PowerShell, et la virgule, qui fait d'un -ComputerName une liste d'hotes)
_METACARACTERES = frozenset(";|&$`'\"<>(){}*?!%^#,")
_LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")
_PORT = re.compile(r"[0-9]{1,5}")


def _montrer(valeur: str, limite: int = 64) -> str:
    """Forme affichable d'une saisie : echappee en ASCII et tronquee."""
    court = valeur if len(valeur) <= limite else valeur[:limite] + "..."
    return ascii(court)


def _verifier_caracteres(brut: str) -> None:
    if not brut.strip():
        raise TargetError("cible vide")
    if len(brut) > _LONGUEUR_MAX:
        raise TargetError(f"cible trop longue (plus de {_LONGUEUR_MAX} caracteres)")
    # C0, DEL et C1 : sequences d'echappement ANSI, retours a la ligne...
    if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in brut):
        raise TargetError("caractere de controle interdit dans la cible")
    if any(c.isspace() for c in brut):
        raise TargetError("espace interdit dans la cible")
    if not brut.isascii():
        raise TargetError(
            "caractere non ASCII interdit dans la cible "
            "(un nom de domaine internationalise s'ecrit en punycode xn--)"
        )
    interdits = sorted(_METACARACTERES.intersection(brut))
    if interdits:
        raise TargetError(
            f"metacaractere interdit dans la cible : {' '.join(interdits)}"
        )
    if brut.startswith("-"):
        raise TargetError("tiret initial interdit dans la cible (injection d'option)")


def _nom_ou_ipv4(hote: str) -> str:
    """Nom d'hote ou IPv4, normalise : minuscules, sans point final."""
    if not hote:
        raise TargetError("hote manquant")
    try:
        return str(ipaddress.IPv4Address(hote))
    except ValueError:
        pass
    nom = hote.lower().removesuffix(".")
    if len(nom) > 253:
        raise TargetError("nom d'hote trop long (253 caracteres au plus)")
    labels = nom.split(".")
    for label in labels:
        if label.startswith("-") or label.endswith("-"):
            raise TargetError("nom d'hote invalide : tiret en debut ou fin de label")
        if not _LABEL.fullmatch(label):
            raise TargetError(
                "nom d'hote invalide : labels de 1 a 63 caracteres [a-z0-9-]"
            )
    # « 10.0.0.256 » ou « 2130706433 » ne sont pas des noms : inet_aton en
    # ferait une IPv4, d'ou un dernier label jamais entierement numerique
    if labels[-1].isdigit():
        raise TargetError("adresse IPv4 invalide")
    return nom


def _ipv6(hote: str) -> str:
    try:
        return str(ipaddress.IPv6Address(hote))
    except ValueError:
        raise TargetError("adresse IPv6 invalide") from None


def _port(brut: str) -> int:
    if not _PORT.fullmatch(brut) or not 1 <= int(brut) <= 65535:
        raise TargetError("port invalide : entier entre 1 et 65535 attendu")
    return int(brut)


def _hote_port(autorite: str) -> tuple[str, int | None]:
    """Hote normalise et port d'une autorite ``hote[:port]``."""
    if "@" in autorite:
        # le message ne reprend pas la saisie : elle contient un mot de passe
        raise TargetError("identifiants interdits dans la cible (user:pass@)")
    if "/" in autorite or "\\" in autorite:
        raise TargetError("chemin interdit apres l'hote")
    if autorite.startswith("["):
        hote_brut, crochet, reste = autorite[1:].partition("]")
        if not crochet:
            raise TargetError("crochet fermant manquant apres l'adresse IPv6")
        hote = _ipv6(hote_brut)
    elif autorite.count(":") > 1:
        raise TargetError("une adresse IPv6 s'ecrit entre crochets : [fe80::1]")
    else:
        hote_brut, deux_points, port_brut = autorite.partition(":")
        reste = deux_points + port_brut
        hote = _nom_ou_ipv4(hote_brut)
    if not reste:
        return hote, None
    if not reste.startswith(":"):
        raise TargetError("caracteres inattendus apres l'hote")
    return hote, _port(reste[1:])


def _chemin_bundle(brut: str) -> Path:
    if not brut:
        raise TargetError("chemin de bundle manquant")
    chemin = Path(brut)
    # apres normalisation : « ./-x » devient « -x »
    if str(chemin).startswith("-"):
        raise TargetError("tiret initial interdit dans le chemin du bundle")
    try:
        mode = chemin.stat().st_mode
    except (OSError, ValueError):
        raise TargetError(f"bundle introuvable : {_montrer(str(chemin))}") from None
    if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
        raise TargetError("bundle : fichier ou dossier attendu")
    return chemin


@dataclass(frozen=True)
class Target:
    """Une cible d'audit validee. A construire via Target.parse()."""

    kind: Kind
    transport: Transport
    address: str | None = None
    port: int | None = None
    path: Path | None = None

    @property
    def id(self) -> str:
        """Forme normalisee : affichage, journaux, comparaison au perimetre."""
        if self.transport is Transport.LOCAL:
            return "local"
        if self.transport is Transport.WINRM and self.address is not None:
            hote = f"[{self.address}]" if ":" in self.address else self.address
            port = "" if self.port is None else f":{self.port}"
            return f"winrm://{hote}{port}"
        if self.transport is Transport.BUNDLE and self.path is not None:
            return f"bundle:{self.path}"
        raise TargetError(f"cible incomplete ({self.kind}/{self.transport})")

    def __str__(self) -> str:
        return self.id

    @classmethod
    def parse(cls, brut: str) -> Target:
        """Valide et normalise une cible ; leve TargetError sinon."""
        _verifier_caracteres(brut)
        schema, separateur, reste = brut.partition(":")
        schema = schema.lower()
        if not separateur and schema in {"local", "localhost"}:
            return cls(Kind.WINDOWS_HOST, Transport.LOCAL)
        if separateur and schema == "winrm":
            if not reste.startswith("//"):
                raise TargetError("syntaxe attendue : winrm://<hote>[:port]")
            hote, port = _hote_port(reste[2:])
            return cls(Kind.WINDOWS_HOST, Transport.WINRM, address=hote, port=port)
        if separateur and schema == "bundle":
            return cls(Kind.WINDOWS_HOST, Transport.BUNDLE, path=_chemin_bundle(reste))
        if "@" in brut:
            raise TargetError("identifiants interdits dans la cible (user:pass@)")
        suggestion = _suggestion(brut)
        if suggestion is not None:
            raise TargetError(f"transport manquant : utiliser {suggestion}")
        if separateur:
            raise TargetError(
                f"schema inconnu {_montrer(schema)} ; schemas pris en charge : {FORMES}"
            )
        raise TargetError(f"cible non reconnue ; formes acceptees : {FORMES}")


def _suggestion(brut: str) -> str | None:
    """Forme winrm:// d'un hote nu (``dc01``, ``10.0.0.5:5986``, ``fe80::1``)."""
    for autorite in (brut, f"[{brut}]"):
        try:
            hote, port = _hote_port(autorite)
        except TargetError:
            continue
        return Target(Kind.WINDOWS_HOST, Transport.WINRM, hote, port).id
    return None
