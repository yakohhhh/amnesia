# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Secrets d'authentification : type ``Secret`` et sources admises.

Un secret (mot de passe WinRM, secret d'application cloud...) ne passe jamais
par la ligne de commande : un argument se lit dans ``ps``, dans
``/proc/<pid>/cmdline``, dans l'historique du shell et dans les événements 4688
du poste de l'auditeur. Il vient d'une des quatre sources ci-dessous, de la plus
explicite à la plus implicite (``resolve()`` les consulte dans cet ordre) :

1. un fichier désigné (``--password-file``), lisible du seul compte courant ;
2. une variable d'environnement nommée, retirée de ``os.environ`` dès sa lecture ;
3. le trousseau du système (module tiers ``keyring``, importé à la demande),
   entrée ``amnesia/<mission>/<nom>`` ;
4. une invite ``getpass``, seulement si un terminal est disponible.

La valeur est enveloppée dans ``Secret`` : ``repr()``, ``str()`` et les f-strings
rendent ``***``, ``json.dumps``, ``pickle`` et ``copy`` échouent, et seule
``reveal()`` la rend, au moment de la remettre au transport. Chaque ``Secret``
créé est enregistré auprès de ``amnesia.log`` : sa valeur est masquée dans les
journaux, les messages d'erreur et le rapport.

Les messages de ``SecretError`` nomment la source, jamais la valeur.
Documentation : docs/SECRETS.md.
"""

from __future__ import annotations

import getpass
import importlib
import logging
import os
import re
import stat
import sys
import warnings
from collections.abc import MutableMapping
from pathlib import Path
from typing import Any, NoReturn

from .log import MASQUE, register_secret

logger = logging.getLogger(__name__)

MAX_FILE_SIZE = 4096
"""Taille maximale, en octets, d'un fichier de secret."""

KEYRING_NAMESPACE = "amnesia"
"""Préfixe des entrées du trousseau : ``amnesia/<mission>/<nom>``."""

# mission et nom d'une entree du trousseau : pas de « / », qui les separe
_NOM = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

# trousseaux du systeme fournis par le paquet keyring lui-meme (Gestionnaire
# d'identifiants Windows, Trousseau macOS, Secret Service, KWallet, libsecret)
_BACKENDS_DU_SYSTEME = "keyring.backends."
# aucun trousseau utilisable : la source est ignoree, pas refusee
_BACKENDS_VIDES = frozenset({"keyring.backends.fail", "keyring.backends.null"})
_CHAINE = "keyring.backends.chainer"


class SecretError(Exception):
    """Secret introuvable, ou source refusée. Le message ne porte aucune valeur."""


class Secret:
    """Valeur secrète, masquée partout sauf par ``reveal()``.

    ``repr()``, ``str()`` et ``format()`` rendent ``***`` ; ``json.dumps`` lève
    ``TypeError`` (type non sérialisable), comme ``pickle``, ``copy`` et
    ``dataclasses.asdict``. La valeur est enregistrée auprès du filtre
    d'expurgation des journaux à la construction.
    """

    __slots__ = ("__valeur",)

    def __init__(self, value: str) -> None:
        # ni la valeur ni son repr() dans ces messages
        if not isinstance(value, str):
            raise TypeError("Secret : chaîne attendue")
        if not value:
            raise ValueError("Secret : valeur vide")
        self.__valeur = value
        register_secret(value)

    def reveal(self) -> str:
        """La valeur en clair : à n'appeler qu'au moment de la remettre au transport."""
        return self.__valeur

    def __repr__(self) -> str:
        return MASQUE

    def __str__(self) -> str:
        return MASQUE

    def __format__(self, format_spec: str) -> str:
        return MASQUE

    def __reduce__(self) -> NoReturn:
        # pickle, copy.copy, copy.deepcopy et donc dataclasses.asdict
        raise TypeError("Secret : sérialisation et copie refusées")


def _terminal_disponible() -> bool:
    flux = sys.stdin
    try:
        return flux is not None and flux.isatty()
    except (AttributeError, ValueError, OSError):
        # flux remplace ou ferme
        return False


def _verifier_droits(path: Path, st: os.stat_result) -> None:
    """Refuse un fichier de secret lisible par d'autres comptes (comme ssh)."""
    # if/else et non retour anticipe : mypy n'analyse os.geteuid que hors Windows
    if sys.platform == "win32":
        # st_mode ne dit rien de l'ACL sous Windows, et sa lecture (icacls, API
        # de securite) n'est pas encore faite : l'operateur est averti
        logger.warning(
            "fichier de secret %s : ACL non vérifiée sous Windows ; seul ton "
            "compte doit pouvoir le lire (icacls)",
            path,
        )
    else:
        if st.st_uid != os.geteuid():
            raise SecretError(
                f"fichier de secret {path} : appartient à un autre compte"
            )
        droits = stat.S_IMODE(st.st_mode)
        if droits & 0o077:
            raise SecretError(
                f"fichier de secret {path} : droits {droits:04o} trop larges, le "
                "groupe ou les autres comptes y ont accès (attendu : 0600 au "
                "plus, « chmod 600 »)"
            )


def from_file(path: Path) -> Secret:
    """Secret lu dans un fichier d'une ligne, lisible du seul compte courant.

    Sous POSIX, le fichier doit appartenir au compte courant et n'accorder
    aucun droit au groupe ni aux autres (0600 ou 0400), comme une clé privée
    pour ssh ; les droits sont lus sur le descripteur ouvert, pas sur le
    chemin. Sous Windows, où le mode ne décrit pas l'ACL, un avertissement
    rappelle de la vérifier. UTF-8 (BOM toléré) ; la fin de ligne finale est
    retirée.

    Lève ``SecretError`` (fichier absent, illisible, trop ouvert, vide, trop
    gros, sur plusieurs lignes ou pas en UTF-8), sans jamais citer le contenu.
    """
    drapeaux = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        # une FIFO ne bloque pas l'ouverture : elle est refusee juste apres
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        fd = os.open(path, drapeaux)
    except OSError as exc:
        raise SecretError(
            f"fichier de secret {path} : {exc.strerror or 'illisible'}"
        ) from None
    try:
        # sur le descripteur : le fichier verifie est celui qui sera lu
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SecretError(
                f"fichier de secret {path} : n'est pas un fichier ordinaire"
            )
        _verifier_droits(path, st)
        flux = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    with flux:
        octets = flux.read(MAX_FILE_SIZE + 1)
    if len(octets) > MAX_FILE_SIZE:
        raise SecretError(
            f"fichier de secret {path} : plus de {MAX_FILE_SIZE} octets, ce n'est "
            "pas un secret d'une ligne"
        )
    try:
        texte = octets.decode("utf-8-sig")
    except UnicodeDecodeError:
        # from None : l'exception d'origine porte les octets lus
        raise SecretError(f"fichier de secret {path} : UTF-8 attendu") from None
    return Secret(_normaliser(texte, f"fichier de secret {path}"))


def _normaliser(texte: str, source: str) -> str:
    """Valeur d'un secret d'une ligne, la même quelle que soit la source.

    Retire la fin de ligne finale (secret de CI, fichier monté dans une
    variable) : gardée, elle fausserait le mot de passe envoyé et empêcherait
    son masquage. Lève ``SecretError``, sans citer la valeur, si elle est vide,
    tient sur plusieurs lignes, porte un octet nul ou n'est pas de l'UTF-8
    (octet brut de l'environnement, vu par Python comme un surrogate isolé).
    """
    texte = texte.removesuffix("\n").removesuffix("\r")
    if not texte:
        raise SecretError(f"{source} : vide")
    if any(c in texte for c in "\r\n\x00"):
        raise SecretError(f"{source} : une seule ligne attendue")
    try:
        texte.encode("utf-8")
    except UnicodeEncodeError:
        # from None : l'exception d'origine cite le caractere et sa position
        raise SecretError(f"{source} : UTF-8 attendu") from None
    return texte


def from_env(
    name: str, environ: MutableMapping[str, str] | None = None
) -> Secret | None:
    """Secret d'une variable d'environnement, retirée de l'environnement.

    ``None`` si la variable est absente. Présente, elle est supprimée de
    ``os.environ`` (donc de l'environnement du processus) avant le retour :
    aucun processus enfant n'en hérite. La fin de ligne finale est retirée,
    comme pour un fichier. Lève ``SecretError`` si elle est vide, sur plusieurs
    lignes ou pas en UTF-8, sans jamais citer la valeur.
    """
    env = os.environ if environ is None else environ
    valeur = env.pop(name, None)
    if valeur is None:
        return None
    return Secret(_normaliser(valeur, f"variable d'environnement {name}"))


def _nom_de_classe(backend: Any) -> str:
    t = type(backend)
    return f"{t.__module__}.{t.__qualname__}"


def _backend_utilisable(backend: Any) -> bool:
    """Vrai si ``backend`` est un trousseau du système ; faux s'il n'y en a aucun.

    Lève ``SecretError`` pour tout autre backend : seuls ceux du paquet
    ``keyring`` (trousseaux chiffrés du système) sont admis. Un backend tiers
    (``keyrings.alt``, dont ``PlaintextKeyring`` écrit les secrets en clair dans
    un fichier) est refusé, y compris au sein d'une chaîne de backends.
    """
    module = type(backend).__module__
    if module in _BACKENDS_VIDES:
        return False
    if module == _CHAINE:
        utilisable = False
        for maillon in getattr(backend, "backends", ()):
            # chaque maillon est verifie, meme apres un premier trousseau admis
            utilisable = _backend_utilisable(maillon) or utilisable
        return utilisable
    if not module.startswith(_BACKENDS_DU_SYSTEME):
        raise SecretError(
            f"trousseau {_nom_de_classe(backend)} refusé : il peut stocker les "
            "secrets en clair (keyrings.alt PlaintextKeyring...) ; seuls les "
            "trousseaux du système sont admis (Gestionnaire d'identifiants "
            "Windows, Trousseau macOS, Secret Service, KWallet)"
        )
    return True


def keyring_entry(mission: str, name: str) -> tuple[str, str]:
    """Service et compte de l'entrée ``amnesia/<mission>/<nom>`` du trousseau.

    Lève ``ValueError`` si ``mission`` ou ``name`` sort de ``[A-Za-z0-9._-]``
    (64 caractères au plus, le premier alphanumérique).
    """
    for role, valeur in (("mission", mission), ("nom", name)):
        if not _NOM.fullmatch(valeur):
            raise ValueError(
                f"{role} d'une entrée du trousseau : lettres, chiffres, « . », "
                "« _ » et « - » seulement, 64 caractères au plus"
            )
    return f"{KEYRING_NAMESPACE}/{mission}", name


def from_keyring(mission: str, name: str) -> Secret | None:
    """Secret de l'entrée ``amnesia/<mission>/<nom>`` du trousseau du système.

    ``None`` si le module ``keyring`` n'est pas installé, si aucun trousseau
    n'est disponible ou si l'entrée n'existe pas. Lève ``SecretError`` si le
    backend actif n'est pas un trousseau du système (stockage en clair), ou si
    la lecture échoue ; le message d'un backend n'est jamais recopié.
    """
    service, compte = keyring_entry(mission, name)
    entree = f"{service}/{compte}"
    try:
        # module tiers optionnel, importe a la demande (jamais au chargement)
        trousseau: Any = importlib.import_module("keyring")
    except ImportError:
        logger.debug("trousseau : module keyring absent, source ignorée")
        return None
    try:
        backend = trousseau.get_keyring()
        if not _backend_utilisable(backend):
            logger.debug("trousseau : aucun trousseau du système, source ignorée")
            return None
        valeur = trousseau.get_password(service, compte)
    except SecretError:
        raise
    except Exception as exc:
        raise SecretError(
            f"trousseau du système : lecture de {entree} impossible "
            f"({type(exc).__name__})"
        ) from None
    if valeur is None:
        return None
    if not isinstance(valeur, str) or not valeur:
        raise SecretError(f"trousseau du système : entrée {entree} vide ou invalide")
    return Secret(_normaliser(valeur, f"trousseau du système : entrée {entree}"))


def from_prompt(prompt: str) -> Secret:
    """Secret saisi au terminal, sans écho.

    Lève ``SecretError`` tout de suite, sans rien lire, si l'entrée standard
    n'est pas un terminal (CI, tube, tâche planifiée) ou si l'écho ne peut pas
    être coupé ; de même pour une saisie vide ou une fin de fichier.
    """
    if not _terminal_disponible():
        raise SecretError("saisie du secret impossible : aucun terminal")
    try:
        with warnings.catch_warnings():
            # sans cela getpass se rabat sur une lecture AVEC echo
            warnings.simplefilter("error", getpass.GetPassWarning)
            valeur = getpass.getpass(prompt)
    except getpass.GetPassWarning:
        raise SecretError(
            "saisie du secret impossible : l'écho du terminal ne peut pas être coupé"
        ) from None
    except EOFError:
        raise SecretError("saisie du secret interrompue") from None
    return Secret(_normaliser(valeur, "saisie du secret"))


def resolve(
    name: str,
    *,
    file: Path | None = None,
    env: str | None = None,
    mission: str | None = None,
    prompt: str | None = None,
) -> Secret:
    """Secret ``name``, de la première source qui le fournit.

    Ordre, du plus explicite au plus implicite : ``file`` (fichier désigné),
    ``env`` (nom d'une variable d'environnement), trousseau du système (entrée
    ``amnesia/<mission>/<name>``, seulement si ``mission`` est donnée), puis
    invite ``prompt`` au terminal. Une source à ``None`` n'est pas consultée.
    La variable ``env`` est retirée de l'environnement même quand le fichier
    l'emporte.

    Lève ``SecretError`` si une source désignée est refusée, ou si aucune ne
    fournit le secret ; sans terminal, l'invite échoue tout de suite au lieu
    d'attendre une saisie.
    """
    if file is not None:
        if env is not None and os.environ.pop(env, None) is not None:
            logger.warning(
                "variable %s ignorée (le fichier désigné l'emporte) et retirée "
                "de l'environnement",
                env,
            )
        return from_file(file)
    essais = []
    if env is not None:
        secret = from_env(env)
        if secret is not None:
            return secret
        essais.append(f"variable d'environnement {env} absente")
    if mission is not None:
        secret = from_keyring(mission, name)
        if secret is not None:
            return secret
        essais.append(
            f"aucune entrée {KEYRING_NAMESPACE}/{mission}/{name} dans le trousseau"
        )
    if prompt is not None:
        if _terminal_disponible():
            return from_prompt(prompt)
        essais.append("aucun terminal pour le saisir")
    raise SecretError(
        f"secret « {name} » introuvable : {', '.join(essais) or 'aucune source'}"
    )
