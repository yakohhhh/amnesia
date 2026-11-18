# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Écriture des livrables sur le poste de l'auditeur : rapport JSON, futurs formats.

Un rapport est la carte des angles morts d'un client (actif A3 du modèle de
menace). Tout livrable écrit dans un fichier passe par ``write_private()`` :

- **lisible du seul compte courant** : 0600 sous POSIX quel que soit l'umask ;
  sous Windows, ACL réduite au compte courant, héritage désactivé, posée par
  ``CreateFileW`` à la création même du fichier : à aucun instant il ne porte
  l'ACL, plus large, de son dossier (M15) ;
- **atomique** : le contenu est écrit dans un temporaire du dossier de
  destination, synchronisé (``fsync``), puis publié en une opération ; en cas
  d'erreur ou d'interruption, le temporaire est supprimé et rien n'apparaît au
  chemin final ;
- **sans écrasement** sauf ``force`` : la publication échoue
  (``FileExistsError``) dès qu'une entrée occupe la destination, sans course
  entre le test et l'écriture. Sous POSIX, ``os.rename`` remplacerait en
  silence : la publication passe par un lien physique (``os.link``), puis le
  temporaire est retiré. Sous Windows, ``os.rename`` (``MoveFileExW`` sans
  ``MOVEFILE_REPLACE_EXISTING``) refuse lui-même une destination existante, y
  compris sur FAT. Avec ``force``, ``os.replace`` remplace l'entrée elle-même,
  jamais ce vers quoi elle pointe ;
- **jamais à travers un lien symbolique** : une destination qui en est un est
  refusée (``UnsafeDestinationError``), même avec ``force``.

Sans ``--out``, le rapport va dans ``amnesia-out/`` (``prepare_default_dir()``) :
dossier en 0700 (ACL du seul compte courant sous Windows) et ``.gitignore``
réduit à ``*``, pour qu'un audit lancé dans un clone ne finisse pas commité par
un ``git add -A`` (M16). ``warn_if_not_ignored()`` avertit quand une
destination est dans un dépôt git sans y être ignorée.

Hors périmètre : chiffrement (#145), motifs ``.gitignore`` du dépôt (#6),
bandeau de classification (#79).
"""

from __future__ import annotations

import contextlib
import errno
import logging
import os
import secrets
import shutil
import stat
import subprocess
import sys
from pathlib import Path

from .facts.collectors import subprocess_env

logger = logging.getLogger(__name__)

DEFAULT_DIR = "amnesia-out"
"""Dossier de sortie par défaut, relatif au répertoire courant."""

DEFAULT_REPORT = "amnesia-report.json"
"""Nom du rapport JSON par défaut, dans ``DEFAULT_DIR``."""

FILE_MODE = 0o600
"""Droits POSIX d'un livrable, quel que soit l'umask."""

DIR_MODE = 0o700
"""Droits POSIX du dossier de sortie par défaut."""

GITIGNORE = b"*\n"
"""``.gitignore`` du dossier par défaut : tout y est ignoré, lui compris."""

# temporaire cache, dans le dossier de destination : la publication reste un
# renommage ou un lien sur le meme systeme de fichiers
_PREFIXE_TEMPORAIRE = ".amnesia-"
_SUFFIXE_TEMPORAIRE = ".tmp"
_ESSAIS_TEMPORAIRE = 8

# os.link refuse sur un systeme de fichiers sans liens physiques (FAT, exFAT,
# certains partages SMB) : publication par creation exclusive de la destination
_SANS_LIEN_PHYSIQUE = frozenset(
    {errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS, errno.EMLINK}
)

# git check-ignore : 0 ignore, 1 non ignore, 128 erreur (depot illisible...)
_GIT_IGNORE = 0
_GIT_NON_IGNORE = 1
_DELAI_GIT = 10.0
# variables qui feraient lire a git un autre depot que celui de la destination
# (posees par exemple dans un hook git)
_VARIABLES_DEPOT_GIT = frozenset(
    {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"}
)


class UnsafeDestinationError(OSError):
    """Destination refusée : lien symbolique, même avec ``force``."""


def default_report_path() -> Path:
    """Chemin du rapport sans ``--out`` : ``amnesia-out/amnesia-report.json``."""
    return Path(DEFAULT_DIR, DEFAULT_REPORT)


def write_private(path: Path, data: bytes, *, force: bool = False) -> None:
    """Écrit ``data`` dans ``path``, lisible du seul compte courant, atomiquement.

    Le dossier de ``path`` doit exister. Sans ``force``, une entrée existante
    (fichier, dossier, lien) n'est jamais modifiée.

    Raises:
        UnsafeDestinationError: ``path`` est un lien symbolique, cassé ou non.
        FileExistsError: ``path`` existe et ``force`` est faux.
        OSError: toute autre erreur d'écriture.

    Après une exception, ni ``path`` ni un temporaire ne restent du fait de
    cet appel.
    """
    if path.is_symlink():
        raise UnsafeDestinationError(f"{path} : lien symbolique refusé")
    fd, temporaire = _creer_temporaire(path.parent)
    try:
        try:
            _ecrire_tout(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        if force:
            # remplace l'entree elle-meme : un lien plante entre-temps est
            # remplace, jamais suivi
            temporaire.replace(path)
        else:
            _publier_sans_ecraser(temporaire, path, data)
    except BaseException:
        # Ctrl-C compris : rien ne doit rester du temporaire
        with contextlib.suppress(OSError):
            temporaire.unlink()
        raise


def prepare_default_dir(directory: Path) -> None:
    """Prépare le dossier de sortie par défaut : 0700 et ``.gitignore`` à ``*``.

    Un dossier absent est créé en 0700 sous POSIX quel que soit l'umask, avec
    l'ACL du seul compte courant sous Windows. Un dossier déjà là est gardé et
    ramené en 0700 sous POSIX (un refus est signalé, pas bloquant). Son
    ``.gitignore`` n'est créé que s'il manque : jamais réécrit, l'auditeur a pu
    l'adapter. Lève ``OSError`` si le dossier ne peut pas être créé, ou si
    ``directory`` existe sans être un dossier.
    """
    try:
        _creer_dossier_prive(directory)
    except FileExistsError:
        if not directory.is_dir():
            raise NotADirectoryError(
                errno.ENOTDIR, "existe et n'est pas un dossier", str(directory)
            ) from None
        _restreindre_dossier(directory)
    gitignore = directory / ".gitignore"
    if not (gitignore.is_symlink() or gitignore.exists()):
        with contextlib.suppress(FileExistsError):
            write_private(gitignore, GITIGNORE)


def git_repository(path: Path) -> Path | None:
    """Racine du dépôt git qui contient ``path``, sinon ``None``.

    Cherche un ``.git`` (dossier, ou fichier d'un worktree ou d'un sous-module)
    dans les dossiers parents de ``path``, sans lancer git.
    """
    for dossier in _absolu(path).parents:
        if _existe(dossier / ".git"):
            return dossier
    return None


def warn_if_not_ignored(path: Path) -> bool:
    """Avertit (journal, stderr) si ``path`` est dans un dépôt git, non ignoré.

    L'ignorance est vérifiée par ``git check-ignore`` quand git est disponible ;
    sans git, seul le ``.gitignore`` écrit par ``prepare_default_dir()`` est
    reconnu, et l'avertissement dit que rien n'a pu être vérifié. Rend vrai si
    un avertissement a été émis.
    """
    racine = git_repository(path)
    if racine is None:
        return False
    absolu = _absolu(path)
    ignore = _ignore_par_git(absolu, racine)
    if ignore is None:
        if _ignore_par_amnesia(absolu):
            return False
        logger.warning(
            "%s : dans le dépôt git %s, sans pouvoir vérifier qu'il y est ignoré "
            "(git indisponible ou en échec) : ne pas le commiter",
            path,
            racine,
        )
        return True
    if ignore:
        return False
    logger.warning(
        "%s : dans le dépôt git %s sans y être ignoré : un « git add -A » le "
        "commiterait ; l'écrire hors du dépôt ou l'y ignorer (.gitignore)",
        path,
        racine,
    )
    return True


def _creer_temporaire(directory: Path) -> tuple[int, Path]:
    """Crée un temporaire privé et exclusif dans ``directory`` (comme ``mkstemp``)."""
    for _ in range(_ESSAIS_TEMPORAIRE):
        nom = directory / (
            f"{_PREFIXE_TEMPORAIRE}{secrets.token_hex(8)}{_SUFFIXE_TEMPORAIRE}"
        )
        try:
            return _creer_fichier_prive(nom), nom
        except FileExistsError:
            continue
    # pas FileExistsError : la destination, elle, n'existe peut-etre pas
    raise OSError(f"{directory} : aucun nom de fichier temporaire libre")


def _ecrire_tout(fd: int, data: bytes) -> None:
    vue = memoryview(data)
    while vue:
        vue = vue[os.write(fd, vue) :]


def _publier_sans_ecraser(temporaire: Path, path: Path, data: bytes) -> None:
    """Publie ``temporaire`` en ``path`` ; ``FileExistsError`` si ``path`` existe."""
    if sys.platform == "win32":
        # MoveFileExW sans MOVEFILE_REPLACE_EXISTING : refus atomique d'une
        # destination existante, lien compris, et valable sur FAT
        temporaire.rename(path)
    else:
        try:
            path.hardlink_to(temporaire)
        except OSError as exc:
            if exc.errno not in _SANS_LIEN_PHYSIQUE:
                raise
            _creer_sans_ecraser(path, data)
        try:
            temporaire.unlink()
        except OSError as exc:
            # le livrable est publie et complet : l'echec ne l'annule pas
            logger.warning(
                "temporaire %s non supprimé : %s", temporaire, exc.strerror or exc
            )


def _creer_sans_ecraser(path: Path, data: bytes) -> None:
    """Repli sans lien physique : ``path`` créé en exclusif (``O_EXCL``), puis écrit.

    Le fichier est visible avant d'être complet, mais rien n'est jamais
    écrasé ; en cas d'erreur, le fichier créé par cet appel est retiré.
    """
    fd = _creer_fichier_prive(path)
    try:
        try:
            _ecrire_tout(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
    except BaseException:
        with contextlib.suppress(OSError):
            path.unlink()
        raise


def _restreindre_dossier(directory: Path) -> None:
    """Ramène un dossier existant en 0700 sous POSIX ; un refus est signalé."""
    if sys.platform == "win32":
        # chaque livrable porte deja l'ACL du seul compte courant, posee a la
        # creation : l'ACL d'un dossier existant n'est pas modifiee
        pass
    else:
        try:
            if stat.S_IMODE(directory.stat().st_mode) != DIR_MODE:
                directory.chmod(DIR_MODE)
        except OSError as exc:
            logger.warning(
                "%s : droits 0700 impossibles à appliquer : %s",
                directory,
                exc.strerror or exc,
            )


def _absolu(path: Path) -> Path:
    try:
        return path.resolve()
    except (OSError, RuntimeError, ValueError):
        # boucle de liens, nom impossible a encoder : chemin absolu lexical
        return path.absolute()


def _existe(path: Path) -> bool:
    try:
        return path.exists()
    except (OSError, ValueError):
        return False


def _ignore_par_amnesia(path: Path) -> bool:
    """Vrai si le dossier de ``path`` porte le ``.gitignore`` d'amnesia (``*``)."""
    try:
        return (path.parent / ".gitignore").read_bytes() == GITIGNORE
    except (OSError, ValueError):
        return False


def _ignore_par_git(path: Path, racine: Path) -> bool | None:
    """Réponse de ``git check-ignore`` pour ``path`` ; ``None`` sans réponse sûre.

    git n'est lancé que par un chemin absolu : sous Windows, ``shutil.which``
    regarde d'abord le répertoire courant, qui n'est pas de confiance.
    ``core.fsmonitor`` est neutralisé : la configuration d'un dépôt venu
    d'ailleurs pourrait sinon faire exécuter une commande à git.
    """
    git = shutil.which("git")
    if git is None or not Path(git).is_absolute():
        return None
    base = {
        nom: valeur
        for nom, valeur in os.environ.items()
        if nom.upper() not in _VARIABLES_DEPOT_GIT
    }
    try:
        relatif = path.relative_to(racine).as_posix()
        resultat = subprocess.run(  # noqa: S603 - git par chemin absolu, argv en liste
            [
                git,
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(racine),
                "check-ignore",
                "-q",
                "--",
                relatif,
            ],
            env=subprocess_env(base),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=_DELAI_GIT,
            check=False,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if resultat.returncode == _GIT_IGNORE:
        return True
    if resultat.returncode == _GIT_NON_IGNORE:
        return False
    return None


if sys.platform == "win32":
    import ctypes
    import functools
    import msvcrt
    from collections.abc import Iterator
    from ctypes import wintypes

    # winnt.h, fileapi.h, securitybaseapi.h, sddl.h
    _GENERIC_WRITE = 0x40000000
    _FILE_SHARE_READ = 0x00000001
    _CREATE_NEW = 1
    _FILE_ATTRIBUTE_NORMAL = 0x00000080
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _TOKEN_QUERY = 0x0008
    _TOKEN_USER = 1  # TOKEN_INFORMATION_CLASS.TokenUser
    _SDDL_REVISION_1 = 1
    # INVALID_HANDLE_VALUE vaut -1, rendu non signe par HANDLE (c_void_p)
    _POIGNEE_INVALIDE = ctypes.c_void_p(-1).value

    class _SecurityAttributes(ctypes.Structure):
        _fields_ = (
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        )

    # instances propres : ctypes.windll est partage, ses argtypes aussi
    _noyau = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi = ctypes.WinDLL("advapi32", use_last_error=True)

    _CreateFileW = _noyau.CreateFileW
    _CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_SecurityAttributes),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    _CreateFileW.restype = wintypes.HANDLE
    _CreateDirectoryW = _noyau.CreateDirectoryW
    _CreateDirectoryW.argtypes = (
        wintypes.LPCWSTR,
        ctypes.POINTER(_SecurityAttributes),
    )
    _CreateDirectoryW.restype = wintypes.BOOL
    _CloseHandle = _noyau.CloseHandle
    _CloseHandle.argtypes = (wintypes.HANDLE,)
    _CloseHandle.restype = wintypes.BOOL
    _LocalFree = _noyau.LocalFree
    _LocalFree.argtypes = (ctypes.c_void_p,)
    _LocalFree.restype = ctypes.c_void_p
    _GetCurrentProcess = _noyau.GetCurrentProcess
    _GetCurrentProcess.argtypes = ()
    _GetCurrentProcess.restype = wintypes.HANDLE
    _OpenProcessToken = _advapi.OpenProcessToken
    _OpenProcessToken.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    )
    _OpenProcessToken.restype = wintypes.BOOL
    _GetTokenInformation = _advapi.GetTokenInformation
    _GetTokenInformation.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    _GetTokenInformation.restype = wintypes.BOOL
    _ConvertSidToStringSidW = _advapi.ConvertSidToStringSidW
    _ConvertSidToStringSidW.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    )
    _ConvertSidToStringSidW.restype = wintypes.BOOL
    _ConvertSddl = _advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    _ConvertSddl.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG),
    )
    _ConvertSddl.restype = wintypes.BOOL

    @functools.cache
    def _sid_courant() -> str:
        """SID du compte qui exécute amnesia (``S-1-5-21-…``), lu dans son jeton."""
        jeton = wintypes.HANDLE()
        if not _OpenProcessToken(
            _GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(jeton)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            taille = wintypes.DWORD()
            # premier appel : echec attendu (tampon nul), taille requise en retour
            _GetTokenInformation(jeton, _TOKEN_USER, None, 0, ctypes.byref(taille))
            tampon = ctypes.create_string_buffer(max(taille.value, 1))
            if not _GetTokenInformation(
                jeton, _TOKEN_USER, tampon, taille, ctypes.byref(taille)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            _CloseHandle(jeton)
        # TOKEN_USER commence par SID_AND_ATTRIBUTES, dont le premier champ
        # est le PSID
        sid = ctypes.c_void_p.from_buffer(tampon).value
        texte = ctypes.c_void_p()
        ok = _ConvertSidToStringSidW(sid, ctypes.byref(texte))
        erreur = ctypes.get_last_error()
        adresse = texte.value
        if not ok or adresse is None:
            raise ctypes.WinError(erreur)
        try:
            return ctypes.wstring_at(adresse)
        finally:
            _LocalFree(texte)

    @contextlib.contextmanager
    def _attributs_prives(heritage: str) -> Iterator[_SecurityAttributes]:
        """Attributs de sécurité : DACL protégée, accès total au seul compte courant.

        ``D:P`` désactive l'héritage ; ``heritage`` (``OICI`` pour un dossier)
        fait hériter cette même ACE par ce qui sera créé dedans.
        """
        sddl = f"D:P(A;{heritage};FA;;;{_sid_courant()})"
        descripteur = ctypes.c_void_p()
        if not _ConvertSddl(sddl, _SDDL_REVISION_1, ctypes.byref(descripteur), None):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            yield _SecurityAttributes(
                ctypes.sizeof(_SecurityAttributes), descripteur.value, False
            )
        finally:
            _LocalFree(descripteur)

    def _creer_fichier_prive(path: Path) -> int:
        """``CreateFileW(CREATE_NEW)`` avec l'ACL du seul compte courant.

        ``FILE_FLAG_OPEN_REPARSE_POINT`` : un lien, même cassé, à ce nom est
        une entrée existante (``FileExistsError``), jamais suivi.
        """
        with _attributs_prives("") as attributs:
            poignee = _CreateFileW(
                os.fspath(path),
                _GENERIC_WRITE,
                _FILE_SHARE_READ,
                ctypes.byref(attributs),
                _CREATE_NEW,
                _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
            erreur = ctypes.get_last_error()
        if poignee is None or poignee == _POIGNEE_INVALIDE:
            raise ctypes.WinError(erreur)
        try:
            return msvcrt.open_osfhandle(poignee, os.O_WRONLY | os.O_BINARY)
        except BaseException:
            _CloseHandle(poignee)
            with contextlib.suppress(OSError):
                path.unlink()
            raise

    def _creer_dossier_prive(directory: Path) -> None:
        """``CreateDirectoryW`` avec l'ACL, héritable, du seul compte courant."""
        with _attributs_prives("OICI") as attributs:
            ok = _CreateDirectoryW(os.fspath(directory), ctypes.byref(attributs))
            erreur = ctypes.get_last_error()
        if not ok:
            raise ctypes.WinError(erreur)

else:

    def _creer_fichier_prive(path: Path) -> int:
        """``O_CREAT | O_EXCL`` en 0600 : un lien, même cassé, n'est jamais suivi."""
        fd = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, FILE_MODE
        )
        try:
            # l'umask a pu retirer des droits du proprietaire : 0600 exactement
            os.fchmod(fd, FILE_MODE)
        except OSError as exc:
            # FAT, exFAT, partage SMB : pas de droits POSIX a appliquer
            logger.warning(
                "%s : droits 0600 impossibles à appliquer : %s",
                path.parent,
                exc.strerror or exc,
            )
        return fd

    def _creer_dossier_prive(directory: Path) -> None:
        """Dossier en 0700 quel que soit l'umask, qui ne fait que retirer des droits."""
        directory.mkdir(mode=DIR_MODE)
        directory.chmod(DIR_MODE)


__all__ = [
    "DEFAULT_DIR",
    "DEFAULT_REPORT",
    "DIR_MODE",
    "FILE_MODE",
    "GITIGNORE",
    "UnsafeDestinationError",
    "default_report_path",
    "git_repository",
    "prepare_default_dir",
    "warn_if_not_ignored",
    "write_private",
]
