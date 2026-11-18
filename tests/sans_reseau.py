# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Lance amnesia dans un processus dont le reseau est coupe (#26).

Usage : ``python tests/sans_reseau.py <arguments d'amnesia>``

Le garde est pose avant tout import d'amnesia : une connexion tentee a l'import
compte aussi. Chaque tentative (creation de socket, connexion, resolution DNS)
leve ReseauInterdit et est consignee. En fin d'execution, le code de sortie est
celui d'amnesia, ou CODE_RESEAU si une tentative a eu lieu, quoi qu'amnesia en
ait fait (sa boucle principale avale les exceptions en code 4). Les tentatives
sont decrites sur stderr, avec la ligne d'amnesia qui les a faites.

Seule exception : socket.socketpair(), une paire de sockets deja connectees
entre elles, sans adresse ni resolution (AF_UNIX sous POSIX, boucle locale
sous Windows) ; toute boucle asyncio en cree une (self-pipe), et un collecteur
qui lancerait pwsh par asyncio.create_subprocess_exec (#48) sortirait sinon en
99 sans la moindre connexion. Toute autre construction de socket, AF_UNIX
compris, reste refusee.

Ce script complete le blocage en processus de tests/conftest.py (#5), que les
tests d'integration en sous-processus ne subissent pas.
"""

from __future__ import annotations

import importlib.util
import socket
import sys
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any, NoReturn

CODE_RESEAU = 99
"""Code de sortie quand au moins une connexion a ete tentee."""

TENTATIVES: list[str] = []

# fonctions du module socket qui joignent le reseau ou le resolveur DNS, en plus
# de la classe socket elle-meme
FONCTIONS = (
    "create_connection",
    "create_server",
    "getaddrinfo",
    "gethostbyname",
    "gethostbyname_ex",
    "gethostbyaddr",
    "getnameinfo",
    "getfqdn",
)


# captures avant la coupure
_VRAIE_SOCKET = socket.socket  # noqa: TID251 - garde du reseau coupe
# fonctions de la bibliotheque standard autorisees a construire une socket :
# socketpair (POSIX ; repli en boucle locale sous Windows) et accept, que ce
# repli appelle sur sa socket d'ecoute
_CREATEURS_LOCAUX = frozenset(
    {socket.socketpair.__code__, _VRAIE_SOCKET.accept.__code__}
)
_HARNAIS = Path(__file__).resolve()


def _paquet() -> Path | None:
    # repertoire du paquet amnesia, sans l'importer (find_spec sur un paquet de
    # premier niveau ne l'execute pas) : le nom du depot ne suffit pas, il
    # s'appelle lui-meme amnesia
    spec = importlib.util.find_spec("amnesia")
    if spec is None or not spec.submodule_search_locations:
        return None
    return Path(next(iter(spec.submodule_search_locations))).resolve()


PAQUET = _paquet()


class ReseauInterdit(RuntimeError):
    """Une connexion sortante a ete tentee alors que le reseau est coupe."""


def _chemin(nom: str) -> Path | None:
    # « <string> », « <frozen ...> » : pas un fichier (nom invalide sous Windows)
    try:
        return Path(nom).resolve()
    except (OSError, ValueError):
        return None


def _origine() -> str:
    """Ligne la plus profonde du paquet amnesia dans la pile, sinon la plus
    profonde hors de ce harnais."""
    cadres = [(cadre, _chemin(cadre.filename)) for cadre in traceback.extract_stack()]
    pile = [(cadre, chemin) for cadre, chemin in cadres if chemin != _HARNAIS]
    for cadre, chemin in reversed(pile):
        if PAQUET is not None and chemin is not None and chemin.is_relative_to(PAQUET):
            return f"{cadre.filename}:{cadre.lineno} ({cadre.name})"
    if not pile:
        return "?"
    cadre = pile[-1][0]
    return f"{cadre.filename}:{cadre.lineno} ({cadre.name})"


def _refuser(nom: str) -> Callable[..., NoReturn]:
    def refus(*_args: Any, **_kwargs: Any) -> NoReturn:
        tentative = f"socket.{nom} depuis {_origine()}"
        TENTATIVES.append(tentative)
        raise ReseauInterdit(tentative)

    return refus


class _SocketInterdite(_VRAIE_SOCKET):
    # Any : une vraie socket, pas une _SocketInterdite, pour socketpair et accept
    def __new__(cls, *args: Any, **kwargs: Any) -> Any:
        # socketpair et accept appellent le nom global socket du module socket,
        # remplace ici : seuls ces appelants obtiennent une vraie socket
        if sys._getframe(1).f_code in _CREATEURS_LOCAUX:
            return _VRAIE_SOCKET(*args, **kwargs)
        _refuser("socket")(*args, **kwargs)


def couper_le_reseau() -> None:
    """Remplace socket.socket et les fonctions de FONCTIONS par des refus."""
    socket.socket = _SocketInterdite  # type: ignore[misc]  # noqa: TID251
    for nom in FONCTIONS:
        setattr(socket, nom, _refuser(nom))


def main(argv: list[str]) -> int:
    couper_le_reseau()
    # apres le garde : une connexion a l'import est consignee aussi
    from amnesia.cli import main as amnesia_main

    try:
        code = amnesia_main(argv)
    except SystemExit as exc:  # --help, --version, erreur d'usage
        code = 0 if exc.code is None else exc.code if isinstance(exc.code, int) else 2
    except ReseauInterdit:
        code = CODE_RESEAU
    if TENTATIVES:
        sys.stderr.write(
            "connexion(s) tentee(s) avec le reseau coupe :\n"
            + "".join(f"  - {t}\n" for t in TENTATIVES)
        )
        return CODE_RESEAU
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
