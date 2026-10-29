"""Lance amnesia dans un processus dont le reseau est coupe (#26).

Usage : ``python tests/sans_reseau.py <arguments d'amnesia>``

Le garde est pose avant tout import d'amnesia : une connexion tentee a l'import
compte aussi. Chaque tentative (creation de socket, connexion, resolution DNS)
leve ReseauInterdit et est consignee. En fin d'execution, le code de sortie est
celui d'amnesia, ou CODE_RESEAU si une tentative a eu lieu, quoi qu'amnesia en
ait fait (sa boucle principale avale les exceptions en code 4). Les tentatives
sont decrites sur stderr, avec la ligne d'amnesia qui les a faites.

Ce script complete le blocage en processus de tests/conftest.py (#5), que les
tests d'integration en sous-processus ne subissent pas.
"""

from __future__ import annotations

import socket
import sys
import traceback
from collections.abc import Callable
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


class ReseauInterdit(RuntimeError):
    """Une connexion sortante a ete tentee alors que le reseau est coupe."""


def _origine() -> str:
    # derniere ligne d'amnesia dans la pile, sinon la derniere ligne tout court
    pile = traceback.extract_stack()[:-2]
    for cadre in reversed(pile):
        if "amnesia" in cadre.filename.replace("\\", "/").split("/"):
            return f"{cadre.filename}:{cadre.lineno} ({cadre.name})"
    return f"{pile[-1].filename}:{pile[-1].lineno}" if pile else "?"


def _refuser(nom: str) -> Callable[..., NoReturn]:
    def refus(*_args: Any, **_kwargs: Any) -> NoReturn:
        tentative = f"socket.{nom} depuis {_origine()}"
        TENTATIVES.append(tentative)
        raise ReseauInterdit(tentative)

    return refus


class _SocketInterdite(socket.socket):
    def __new__(cls, *args: Any, **kwargs: Any) -> NoReturn:
        _refuser("socket")(*args, **kwargs)


def couper_le_reseau() -> None:
    """Remplace socket.socket et les fonctions de FONCTIONS par des refus."""
    socket.socket = _SocketInterdite  # type: ignore[assignment,misc]
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
