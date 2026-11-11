"""Extras optionnels : dépendances tierces d'exécution, importées à la demande.

Le socle (``amnesia-dfr`` installé sans extra) n'a aucune dépendance tierce :
``amnesia list-checks``, l'audit local et la lecture d'un rapport fonctionnent
avec la seule bibliothèque standard. Un domaine qui a besoin d'un SDK (WinRM,
LDAP, Microsoft Graph, boto3...) le déclare dans un extra, à la fois dans
``[project.optional-dependencies]`` de pyproject.toml et dans ``EXTRAS``, et
ne l'importe qu'au moment de s'en servir, jamais au niveau du module :

.. code-block:: python

    def collect(self, target, names, *, timeout):
        require_extra("aws")
        import boto3  # extra aws, importe a l'execution

Un test statique refuse tout import tiers exécuté au chargement d'un module de
``amnesia``. Sans l'extra, ``require_extra`` lève ``MissingExtra`` ; le moteur
la traduit en résultat « non évalué » (``skipped`` / ``not_collected``) dont le
message donne la commande d'installation, sans traceback.

Ce module n'importe rien d'amnesia : tout module peut s'en servir sans créer de
cycle. Convention et politique d'acceptation d'une dépendance :
``docs/dev/dependances.md``.
"""

from __future__ import annotations

import importlib
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

logger = logging.getLogger(__name__)

DISTRIBUTION = "amnesia-dfr"
"""Nom de distribution d'amnesia, repris par les commandes d'installation."""

ALL = "all"
"""Extra agrégat : référence tous les autres extras (``amnesia-dfr[aws,...]``)."""


@dataclass(frozen=True, slots=True)
class Package:
    """Paquet tiers d'un extra : nom de distribution et module importé.

    ``distribution`` est le nom déclaré dans pyproject.toml (``msgraph-sdk``),
    ``module`` celui qu'importe le code (``msgraph``) : les deux diffèrent
    souvent, et seul le second se voit dans un ``import``.
    """

    distribution: str
    module: str


EXTRAS: Mapping[str, tuple[Package, ...]] = MappingProxyType({})
"""Extras déclarés, ``all`` excepté, et les paquets tiers de chacun.

Vide tant qu'aucun domaine n'a de dépendance tierce : chaque extra est ajouté
par le ticket qui introduit sa première dépendance, ici et dans
``[project.optional-dependencies]``, puis référencé par ``all``. Un test
vérifie la concordance des deux déclarations.
"""


class MissingExtra(Exception):
    """Extra non installé : au moins un de ses paquets ne s'importe pas.

    ``extra`` est le nom de l'extra, ``packages`` les distributions manquantes
    et ``command`` la commande qui les installe, reprise par le message.
    """

    def __init__(self, extra: str, packages: Iterable[str]) -> None:
        paquets = tuple(packages)
        # tous les arguments dans args : copy et pickle reconstruisent l'exception
        super().__init__(extra, paquets)
        self.extra = extra
        self.packages = paquets

    @property
    def command(self) -> str:
        """Commande d'installation de l'extra."""
        return install_command(self.extra)

    def __str__(self) -> str:
        manquants = ", ".join(self.packages) or "paquet inconnu"
        return (
            f"extra {self.extra} non installé (manquant : {manquants}) ; "
            f"pour l'installer : {self.command}"
        )


def install_command(extra: str) -> str:
    """Commande pip qui installe ``extra`` : ``pip install "amnesia-dfr[aws]"``.

    Guillemets compris : sans eux, zsh interpréterait les crochets.
    """
    return f'pip install "{DISTRIBUTION}[{extra}]"'


def require_extra(extra: str) -> None:
    """Importe les paquets de ``extra`` ; lève ``MissingExtra`` s'il en manque.

    À appeler au moment de se servir du SDK (dans ``collect()``), jamais au
    niveau du module. Un paquet présent mais dont l'import échoue (dépendance
    transitive absente, installation abîmée) compte comme manquant : réinstaller
    l'extra le répare.

    Lève ``TypeError`` ou ``ValueError`` pour un extra non déclaré dans
    ``EXTRAS``, ``all`` compris : c'est une erreur de programmation, qu'aucune
    installation ne corrige.
    """
    if not isinstance(extra, str):
        raise TypeError(f"extra : chaîne attendue, reçu {type(extra).__name__}")
    paquets = EXTRAS.get(extra)
    if paquets is None:
        declares = ", ".join(sorted(EXTRAS)) or "aucun"
        raise ValueError(f"extra non déclaré : {extra!r} (déclarés : {declares})")
    manquants: list[str] = []
    for paquet in paquets:
        try:
            importlib.import_module(paquet.module)
        except ImportError as exc:
            # type seul : le message peut citer un chemin du poste de l'auditeur
            logger.debug(
                "extra %s : import de %s impossible (%s)",
                extra,
                paquet.module,
                type(exc).__name__,
            )
            manquants.append(paquet.distribution)
    if manquants:
        raise MissingExtra(extra, manquants)
