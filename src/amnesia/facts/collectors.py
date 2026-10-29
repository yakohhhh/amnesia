"""Collecteurs de faits : protocole ``Collector`` et implémentations de base.

Un collecteur joint la cible (processus local, WinRM, bundle hors ligne, API) et
rend un ``FactSet`` ; les checks n'accèdent jamais eux-mêmes à la cible.

Règles pour tout collecteur :

- argv passé en liste, jamais ``shell=True`` (règles ruff S602 et S604) ;
- timeout explicite sur chaque appel, propagé depuis ``collect(..., timeout=)`` ;
- aucune analyse de texte localisé : uniquement des GUID, des valeurs
  numériques, le registre et l'EventData XML ;
- un échec de collecte d'un fait donne un fait ``unavailable`` avec son motif,
  pas une exception ; une clé de registre absente est une valeur ``None`` ;
- tout sous-processus reçoit l'environnement de ``subprocess_env()`` : un
  ``pwsh`` lancé sans lui envoie une télémétrie à Microsoft et vérifie ses
  mises à jour au démarrage (#26).

Frontière réseau (#26) : ce module, et le paquet ``collectors/`` qui lui
succédera, sont les seuls de ``src/`` autorisés à ouvrir une connexion
(``per-file-ignores`` de la règle ruff TID251, liste vérifiée par
``tests/test_reseau.py``). Un collecteur ne joint que la cible désignée par
l'utilisateur ; aucun autre module d'amnesia ne contacte quoi que ce soit.

Hors périmètre ici : collecteur PowerShell et schéma détaillé des faits Windows
(#48), WinRM (#63), import de bundle (#52), collecteurs cloud (#95).
"""

from __future__ import annotations

import logging
import math
import os
import sys
import threading
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from ..target import Target, Transport
from .model import Fact, FactSet, UnavailableReason, load_facts, validate_fact_name

logger = logging.getLogger("amnesia.collector")

SUBPROCESS_ENV: Mapping[str, str] = {
    # PowerShell 7 : telemetrie au demarrage puis pendant la session
    # (about_Telemetry) ; la variable n'a d'effet que posee avant le lancement
    "POWERSHELL_TELEMETRY_OPTOUT": "1",
    # PowerShell 7 : verification des mises a jour au demarrage
    # (about_Update_Notifications), une requete HTTPS vers Microsoft
    "POWERSHELL_UPDATECHECK": "Off",
    # outils .NET (dotnet) : meme regle
    "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
}
"""Variables imposées à tout sous-processus lancé par un collecteur (#26)."""


def subprocess_env(base: Mapping[str, str] | None = None) -> dict[str, str]:
    """Environnement d'un sous-processus : ``base`` (défaut ``os.environ``) et
    ``SUBPROCESS_ENV``, qui l'emporte.

    À passer en ``env=`` à chaque ``subprocess.run`` d'un collecteur : un
    ``pwsh`` lancé sans ``POWERSHELL_TELEMETRY_OPTOUT=1`` envoie une télémétrie
    à Microsoft, et sans ``POWERSHELL_UPDATECHECK=Off`` vérifie ses mises à
    jour, ce qui contredirait l'engagement « hors ligne par défaut ».
    """
    return {**(os.environ if base is None else base), **SUBPROCESS_ENV}


class Collector(Protocol):
    """Rend les faits ``names`` de ``target``, en ``timeout`` secondes au plus.

    Un fait demandé mais absent du ``FactSet`` rendu compte comme non collecté.
    """

    def collect(
        self, target: Target, names: Iterable[str], *, timeout: float
    ) -> FactSet: ...


def _verifier_timeout(timeout: float) -> None:
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, int | float)
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError(f"timeout invalide : {timeout!r} (secondes > 0 attendues)")


def _noms(names: Iterable[str]) -> list[str]:
    """Noms validés, sans doublon, dans l'ordre de la demande."""
    if isinstance(names, str):
        # une chaine serait lue caractere par caractere
        raise TypeError("names : itérable de noms attendu, pas une chaîne")
    return [validate_fact_name(n) for n in dict.fromkeys(names)]


def _maintenant() -> datetime:
    return datetime.now(UTC)


class CachingCollector:
    """Mémoïse un collecteur par (cible, fait) pendant un audit.

    Un fait demandé par plusieurs checks n'est collecté qu'une fois par cible ;
    un fait que le collecteur n'a pas rendu est mémorisé comme absent. Une
    instance par audit : rien ne passe d'un audit à l'autre. Les appels sont
    sérialisés (verrou), si bien qu'un fait n'est jamais collecté deux fois en
    parallèle.
    """

    def __init__(self, inner: Collector) -> None:
        self.inner = inner
        self._cache: dict[tuple[str, str], Fact | None] = {}
        self._verrou = threading.Lock()

    def collect(
        self, target: Target, names: Iterable[str], *, timeout: float
    ) -> FactSet:
        _verifier_timeout(timeout)
        demandes = _noms(names)
        cible = target.id
        with self._verrou:
            manquants = [n for n in demandes if (cible, n) not in self._cache]
            if manquants:
                obtenus = self.inner.collect(target, manquants, timeout=timeout)
                for nom in manquants:
                    self._cache[(cible, nom)] = obtenus.get(nom)
            faits = [self._cache[(cible, n)] for n in demandes]
        return FactSet(f for f in faits if f is not None)


class FixtureCollector:
    """Faits lus dans un fichier JSON (``tests/fixtures/facts/*.json``).

    Le fichier est lu et validé à la construction : une version de schéma
    inconnue lève ``FactsFormatError`` avec un message explicite. Les faits sont
    rendus quelle que soit la cible ; un fait absent du fichier n'est pas rendu.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.facts = load_facts(self.path)

    def collect(
        self, target: Target, names: Iterable[str], *, timeout: float
    ) -> FactSet:
        _verifier_timeout(timeout)
        return self.facts.subset(_noms(names))


class LocalCollector:
    """Collecte sur la machine courante (cible ``local``).

    Version minimale : hors Windows, tous les faits ``windows.*`` sont
    ``unavailable/unsupported`` ; les autres faits, et les faits Windows sous
    Windows tant que leur collecte n'existe pas (#48), sont
    ``unavailable/not_collected``. Aucun processus n'est lancé.
    """

    def __init__(
        self,
        *,
        platform: str = sys.platform,
        clock: Callable[[], datetime] = _maintenant,
    ) -> None:
        self.platform = platform
        self.clock = clock

    def collect(
        self, target: Target, names: Iterable[str], *, timeout: float
    ) -> FactSet:
        _verifier_timeout(timeout)
        if target.transport is not Transport.LOCAL:
            raise ValueError(
                f"LocalCollector : cible locale attendue, reçu {target.transport.value}"
            )
        instant = self.clock()
        source = f"collecteur local ({self.platform})"
        faits = []
        for nom in _noms(names):
            if nom.startswith("windows.") and self.platform != "win32":
                raison = UnavailableReason.UNSUPPORTED
            else:
                raison = UnavailableReason.NOT_COLLECTED
            faits.append(
                Fact.unavailable(nom, raison, source=source, collected_at=instant)
            )
        logger.debug("collecte locale : %d fait(s) indisponible(s)", len(faits))
        return FactSet(faits)
