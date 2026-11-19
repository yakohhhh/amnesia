# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Collecteurs de faits : protocole ``Collector`` et implémentations de base.

Un collecteur joint la cible (processus local, WinRM, bundle hors ligne, API) et
rend un ``FactSet`` ; les checks n'accèdent jamais eux-mêmes à la cible.

Règles pour tout collecteur :

- lecture seule (ADR 0006) : un exécutable ne se lance que par
  ``run_command()``, qui refuse par ``ReadOnlyViolation`` tout ce qui sort de
  l'allowlist (``amnesia.readonly``) avant de créer le moindre processus ;
  cette exception signale un bug, elle remonte hors de tout ``except
  Exception`` ;
- argv passé en liste, jamais ``shell=True`` (règles ruff S602 et S604),
  programme désigné par son chemin complet (S607) ;
- timeout explicite sur chaque appel, propagé depuis ``collect(..., timeout=)`` ;
- aucune analyse de texte localisé : uniquement des GUID, des valeurs
  numériques, le registre et les métadonnées des journaux ;
- minimisation (#41, docs/DONNEES.md) : jamais le contenu d'un événement
  (``Message``, ``Properties``, ``UserId``, ``MachineName``, EventData) ; un
  fait qui en porte un champ est refusé par ``amnesia.facts.model``, et une
  sortie brute n'est gardée sur disque que sur demande (``RawSink``) ;
- un échec de collecte d'un fait donne un fait ``unavailable`` avec son motif,
  pas une exception ; une clé de registre absente est une valeur ``None`` ;
- seule exception à la règle précédente : un SDK tiers s'importe dans
  ``collect()`` après ``amnesia.deps.require_extra()``, et la ``MissingExtra``
  qu'il lève sans l'extra doit remonter, hors de tout ``except Exception`` :
  le moteur la traduit en « non évalué » avec la commande d'installation
  (docs/dev/dependances.md) ;
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
import subprocess
import sys
import threading
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath
from typing import Protocol

from ..readonly import check_command
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

    À passer en ``env=`` à chaque sous-processus lancé par amnesia (vérifié sur
    l'AST de ``src/`` par ``tests/test_reseau.py``) : un ``pwsh`` lancé sans
    ``POWERSHELL_TELEMETRY_OPTOUT=1`` envoie une télémétrie à Microsoft, et sans
    ``POWERSHELL_UPDATECHECK=Off`` vérifie ses mises à jour, ce qui
    contredirait l'engagement « hors ligne par défaut ».

    Une variable de ``base`` homonyme à la casse près est retirée : Windows ne
    distingue pas la casse des noms de variables, et un
    ``powershell_telemetry_optout=0`` resté dans le bloc d'environnement
    pourrait l'emporter sur la valeur imposée.
    """
    source = os.environ if base is None else base
    imposees = {nom.upper() for nom in SUBPROCESS_ENV}
    env = {nom: val for nom, val in source.items() if nom.upper() not in imposees}
    env.update(SUBPROCESS_ENV)
    return env


class Collector(Protocol):
    """Rend les faits ``names`` de ``target``, en ``timeout`` secondes au plus.

    Un fait demandé mais absent du ``FactSet`` rendu compte comme non collecté.
    Un échec de collecte donne un fait ``unavailable``, pas une exception, sauf
    ``MissingExtra`` (extra absent, ``amnesia.deps.require_extra``), à laisser
    remonter : le moteur la traduit en « non évalué » avec la commande
    d'installation.
    """

    def collect(
        self, target: Target, names: Iterable[str], *, timeout: float
    ) -> FactSet: ...


class RawSink(Protocol):
    """Destination des sorties brutes d'une commande de collecte.

    Fournie seulement sur demande explicite (``amnesia audit --keep-raw``,
    ``amnesia.output.RawStore``) : sans elle, une sortie brute ne vit qu'en
    mémoire, le temps d'en extraire les faits. ``name`` désigne la commande,
    ``data`` sa sortie standard telle quelle.
    """

    def __call__(self, name: str, data: bytes) -> None: ...


def _verifier_timeout(timeout: float) -> None:
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, int | float)
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError(f"timeout invalide : {timeout!r} (secondes > 0 attendues)")


def run_command(
    argv: Sequence[str], *, timeout: float, raw: RawSink | None = None
) -> subprocess.CompletedProcess[bytes]:
    """Lance un exécutable de l'allowlist et rend sa sortie brute.

    Seul point de lancement d'un processus par un collecteur (vérifié sur l'AST
    de ``amnesia.facts`` par ``tests/unit/test_readonly.py``). ``argv`` est
    confronté à ``amnesia.readonly.check_command`` avant tout lancement :
    programme hors allowlist, appelé sans son chemin complet ou avec d'autres
    arguments que ses formes figées, et ``ReadOnlyViolation`` est levée sans
    qu'aucun processus soit créé.

    Sans shell, sans entrée standard, avec le délai ``timeout`` (secondes) et
    l'environnement de ``subprocess_env()``. Les sorties sont rendues en
    octets : leur décodage dépend de l'outil (page de code OEM, UTF-16) et
    revient au collecteur. Le code de retour n'est pas vérifié ici ;
    ``subprocess.TimeoutExpired`` et ``OSError`` remontent à l'appelant, qui en
    fait un fait ``unavailable``.

    Minimisation (#41) : la sortie brute n'est écrite nulle part. ``raw``,
    absent par défaut, la reçoit quand l'auditeur a demandé à la garder
    (``--keep-raw``) ; elle n'entre jamais dans le rapport.
    """
    _verifier_timeout(timeout)
    commande = check_command(argv)
    resultat = subprocess.run(  # noqa: S603 - argv verifie par l'allowlist, sans shell
        list(commande),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        check=False,
        env=subprocess_env(),
    )
    if raw is not None:
        raw(PureWindowsPath(commande[0]).stem, resultat.stdout)
    return resultat


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

    ``raw`` (``--keep-raw``) : destination des sorties brutes, absente par
    défaut. Le collecteur PowerShell (#48) la passera à ``run_command`` ;
    d'ici là, rien n'y est écrit.
    """

    def __init__(
        self,
        *,
        platform: str = sys.platform,
        clock: Callable[[], datetime] = _maintenant,
        raw: RawSink | None = None,
    ) -> None:
        self.platform = platform
        self.clock = clock
        self.raw = raw

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
