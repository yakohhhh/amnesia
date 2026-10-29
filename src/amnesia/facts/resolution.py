"""Traduction des faits indisponibles en résultat de check, sans jamais de Gap.

Le moteur (#21) appelle ``resolve()`` avant ``evaluate()`` : si un fait requis
n'est pas observé, le check n'est pas évalué et son résultat dit pourquoi.

==========================================  ==================================
Fait requis                                 Résultat
==========================================  ==================================
absent du FactSet ou ``not_collected``      ``skipped`` / ``not_collected``
``access_denied``                           ``error`` / ``access_denied``
``timeout``                                 ``error`` / ``timeout``
``unreachable``                             ``error`` / ``unreachable``
``unsupported``                             ``not_applicable``
==========================================  ==================================

Plusieurs faits indisponibles : l'erreur l'emporte sur le saut, qui l'emporte
sur ``not_applicable`` (seul statut « vérifié » des trois). Un check n'est donc
sans objet que si tous ses faits manquants sont ``unsupported`` : le doute
penche vers « non évalué », jamais vers « vérifié ».
"""

from __future__ import annotations

from collections.abc import Iterable

from ..checks.base import CheckResult, Reason, assainir
from .model import Fact, FactSet, UnavailableReason

_MOTIF_D_ERREUR: dict[UnavailableReason, Reason] = {
    UnavailableReason.ACCESS_DENIED: Reason.ACCESS_DENIED,
    UnavailableReason.TIMEOUT: Reason.TIMEOUT,
    UnavailableReason.UNREACHABLE: Reason.UNREACHABLE,
}


class FactUnavailableError(Exception):
    """Fait requis indisponible ; porte l'``ErrorInfo`` d'un résultat error."""

    def __init__(self, fact: Fact) -> None:
        raison = fact.unavailable_reason
        motif = "?" if raison is None else raison.value
        super().__init__(
            f"fait {fact.name} indisponible ({motif}), source : {fact.source}"
        )
        self.fact = fact


def resolve(
    check_id: str,
    target: str,
    requires_facts: Iterable[str],
    facts: FactSet,
) -> CheckResult | None:
    """Résultat imposé par les faits requis indisponibles, ou None.

    None : tous les faits requis sont observés (``ok``, valeur ``None``
    comprise) et ``evaluate()`` peut être appelé. Sinon, un résultat ``error``,
    ``skipped`` ou ``not_applicable`` ; jamais ``gap`` ni ``pass``.
    """
    erreurs: list[tuple[Fact, Reason]] = []
    non_collectes: list[str] = []
    sans_objet: list[Fact] = []
    for nom in dict.fromkeys(requires_facts):
        fait = facts.get(nom)
        if fait is not None and fait.available:
            continue
        raison = None if fait is None else fait.unavailable_reason
        if fait is None or raison is None or raison is UnavailableReason.NOT_COLLECTED:
            non_collectes.append(nom)
        elif raison is UnavailableReason.UNSUPPORTED:
            sans_objet.append(fait)
        else:
            erreurs.append((fait, _MOTIF_D_ERREUR[raison]))
    if erreurs:
        # premier fait requis en erreur, dans l'ordre de requires_facts
        fait, motif = erreurs[0]
        return CheckResult.failed(check_id, target, motif, FactUnavailableError(fait))
    if non_collectes:
        return CheckResult.skipped(
            check_id,
            target,
            Reason.NOT_COLLECTED,
            f"fait(s) non collecté(s) : {', '.join(non_collectes)}",
        )
    if sans_objet:
        noms = ", ".join(f.name for f in sans_objet)
        # source ecrite par un collecteur ou lue d'un bundle : peut porter un
        # secret (winrm://user:mdp@hote, /p:...), caviardee comme une erreur
        return CheckResult.not_applicable(
            check_id,
            target,
            f"fait(s) non pris en charge par la cible : {noms} "
            f"(source : {assainir(sans_objet[0].source)})",
        )
    return None
