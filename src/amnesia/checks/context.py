"""Contexte d'évaluation d'un check : cible, configuration, horloge et logger.

``evaluate()`` est une fonction pure : tout ce qui varie d'un audit à l'autre
lui parvient par le ``FactSet`` ou par ce contexte, jamais par une I/O. Les
tests injectent une horloge figée (fixture ``horloge_figee``).
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any

from ..target import Target


def _maintenant() -> datetime:
    return datetime.now(UTC)


def _configuration_vide() -> Mapping[str, Any]:
    return MappingProxyType({})


@dataclass(frozen=True)
class Context:
    """Ce qu'un check reçoit en plus des faits.

    ``config`` : réglages de l'audit en lecture seule (modèle à venir) ;
    ``clock`` : horloge UTC, seule source de « maintenant » pour un check ;
    ``logger`` : ``amnesia.check.<id>`` via ``for_check``.
    """

    target: Target
    config: Mapping[str, Any] = field(default_factory=_configuration_vide)
    clock: Callable[[], datetime] = _maintenant
    logger: logging.Logger = field(
        default_factory=lambda: logging.getLogger("amnesia.check")
    )

    @classmethod
    def for_check(
        cls,
        check_id: str,
        target: Target,
        *,
        config: Mapping[str, Any] | None = None,
        clock: Callable[[], datetime] = _maintenant,
    ) -> Context:
        """Contexte d'un check, avec le logger ``amnesia.check.<id>``."""
        return cls(
            target=target,
            config=MappingProxyType(dict(config or {})),
            clock=clock,
            logger=logging.getLogger(f"amnesia.check.{check_id}"),
        )
