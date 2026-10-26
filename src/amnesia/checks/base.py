"""Modele d'un check et d'un angle mort (Gap)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..target import Target


@dataclass
class Gap:
    """Une question d'enquete a laquelle on ne pourra PAS repondre, et pourquoi."""

    question: str
    reason: str
    severity: str = "medium"  # low | medium | high


class Check:
    """Un controle de forensic readiness. Les sous-classes implementent run()."""

    id: str = "base"
    title: str = "base"

    def run(self, target: Target) -> list[Gap]:  # pragma: no cover - stub
        raise NotImplementedError("check non implemente — voir docs/ROADMAP.md")
