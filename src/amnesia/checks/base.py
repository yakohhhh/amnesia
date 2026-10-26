"""Modèle d'un check et d'un angle mort (Gap)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Gap:
    """Une question d'enquête à laquelle on ne pourra PAS répondre, et pourquoi."""

    question: str
    reason: str
    severity: str = "medium"  # low | medium | high


class Check:
    """Un contrôle de forensic readiness. Les sous-classes implémentent run()."""

    id: str = "base"
    title: str = "base"

    def run(self, target: str) -> list[Gap]:  # pragma: no cover - stub
        raise NotImplementedError("check non implémenté — voir docs/ROADMAP.md")
