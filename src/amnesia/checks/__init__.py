from .base import Check, Gap
from . import windows


def default_checks() -> list[Check]:
    """Tous les checks enregistres."""
    return list(windows.CHECKS)


__all__ = ["Check", "Gap", "default_checks"]
