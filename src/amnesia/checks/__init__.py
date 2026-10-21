from . import windows
from .base import Check, Gap


def default_checks() -> list[Check]:
    """Tous les checks enregistres."""
    return list(windows.CHECKS)


__all__ = ["Check", "Gap", "default_checks"]
