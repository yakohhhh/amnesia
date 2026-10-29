"""Checks d'amnesia : modèle (``base``) et registre (``registry``).

Importer ce paquet ne charge aucun check : le registre importe les paquets de
domaine (``windows``, ``ad``...) au premier besoin.
"""

from .base import (
    Check,
    Confidence,
    Evidence,
    Gap,
    Reference,
    ReferenceKind,
    Severity,
)
from .registry import (
    REGISTRY,
    CheckMeta,
    CheckRegistrationError,
    Domain,
    DuplicateCheckError,
    InvalidCheckError,
    Registry,
    register,
)


def default_checks() -> list[Check]:
    """Une instance neuve de chaque check enregistré, à chaque appel."""
    return REGISTRY.create_all()


__all__ = [
    "REGISTRY",
    "Check",
    "CheckMeta",
    "CheckRegistrationError",
    "Confidence",
    "Domain",
    "DuplicateCheckError",
    "Evidence",
    "Gap",
    "InvalidCheckError",
    "Reference",
    "ReferenceKind",
    "Registry",
    "Severity",
    "default_checks",
    "register",
]
