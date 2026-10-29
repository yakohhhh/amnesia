"""Politique d'audit avancée d'un hôte Windows."""

from ...target import Kind
from ..base import Check
from ..registry import Domain, register


@register
class WindowsAuditPolicy(Check):
    """Sous-catégories d'audit avancé activées (succès et échecs)."""

    id = "win.audit_policy"
    title = "Politique d'audit avancée (logon, process creation, object access)"
    description = (
        "Vérifie que les sous-catégories d'audit avancé utiles à l'enquête "
        "(ouvertures de session, création de processus, accès aux objets) sont "
        "activées : sans elles, les événements ne sont jamais produits."
    )
    domain = Domain.WINDOWS
    target_kinds = (Kind.WINDOWS_HOST,)
    version = 1
    default_severity = "high"
