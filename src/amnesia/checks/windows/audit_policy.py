# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

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
    requires_facts = ("windows.auditpol.backup",)
    # questions du catalogue auxquelles ce check contribue ; chacune le
    # liste dans son champ checks (amnesia catalog validate)
    question_ids = (
        "Q-WIN-AUDIT-CHANGE",
        "Q-WIN-AUTORUN",
        "Q-WIN-EXPLICIT-CREDS",
        "Q-WIN-LOCAL-ADMIN",
        "Q-WIN-NETWORK-LOGON",
        "Q-WIN-OUTBOUND",
        "Q-WIN-PRIV-LOGON",
        "Q-WIN-PROCESS-CMDLINE",
        "Q-WIN-RDP-LOGON",
        "Q-WIN-SCHTASK",
        "Q-WIN-SERVICE-INSTALL",
        "Q-WIN-SHADOW-DELETE",
        "Q-WIN-SHARE-ACCESS",
        "Q-WIN-TIME-CHANGE",
        "Q-WIN-USB",
    )
