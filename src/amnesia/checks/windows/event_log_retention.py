# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Taille et rétention des journaux d'événements d'un hôte Windows."""

from ...target import Kind
from ..base import Check
from ..registry import Domain, register


@register
class EventLogRetention(Check):
    """Taille maximale et mode de rétention des journaux d'événements.

    Couvre tous les journaux utiles à l'enquête (Security, System,
    PowerShell/Operational, Sysmon...), pas seulement Security. Renommé avant
    toute publication de l'id (#17) : l'ancien id et l'ancienne classe ne
    nommaient que la taille du journal Security. Aucun alias n'est gardé.
    """

    id = "win.event_log_retention"
    title = "Taille et rétention des journaux d'événements (risque d'écrasement)"
    description = (
        "Estime la profondeur d'historique de chaque journal d'événements utile "
        "à l'enquête (Security en premier) d'après sa taille maximale et son "
        "mode de rétention : un journal trop petit est écrasé avant que "
        "l'incident ne soit découvert."
    )
    domain = Domain.WINDOWS
    target_kinds = (Kind.WINDOWS_HOST,)
    version = 1
    default_severity = "high"
    requires_facts = ("windows.eventlog.config:Security",)
    # questions du catalogue auxquelles ce check contribue ; chacune le
    # liste dans son champ checks (amnesia catalog validate)
    question_ids = (
        "Q-WIN-AUDIT-CHANGE",
        "Q-WIN-AUTORUN",
        "Q-WIN-DEFENDER-TAMPER",
        "Q-WIN-DNS",
        "Q-WIN-EXPLICIT-CREDS",
        "Q-WIN-LOCAL-ADMIN",
        "Q-WIN-LOG-CLEARED",
        "Q-WIN-NETWORK-LOGON",
        "Q-WIN-OUTBOUND",
        "Q-WIN-POWERSHELL",
        "Q-WIN-PRIV-LOGON",
        "Q-WIN-PROCESS-CMDLINE",
        "Q-WIN-RDP-LOGON",
        "Q-WIN-SCHTASK",
        "Q-WIN-SERVICE-INSTALL",
        "Q-WIN-SHADOW-DELETE",
        "Q-WIN-SHARE-ACCESS",
        "Q-WIN-TIME-CHANGE",
        "Q-WIN-USB",
        "Q-WIN-WMI-PERSIST",
    )
