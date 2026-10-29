"""Synchronisation horaire d'un hôte Windows."""

from ...target import Kind
from ..base import Check
from ..registry import Domain, register


@register
class TimeSync(Check):
    """Synchronisation NTP du service de temps Windows."""

    id = "win.time_sync"
    title = "Synchronisation NTP (cohérence des horodatages)"
    description = (
        "Vérifie que l'hôte synchronise son horloge sur une source fiable : "
        "sans horodatages cohérents, les événements de plusieurs machines ne "
        "peuvent pas être corrélés."
    )
    domain = Domain.WINDOWS
    target_kinds = (Kind.WINDOWS_HOST,)
    version = 1
    default_severity = "medium"
    requires_facts = ("windows.w32time.config", "windows.w32time.status")
