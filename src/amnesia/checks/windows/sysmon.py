"""Présence et configuration de Sysmon sur un hôte Windows."""

from ...target import Kind
from ..base import Check
from ..registry import Domain, register


@register
class SysmonPresent(Check):
    """Sysmon installé, actif et configuré."""

    id = "win.sysmon"
    title = "Sysmon installé et configuré"
    description = (
        "Vérifie que Sysmon est installé, que son service tourne et qu'une "
        "configuration est chargée : il détaille la création de processus, les "
        "connexions réseau et les chargements d'images."
    )
    domain = Domain.WINDOWS
    target_kinds = (Kind.WINDOWS_HOST,)
    version = 1
    default_severity = "medium"
    requires_facts = ("windows.sysmon.service", "windows.sysmon.config")
