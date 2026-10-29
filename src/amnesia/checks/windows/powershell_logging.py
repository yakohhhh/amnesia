"""Journalisation PowerShell d'un hôte Windows."""

from ...target import Kind
from ..base import Check
from ..registry import Domain, register


@register
class WindowsPowerShellLogging(Check):
    """Script block logging et module logging de PowerShell."""

    id = "win.powershell_logging"
    title = "PowerShell script block + module logging activés"
    description = (
        "Vérifie que le script block logging et le module logging de PowerShell "
        "sont activés : sans eux, le contenu des scripts exécutés par un "
        "attaquant reste invisible."
    )
    domain = Domain.WINDOWS
    target_kinds = (Kind.WINDOWS_HOST,)
    version = 1
    default_severity = "high"
