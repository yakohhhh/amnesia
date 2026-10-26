"""Checks Windows / Active Directory (métadonnées pour l'instant, run() à écrire)."""

from .base import Check


class WindowsAuditPolicy(Check):
    id = "win.audit_policy"
    title = "Politique d'audit avancée (logon, process creation, object access)"


class WindowsPowerShellLogging(Check):
    id = "win.powershell_logging"
    title = "PowerShell script block + module logging activés"


class SecurityLogRetention(Check):
    id = "win.security_log_size"
    title = "Taille/rétention du journal Security (risque d'écrasement)"


class SysmonPresent(Check):
    id = "win.sysmon"
    title = "Sysmon installé et configuré"


class TimeSync(Check):
    id = "win.time_sync"
    title = "Synchronisation NTP (cohérence des horodatages)"


CHECKS = [
    WindowsAuditPolicy(),
    SysmonPresent(),
    WindowsPowerShellLogging(),
    SecurityLogRetention(),
    TimeSync(),
]
