"""Checks Windows / Active Directory (metadonnees pour l'instant, run() a ecrire)."""
from .base import Check


class WindowsAuditPolicy(Check):
    id = "win.audit_policy"
    title = "Politique d'audit avancee (logon, process creation, object access)"


class WindowsPowerShellLogging(Check):
    id = "win.powershell_logging"
    title = "PowerShell script block + module logging actives"


class SecurityLogRetention(Check):
    id = "win.security_log_size"
    title = "Taille/retention du journal Security (risque d'ecrasement)"


class SysmonPresent(Check):
    id = "win.sysmon"
    title = "Sysmon installe et configure"


class TimeSync(Check):
    id = "win.time_sync"
    title = "Synchronisation NTP (coherence des horodatages)"


CHECKS = [
    WindowsAuditPolicy(),
    SysmonPresent(),
    WindowsPowerShellLogging(),
    SecurityLogRetention(),
    TimeSync(),
]
