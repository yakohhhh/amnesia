"""Checks Windows / Active Directory (faits requis déclarés, evaluate() à écrire)."""

from .base import Check


class WindowsAuditPolicy(Check):
    id = "win.audit_policy"
    title = "Politique d'audit avancée (logon, process creation, object access)"
    requires_facts = ("windows.auditpol.backup",)


class WindowsPowerShellLogging(Check):
    id = "win.powershell_logging"
    title = "PowerShell script block + module logging activés"
    requires_facts = ("windows.powershell.logging_policy",)


class SecurityLogRetention(Check):
    id = "win.security_log_size"
    title = "Taille/rétention du journal Security (risque d'écrasement)"
    requires_facts = ("windows.eventlog.config:Security",)


class SysmonPresent(Check):
    id = "win.sysmon"
    title = "Sysmon installé et configuré"
    requires_facts = ("windows.sysmon.service", "windows.sysmon.config")


class TimeSync(Check):
    id = "win.time_sync"
    title = "Synchronisation NTP (cohérence des horodatages)"
    requires_facts = ("windows.w32time.config", "windows.w32time.status")


CHECKS = [
    WindowsAuditPolicy(),
    SysmonPresent(),
    WindowsPowerShellLogging(),
    SecurityLogRetention(),
    TimeSync(),
]
