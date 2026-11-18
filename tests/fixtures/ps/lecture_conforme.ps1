# Script de collecte fictif : uniquement des lectures de l'allowlist.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$journal = Get-WinEvent -ListLog 'Security' 2>$null
$plusAncien = Get-WinEvent -LogName 'Security' -MaxEvents 1 -Oldest
$cle = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$journalisation = $null
if (Test-Path -LiteralPath $cle) {
    $journalisation = Get-ItemProperty -LiteralPath $cle
}
$services = Get-Service -Name 'EventLog', 'W32Time' |
    Select-Object -Property Name, Status, StartType |
    Sort-Object -Property Name
$compte = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$sortie = [ordered]@{
    compte         = $compte.Name
    collecte       = (Get-Date).ToUniversalTime().ToString('o')
    taille_max     = $journal.MaximumSizeInBytes
    plus_ancien    = $plusAncien.ToXml()
    journalisation = $journalisation
    services       = $services
}
ConvertTo-Json -InputObject $sortie -Depth 4 -Compress
