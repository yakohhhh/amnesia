# Script de collecte fictif : uniquement des lectures de l'allowlist.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$journal = Get-WinEvent -ListLog 'Security' 2>$null
# minimisation (#41) : seul l'horodatage du plus ancien evenement est lu
$plusAncien = (Get-WinEvent -LogName 'Security' -MaxEvents 1 -Oldest).TimeCreated
$plusRecent = Get-WinEvent -LogName 'Security' -MaxEvents 1 |
    Select-Object -Property TimeCreated, RecordId
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
    enregistrements = $journal.RecordCount
    plus_ancien    = $plusAncien.ToUniversalTime().ToString('o')
    plus_recent    = $plusRecent
    journalisation = $journalisation
    services       = $services
}
ConvertTo-Json -InputObject $sortie -Depth 4 -Compress
