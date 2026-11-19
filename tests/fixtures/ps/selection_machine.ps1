# Projection explicite, mais d'une propriete de contenu d'evenement.
Get-WinEvent -LogName 'Security' -MaxEvents 1 |
    Select-Object -Property TimeCreated, MachineName
