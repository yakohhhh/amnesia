# Serialise l'evenement entier, sans projection.
Get-WinEvent -LogName 'Security' -MaxEvents 1 | ConvertTo-Json -Depth 2 -Compress
