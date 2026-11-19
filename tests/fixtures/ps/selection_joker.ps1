# Projection de toutes les proprietes : aucune minimisation.
Get-WinEvent -LogName 'Security' -MaxEvents 1 | Select-Object -Property *
