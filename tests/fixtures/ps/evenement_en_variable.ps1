# Range l'evenement entier dans une variable, puis le serialise.
$evenement = Get-WinEvent -LogName 'Security' -MaxEvents 1 -Oldest
ConvertTo-Json -InputObject $evenement -Depth 2 -Compress
