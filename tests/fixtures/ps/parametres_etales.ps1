# Parametres etales : leur nom n'apparait pas dans la commande.
$parametres = @{ ListLog = 'Security' }
$journal = Get-WinEvent @parametres
