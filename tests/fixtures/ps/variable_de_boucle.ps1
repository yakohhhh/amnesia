# Variable d'iteration qualifiee par un lecteur : ecrit par un fournisseur.
foreach (${C:\Windows\Temp\exemple.txt} in 'a', 'b') {
    Write-Output 'tour'
}
