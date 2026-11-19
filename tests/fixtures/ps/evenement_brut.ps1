# Rend l'evenement brut : compte, adresse IP et poste sortiraient de la cible.
Get-WinEvent -LogName 'Security' -MaxEvents 1 -Oldest
