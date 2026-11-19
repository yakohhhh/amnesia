# Rend l'evenement entier sans nommer aucune propriete de son contenu.
(Get-WinEvent -LogName 'Security' -MaxEvents 1).PSObject.BaseObject
