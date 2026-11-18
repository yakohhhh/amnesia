# Modifie la configuration d'un journal sans aucune cmdlet d'ecriture.
$journal = Get-WinEvent -ListLog 'Security'
$journal.MaximumSizeInBytes = 1MB
$journal.SaveChanges()
