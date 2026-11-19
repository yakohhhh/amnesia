# Lit le texte de l'evenement : il nomme le compte, l'adresse et le poste.
(Get-WinEvent -LogName 'Security' -MaxEvents 1 -Oldest).Message
