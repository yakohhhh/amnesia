# amnesia — questions d'enquête sans réponse

- Rapport : 5f0c6b1e-8a3d-4c2b-9e7f-1a2b3c4d5e6f (amnesia 0.1.0, format 1.0.0)
- Audit du : 2026-10-21T09:30:00Z
- Cibles : winrm\://srv-file.exemple.invalid

**Audit incomplet : certains checks n'ont pas été vérifiés.**

## Sévérité élevée (high) : 1 angle mort

- **Qui s'est connecté en RDP sur SRV-FILE il y a trois semaines ?**
  - → Impossible : le journal Security fait 20 Mo et a été écrasé il y a 4 jours.
  - Sévérité : élevée (high)
  - Cible : winrm\://srv-file.exemple.invalid
  - Fenêtre observée 4 j / exigée 90 j

## Sévérité moyenne (medium) : 1 angle mort

- **Quelles commandes PowerShell l'attaquant a-t-il exécutées ?**
  - → Impossible : la journalisation des blocs de script est désactivée.
  - Sévérité : moyenne (medium)
  - Cible : winrm\://srv-file.exemple.invalid

## Non vérifié : 2 checks

Ces checks n'ont pas pu être évalués : ils ne sont jamais comptés conformes.

| Check | Cible | Statut | Motif | Message |
| --- | --- | --- | --- | --- |
| win.sysmon | winrm\://srv-file.exemple.invalid | erreur | accès refusé | accès refusé à la configuration Sysmon |
| win.time\_sync | winrm\://srv-file.exemple.invalid | non exécuté | check non implémenté |  |

## Résumé

Synthèse : 2 angles morts détectés ; 2 checks non vérifiés, au résultat inconnu.

| Compteur | Nombre |
| --- | ---: |
| Résultats | 6 |
| Résultats conformes (pass) | 1 |
| Résultats avec angle mort (gap) | 2 |
| Résultats en erreur (error) | 1 |
| Résultats non exécutés (skipped) | 1 |
| Résultats sans objet (not_applicable) | 1 |
| Angles morts | 2 |
| Angles morts de sévérité critique (critical) | 0 |
| Angles morts de sévérité élevée (high) | 1 |
| Angles morts de sévérité moyenne (medium) | 1 |
| Angles morts de sévérité faible (low) | 0 |
| Angles morts de sévérité info (info) | 0 |
| Non évalués | 2 |
| Exclus par l'utilisateur | 0 |
