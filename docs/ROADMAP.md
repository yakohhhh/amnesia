# Roadmap & issues — amnesia

Créées automatiquement par `scripts/create-github-repo.sh`.

## M0 — Scaffold
- **CI : ruff + pytest**
- **Moteur de checks + agrégation des Gaps** — exécuter les checks, collecter les `Gap`.
- **Rapport JSON + rendu « questions sans réponse »** — sortie machine + lisible.

## M1 — MVP (Windows + AD)
- **Check politique d'audit avancée** — logon, process creation, object access.
- **Check Sysmon** — présent et configuré.
- **Check logging PowerShell** — script block + module logging.
- **Check taille/rétention des journaux** — surtout Security (risque d'écrasement).
- **Check NTP / time sync** — cohérence des horodatages.
- **Collecte distante via WinRM** — exécuter les checks sur un hôte distant.

## M2 — Cloud
- **Check rétention Microsoft 365 / Entra ID** — audit log, sign-in logs.
- **Check AWS CloudTrail** — activé, multi-région, rétention.
- **Check forwarding SIEM** — les événements partent-ils vraiment ?

## Backlog
- **Scoring de maturité + export PDF** — pour livrer une mission d'audit.
- **Rapport client en marque blanche** — packaging « prestation ».
