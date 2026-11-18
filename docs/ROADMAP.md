# Feuille de route

L'avancement se lit dans les
[milestones GitHub](https://github.com/yakohhhh/amnesia/milestones) : elles
seules font foi, avec leurs issues. Ce document n'en garde que la vision,
milestone par milestone, sans recopier la liste des issues.

Les milestones sont déclarées dans
[`.github/milestones.yml`](../.github/milestones.yml) et appliquées sur GitHub
par `scripts/sync_github.py` ([`dev/github.md`](dev/github.md)). La version du
paquet que livre chacune est fixée par
[`RELEASING.md`](RELEASING.md#milestones-et-versions).

## M0 — Scaffold

[Milestone GitHub](https://github.com/yakohhhh/amnesia/milestone/1) · version 0.1.0

Le socle, sans aucun check évalué : outillage et CI, modèle des checks et des
faits, moteur d'audit, rapport JSON versionné, rendus texte et Markdown,
commande `audit` avec ses codes de sortie, écriture protégée du rapport,
fonctionnement hors ligne. Il se clôt par le choix du nom définitif du projet
et la première publication sur PyPI.

## M1 — MVP (Windows + AD)

[Milestone GitHub](https://github.com/yakohhhh/amnesia/milestone/2) · version 0.2.0

Le premier audit utile : collecte en lecture seule des hôtes Windows (locale,
distante par WinRM, ou hors ligne par un collecteur PowerShell et son bundle),
checks Windows et Active Directory, périmètre autorisé vérifié avant toute
connexion, et rapport des angles morts lisible par un client (HTML, résumé
exécutif, plan d'action).

## M2 — Cloud

[Milestone GitHub](https://github.com/yakohhhh/amnesia/milestone/3) · version 0.3.0

La télémétrie hors du parc Windows : rétention et activation des journaux
Microsoft 365 et Entra ID, AWS CloudTrail, et vérification que les événements
arrivent vraiment dans le SIEM (forwarding, trous et latence d'ingestion).

## M3 — Linux & virtualisation

[Milestone GitHub](https://github.com/yakohhhh/amnesia/milestone/6) · version 0.4.0

Les cibles Linux et la virtualisation : collecte par SSH ou par un collecteur
POSIX hors ligne, journalisation système (journald, rsyslog, logrotate),
auditd, vSphere (vCenter et ESXi).

## Offre v0 — prestation pilote

[Milestone GitHub](https://github.com/yakohhhh/amnesia/milestone/5) · sans version du paquet

La piste commerciale et juridique du premier diagnostic payant :
positionnement, offre, cadre contractuel, méthodologie de mission et pilote
client. Son calendrier est propre et dépend du livrable du M1.

## Backlog

[Milestone GitHub](https://github.com/yakohhhh/amnesia/milestone/4) · sans version du paquet

Ce qui n'est pas planifié. Un ticket rejoint une milestone versionnée avant
d'être livré.
