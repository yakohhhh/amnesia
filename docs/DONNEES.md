# Données traitées par amnesia

Inventaire de ce qu'amnesia lit sur une cible, de ce qu'il en garde et de
l'endroit où il l'écrit. Il sert au cabinet ou au MSP qui audite pour le compte
d'un client : en sous-traitant (RGPD, art. 28), il doit décrire précisément ce
qu'il traite, et son client doit pouvoir compléter son registre des traitements
(art. 30).

Ce document décrit le comportement du code ; il ne remplace ni le contrat de
sous-traitance, ni l'analyse du délégué à la protection des données. Les règles
de stockage et de transmission côté auditeur sont dans
[`SECURITY.md`](../SECURITY.md) (« Données manipulées »).

## Règle

**Seules des configurations et des métadonnées de journaux sortent de la cible,
jamais le contenu d'un événement.**

Un événement 4624 porte un compte, un domaine, une adresse IP et un nom de
poste : des données personnelles (art. 4). Estimer la rétention réelle d'un
journal n'exige aucune d'elles. C'est la minimisation (art. 5.1.c), appliquée
dès la conception (art. 25) :

- **filtrage sur la cible** : un script de collecte ne lit d'un événement que
  son horodatage, par exemple
  `(Get-WinEvent -LogName Security -Oldest -MaxEvents 1).TimeCreated` ; seul un
  horodatage est sérialisé ;
- **débit sans énumération** : aucun parcours des événements, coûteux sur un
  contrôleur de domaine ; le débit est estimé par
  `RecordCount / (plus récent - plus ancien)` ;
- **rien de brut sur le disque** : la sortie d'une commande de collecte ne vit
  qu'en mémoire, le temps d'en extraire les faits (section « Sorties brutes »).

Le code qui porte cette règle est `amnesia.privacy` ; chaque liste de cette page
en vient, et un test vérifie qu'elles concordent.

## Inventaire

| Donnée | Source | Finalité | Stockage | Conservation |
|---|---|---|---|---|
| Configuration de journalisation : taille maximale, taille du fichier, nombre d'enregistrements, mode de rétention, journal activé ou non | `Get-WinEvent -ListLog`, registre, `wevtutil gl` | Estimer la profondeur d'historique de chaque journal | Rapport (`gaps[].evidence`) | Celle du rapport |
| Horodatages du plus ancien et du plus récent événement d'un journal | `Get-WinEvent`, propriété `TimeCreated` seule | Mesurer la fenêtre réellement couverte et le débit | Rapport (`gaps[].evidence`) | Celle du rapport |
| Paramètres d'audit : politique d'audit, journalisation PowerShell, Sysmon, synchronisation horaire | `auditpol`, registre, services | Dire quelles questions d'enquête resteront sans réponse | Rapport (`gaps[]`, `results[]`) | Celle du rapport |
| Noms d'hôtes et FQDN des cibles (`host_name`) | Ligne de commande de l'auditeur | Rattacher chaque constat à la machine concernée | Rapport (`targets[].id`, `results[].target`, `gaps[].target`), journal d'exécution | Celle du rapport et du journal |
| Comptes d'administration utilisés ou cités (`admin_account`) | Identifiants fournis par l'auditeur, configuration lue | Tracer le compte qui a servi à la collecte ; désigner le compte qu'une remédiation concerne | Journal d'exécution ; rapport seulement si une configuration le cite | Celle du journal et du rapport |
| Compte local de l'auditeur (`operator_account`) | Poste de l'auditeur | Imputer l'exécution (#40) | Journal d'exécution seulement, jamais le rapport remis au client | Celle du journal |
| Ligne de commande de l'audit | Poste de l'auditeur | Reproduire l'audit | Rapport (`run.argv`), secrets et chemins masqués | Celle du rapport |
| Diagnostics d'un check qui n'a pas conclu | amnesia | Expliquer pourquoi un point n'a pas été évalué | Rapport (`results[].message`, `results[].error`), journal | Celle du rapport et du journal |
| Sorties brutes des commandes de collecte | Cible | Diagnostic d'un collecteur, sur demande explicite | Aucun par défaut ; `amnesia-out/raw/` avec `--keep-raw` | À supprimer dès la fin de l'analyse |

amnesia ne supprime aucun fichier de lui-même : la durée de conservation du
rapport et du journal est celle que fixe le contrat entre l'auditeur et son
client.

État : aucun collecteur ne joint encore une cible (collecteur PowerShell : #48 ;
journal d'exécution : #40 ; collecteurs cloud : #95). Les sources ci-dessus
décrivent ce que ces collecteurs auront le droit de lire ; les contrôles de
cette page s'appliquent déjà à tout fait, à toute preuve et à tout script.

## Données personnelles admises

Trois catégories, et aucune autre :

| Champ | Donnée | Finalité | Où |
|---|---|---|---|
| `host_name` | Noms d'hôtes et FQDN des cibles auditées | Rattacher chaque constat à la machine concernée | Rapport, journal d'exécution |
| `admin_account` | UPN ou noms des comptes d'administration utilisés ou cités par une configuration | Tracer le compte qui a servi à la collecte, désigner le compte qu'une remédiation concerne | Journal d'exécution ; rapport seulement si une configuration le cite |
| `operator_account` | Compte local de l'auditeur qui a lancé l'audit | Imputer l'exécution dans le journal d'exécution (#40) | Journal d'exécution seulement, jamais le rapport |

Le nom du compte de l'auditeur est exclu du rapport client : celui-ci ne porte
ni ce compte, ni l'arborescence de son poste.

## Ce qui ne sort jamais de la cible

Propriétés d'un événement qu'aucun script de collecte ne lit ni ne nomme :
`Message`, `Properties`, `UserId`, `MachineName`. Les méthodes qui rendent le
contenu entier d'un événement (`ToXml`, `FormatDescription`) sont refusées de
la même façon.

Champs d'`EventData` : `EventData`, `UserData`, `TargetUserName`,
`TargetDomainName`, `TargetUserSid`, `TargetLogonId`, `SubjectUserName`,
`SubjectDomainName`, `SubjectUserSid`, `SubjectLogonId`, `IpAddress`, `IpPort`,
`WorkstationName`.

Trois contrôles, indépendants :

1. **Scripts PowerShell.** `amnesia.privacy.check_script_privacy` juge l'AST de
   chaque script de `src/amnesia/ps/`, dressé par `scripts/inventaire_ps.ps1`
   et rejoué en CI sous Linux et Windows. Sont refusés : toute référence à une
   des quatre propriétés (accès `.Message`, nom passé à `Select-Object`), une
   propriété au nom calculé à l'exécution, et tout résultat de `Get-WinEvent`
   qui n'est pas projeté aussitôt, par une propriété unique
   (`(Get-WinEvent ...).TimeCreated`) ou par
   `Select-Object -Property <noms>` à noms constants, sans joker. La
   projection suit une liste fermée, pas une liste noire : seules les
   métadonnées `TimeCreated`, `RecordId`, `Id`, `LogName`, `ProviderName` et
   `Level` sont admises. Toute autre propriété est refusée, connue ou non :
   `(Get-WinEvent ...).PSObject.BaseObject` rendrait l'événement entier sans
   nommer aucune des quatre propriétés interdites. Un événement rangé dans une
   variable est refusé de même : l'analyse ne suit pas ce qu'elle devient.
   `Get-WinEvent -ListLog` et `-ListProvider` rendent une configuration et ne
   sont pas concernés.
2. **Faits.** Un fait dont la valeur porte une des clés ci-dessus, à n'importe
   quelle profondeur et quelle que soit la casse, est refusé en entier
   (`FactsFormatError`) : un bundle importé ou un collecteur fautif ne fait pas
   entrer un événement dans l'audit. Le check qui l'attendait est en erreur,
   jamais conforme.
3. **Preuves et rapport.** Voir la section suivante.

Aucun message de refus ne reprend la valeur refusée, ni une clé inconnue.

Collecteurs cloud à venir (#95) : pour Microsoft Graph, seul `createdDateTime`
sera sérialisé (`$select` là où l'API le permet), jamais `userPrincipalName`,
`ipAddress` ni `location` d'un journal de connexion ; pour AWS, lecture de
configuration uniquement.

## Preuve d'un angle mort

La preuve d'un Gap (`gaps[].evidence`) suit un schéma fermé : des nombres, des
durées, des horodatages et des noms de paramètres. Une clé absente de la table
est refusée à la construction (`ValueError`), comme une valeur d'une autre
nature que celle déclarée.

| Clé de `details` | Nature | Contenu |
|---|---|---|
| `max_size_bytes` | nombre | Taille maximale du journal (`MaximumSizeInBytes`) |
| `file_size_bytes` | nombre | Taille du fichier du journal (`FileSize`) |
| `record_count` | nombre | Nombre d'enregistrements (`RecordCount`) |
| `log_mode` | paramètre | Mode de rétention (`LogMode` : `Circular`, `AutoBackup`, `Retain`) |
| `oldest_event_utc` | horodatage | Horodatage du plus ancien événement |
| `newest_event_utc` | horodatage | Horodatage du plus récent événement |
| `events_per_day` | nombre | Débit estimé |
| `retention_days` | durée | Durée de conservation configurée, en jours |
| `enabled` | booléen | Journal, stratégie ou service activé ou non |
| `setting` | paramètre | Nom du paramètre en défaut |
| `settings` | liste de paramètres | Noms des paramètres en défaut |
| `channels` | liste de paramètres | Noms des journaux concernés |

`observed` et `expected` portent un nombre, un booléen, un horodatage, un nom
ou une valeur de paramètre, une liste plate de ces valeurs, ou un dictionnaire
aux clés de la table. Un texte y est borné à 256 caractères.

Limite : le schéma ferme les clés et type les valeurs, il ne lit pas le sens
d'un texte court. Qu'un check ne range que des noms de paramètres dans une
valeur de nature « paramètre » reste vérifié en revue, check par check.

Un check qui a besoin d'une nouvelle valeur l'ajoute à
`amnesia.privacy.EVIDENCE_FIELDS` et à cette table, dans la même PR : chaque
donnée nouvelle passe ainsi en revue.

Le rapport entier suit la même logique :
`amnesia.privacy.report_text_violations()` parcourt un rapport JSON et signale
tout champ texte hors de `REPORT_TEXT_FIELDS`. Un test l'applique aux rapports
de référence et à ceux que produit `amnesia audit`.

## Sorties brutes

Par défaut, aucune sortie brute n'est écrite sur le disque, et il n'existe
aucun cache d'un audit à l'autre.

`amnesia audit --keep-raw` est un choix explicite, pour diagnostiquer un
collecteur :

- les sorties vont dans `amnesia-out/raw/`, créé en 0700 (ACL du seul compte
  courant sous Windows), chaque fichier en 0600, le tout ignoré par git ;
- un avertissement est affiché à chaque audit ;
- ces sorties n'entrent jamais dans le rapport ;
- elles peuvent contenir des données personnelles : elles se suppriment dès la
  fin de l'analyse et ne se transmettent pas.

## Hors périmètre

- Pseudonymisation d'un rapport partagé : #144.
- Clauses contractuelles de sous-traitance : #89.
