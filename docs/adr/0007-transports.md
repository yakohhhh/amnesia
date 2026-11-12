# 0007. Transports : WinRM, SSH par le client OpenSSH, bundles hors ligne

- Statut : accepté
- Date : 2026-10-29
- Décideurs : mainteneur
- Tickets : #63, #64, #119, #48, #52

## Contexte et problème

amnesia doit lire la configuration de cibles de trois natures : des hôtes
Windows (postes, serveurs, contrôleurs de domaine), des hôtes Linux, et des
cibles qu'aucun accès réseau ne permet de joindre (réseau isolé, client qui
refuse toute connexion entrante, audit sans compte). Chaque transport ajoute
une surface d'attaque (flux F1, F5 et F6 du modèle de menace), une dépendance
et un mode d'authentification. Il faut choisir lesquels on prend en charge, et
avec quoi.

## Facteurs de décision

- chiffrement et authentification forte par défaut, sans option « en clair » ;
- aucun agent à installer sur la cible : amnesia s'exécute depuis le poste de
  l'auditeur, ou pas du tout ;
- une dépendance de moins vaut mieux qu'une de plus : chaque SDK est une
  surface d'approvisionnement (Z5) et une chose à épingler ;
- la lecture seule doit pouvoir être contrainte côté cible
  ([ADR 0006](0006-garantie-lecture-seule.md)) ;
- le même check doit s'exécuter quel que soit le transport
  ([ADR 0004](0004-separation-collecte-evaluation.md)).

## Options envisagées

Pour Windows :

1. WinRM/PSRP, le transport natif de PowerShell à distance ;
2. SMB et le registre distant (RPC) ;
3. un agent déployé sur chaque hôte.

Pour Linux :

4. SSH par le **client OpenSSH** du poste (`ssh` en sous-processus) ;
5. SSH par une bibliothèque Python (paramiko, asyncssh).

Pour les cibles injoignables :

6. un **collecteur autonome** (script PowerShell, #48) exécuté par
   l'administrateur du client, qui produit un **bundle** JSON audité hors
   ligne (`bundle:<chemin>`, #52) ;
7. pas de mode hors ligne : accès réseau obligatoire.

## Décision

Trois transports, un collecteur chacun, derrière le même protocole
`Collector` :

- **WinRM/PSRP** (option 1, #63) pour les hôtes Windows : HTTPS 5986 avec
  validation du certificat et Kerberos par défaut ; HTTP 5985 seulement avec
  chiffrement des messages, jamais Basic en clair. Il permet un endpoint JEA
  sans commande libre (#64), ce qu'aucune autre option n'offre.
- **SSH par le client OpenSSH** (option 4, #119) pour les hôtes Linux : amnesia
  lance `ssh` en sous-processus (argv en liste, délai, `BatchMode=yes`,
  `StrictHostKeyChecking` strict) et réutilise la configuration, les clés, les
  agents, les hôtes connus et les sauts (`ProxyJump`) déjà en place sur le
  poste de l'auditeur. Aucune bibliothèque SSH n'entre dans les dépendances ;
  OpenSSH est un prérequis du poste, documenté.
- **Bundles hors ligne** (option 6, #48, #52) : un collecteur PowerShell
  autonome, figé et remis avec son SHA-256, exécuté par l'administrateur du
  client avec ses propres droits ; il produit un bundle (`amnesia.facts/1`,
  manifeste, empreintes) que `bundle:<chemin>` audite sans aucune connexion.
  Le mode hors ligne est un transport à part entière, pas un mode dégradé :
  tout check Windows doit s'y exécuter.

Les API cloud (Microsoft Graph, AWS, #95) sont des transports au même titre,
traités dans leur propre ticket : HTTPS avec jeton OAuth 2.0 ou signature SigV4,
rôle en lecture seule, et SDK en extras optionnels.

Un transport s'ajoute par un collecteur et une forme de `--target` ; il ne
touche ni aux checks, ni au moteur, ni au rapport. Chaque transport doit figurer
dans le modèle de menace avant d'être mergé (règle de révision de
`docs/threat-model.md`).

### Conséquences

- Bien : aucun agent, aucune dépendance SSH, et un mode hors ligne qui couvre
  les clients les plus contraints, ceux qui en ont le plus besoin.
- Bien : SSH hérite de tout ce que l'auditeur a déjà configuré (clés
  matérielles, agents, bastions), sans réimplémenter l'authentification.
- Mal : SSH dépend d'un binaire externe et de sa version ; les tests
  d'intégration exigent OpenSSH, et l'analyse de ses erreurs passe par son
  code de sortie et stderr, pas par une API.
- Mal : WinRM apporte un SDK Python à épingler et à surveiller (M21) ; le
  mode hors ligne ajoute un script PowerShell à figer et un format de bundle à
  versionner.
- Mal : trois collecteurs, c'est trois fois les mêmes faits à produire ; le
  vocabulaire des clés de faits (#48) est le contrat qui les tient alignés.

### Confirmation

- `src/amnesia/target.py` : seules les formes `local`, `winrm://`, `bundle:`
  sont acceptées aujourd'hui ; `ssh://` arrivera avec #119.
- `docs/threat-model.md` : flux F1 (WinRM), F5 et F6 (bundle), à compléter
  pour SSH par #119.
- `tests/test_architecture.py` : un collecteur n'importe ni le moteur ni les
  checks de domaine.

## Avantages et inconvénients des options

### Option 1 : WinRM/PSRP

- Bien : natif, Kerberos, HTTPS, JEA ; déjà ouvert dans la plupart des
  domaines.
- Mal : SDK Python tiers ; configuration HTTPS côté client parfois absente.

### Option 2 : SMB et registre distant

- Bien : aucun PowerShell distant.
- Mal : RPC/SMB exposent plus de surface, pas de JEA, et le journal des
  événements ou `auditpol` ne se lisent pas ainsi sans commande distante.

### Option 3 : agent sur la cible

- Bien : collecte riche et continue.
- Mal : déploiement et mise à jour chez chaque client, surface d'attaque
  permanente, incompatible avec un audit ponctuel.

### Option 4 : client OpenSSH

- Bien : aucune dépendance, authentification et bastions déjà en place,
  comportement connu des auditeurs.
- Mal : binaire externe, sortie à analyser, tests d'intégration plus lourds.

### Option 5 : bibliothèque SSH Python

- Bien : API, tests unitaires faciles.
- Mal : dépendance à épingler et à auditer, réimplémentation de l'agent, des
  clés matérielles, des `ProxyJump` et des hôtes connus ; une bibliothèque
  SSH est une cible privilégiée d'attaque de la chaîne d'approvisionnement.

### Option 6 : collecteur autonome et bundle

- Bien : aucun accès réseau ni compte à fournir à amnesia ; exécution sous le
  contrôle de l'admin du client ; moins d'exposition à une cible compromise
  (RR7).
- Mal : script à figer et à vérifier (SHA-256) ; bundle à transporter et à
  vérifier (empreintes) ; décalage entre la collecte et l'audit.

### Option 7 : pas de mode hors ligne

- Bien : un transport de moins.
- Mal : exclut les clients les plus contraints.

## Pour aller plus loin

- [`docs/threat-model.md`](../threat-model.md) : flux F1, F5, F6 ; menaces
  liées aux transports.
- [`docs/dev/faits.md`](../dev/faits.md) : règles pour tout collecteur.
- [ADR 0006](0006-garantie-lecture-seule.md) : ce que chaque transport
  contraint côté cible.
