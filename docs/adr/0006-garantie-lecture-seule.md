# 0006. Garantie de lecture seule

- Statut : accepté
- Date : 2026-10-29
- Décideurs : mainteneur
- Tickets : #27, #39, #37, #64

## Contexte et problème

amnesia se connecte avec des identifiants privilégiés à des contrôleurs de
domaine, des serveurs et des tenants cloud de clients, parfois déjà compromis.
Le README promet « lecture seule, sur un périmètre que tu es autorisé à
auditer ». Le modèle de menace (#27) retient la modification accidentelle d'une
cible par une erreur de code ou d'usage (M11) et l'audit d'une cible hors
mandat (M10). Une promesse dans un README ne vaut rien sans mécanisme : il faut
décider où la garantie s'applique et comment on la vérifie.

## Facteurs de décision

- la garantie doit tenir contre un bug d'amnesia, pas seulement contre une
  intention ; contre du code qui s'exécute dans le processus d'amnesia (check
  tiers, #149, ou dépendance compromise), seule une contrainte côté cible
  tient ;
- elle doit être vérifiable en CI, sur chaque PR ;
- elle doit rester vraie pour chaque transport (local, WinRM, SSH, cloud) ;
- un mandat écrit (H2) fixe le périmètre : la lecture seule s'entend sur ce
  périmètre, et nulle part ailleurs.

## Options envisagées

1. **Garantie en couches** : les checks ne joignent jamais la cible (fonctions
   pures, [ADR 0004](0004-separation-collecte-evaluation.md)) ; seuls les
   collecteurs exécutent des opérations, tirées d'une **allowlist** de
   commandes et d'API de lecture testée en CI (#39) ; côté cible, un endpoint
   contraint sans commande libre quand le transport le permet (JEA pour WinRM,
   #64) ; un fichier de périmètre vérifié avant toute connexion (#37).
2. Une revue de code attentive et une règle écrite dans `CONTRIBUTING.md`.
3. Un compte d'audit à droits réduits côté client, et rien dans l'outil.

## Décision

Option 1. La garantie est **structurelle** et se cumule :

1. un check ne reçoit que des faits : il n'a ni connexion, ni processus, ni
   fichier. Pour les checks du dépôt, `tests/test_architecture.py` le vérifie
   par une liste blanche : modules de calcul de la bibliothèque standard,
   noms publics de `amnesia.checks.base`, `amnesia.checks.registry` et
   `amnesia.target`, et aucun appel à `open`, `__import__`, `exec`, `eval`,
   `compile` ni `breakpoint` (détail dans `docs/architecture.md`). C'est un
   garde-fou contre l'erreur, **pas une isolation** : un check tiers (#149),
   installé hors du dépôt, n'est jamais analysé, et du code malveillant garde
   tous les droits de Python dans le processus d'amnesia ;
2. un collecteur n'exécute que des opérations de l'allowlist de #39, qui
   lisent sans rien écrire sur la cible (`Get-WinEvent -Oldest`, lecture de
   registre, `Get-ItemProperty`, API `AuditQuerySystemPolicy` pour la
   politique d'audit...), jamais `shell=True`, toujours avec un délai ; une
   opération absente de l'allowlist est un échec de test, pas un
   avertissement ;
3. quand la cible le permet, l'exécution est contrainte côté cible (endpoint
   JEA pour WinRM, #64 ; rôle en lecture seule pour le cloud, #95) : même un
   amnesia bogué ou compromis ne peut pas écrire ;
4. aucune connexion hors du périmètre autorisé (#37), vérifié sur la forme
   normalisée de la cible avant tout accès.

Une opération d'écriture n'entre jamais dans l'allowlist, même « inoffensive »
(création d'un fichier temporaire sur la cible, par exemple). Une commande qui
ne lit qu'en écrivant en est une : `auditpol /backup /file:<fichier>` écrit la
politique d'audit dans un fichier CSV sur la cible, ce qui modifie la cible
(M11) et ouvre une course sur un répertoire partagé d'une cible peut-être
compromise (H4). En ligne, la politique d'audit se lit donc par une source qui
n'écrit rien et ne dépend pas de la langue : l'API `AuditQuerySystemPolicy`,
qui donne une valeur numérique par GUID de sous-catégorie. Le collecteur hors
ligne (#48), lui, s'exécute sous le contrôle de l'administrateur du client, pas
d'amnesia : ce qu'il écrit sur l'hôte (son bundle) relève de cet
administrateur.

Mise en œuvre du point 2 (#39) : l'allowlist est le registre
`ALLOWED_OPERATIONS` de `amnesia.readonly`, source unique dont
[`docs/READ-ONLY.md`](../READ-ONLY.md) est généré. Tout ce qui en sort est
refusé avant exécution par `ReadOnlyViolation` :

- un exécutable n'est lancé que par son chemin complet, sous une forme
  d'arguments figée (`wevtutil.exe gl <canal>`, jamais `wevtutil cl`) ;
- un script PowerShell vit dans `src/amnesia/ps/`, est inscrit au registre
  avec son empreinte SHA-256, et la CI analyse son AST : commande, alias,
  méthode .NET ou type hors allowlist (une conversion `[Type]$valeur` appelle
  un constructeur), paramètre qui joint un autre hôte, affectation à une
  propriété ou redirection vers un fichier font échouer le test ;
- une connexion LDAP est enveloppée (bind et search seulement) ; un client
  AWS ou HTTP reçoit une garde qui refuse l'opération avant tout envoi.

Pour AWS et HTTP, la règle admet les lectures par préfixe (`Get*`, `List*`,
`Describe*`) ou par verbe (`GET`), puis retire celles qui renvoient un secret
ou du contenu, émettent des identifiants ou lancent une recherche
(`AWS_DENIED`, `HTTP_DENIED`). Une liste de refus est incomplète par nature :
chaque collecteur cloud (#95, #112, #113) remplacera la règle large de son
API par les services et les endpoints qu'il nomme.

Être en lecture seule ne suffit pas à faire une bonne source : la commande
`auditpol.exe /get /category:* /r` est dans l'allowlist parce qu'elle n'écrit
rien, mais ses libellés sont traduits, et la règle « aucune analyse de
texte localisé » de [`docs/dev/faits.md`](../dev/faits.md) continue de
s'appliquer à ce qu'un collecteur en lit.

Trois opérations ne modifient aucune configuration mais laissent un objet
ou consomment un quota chez le client (requête sur le journal d'audit
unifié de Microsoft Graph, job de recherche Splunk, `sts:AssumeRole`) :
elles sont nommées, refusées par défaut, et ne passent qu'avec un opt-in
explicite de l'auditeur, une par une.

Contre un amnesia compromis ou un check tiers malveillant, les points 1 et 2
ne valent rien, puisqu'ils sont du code dans le même processus : seuls le
point 3 (contrainte côté cible) et un compte d'audit à droits réduits
tiennent. Installer un check tiers, c'est lui confier les droits de
l'auditeur.

Les options 2 et 3 ne sont pas rejetées, elles s'ajoutent : la revue reste
nécessaire, et le compte d'audit à droits réduits est recommandé dans le guide
d'exploitation (#82). Aucune des deux ne suffit seule.

### Conséquences

- Bien : la lecture seule est une propriété du code d'amnesia, testée, et
  non une promesse ; contre du code hostile dans le processus, elle repose sur
  la contrainte côté cible (JEA, rôle en lecture seule), que le client peut
  vérifier sans lire le code.
- Bien : l'allowlist documente, commande par commande, ce qu'amnesia fait sur
  une cible : un client peut la relire avant de donner un accès.
- Mal : le garde-fou des checks est statique ; il ne couvre ni les checks
  tiers (#149) ni le code malveillant, et le dire évite qu'un client ou un
  relecteur croie à une isolation qui n'existe pas.
- Mal : certaines mesures utiles sont interdites (lancer `gpupdate`, créer un
  événement de test pour vérifier qu'un pipeline SIEM fonctionne) ; le check
  « pipeline » devra observer sans émettre, ou documenter une procédure
  manuelle.
- Mal : l'allowlist doit être tenue à chaque nouveau fait collecté ; la CI le
  rappelle.

### Confirmation

- `tests/test_architecture.py` : un module de `amnesia.checks.<domaine>`
  n'importe que la liste blanche (ni `subprocess`, `socket`, `os`, `pathlib`,
  `io`, `tempfile`, `importlib`, ni collecteur, ni nom réexporté par
  `amnesia.checks.base`) et n'appelle ni `open` ni `exec` ; un module piège
  vérifie que les contournements connus sont vus.
- `tests/test_regles_ruff.py` : règles S602, S604, S605 (`shell=True`) et S607
  (programme sans chemin complet) actives sur `src/`.
- `tests/unit/test_readonly.py` (#39) : chaque forme de l'allowlist passe,
  chaque écriture connue est refusée sans requête ni processus ; dans
  `amnesia.facts`, un processus ne se lance que par `run_command()` ;
  `docs/READ-ONLY.md` est à jour.
- `tests/integration/test_scripts_powershell.py` (#39) : `pwsh` analyse l'AST
  des scripts ; ignoré sans `pwsh` sur un poste, en échec sans lui sur la CI.
- Modèle de PR : case « Lecture seule respectée ».

## Avantages et inconvénients des options

### Option 1 : garantie en couches

- Bien : tient contre un bug, vérifiable en CI, lisible par le client.
- Mal : contraint les checks ; allowlist à tenir.

### Option 2 : revue et règle écrite

- Bien : aucun coût technique.
- Mal : une faute d'inattention suffit ; invérifiable par le client.

### Option 3 : compte à droits réduits seulement

- Bien : protège même contre un amnesia compromis.
- Mal : dépend de chaque client ; la lecture du journal Security exige déjà
  des privilèges élevés ; ne protège pas contre une cible hors mandat.

## Pour aller plus loin

- [`docs/threat-model.md`](../threat-model.md) : M10, M11, hypothèse H2.
- [`docs/READ-ONLY.md`](../READ-ONLY.md) : l'allowlist, opération par
  opération.
- [`docs/dev/faits.md`](../dev/faits.md) : règles pour tout collecteur.
- [ADR 0007](0007-transports.md) : ce que chaque transport permet de
  contraindre côté cible.
