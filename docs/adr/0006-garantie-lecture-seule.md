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

- la garantie doit tenir même contre un bug d'amnesia ou d'un check tiers
  (#149), pas seulement contre une intention ;
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

1. un check ne peut pas écrire sur la cible : il n'a ni connexion, ni
   processus, ni fichier, et la table des dépendances de
   `docs/architecture.md` interdit à un module de check d'importer un module
   d'I/O ou un collecteur ;
2. un collecteur n'exécute que des opérations de l'allowlist de #39 (lecture de
   configuration : `auditpol /backup`, `Get-WinEvent -Oldest`, lecture de
   registre, `Get-ItemProperty`...), jamais `shell=True`, toujours avec un
   délai ; une opération absente de l'allowlist est un échec de test, pas un
   avertissement ;
3. quand la cible le permet, l'exécution est contrainte côté cible (endpoint
   JEA pour WinRM, #64 ; rôle en lecture seule pour le cloud, #95) : même un
   amnesia bogué ou compromis ne peut pas écrire ;
4. aucune connexion hors du périmètre autorisé (#37), vérifié sur la forme
   normalisée de la cible avant tout accès.

Une opération d'écriture n'entre jamais dans l'allowlist, même « inoffensive »
(création d'un fichier temporaire sur la cible, par exemple) : le collecteur
hors ligne (#48) s'exécute sous le contrôle de l'administrateur du client, pas
d'amnesia.

Les options 2 et 3 ne sont pas rejetées, elles s'ajoutent : la revue reste
nécessaire, et le compte d'audit à droits réduits est recommandé dans le guide
d'exploitation (#82). Aucune des deux ne suffit seule.

### Conséquences

- Bien : la lecture seule est une propriété du code, testée, et non une
  promesse ; un check tiers hérite de la garantie sans effort.
- Bien : l'allowlist documente, commande par commande, ce qu'amnesia fait sur
  une cible : un client peut la relire avant de donner un accès.
- Mal : certaines mesures utiles sont interdites (lancer `gpupdate`, créer un
  événement de test pour vérifier qu'un pipeline SIEM fonctionne) ; le check
  « pipeline » devra observer sans émettre, ou documenter une procédure
  manuelle.
- Mal : l'allowlist doit être tenue à chaque nouveau fait collecté ; la CI le
  rappelle.

### Confirmation

- `tests/test_architecture.py` : aucun module de `amnesia.checks.<domaine>`
  n'importe `subprocess`, `socket`, `os`, `pathlib` ni de collecteur.
- `tests/test_regles_ruff.py` : règles S602, S604, S605 (`shell=True`) actives
  sur `src/`.
- #39 : test CI de l'allowlist des opérations des collecteurs.
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
- [`docs/dev/faits.md`](../dev/faits.md) : règles pour tout collecteur.
- [ADR 0007](0007-transports.md) : ce que chaque transport permet de
  contraindre côté cible.
