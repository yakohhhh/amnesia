# Périmètre autorisé

amnesia ne s'utilise que sur un périmètre couvert par une autorisation écrite
du propriétaire du système. Cette page décrit comment déclarer ce périmètre,
comment il est contrôlé avant toute collecte, et ce que le rapport en retient.

## Cadre légal

Le fait d'accéder ou de se maintenir, frauduleusement, dans tout ou partie d'un
système de traitement automatisé de données est puni de trois ans
d'emprisonnement et de 100 000 € d'amende
([article 323-1 du Code pénal](https://www.legifrance.gouv.fr/codes/id/LEGISCTA000006149839),
modifié par la loi n° 2023-22 du 24 janvier 2023). La peine est de cinq ans
d'emprisonnement et de 150 000 € d'amende lorsqu'il en est résulté la
suppression ou la modification de données contenues dans le système, ou une
altération de son fonctionnement.

Une faute de frappe sur `--target` (filiale non couverte, autre client d'un
prestataire) suffit à ouvrir un accès hors mandat. L'infraction suppose
l'intention, mais un tel accès engage au minimum la responsabilité
contractuelle de l'auditeur, et s'y maintenir en connaissance de cause peut
constituer un maintien frauduleux. L'auditeur doit aussi pouvoir prouver son
autorisation : lettre de mission, signataire, dates.

**Prestataires de services managés (MSP)** : un accès délégué ne vaut pas
mandat d'audit. Une relation GDAP sur le tenant Microsoft d'un client, un rôle
cross-account sur son compte AWS ou un agent de supervision installé sur ses
machines donnent un accès technique pour un service convenu ; un audit demande
une autorisation écrite qui le nomme, avec son périmètre et sa période.

Ce contrôle est un garde-fou technique, pas un avis juridique : il ne remplace
ni la lettre de mission ni sa relecture. Le modèle d'autorisation et le kit
contractuel relèvent de #89.

## Déclarer le périmètre

Deux emplacements, un seul schéma :

- la section `[scope]` du fichier de mission ([`mission.md`](mission.md)) ;
- un fichier séparé, désigné par `--scope FICHIER`, qui ne contient que cette
  section.

Les deux à la fois sont refusés (code 2), comme une surcharge `--set scope.…` :
une autorisation ne s'élargit pas sur la ligne de commande.

Le périmètre d'un `amnesia.toml` trouvé dans le répertoire courant, sans
`--config`, s'applique comme le reste de ce fichier : avec l'avertissement et
les refus décrits dans [`mission.md`](mission.md), et le rapport dit d'où vient
le fichier (`run.config_source`). Désigner le fichier (`--config`, `--scope`)
lève le doute.

```toml
[scope]
mission_id = "MISSION-0001"
valid_from = 2026-01-12
valid_until = 2026-01-16
active_tests = false

[scope.authorization]
reference = "LM-2026-001"
date = 2026-01-05
signatory = "Prénom Nom"
signatory_role = "RSSI"

[scope.include]
hosts = ["srv01.corp.example", "192.0.2.10"]
dns = ["*.corp.example"]
ad_domains = ["corp.example"]
cidrs = ["192.0.2.0/24", "2001:db8::/32"]
entra_tenants = ["00000000-0000-4000-8000-000000000000"]
aws_accounts = ["000000000000"]

[scope.exclude]
hosts = ["srv02.corp.example"]
cidrs = ["192.0.2.128/25"]
```

| Clé | Type | Contenu |
| --- | --- | --- |
| `scope.mission_id` | chaîne, obligatoire | Identifiant de la mission. |
| `scope.valid_from` | date, obligatoire | Premier jour où l'audit est autorisé. |
| `scope.valid_until` | date, obligatoire | Dernier jour autorisé, inclus ; jamais avant `valid_from`. |
| `scope.active_tests` | booléen, défaut `false` | Verrou des tests actifs (#155) : aucun check n'en fait aujourd'hui. |
| `scope.authorization.reference` | chaîne, obligatoire | Référence de l'autorisation écrite (lettre de mission). |
| `scope.authorization.date` | date, obligatoire | Date de l'autorisation ; jamais après `valid_from`. |
| `scope.authorization.signatory` | chaîne, obligatoire | Nom du signataire. |
| `scope.authorization.signatory_role` | chaîne, obligatoire | Fonction du signataire. |
| `scope.include` | table, obligatoire | Inclusions, au moins une. |
| `scope.exclude` | table | Exclusions, prioritaires sur toute inclusion. |

`include` et `exclude` acceptent les mêmes types, chacun un tableau de chaînes :

| Type | Contenu | Exemple |
| --- | --- | --- |
| `hosts` | Noms d'hôte ou adresses IP exacts. | `"srv01.corp.example"`, `"192.0.2.10"` |
| `dns` | Motifs `*.domaine` : un seul label en inclusion, toute profondeur en exclusion. | `"*.corp.example"` |
| `ad_domains` | Domaines Active Directory. | `"corp.example"` |
| `cidrs` | Plages IPv4 ou IPv6, sans bit d'hôte. | `"192.0.2.0/24"` |
| `entra_tenants` | GUID de tenants Entra. | `"00000000-0000-4000-8000-000000000000"` |
| `aws_accounts` | Identifiants de comptes AWS, 12 chiffres entre guillemets. | `"000000000000"` |

Validation stricte, comme pour le reste du fichier de mission : une clé
inconnue, une clé obligatoire absente, une date qui n'est pas ISO 8601, un
motif mal formé, une plage avec des bits d'hôte (`10.0.1.7/16`) ou une plage
qui couvre toutes les adresses (`0.0.0.0/0`) arrêtent la commande avec le
code 2. Les textes suivent les règles de [`mission.md`](mission.md) : 200
caractères au plus, aucun caractère de contrôle, rien qui ressemble à un
secret.

`amnesia config show` (avec `--scope` ou `--config` si besoin) affiche le
périmètre lu et son condensat `scope.sha256`, sans lancer d'audit.

## Contrôle avant toute collecte

`amnesia audit` vérifie le périmètre juste après avoir lu la configuration,
avant de lire un mot de passe, de créer le dossier des livrables ou de joindre
la cible. Un refus se termine avec le **code de sortie 5** : aucune connexion
n'a été ouverte, aucun rapport n'est écrit, et le motif est donné sur stderr.

Règle générale : en cas de doute, la cible est refusée.

- **Période** : la date du jour doit être entre `valid_from` et `valid_until`,
  bornes comprises. Aux bornes, la date du poste et la date UTC peuvent
  différer : les deux doivent être dans la période.
- **Forme normalisée** : la cible est comparée sous la forme que
  `--target` lui donne (minuscules, sans point final, IPv6 canonique). Le
  port ne compte pas.
- **Exclusions** : une cible exclue est refusée, quelles que soient les
  inclusions.
- **Noms** : `hosts` compare le nom exact. En inclusion, `*.corp.example`
  couvre exactement un label, comme dans un certificat : `srv01.corp.example`,
  mais ni `corp.example` ni `srv01.filiale.corp.example` (une filiale se
  déclare par son propre motif), et `ad_domains` couvre le nom du domaine et
  ses hôtes directs. En exclusion, les mêmes règles couvrent toute la
  profondeur : exclure `*.filiale.corp.example` ou le domaine
  `filiale.corp.example` écarte aussi `srv01.paris.filiale.corp.example`.
- **Adresses** : une cible désignée par une adresse IP doit appartenir à une
  plage de `cidrs` ou figurer dans `hosts`. Elle n'est jamais comparée aux
  noms : aucune résolution inverse n'est faite.
- **Nom et plages** : quand seule une plage peut couvrir une cible désignée
  par un nom, ou quand des exclusions portent sur des adresses, le nom doit
  être résolu, et **toutes** ses adresses doivent être incluses, aucune
  exclue. Une seule adresse hors des plages suffit au refus.
- **Machine locale** : la cible `local` est désignée par le nom de la machine
  (celui que rend le système, sans résolution), comparé comme tout autre nom.
- **Tenants et comptes** : les cibles cloud (#95) seront comparées à
  `entra_tenants` et `aws_accounts`.
- **Bundle** : `bundle:<chemin>` relit une collecte déjà faite. Aucun système
  n'est joint, aucun contrôle n'est appliqué ; le rapport le note
  (`scope.basis` vaut `offline`).

Limites à connaître :

- amnesia ne résout encore aucun nom : hors des collecteurs, le code n'ouvre
  aucune connexion, résolution DNS comprise, et le collecteur WinRM n'existe
  pas (#63). Une cible désignée par un nom que seule une plage pourrait
  couvrir, ou un périmètre dont les exclusions portent sur des adresses, donne
  donc un refus : désigner la cible par son adresse IP, ou déclarer son nom
  dans `include.hosts` et des exclusions par nom ;
- une exclusion par nom ne couvre pas la même machine désignée par son
  adresse, et inversement : exclure une machine par son nom **et** par son
  adresse ;
- le nom d'une machine locale hors de la grammaire des noms d'hôte (tiret bas
  d'un nom NetBIOS) ne peut pas être comparé : la cible est refusée.

## Sans périmètre

Aucun périmètre déclaré ne veut pas dire audit libre :

- **au terminal**, `amnesia audit` affiche la cible et demande de ressaisir
  son nom exact (l'hôte d'une cible distante, `local` pour la machine
  locale) ; une autre saisie est un refus ;
- **hors terminal** (CI, RMM, tâche planifiée, entrée ou sortie d'erreur
  redirigée), l'option `--authorized-by "<référence de la lettre de mission>"`
  est obligatoire, sinon l'audit est refusé.

`--authorized-by` déclare une référence, il ne vérifie rien : la cible n'est
comparée à aucun périmètre, ce qu'un avertissement rappelle à chaque audit.
Avec un périmètre déclaré, l'option est refusée (code 2) : la référence du
périmètre fait foi.

```bash
amnesia audit --target winrm://srv01.corp.example --scope perimetre.toml
amnesia audit --authorized-by "LM-2026-001"
```

## Trace dans le rapport

Le rapport JSON recopie la base d'autorisation dans `scope`
([`format-rapport.md`](format-rapport.md)) : `basis` (`scope`,
`authorized-by`, `confirmation` ou `offline`), `mission_id`, la référence et
la date de l'autorisation, la période, les inclusions, les exclusions et
`sha256`. Le nom du signataire n'y figure pas : il reste dans le fichier de
périmètre, que `sha256` identifie.

`scope.sha256` est le SHA-256 du JSON canonique du périmètre déclaré, signataire
compris (clés triées, sans espace, UTF-8, dates ISO 8601, entrées normalisées
et triées). Le même périmètre a le même condensat qu'il soit déclaré dans le
fichier de mission ou dans un fichier séparé, quels que soient les
commentaires et l'ordre des entrées. Il ne fait pas partie de `config_hash`.

La décision est aussi journalisée (`-v` pour un périmètre vérifié, toujours
pour un refus ou pour `--authorized-by`). Le journal d'exécution chaîné (#40)
la reprendra.

## Codes de sortie

| Situation | Code |
| --- | --- |
| Fichier de périmètre illisible ou mal formé, deux périmètres déclarés, `--authorized-by` avec un périmètre | 2 |
| Cible hors périmètre ou exclue, périmètre expiré ou pas encore valide, nom impossible à résoudre, aucune autorisation hors terminal, confirmation refusée | 5 |
