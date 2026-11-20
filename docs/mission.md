# Fichier de mission `amnesia.toml`

Un audit se décrit dans un fichier plutôt qu'en options de ligne de commande :
le client, la référence, l'auditeur, les dates, le marquage TLP, le profil, la
langue et les seuils des checks. Le rapport en garde la trace (`mission`,
`run.profile`, `config_hash` : [`format-rapport.md`](format-rapport.md)), et le
même fichier redonne le même audit.

```bash
amnesia init                 # écrit ./amnesia.toml, chaque clé commentée
amnesia config show          # configuration effective et origine des valeurs
amnesia audit                # lit ./amnesia.toml s'il existe
amnesia audit --config missions/exemple.toml --lang en \
    --set thresholds.security_log_min_retention_days=180
```

## Emplacement

`--config FICHIER`, sinon `amnesia.toml` dans le répertoire courant s'il existe,
sinon les seules valeurs par défaut. `amnesia init [FICHIER]` écrit l'exemple en
0600 (le fichier nomme le client) et n'écrase rien sans `--overwrite`.

Le fichier trouvé dans le répertoire courant est appliqué sans avoir été
désigné : un tiers qui peut écrire dans ce répertoire pourrait y poser un
marquage `TLP:CLEAR` ou des seuils au minimum. Trois garde-fous :

- un avertissement sur stderr, visible sans `-v`, à chaque commande qui
  l'applique ; `--config amnesia.toml` le désigne et fait taire
  l'avertissement ;
- ce fichier est refusé (code 2) s'il est un lien symbolique, s'il appartient
  à un autre compte ou si le groupe ou les autres comptes peuvent l'écrire
  (`chmod go-w amnesia.toml`). Sous Windows, où ces droits ne se lisent pas
  dans le mode du fichier, seul le lien est refusé ;
- le rapport dit d'où vient le fichier (`run.config_source` : `cwd` ou
  `--config`), et son `config_hash` change dès qu'une valeur effective change.

Un fichier désigné par `--config` n'est soumis à aucun de ces refus.

## Clés

| Clé | Type | Défaut | Contenu |
| --- | --- | --- | --- |
| `profile` | chaîne | aucun | Nom du profil retenu (minuscules, chiffres, `-`, `_`). Le contenu des profils relève de #47 : le nom est seulement reporté dans le rapport. |
| `mission.client` | chaîne | aucun | Client audité. |
| `mission.reference` | chaîne | aucun | Référence de la mission. |
| `mission.auditor` | chaîne | aucun | Auditeur ou équipe. |
| `mission.start` | date | aucun | Début, ISO 8601 (`2026-01-12`, date TOML ou chaîne). |
| `mission.end` | date | aucun | Fin, jamais avant `mission.start`. |
| `mission.tlp` | chaîne | aucun | Marquage TLP 2.0 : `TLP:CLEAR`, `TLP:GREEN`, `TLP:AMBER`, `TLP:AMBER+STRICT` ou `TLP:RED`. `TLP:WHITE` (TLP 1.0) est refusé : il est devenu `TLP:CLEAR`. |
| `report.lang` | chaîne | `fr` | Langue du livrable : `fr` ou `en`. |
| `report.formats` | tableau | `["json"]` | Formats du livrable : `json`, `md`, `text`. |
| `report.output_dir` | chaîne | `amnesia-out` | Dossier des livrables. Dans le fichier : chemin relatif sans `..` (ni chemin absolu, ni lecteur, ni partage UNC) ; un chemin absolu se donne par `--set report.output_dir=CHEMIN`. |
| `thresholds.security_log_min_retention_days` | entier, 1 à 3650 | `90` | Profondeur minimale du journal Security avant écrasement, en jours. |
| `thresholds.ntp_max_offset_seconds` | nombre, 0.001 à 3600 | `5.0` | Écart d'horloge maximal toléré avec la source de temps, en secondes. |

Les chaînes font 200 caractères au plus (1024 pour `report.output_dir`) et ne
contiennent ni caractère de contrôle ou de format (séquences ANSI, contrôles
bidirectionnels), ni saut de ligne ; l'espace insécable est admise.

Une clé de premier niveau (`profile`) s'écrit avant la première section : en
TOML, toute clé qui suit un en-tête `[section]` lui appartient.

La section `[scope]` déclare le périmètre autorisé : identifiant de mission,
autorisation écrite, période de validité, inclusions et exclusions. Elle a sa
propre page, [`perimetre.md`](perimetre.md), et son propre condensat
(`scope.sha256`), hors de `config_hash`. Elle ne se surcharge pas par `--set`,
et peut vivre dans un fichier séparé désigné par `--scope FICHIER`.

`report.lang`, `report.formats` et `report.output_dir` sont validés, affichés
et comptés dans `config_hash`, mais `amnesia audit` ne les applique pas
encore : il écrit toujours le rapport JSON désigné par `--out`, en français.
Les seuils sont remis aux checks (`Context.config["thresholds"]`) ; aucun check
ne les lit tant que les checks Windows ne sont pas évalués.

## Priorité

De la plus forte à la plus faible : ligne de commande (`--lang`,
`--set CLÉ=VALEUR`, répétable), fichier, valeurs par défaut. `amnesia config
show` affiche l'origine de chaque valeur : `cli`, `fichier` ou `défaut`.

## Validation

Toute erreur arrête la commande avec le code 2, avant l'audit, et cite le
chemin de la clé :

- clé inconnue, avec la clé la plus proche en suggestion ;
- type inattendu, date qui n'est pas ISO 8601, `mission.end` avant
  `mission.start`, marquage hors TLP 2.0 ;
- seuil hors bornes ;
- périmètre mal déclaré (clé obligatoire absente, motif ou plage mal formés),
  ou déclaré deux fois ([`perimetre.md`](perimetre.md)) ;
- fichier illisible, trop gros ou mal formé : il est lu par la couche d'analyse
  sûre ([`dev/entrees.md`](dev/entrees.md)).

## Aucun secret

Une clé au nom de secret (`password`, `passwd`, `secret`, `token`, `*_key`…),
dans le fichier comme dans `--set`, arrête la commande avec le code 2 ; sa
valeur n'est jamais affichée. Les secrets passent par les sources de
[`SECRETS.md`](SECRETS.md) : `--password-file`, variable d'environnement,
saisie au terminal.

Les textes libres (`mission.client`, `mission.reference`, `mission.auditor`,
`report.output_dir`) sont recopiés dans le rapport et par `config show` : une
valeur qui ressemble à un secret (`password=…`, `token: …`, identifiants dans
une URL, valeur d'un secret déjà lu) est refusée de la même façon. Ce contrôle
reconnaît des formes, pas tous les secrets : ne mets aucun secret dans ces
champs.

## `config_hash`

SHA-256 du JSON canonique de la configuration effective (clés triées, sans
espace, UTF-8, dates ISO 8601). Deux rapports de même `config_hash` ont été
produits avec la même mission, le même profil et les mêmes seuils, que les
valeurs viennent du fichier ou de la ligne de commande.
