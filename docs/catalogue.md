# Catalogue des questions d'enquête

amnesia rend la liste des questions auxquelles l'enquête ne pourra pas répondre
le jour de l'incident. Ces questions ne sont pas du texte libre semé dans les
checks : elles forment un **catalogue**, une donnée versionnée embarquée dans le
paquet, que les checks désignent par identifiant. Une même question a ainsi une
seule formulation, un identifiant stable d'un rapport à l'autre, et la liste des
sources de télémétrie qui permettent d'y répondre.

Le catalogue est en TOML pour être relu et corrigé par un analyste DFIR qui
n'écrit pas de Python : aucune ligne de code n'est à toucher pour reformuler une
question ou corriger un Event ID.

- Données : [`src/amnesia/catalog/`](../src/amnesia/catalog/) ;
- code : `amnesia.catalog` (`load_catalog()`, `render_question()`) ;
- commandes : `amnesia catalog list`, `amnesia catalog show <id>`,
  `amnesia catalog validate`.

## Arborescence

```text
src/amnesia/catalog/
├── VERSION                  version CalVer du catalogue (2026.11.0)
├── ids.lock                 identifiants de questions déjà publiés
├── questions/
│   ├── windows.toml         questions Q-WIN-...
│   └── ad.toml              questions Q-AD-...
└── sources/
    ├── windows.toml         sources SRC-...
    └── ad.toml
```

Un fichier par domaine (`windows`, `ad`, puis `m365`, `aws`, `siem` : les
domaines du registre des checks). Un fichier d'un autre nom est refusé.

## Une question

```toml
[[question]]
id = "Q-WIN-RDP-LOGON"
status = "active"
domain = "windows"
theme = "authentication"
roles = ["dc", "server", "workstation"]
severity_default = "high"
text.fr = "Qui s'est connecté en RDP sur {host} il y a {lookback} ?"
why.fr = "Sans trace des ouvertures de session à distance, l'enquête ne peut ni dater l'arrivée de l'attaquant sur l'hôte, ni nommer le compte et le poste source qu'il a utilisés."
sources = [
  "SRC-SEC-4624-T10",
  "SRC-TS-LSM-21-24-25",
]
checks = ["win.audit_policy", "win.event_log_retention"]
references = [
  { kind = "anssi", id = "ANSSI-PB-090", version = "1.1" },
]
```

| Champ | Obligatoire | Contenu |
|---|---|---|
| `id` | oui | `Q-<DOMAINE>-<SUJET>` en majuscules, chiffres et tirets ; le préfixe suit le domaine (`Q-WIN-`, `Q-AD-`). Immuable, jamais réutilisé. |
| `status` | oui | `active` (au moins un check y contribue), `planned` (aucun check pour l'instant) ou `deprecated` (remplacée, voir `replaced_by`). |
| `replaced_by` | si `deprecated` | Identifiant de la question qui la remplace, elle-même non dépréciée. |
| `domain` | oui | Domaine du fichier : `windows`, `ad`... |
| `theme` | oui | `authentication`, `execution`, `persistence`, `lateral_movement`, `exfiltration` ou `anti_forensics` (authentification, exécution, persistance, mouvement latéral, exfiltration, anti-forensic). |
| `roles` | oui | Rôles d'hôte concernés : `dc` (contrôleur de domaine), `server` (serveur), `workstation` (poste). |
| `text.fr` | oui | Gabarit de la question, sur une ligne. Variables : `{host}`, `{lookback}`, `{account}`, `{share}`, sans mise en forme. `text.en` est prévu et reste vide jusqu'à #138. |
| `why.fr` | oui | Ce que l'enquête perd sans réponse. `why.en` : comme `text.en`. |
| `severity_default` | oui | Sévérité par défaut d'un angle mort sur cette question ([`severite.md`](severite.md)). |
| `sources` | oui | Sources de télémétrie **alternatives** : une seule suffit à répondre. Au moins une. |
| `checks` | si `active` | Ids du registre des checks qui contribuent à la question. Vide pour `planned` et `deprecated`. |
| `scenarios` | non | Étiquettes de scénarios, définies par #75. |
| `references` | non | Références (`kind`, `id`, `version`, `url` en `https://`), comme celles d'un Gap. |
| `attack` | non | Réservé à la correspondance ATT&CK (#147) : absent ou vide. |

Toute autre clé est refusée : une faute de frappe (`severity_defaut`) ne passe
pas inaperçue.

## Une source

Une source décrit la télémétrie à produire : un **événement** (`kind =
"event"`) ou un **réglage** de l'hôte (`kind = "setting"`).

```toml
[[source]]
id = "SRC-SEC-4688-CMDLINE"
kind = "event"
title = "Création de processus avec sa ligne de commande"
channel = "Security"
provider = "Microsoft-Windows-Security-Auditing"
event_ids = [4688]
enabled_by_default = false
prerequisites = [
  { kind = "audit_subcategory", guid = "{0CCE922B-69AE-11D9-BED3-505054503030}", name = "Process Creation", success = true },
  { kind = "registry_value", key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit', name = "ProcessCreationIncludeCmdLine_Enabled", value = 1 },
]
```

| Champ | Contenu |
|---|---|
| `id` | `SRC-<...>` en majuscules, chiffres et tirets (`SRC-SEC-4624-T10`). |
| `kind` | `event` ou `setting`. |
| `title` | Libellé court, en français. |
| `channel`, `provider`, `event_ids` | Pour `event` : canal du journal, fournisseur, Event IDs. |
| `filters` | Pour `event`, facultatif : champ de l'événement et valeur attendue (`{ LogonType = 10 }`) ; une liste donne des valeurs alternatives. |
| `setting` | Pour `setting` : le réglage attendu, en clair. |
| `prerequisites` | Ce qui doit être en place pour que la source existe (tableau ci-dessous). |
| `enabled_by_default` | `true` ou `false` : état sur une installation par défaut. Omis tant qu'il n'est pas établi ; les valeurs présentes restent à confirmer sur des hôtes de référence (#50). |

| Prérequis (`kind`) | Champs |
|---|---|
| `audit_subcategory` | `guid` de la sous-catégorie d'audit avancé, entre accolades, `name`, et `success` ou `failure` (au moins l'un des deux à `true`). |
| `registry_value` | `key`, `name`, `value` (chaîne ou entier). Une clé de registre s'écrit entre apostrophes, sans doubler les barres obliques inverses. |
| `channel_enabled` | `channel` : le canal doit être activé (ou exister : Sysmon). |
| `sacl` | `object` : ce qui doit porter une entrée d'audit ; `guids` : droits étendus à auditer, s'il y en a. |

Les identifiants de sources servent de liens à l'intérieur du catalogue. Ils ne
figurent pas encore dans le rapport et ne sont pas consignés dans `ids.lock`.

## Identifiants et versions

Un `question_id` est une surface publique d'amnesia
([`RELEASING.md`](RELEASING.md)) : il figure dans les rapports remis aux clients
et sert à comparer deux audits.

- `ids.lock` liste les identifiants publiés, un par ligne, triés. Une nouvelle
  question s'y ajoute dans la PR qui la crée ;
- un identifiant de `ids.lock` absent des questions fait échouer la validation
  et les tests : **on ne supprime pas une question, on la déprécie**
  (`status = "deprecated"`, `replaced_by = "Q-..."`). Elle reste lisible par
  `amnesia catalog show`, pour qui relit un ancien rapport ;
- `VERSION` suit CalVer, `AAAA.M.N` : année et mois de la modification, puis un
  numéro d'ordre dans le mois, à partir de 0. Elle est recopiée dans
  `tool.catalog_version` du rapport ([`format-rapport.md`](format-rapport.md)).
  Toute PR qui change le contenu du catalogue (question ajoutée ou dépréciée,
  source corrigée, texte reformulé) l'incrémente.

## Lien avec les checks et les Gaps

- Un check déclare les questions auxquelles il contribue dans `question_ids`
  (métadonnées du registre) ; chaque question liste ses checks dans `checks`.
  Le lien est réciproque, et `amnesia catalog validate` refuse tout écart.
- Chaque `Gap` porte un `question_id`, obligatoire. Son texte (`question`) est
  toujours produit par `render_question()`, jamais écrit en dur dans un check :

  ```python
  from amnesia.catalog import render_question

  question = render_question("Q-WIN-RDP-LOGON", host="SRV-FILE", lookback_days=21)
  # "Qui s'est connecté en RDP sur SRV-FILE il y a trois semaines ?"
  ```

- Le moteur lit et valide le catalogue avant le premier check, et refuse
  (`error` / `internal_error`) un résultat dont un Gap cite une question
  inconnue : le rapport n'annonce `tool.catalog_version` que pour des questions
  que ce catalogue définit.
- `tests/unit/test_catalogue_checks.py` analyse le code de
  `src/amnesia/checks/` (AST) : une chaîne littérale passée à `Gap(question=...)`
  ou un identifiant de question absent du catalogue font échouer la suite.

### Rendu d'une question

`render_question(id, host=..., lookback_days=..., account=..., share=...)`
remplace les variables du gabarit. Une variable sans valeur est une erreur ; une
valeur que le gabarit n'emploie pas est ignorée, pour qu'une reformulation ne
casse aucun check. Les valeurs viennent de la cible : elles sont caviardées et
rendues imprimables comme tout texte qui entre dans un résultat.

`lookback_days` (entier, au moins 1) alimente `{lookback}`, écrit en durée
lisible :

| Jours | Rendu |
|---|---|
| 1, 4, 10 | « 1 jour », « 4 jours », « 10 jours » |
| 7, 14, 21 | « une semaine », « deux semaines », « trois semaines » |
| 30, 60, 90 | « un mois », « deux mois », « trois mois » |
| 365, 730 | « un an », « deux ans » |

Un multiple exact de 365, de 30 ou de 7 jours se dit en années, en mois ou en
semaines, le nombre en lettres jusqu'à douze ; le reste se dit en jours.

## Validation

`amnesia catalog validate` relit le catalogue embarqué et son lien avec le
registre des checks. Il rend 0 si tout est cohérent, et le code fatal (4) sinon,
avec une ligne par erreur, qui nomme le fichier, l'entrée et le champ :

```text
catalogue invalide : questions/windows.toml : question n° 3 (Q-WIN-EXPLICIT-CREDS) : sources : source inconnue 'SRC-SEC-9999'
```

Sont refusés, entre autres : un identifiant dupliqué ou mal formé, une source
ou un check inconnus, un GUID mal formé, une question `active` sans check ou
`deprecated` sans `replaced_by`, une variable de gabarit inconnue, une clé
inconnue, un identifiant de `ids.lock` disparu ou une question absente de
`ids.lock`, une `VERSION` qui n'est pas en CalVer. La même validation s'applique
à chaque chargement (`load_catalog()`) : un catalogue invalide n'audite rien.
La suite de tests la rejoue en CI, sous Linux et sous Windows.

## Ajouter ou modifier une question

1. Ajouter les sources manquantes dans `sources/<domaine>.toml`.
2. Ajouter la table `[[question]]` dans `questions/<domaine>.toml`, en
   `status = "planned"` tant qu'aucun check n'y contribue ; ajouter son
   identifiant à `ids.lock`.
3. Si un check y contribue : le citer dans `checks`, passer la question en
   `active`, et ajouter l'identifiant aux `question_ids` du check.
4. Incrémenter `VERSION`, puis lancer `amnesia catalog validate` et la suite de
   tests.
5. CHANGELOG : une entrée si un utilisateur voit le changement (nouvelle
   question, question dépréciée).

Reformuler `text.fr` ne change pas l'identifiant : la question posée doit rester
la même. Une question qui change de sens est une nouvelle question, et
l'ancienne est dépréciée.

## Sources documentaires et licences

Les formulations des questions et des libellés sont originales. Les Event IDs,
canaux, fournisseurs, valeurs de registre et GUID sont des faits techniques,
recoupés avec :

- la documentation publique de Microsoft, dont la spécification
  [MS-GPAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d)
  (GUID des sous-catégories d'audit) et le schéma Active Directory
  ([droits de réplication](https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-all)) ;
- le guide **ANSSI-PB-090**, « Recommandations de sécurité pour la
  journalisation des systèmes Microsoft Windows en environnement Active
  Directory », version 1.1 du 18/07/2022, publié par l'Agence nationale de la
  sécurité des systèmes d'information (ANSSI) sous Licence Ouverte v2.0
  (Etalab), qui autorise la réutilisation sous réserve de mentionner la
  paternité. Les questions qui s'y rattachent le citent dans `references`.

Rien n'est repris de projets dont la licence est incompatible avec celle
d'amnesia (MIT) : ni des scripts Yamato Security EnableWindowsLogSettings
(GPL-3.0), ni des benchmarks CIS (CC BY-NC-SA 4.0). Une contribution au
catalogue respecte la même règle ([`CONTRIBUTING.md`](../CONTRIBUTING.md)).

## Hors périmètre

Le catalogue dit **quelles** questions existent et **quelle** télémétrie y
répond. Viendront ensuite : les seuils et la profondeur d'historique exigée
(#47), l'état « répondable » ou « partiel » de chaque question dans le rapport
(#62), les scénarios (#75), les textes de remédiation (#76), la correspondance
ATT&CK (#147) et la traduction anglaise (#138).
