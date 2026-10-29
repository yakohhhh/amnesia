# Format du rapport JSON (v1)

Le rapport JSON est le contrat machine d'amnesia : les rendus lisibles (#23,
#77), le diff entre deux audits (#142), le scoring (#139), la marque blanche
(#141) et les intégrations MSP le lisent. Il est versionné, validé par un JSON
Schema et déterministe.

- Code : `src/amnesia/report.py`. `build_report(audit, argv=..., check_versions=...)`
  transforme un `AuditResult` (#21) en document ; `dumps_report(rapport)` rend son
  texte JSON.
- Schéma : `src/amnesia/schemas/report-v1.schema.json` (JSON Schema draft
  2020-12), embarqué dans le paquet, lu par `amnesia.report.load_schema()` et
  affiché par `amnesia schema` (octets UTF-8 embarqués, même sortie redirigée
  sous Windows : `amnesia schema > report-v1.schema.json`).
- Exemple complet : en fin de document ; il est validé par le schéma dans les
  tests, comme le golden `tests/golden/report.json`.
- Écriture du fichier (`--out`, permissions) : #24 et #25.

## Déterminisme

Deux sérialisations du même audit sont identiques octet pour octet :

- clés dans un ordre fixe, celui de ce document ;
- `results` trié par `check_id` puis `target` ;
- `gaps` trié par sévérité décroissante (de `critical` à `info`), puis par
  domaine (premier segment de `check_id` : `ad`, `win`...), `check_id` et
  `target` ; les Gaps d'un même résultat sont départagés par question, ressource
  et empreinte (`Gap.sort_key()`) ;
- horodatages RFC 3339 en UTC, suffixe `Z` ;
- UTF-8 sans BOM, `ensure_ascii=False` (accents lisibles), indentation de 2
  espaces, saut de ligne final ;
- caractères de contrôle toujours échappés en `\uXXXX` (voir « Sécurité et
  confidentialité »).

Le golden `tests/golden/report.json` se régénère avec :

```bash
AMNESIA_UPDATE_GOLDEN=1 uv run pytest tests/unit/test_rapport.py
```

Puis relire le diff : tout changement du golden est un changement du format.

## Champs

Tous les champs sont toujours présents ; une valeur absente vaut `null`.

### Racine

| Champ | Type | Contenu |
| --- | --- | --- |
| `schema_version` | chaîne | Version SemVer du format : `1.0.0`. Le schéma v1 accepte toute version `1.x.y`. |
| `tool` | objet | Outil qui a produit le rapport. |
| `run` | objet | Exécution de l'audit. |
| `targets` | tableau | Cibles auditées, au moins une. |
| `results` | tableau | Un résultat par check et par cible, quel que soit son statut. |
| `gaps` | tableau | Angles morts (Gaps v1, #16). |
| `summary` | objet | Comptes dérivés de `results` et de `gaps`. |

### `tool`

| Champ | Type | Contenu |
| --- | --- | --- |
| `name` | chaîne | Toujours `amnesia`. |
| `version` | chaîne | Version d'amnesia qui a mené l'audit (`amnesia.__version__`). |
| `catalog_version` | chaîne ou `null` | Version du catalogue de questions ; `null` tant que le catalogue (#46) n'existe pas. |

### `run`

| Champ | Type | Contenu |
| --- | --- | --- |
| `id` | chaîne | Identifiant de l'exécution, UUID version 4 en minuscules. |
| `started_at` | chaîne | Début de l'audit, RFC 3339 UTC (`2026-10-21T09:30:00Z`). |
| `finished_at` | chaîne | Fin de l'audit, même forme ; fraction de seconde éventuelle (`.250000`). |
| `duration_s` | nombre | Durée de l'audit en secondes (horloge monotone). |
| `complete` | booléen | Vrai si chaque check a été évalué ou exclu par l'utilisateur, sans interruption. Faux dès qu'un résultat est en `error`, ou en `skipped` pour un autre motif que `user_excluded`. |
| `interrupted` | booléen | Vrai si l'audit a été interrompu (Ctrl+C) : résultats partiels. |
| `profile` | chaîne ou `null` | Profil d'audit ; `null` tant que les profils (#47) n'existent pas. |
| `argv` | tableau de chaînes | Arguments de la ligne de commande, sans le programme ; valeurs sensibles masquées, chemins réduits au nom de fichier (voir plus bas). |

### `targets[]`

| Champ | Type | Contenu |
| --- | --- | --- |
| `id` | chaîne | Forme normalisée de la cible (`Target.id`, #18) : `local`, `winrm://<hôte>[:port]` ou `bundle:<chemin>`. |
| `kind` | énumération | `windows_host`, `m365_tenant`, `aws_account` ou `siem`. |
| `transport` | énumération | `local`, `winrm`, `bundle` ou `api`. |

### `results[]`

Un résultat par check et par cible : aucun check lancé n'est omis, y compris en
`error` ou en `skipped`. Ce qui n'a pas été évalué n'est jamais conforme.

| Champ | Type | Contenu |
| --- | --- | --- |
| `check_id` | chaîne | Identifiant du check (`win.event_log_retention`). |
| `check_version` | entier ou `null` | Version de la logique du check (registre, #17) ; `null` si elle est inconnue. |
| `target` | chaîne | `id` de la cible. |
| `status` | énumération | `pass`, `gap`, `error`, `skipped` ou `not_applicable` (#15). |
| `reason` | énumération ou `null` | Motif d'un `skipped` (`user_excluded`, `missing_privilege`, `not_implemented`, `not_collected`) ou d'un `error` (`access_denied`, `timeout`, `unreachable`, `internal_error`) ; `null` pour les autres statuts. |
| `message` | chaîne | Explication libre, éventuellement vide. |
| `error` | objet ou `null` | Exception d'un statut `error`, `null` sinon : `type` (nom qualifié), `message` (caviardé : identifiants, mots de passe) et `traceback` (frames seules, présentes uniquement en mode debug, `null` sinon). |
| `duration_s` | nombre ou `null` | Durée du check en secondes. |

### `gaps[]`

Forme de `Gap.to_dict()` (modèle Gap v1, #16 ; grille de sévérité :
[`docs/severite.md`](severite.md)).

| Champ | Type | Contenu |
| --- | --- | --- |
| `fingerprint` | chaîne | SHA-256 hexadécimal de `check_id`, `question_id`, `target` et `resource` : identifie le constat d'un audit à l'autre (#142). |
| `check_id` | chaîne | Check qui a produit le Gap. |
| `target` | chaîne | `id` de la cible. |
| `resource` | chaîne | Ressource en défaut : journal, GPO, objet AD... |
| `question_id` | chaîne ou `null` | Question du catalogue (#46). |
| `question` | chaîne | Question d'enquête qui restera sans réponse. |
| `reason` | chaîne | Pourquoi. |
| `severity` | énumération | `critical`, `high`, `medium`, `low` ou `info`. |
| `evidence` | objet | Preuve chiffrée (ci-dessous). |
| `remediation` | chaîne | Remédiation courte (chemin de GPO, commande). |
| `remediation_id` | chaîne ou `null` | Remédiation de référence (#76). |
| `references` | tableau | Références externes (ci-dessous). |
| `compromise_indicator` | booléen | Le constat peut traduire une compromission (journal effacé...) : à investiguer avant de corriger. |

`evidence` :

| Champ | Type | Contenu |
| --- | --- | --- |
| `observed` | valeur JSON | Valeur observée. |
| `expected` | valeur JSON | Valeur attendue. |
| `unit` | chaîne ou `null` | Unité (`bytes`, `days`, `bool`...). |
| `observed_window_days` | nombre ou `null` | Fenêtre couverte, en jours. |
| `required_window_days` | nombre ou `null` | Fenêtre exigée, en jours. |
| `confidence` | énumération | `measured` (lue), `estimated` (extrapolée) ou `assumed` (supposée). |
| `source` | chaîne | Commande ou API lue, caviardée. |
| `details` | objet | Valeurs brutes ; un horodatage y est en RFC 3339 UTC. |

`references[]` :

| Champ | Type | Contenu |
| --- | --- | --- |
| `kind` | énumération | `attack`, `anssi`, `microsoft`, `cis` ou `other`. |
| `id` | chaîne | Identifiant (`T1021.001`, `DC0067`...). |
| `version` | chaîne ou `null` | Version du référentiel, obligatoire pour ATT&CK (`v20`). |
| `url` | chaîne ou `null` | Lien `https://`, sans identifiants. |

### `summary`

| Champ | Type | Contenu |
| --- | --- | --- |
| `total` | entier | Nombre de résultats (longueur de `results`). |
| `by_status` | objet | Nombre de résultats par statut ; les 5 clés sont toujours présentes : `pass`, `gap`, `error`, `skipped`, `not_applicable`. |
| `by_severity` | objet | Nombre de Gaps par sévérité, de `critical` à `info` (`critical`, `high`, `medium`, `low`, `info`), à zéro s'il le faut. |
| `gaps` | entier | Nombre de Gaps (longueur de `gaps`). |
| `excluded` | entier | Résultats exclus par l'utilisateur (`skipped` / `user_excluded`). |
| `not_evaluated` | entier | Résultats non évalués : `error`, ou `skipped` pour un autre motif. |

## Compatibilité

`schema_version` suit le versionnage sémantique, indépendamment de la version
d'amnesia :

- **MAJEURE** (`2.0.0`) : suppression ou renommage d'un champ, changement de
  type ou de sens d'un champ, nouvelle valeur d'une énumération (`status`,
  `reason`, `severity`...), champ rendu obligatoire ;
- **MINEURE** (`1.1.0`) : champ optionnel ajouté ;
- **CORRECTIVE** (`1.0.1`) : précision de la documentation ou du schéma, sans
  changement des rapports produits.

Un consommateur lit `schema_version`, refuse une version MAJEURE qu'il ne connaît
pas et ignore les champs inconnus : le schéma v1 ne déclare pas
`additionalProperties: false`, et valide donc un rapport `1.x.y`. Les tests
vérifient en revanche qu'amnesia n'écrit aucun champ absent du schéma. La
politique de versionnage du projet (#31) reprend cette règle.

## Sécurité et confidentialité

- **Arguments masqués** : dans `run.argv`, la valeur de `--password`,
  `--token`, `--secret` et `--client-secret`, et de leurs abréviations acceptées
  par argparse (`--tok`), est remplacée par `***` : `--token abc` devient
  `--token ***` et `--token=abc` devient `--token=***`. Les autres arguments
  sont caviardés comme les messages d'erreur (identifiants dans une URL,
  `password=...`). Le chemin du programme (`sys.argv[0]`) n'est pas repris.
- **Pas de chemin du poste de l'auditeur** : `--out` et `--log-file`, leurs
  abréviations (`--ou`) et leur forme `--out=...` ne gardent que le nom de
  fichier, chemin POSIX ou Windows : `--out /home/<compte>/clients/r.json` et
  `--out C:\Users\<compte>\r.json` deviennent `--out r.json`. Limite : la
  cible d'un bundle (`bundle:<chemin>`, #18) est reprise telle quelle dans
  `targets[].id` et dans `run.argv` ; un chemin relatif évite d'y écrire
  l'arborescence du poste.
- **Pas d'opérateur** : le compte local qui a lancé l'audit
  (`AuditResult.operator`) n'est pas écrit dans le rapport remis au client.
- **Texte non UTF-8** : un surrogate isolé (octet non UTF-8 d'un argument ou
  d'un chemin de bundle, décodé en `surrogateescape`) est remplacé par son
  échappement `\udcff`, comme sur la sortie de la CLI
  ([`docs/dev/encodage.md`](dev/encodage.md)) : le rapport s'écrit toujours en
  UTF-8 strict. La forme est déterministe, mais ne se distingue pas d'un texte
  qui contenait déjà `\udcff`.
- **Valeurs venues de la cible : aucun caractère de contrôle brut** : messages,
  textes et preuves des Gaps gardent la valeur observée, mais les caractères de
  contrôle n'apparaissent dans le fichier que sous forme d'échappement JSON.
  JSON échappe ceux sous U+0020 (`\u001b`) ; `dumps_report()` échappe aussi DEL
  et les contrôles C1 (U+007F à U+009F, dont CSI U+009B et OSC U+009D), les
  contrôles de direction bidirectionnelle (U+061C, U+200E, U+200F, U+202A à
  U+202E, U+2066 à U+2069) et les séparateurs U+2028/U+2029 (`\u009b`,
  `\u202e`). `json.loads()` relit exactement la même valeur, mais `cat`, `less`,
  `jq` ou un diff du rapport ne peuvent plus piloter le terminal ni inverser le
  texte affiché (Trojan Source). Les accents restent lisibles. Les rendus (#23,
  #45, #77) neutralisent toujours ces caractères à l'affichage, une fois la
  valeur décodée.

## Exemple complet

Audit fictif d'un serveur de fichiers : un check conforme, deux angles morts, une
erreur, un check non implémenté et un check sans objet. C'est le golden
`tests/golden/report.json`.

```json
{
  "schema_version": "1.0.0",
  "tool": {
    "name": "amnesia",
    "version": "0.1.0",
    "catalog_version": null
  },
  "run": {
    "id": "5f0c6b1e-8a3d-4c2b-9e7f-1a2b3c4d5e6f",
    "started_at": "2026-10-21T09:30:00Z",
    "finished_at": "2026-10-21T09:30:04.250000Z",
    "duration_s": 4.25,
    "complete": false,
    "interrupted": false,
    "profile": null,
    "argv": [
      "audit",
      "--target",
      "winrm://srv-file.exemple.invalid",
      "--token",
      "***",
      "--out",
      "rapport-srv-file.json"
    ]
  },
  "targets": [
    {
      "id": "winrm://srv-file.exemple.invalid",
      "kind": "windows_host",
      "transport": "winrm"
    }
  ],
  "results": [
    {
      "check_id": "ad.exemple_controleur",
      "check_version": null,
      "target": "winrm://srv-file.exemple.invalid",
      "status": "not_applicable",
      "reason": null,
      "message": "la cible n'est pas un contrôleur de domaine",
      "error": null,
      "duration_s": 0.0
    },
    {
      "check_id": "win.audit_policy",
      "check_version": 1,
      "target": "winrm://srv-file.exemple.invalid",
      "status": "pass",
      "reason": null,
      "message": "",
      "error": null,
      "duration_s": 0.125
    },
    {
      "check_id": "win.event_log_retention",
      "check_version": 2,
      "target": "winrm://srv-file.exemple.invalid",
      "status": "gap",
      "reason": null,
      "message": "",
      "error": null,
      "duration_s": 0.5
    },
    {
      "check_id": "win.powershell_logging",
      "check_version": 1,
      "target": "winrm://srv-file.exemple.invalid",
      "status": "gap",
      "reason": null,
      "message": "",
      "error": null,
      "duration_s": 0.25
    },
    {
      "check_id": "win.sysmon",
      "check_version": 1,
      "target": "winrm://srv-file.exemple.invalid",
      "status": "error",
      "reason": "access_denied",
      "message": "accès refusé à la configuration Sysmon",
      "error": {
        "type": "PermissionError",
        "message": "accès refusé à la configuration Sysmon",
        "traceback": null
      },
      "duration_s": 1.5
    },
    {
      "check_id": "win.time_sync",
      "check_version": 1,
      "target": "winrm://srv-file.exemple.invalid",
      "status": "skipped",
      "reason": "not_implemented",
      "message": "check non implémenté",
      "error": null,
      "duration_s": null
    }
  ],
  "gaps": [
    {
      "fingerprint": "8bcac978c5c18ccbffdca61a07951bee2e73e11430676cc6961095bcfa02ba4b",
      "check_id": "win.event_log_retention",
      "target": "winrm://srv-file.exemple.invalid",
      "resource": "Security",
      "question_id": null,
      "question": "Qui s'est connecté en RDP sur SRV-FILE il y a trois semaines ?",
      "reason": "Le journal Security fait 20 Mo et a été écrasé il y a 4 jours.",
      "severity": "high",
      "evidence": {
        "observed": 4,
        "expected": 90,
        "unit": "days",
        "observed_window_days": 4,
        "required_window_days": 90,
        "confidence": "measured",
        "source": "Get-WinEvent -LogName Security -Oldest -MaxEvents 1",
        "details": {
          "max_size_bytes": 20971520,
          "log_mode": "Circular",
          "oldest_event_utc": "2026-10-17T09:30:00Z"
        }
      },
      "remediation": "Porter le journal Security à 4 Go au moins par GPO : Configuration ordinateur > Stratégies > Modèles d'administration > Composants Windows > Service Journal des événements > Sécurité.",
      "remediation_id": null,
      "references": [
        {
          "kind": "attack",
          "id": "T1021.001",
          "version": "v20",
          "url": "https://attack.mitre.org/techniques/T1021/001/"
        }
      ],
      "compromise_indicator": false
    },
    {
      "fingerprint": "56f5e1ed812ee96cc1c60df9e2c2b3683cb3009f7f8d67f490be554ac21e019d",
      "check_id": "win.powershell_logging",
      "target": "winrm://srv-file.exemple.invalid",
      "resource": "ScriptBlockLogging",
      "question_id": null,
      "question": "Quelles commandes PowerShell l'attaquant a-t-il exécutées ?",
      "reason": "La journalisation des blocs de script est désactivée.",
      "severity": "medium",
      "evidence": {
        "observed": false,
        "expected": true,
        "unit": "bool",
        "observed_window_days": null,
        "required_window_days": null,
        "confidence": "measured",
        "source": "registre HKLM PowerShell ScriptBlockLogging",
        "details": {}
      },
      "remediation": "Activer « Activer la journalisation des blocs de scripts PowerShell » par GPO.",
      "remediation_id": null,
      "references": [],
      "compromise_indicator": false
    }
  ],
  "summary": {
    "total": 6,
    "by_status": {
      "pass": 1,
      "gap": 2,
      "error": 1,
      "skipped": 1,
      "not_applicable": 1
    },
    "by_severity": {
      "critical": 0,
      "high": 1,
      "medium": 1,
      "low": 0,
      "info": 0
    },
    "gaps": 2,
    "excluded": 0,
    "not_evaluated": 2
  }
}
```
