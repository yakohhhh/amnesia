# Dépendances : extras, acceptation, mises à jour et audit

Deux familles de dépendances, deux règles :

- **dépendances d'exécution** (SDK WinRM, LDAP, Microsoft Graph, boto3...) :
  installées chez l'utilisateur avec amnesia, toujours dans un extra optionnel,
  avec une borne basse testée. Les sections « Extras optionnels » à « Accepter
  une dépendance d'exécution » les régissent ;
- **outils de développement et de CI** : tout ce qu'exécutent le développement
  et la CI est figé, actions par SHA de commit, paquets Python par version exacte
  avec empreintes dans `uv.lock`, binaires téléchargés par SHA-256. Rien ne bouge
  donc tout seul : la suite du document dit ce qui est mis à jour
  automatiquement, ce qui l'est à la main, et comment les vulnérabilités connues
  sont détectées.

Règle commune : **aucune version publiée depuis moins de 7 jours**, le temps
qu'une release compromise soit détectée (`exclude-newer = "7 days"` dans
`[tool.uv]`, `cooldown` de Dependabot, même délai pour les montées manuelles).

## Extras optionnels

Le socle, c'est-à-dire `amnesia-dfr` installé sans extra, n'a **aucune
dépendance tierce d'exécution** : `pyproject.toml` ne déclare pas de
`dependencies`, et le wheel ne porte aucun `Requires-Dist` sans marqueur
`extra == "..."`. Seule exception admise : un backport conditionnel de la
bibliothèque standard (`tomli ; python_version < "3.11"`), inutile tant que le
plancher reste Python 3.11 ([`docs/PAQUET.md`](../PAQUET.md)). Tout installer
pour auditer un seul poste Windows alourdirait l'installation et la surface
d'attaque d'un outil qui s'exécute chez des clients, avec des identifiants
privilégiés (menace M21 du [modèle de menace](../threat-model.md)).

Chaque domaine qui a besoin d'un SDK le déclare dans un extra, créé par le ticket
qui introduit sa première dépendance :

| Extra | Dépendances prévues | Ticket |
| --- | --- | --- |
| `windows` | client PowerShell Remoting (pypsrp, choix final dans #63) | #63 |
| `ad` | client LDAP, à choisir avec #66 : msldap (MIT) ; ldap3, sous LGPL-3.0, est refusé sauf dérogation | #66 |
| `cloud-m365` | msgraph-sdk et azure-identity | #95 |
| `aws` | boto3 | #95 |
| `azure` | SDK Azure Monitor / Log Analytics | #95, #112 |
| `report` | jinja2 (rapport HTML) | #77 |
| `all` | agrégat auto-référencé de tous les autres extras : `amnesia-dfr[windows,ad,...]` | déclaré, vide (#44) |

Le moteur PDF du rapport (#140) relève des éditions commerciales
([ADR 0001](../adr/0001-modele-de-licence.md)) : il n'entre dans aucun extra de
ce dépôt.

`all` est déclaré dès maintenant, vide : `.[all]` s'installe aujourd'hui et
installera demain chaque extra ajouté. Déclarer un extra, dans une même PR :

1. `pyproject.toml`, `[project.optional-dependencies]` : l'extra et ses
   dépendances, chacune à borne basse (section « Bornes de version »), puis
   l'extra ajouté à `all` (`all = ["amnesia-dfr[aws,windows]"]`) ;
2. `src/amnesia/deps.py`, `EXTRAS` : chaque distribution avec le module qu'elle
   fournit (`Package("msgraph-sdk", "msgraph")`), lu par `require_extra()` et
   par le test des imports paresseux ;
3. `uvx uv@0.13.0 lock`, puis `uv.lock` commité ;
4. la fiche d'acceptation de chaque dépendance, dans la description de la PR et
   dans la section « Dépendances d'exécution acceptées » ;
5. un override `[[tool.mypy.overrides]]` limité aux modules du SDK s'il n'est pas
   typé, et le modèle de menace si l'extra apporte un transport ou un connecteur.

`tests/test_paquet.py` vérifie sur les métadonnées du wheel qu'aucun
`Requires-Dist` n'échappe à un extra (backports conditionnels exceptés), que
`all` référence tous les extras déclarés et seulement eux, et que `EXTRAS`
concorde avec `pyproject.toml`. La session `uv run nox -s build` (jobs `build`
et `nox-windows`) installe le wheel sans extra dans un venv vierge, sans index,
vérifie qu'aucun autre paquet n'y est installé, puis lance `amnesia
list-checks`.

Le nom d'un extra figure dans les commandes d'installation et les scripts des
utilisateurs : le renommer les casserait. Il se choisit donc une fois pour
toutes, en minuscules et tirets (forme normalisée de la PEP 685, vérifiée par
les tests).

Depuis les sources : `uv sync --extra <extra>` (ou `--all-extras`), ou
`pip install -e ".[<extra>]"` dans un environnement virtuel.

## Import paresseux

Aucun module de `src/amnesia/` n'importe de paquet tiers à son chargement :
seulement la bibliothèque standard et amnesia. Un SDK s'importe dans la fonction
qui s'en sert, après `amnesia.deps.require_extra()` :

```python
from amnesia.deps import require_extra


class CollecteurAws:
    def collect(self, target, names, *, timeout):
        require_extra("aws")
        import boto3  # extra aws : importe a l'execution, jamais au chargement

        ...
```

- Un import sous `if TYPE_CHECKING:` (annotations) est permis : il n'est jamais
  exécuté.
- `tests/test_extras.py` parcourt l'AST de `src/amnesia/` et refuse tout import
  tiers exécuté au chargement : corps de module ou de classe, `try`, `if`. Le
  message nomme l'extra qui fournit le module.
  `tests/integration/test_cli_processus.py` lance `list-checks` avec les SDK
  rendus inimportables.
- `require_extra(extra)` importe chaque module de l'extra. S'il en manque un,
  ou si son import échoue (dépendance transitive absente), il lève
  `MissingExtra(extra, paquets)`, dont le message donne la commande
  d'installation de l'extra (`MissingExtra.command`). Un extra non déclaré dans
  `EXTRAS` lève `ValueError` : c'est une erreur de programmation.
- Le moteur traduit `MissingExtra`, levée par un collecteur, par un check ou par
  sa propre vérification, en résultat `skipped` / `not_collected` : « non
  évalué », jamais conforme, et l'audit est incomplet. Le message donne la
  commande d'installation ; aucune trace, même avec `--debug`. Un motif dédié
  serait une nouvelle valeur de `reason`, donc un changement majeur du format de
  rapport ([`docs/format-rapport.md`](../format-rapport.md)).
- Un check dont l'API exige un SDK quel que soit le transport (cloud) le
  déclare : `requires_extra = "aws"`. Le registre refuse un extra non déclaré, le
  moteur vérifie l'extra avant toute collecte et `amnesia list-checks` l'affiche
  (`[aws]` ; `-` sans extra). Un extra propre à un transport (`windows` pour
  WinRM) relève de son collecteur, qui appelle `require_extra()` : les mêmes
  checks restent évaluables sur un bundle hors ligne, sans SDK.
- Tant que le nom `amnesia-dfr` n'est pas publié (#33), la commande du message,
  qui installe par le nom, ne vaut que dans un environnement où amnesia est déjà
  installé ; ailleurs, installer l'extra depuis les sources
  ([`docs/PAQUET.md`](../PAQUET.md)).

## Bornes de version

- Chaque dépendance d'exécution a une **borne basse** `>=`, la plus ancienne
  version testée. Jamais de version figée (`==`, `~=`) : amnesia cohabite avec
  les autres paquets de l'environnement de l'utilisateur, et ses extras entre
  eux.
- **Pas de borne haute** sans incompatibilité connue, décrite dans la fiche de
  la dépendance et reprise dans `BORNES_HAUTES` de `tests/test_paquet.py`.
- `uv.lock` fige la version la plus récente admise, délai de carence compris :
  c'est elle que testent les jobs `test` et `nox-windows`. Dependabot propose
  chaque nouvelle version d'une dépendance d'exécution dans une PR à part ; seul
  `uv.lock` doit y changer. Une PR qui relève aussi la borne basse sans que le
  code l'exige est corrigée avant le merge : borne d'origine rétablie, puis
  `uvx uv@0.13.0 lock`.
- Le job CI **`lowest-direct`** (session `uv run nox -s lowest-direct`, requise
  par `ci-ok`) teste les bornes basses sur le plancher de Python : outils de dev
  depuis `uv.lock`, puis `uv pip install --resolution lowest-direct --upgrade -e
  ".[all]"` (dépendances directes à leur borne basse, transitives au plus récent
  avec le délai de carence), `uv pip check`, puis la suite de tests.
  `--upgrade` : sans lui, une version déjà installée pour un outil de dev serait
  gardée au lieu de la borne basse.
- Une installation depuis PyPI ne lit ni `uv.lock` ni le délai de carence :
  risque résiduel RR10 du modèle de menace.

## Accepter une dépendance d'exécution

Toute PR qui ajoute une dépendance d'exécution, directe ou portée par un extra,
remplit la fiche ci-dessous. Une dépendance de moins vaut mieux qu'une de plus :
chaque SDK s'exécute sur le poste de l'auditeur, avec ses identifiants.

- **Licence** : liste blanche MIT, BSD, Apache-2.0, ISC, MPL-2.0 et PSF. La
  MPL-2.0, copyleft au niveau du fichier, est admise tant que ses fichiers ne
  sont ni modifiés ni copiés dans le dépôt. GPL, AGPL et LGPL sont refusées en
  exécution, sauf dérogation documentée dans la fiche et validée au regard de
  l'[ADR 0001](../adr/0001-modele-de-licence.md) : le cœur est sous MIT, et les
  éditions commerciales en dépendent. La règle vaut pour la dépendance et pour
  chacune de ses dépendances transitives d'exécution. Vérification automatique
  et inventaire des licences : #83.
- **Maintenance** : versions récentes (une release dans les douze derniers mois),
  failles de sécurité traitées (avis GitHub et OSV corrigés, aucune
  vulnérabilité connue ouverte : job `pip-audit`), mainteneurs identifiables,
  idéalement plusieurs.
- **Surface d'attaque** : nombre de dépendances transitives
  (`uv tree --package <distribution>`), extensions natives (wheels binaires, compilation
  à l'installation), accès réseau ou exécution de code à l'import (télémétrie,
  mise à jour automatique, plugins chargés par entry points), wheels pour
  Windows, Linux et macOS et pour chaque version de Python de la matrice.
- **Stdlib** : préférer la bibliothèque standard quand l'écart fonctionnel est
  faible (`urllib.request` pour un appel HTTPS simple, `tomllib` pour lire du
  TOML) ; la fiche dit pourquoi elle ne suffit pas.

Fiche, à recopier dans la description de la PR et dans la section suivante :

```markdown
### <distribution> (extra `<extra>`, #<ticket>)

- Licence : <identifiant SPDX> ; dépendances transitives : <licences>
- Versions : `>=<version>` (<pourquoi cette borne basse>) ; borne haute : aucune
- Maintenance : dernière release <date>, <n> mainteneurs, avis de sécurité <état>
- Surface d'attaque : <n> dépendances transitives, extensions natives <oui/non>,
  réseau ou code exécuté à l'import <oui/non>
- Stdlib : <pourquoi elle ne suffit pas>
- Dérogation : aucune
```

### Dépendances d'exécution acceptées

Aucune : le socle n'a aucune dépendance tierce et aucun extra n'est encore
déclaré, `all` excepté. Chaque PR qui en ajoute une ajoute ici sa fiche.

## Dependabot

`.github/dependabot.yml`, chaque lundi :

| Écosystème | Fichiers | Regroupement |
| --- | --- | --- |
| `github-actions` | `.github/workflows/*.yml` | groupe `actions` : toutes les actions dans une seule PR |
| `uv` | `pyproject.toml` et `uv.lock` | groupe `dev-tools` : tous les outils des `[dependency-groups]` dans une seule PR |

- `cooldown` de 7 jours, aligné sur `exclude-newer` : sans lui, Dependabot
  proposerait une version que `uv lock` refuserait.
- Les actions sont épinglées par SHA avec la version en commentaire
  (`@<sha> # vX.Y.Z`) : Dependabot remplace les deux ensemble.
- Une dépendance d'exécution (SDK WinRM, Microsoft Graph, boto3) ne fait partie
  d'aucun groupe : une PR par dépendance, à relire une par une.
- Un outil ajouté à un `[dependency-groups]` doit aussi l'être aux motifs du groupe
  `dev-tools` ; `tests/test_dependances.py` le vérifie.
- **setuptools** est exclu du groupe : il est figé deux fois (groupe `dev` et
  `build-constraint-dependencies`) et Dependabot ne modifie que le premier. Sa PR,
  à part, échoue sur `tests/test_paquet.py` tant que
  `build-constraint-dependencies` n'est pas aligné à la main sur la même branche.
- Labels `type:chore` et `area:ci` ; préfixes de commit `ci` (actions) et `deps`
  (Python).

Vérification après un changement de `dependabot.yml` : Insights → Dependency
graph → Dependabot, le dernier job de chaque écosystème se termine sans erreur
(par exemple si la version de uv de Dependabot ne comprenait pas `exclude-newer`).

## Montées de version manuelles

Dependabot ne voit ni les variables de `ci.yml`, ni les hooks Go de pre-commit, ni
le lock PEP 723 du script de synchronisation GitHub. Chaque montée se fait dans une
PR dédiée, avec une version publiée depuis plus de 7 jours.

### uv

`ci.yml` : `UV_VERSION`, `UV_SHA256_LINUX_X64` et `UV_SHA256_WINDOWS_X64`, à
changer ensemble. Chaque empreinte est vérifiée auprès de trois sources, qui
doivent concorder :

1. le `digest` de l'archive dans la release GitHub (immuable) :
   `gh release view <version> -R astral-sh/uv --json assets` ;
2. le fichier `.sha256` publié à côté de l'archive
   (`uv-x86_64-unknown-linux-gnu.tar.gz.sha256`,
   `uv-x86_64-pc-windows-msvc.zip.sha256`) ;
3. la table d'empreintes de `astral-sh/setup-uv`, à la version épinglée dans
   `ci.yml`.

Mettre ensuite à jour la version citée par `uvx uv@<version> lock`
(`docs/dev/github.md`, ce document, en-tête de `scripts/sync_github.py` ;
`tests/test_dependances.py` vérifie qu'aucune n'est oubliée) et relancer
`uvx uv@<version> lock` : le lock doit rester identique ou n'être modifié que
par le nouveau format.

### actionlint et gitleaks

Chacun est figé deux fois, à la même version (`tests/test_dependances.py` le
vérifie) :

- `ci.yml` : `ACTIONLINT_VERSION` et `ACTIONLINT_SHA256`, `GITLEAKS_VERSION` et
  `GITLEAKS_SHA256`. L'empreinte est celle de l'archive `linux_amd64` (actionlint)
  ou `linux_x64` (gitleaks), lue dans le fichier `*_checksums.txt` de la release
  et recoupée avec le `digest` de `gh release view` ;
- `.pre-commit-config.yaml` : `rev` figé sur le SHA de commit du tag
  (`git ls-remote <dépôt> 'refs/tags/vX.Y.Z^{}'`), commentaire
  `# frozen: vX.Y.Z`, et `language_version` de Go si la nouvelle version l'exige.
  `pre-commit autoupdate` prendrait le dernier tag, sans délai de carence.

### setuptools

Même version dans le groupe `dev` et dans `build-constraint-dependencies`, sous la
borne haute de `build-system.requires`, puis `uvx uv@0.13.0 lock`.

### Script de synchronisation GitHub

PyYAML, déclaré dans l'en-tête PEP 723 de `scripts/sync_github.py`, est figé dans
`scripts/sync_github.py.lock` : `uvx uv@0.13.0 lock --script scripts/sync_github.py`.

## Audit des vulnérabilités

Le job CI `pip-audit` (requis par `ci-ok`) audite toutes les dépendances de
`uv.lock`, groupes compris, contre la base de vulnérabilités de PyPI. Il tourne à
chaque push et chaque PR, et chaque lundi sur `main` : une vulnérabilité publiée
sur un lock inchangé fait échouer la CI sans attendre une PR. Toute vulnérabilité
connue le fait échouer.

Le lock est exporté au format PEP 751 (`pylock.toml`) et non en
`requirements.txt` : avec `-r`, pip-audit évalue les marqueurs d'environnement et
ignore les paquets d'une autre plateforme (`colorama ; sys_platform == 'win32'`
sur le runner Linux), alors qu'avec `--locked` il audite chaque paquet du lock.

En local (réseau requis) :

```sh
uv export --quiet --locked --all-groups --all-extras --no-emit-project \
  --format pylock.toml --output-file /tmp/amnesia-audit/pylock.toml
uv run --only-group audit pip-audit --strict --locked --aliases=on /tmp/amnesia-audit
```

### Corriger une vulnérabilité

1. Monter le paquet vers une version corrigée publiée depuis plus de 7 jours :
   `uvx uv@0.13.0 lock --upgrade-package <paquet>` pour une dépendance
   transitive, ou la version `==` de `pyproject.toml` pour une dépendance directe.
2. Si aucune version corrigée n'a encore 7 jours, ou s'il n'en existe pas : ajouter
   une exception temporaire.

### Exceptions

Uniquement dans le tableau `exceptions` de l'étape `pip-audit` de `ci.yml`, une
par ligne, avec l'identifiant, la raison et la date de revue :

```bash
exceptions=(
  --ignore-vuln=GHSA-xxxx-xxxx-xxxx  # outil de dev, code vulnérable jamais appelé ; revue le 2026-12-01
)
```

`tests/test_dependances.py` refuse une exception sans identifiant, sans raison ou
sans date, et toute autre option ajoutée à la commande `pip-audit` (argparse
accepterait une forme abrégée comme `--ig=…` hors du tableau). À la date de revue : retirer l'exception si une version corrigée est
disponible, sinon justifier à nouveau et repousser la date.

## Réglages du dépôt (propriétaire)

Ces réglages relèvent du compte et ne sont pas versionnés ; ils sont à activer par
le propriétaire, avec les autres réglages du dépôt (#13) :

- alertes Dependabot : `gh api -X PUT repos/yakohhhh/amnesia/vulnerability-alerts`,
  vérifiées par `gh api repos/yakohhhh/amnesia/vulnerability-alerts` (204) ;
- mises à jour de sécurité Dependabot :
  `gh api -X PUT repos/yakohhhh/amnesia/automated-security-fixes`. Elles ne
  respectent pas le `cooldown` : une correction publiée depuis moins de 7 jours
  échoue sur `exclude-newer`, et l'exception temporaire ci-dessus prend le relais.
