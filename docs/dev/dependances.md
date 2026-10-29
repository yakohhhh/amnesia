# Mises à jour et audit des dépendances

Tout ce qu'exécutent le développement et la CI est figé : actions par SHA de
commit, paquets Python par version exacte avec empreintes dans `uv.lock`, binaires
téléchargés par SHA-256. Rien ne bouge donc tout seul : ce document dit ce qui est
mis à jour automatiquement, ce qui l'est à la main, et comment les vulnérabilités
connues sont détectées.

Règle commune : **aucune version publiée depuis moins de 7 jours**, le temps
qu'une release compromise soit détectée (`exclude-newer = "7 days"` dans
`[tool.uv]`, `cooldown` de Dependabot, même délai pour les montées manuelles).

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
(`docs/dev/github.md`, en-tête de `scripts/sync_github.py`) et relancer
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
uv export --locked --all-groups --no-emit-project --format pylock.toml \
  --output-file /tmp/amnesia-audit/pylock.toml
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
sans date. À la date de revue : retirer l'exception si une version corrigée est
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
