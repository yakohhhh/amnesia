# Labels et milestones GitHub

Les labels et les milestones du dépôt sont décrits dans deux fichiers versionnés :

- `.github/labels.yml` : la taxonomie (`type:*`, `priority:*`, `area:*`,
  `good first issue` et les labels par défaut de GitHub conservés), avec couleur et
  description ;
- `.github/milestones.yml` : les milestones, identifiées par leur titre exact
  (tiret cadratin compris).

`scripts/sync_github.py` aligne GitHub sur ces fichiers, via `gh api` :

```sh
gh auth status                                     # gh doit être connecté
uv run --locked scripts/sync_github.py --dry-run   # plan, aucune écriture
uv run --locked scripts/sync_github.py             # applique le plan
uv run --locked scripts/sync_github.py --dry-run   # « Aucune modification »
```

- **Idempotent** : seuls les écarts sont créés ou modifiés ; une deuxième
  exécution n'annonce et n'effectue rien.
- **`--dry-run`** : lit l'état distant et affiche le plan, sans aucun appel en
  écriture.
- **Aucune erreur avalée** : au premier appel `gh` en échec (authentification,
  422, 404…), le script s'arrête en code 1 et affiche le message de GitHub.
- **`--prune`** : supprime en plus les labels absents de `labels.yml` (aujourd'hui
  `accessibility`, `bug`, `documentation`, `enhancement`), seulement si aucune issue
  ni PR, ouverte ou fermée, ne les porte ; sinon rien n'est écrit. Les milestones
  ne sont jamais supprimées.
- Un champ `state` (`open` ou `closed`) est facultatif dans `milestones.yml` : sans
  lui, l'état choisi sur GitHub est laissé tel quel.
- PyYAML, seule dépendance, est déclarée dans l'en-tête du script (PEP 723) et
  figée avec ses empreintes dans `scripts/sync_github.py.lock`. Après une montée de
  version : `uvx uv@0.13.0 lock --script scripts/sync_github.py`.

Pour ajouter un label ou une milestone : modifier le fichier YAML dans une PR,
puis lancer la synchronisation une fois la PR mergée. Renommer une milestone dans
le fichier en crée une nouvelle : la renommer d'abord sur GitHub.

## Pourquoi le bootstrap s'est arrêté après l'issue #1

L'ancien `scripts/create-github-repo.sh` (retiré) devait créer le dépôt, les
labels, les milestones et 14 issues. Le 20/10/2026, seule l'issue #1 a été créée
(19:16:45 UTC, milestones créées entre 19:16:41 et 19:16:43).

Cause : sur macOS, `#!/usr/bin/env bash` choisit le bash 3.2.57 du système, qui
ne sait pas analyser un heredoc placé dans une substitution `$(...)` quand ce
heredoc contient une apostrophe. Le corps de la 2e issue contenait « n'arrete » :
bash 3.2 cherche l'apostrophe fermante jusqu'à la fin du fichier et s'arrête en
code 2, juste après la création de l'issue #1.

Reproduction (avec le script de l'historique, par exemple `git show 8e24512:scripts/create-github-repo.sh > /tmp/create.sh`) :

```sh
/bin/bash -n /tmp/create.sh
# line 162: unexpected EOF while looking for matching `''   (rc=2)
```

Le script avait d'autres défauts, qui ont motivé son remplacement plutôt que sa
correction :

- avec un bash récent, `issue()` sans garde, combiné à `set -e`, aurait tout
  arrêté au premier échec, alors que `label()` et `milestone()` avalaient leurs
  erreurs (`>/dev/null 2>&1 || true`) ;
- il se disait « Idempotent », mais une relance aurait recréé en double les issues
  déjà ouvertes ;
- chaque exécution indexait tout l'arbre de travail (`git add -A`) puis le
  commitait ;
- il renvoyait vers un fichier `GO-LIVE.md` inexistant, et ses 5 labels, aux
  descriptions sans accents, ne couvraient pas la taxonomie du backlog.

Les issues du backlog ont depuis été créées hors de ce script ; la création
d'issues en masse n'est pas reprise dans `sync_github.py`.
