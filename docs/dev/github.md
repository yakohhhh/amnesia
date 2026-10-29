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

- **Dépôt cible** : `--repo propriétaire/dépôt`, ou par défaut le dépôt de ce
  checkout. `gh` est toujours lancé depuis la racine du dépôt et sans `GH_REPO` :
  lancer le script depuis un autre répertoire ne change pas la cible.
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

## Passage en public

Le dépôt est public depuis le 29/10/2026. En GitHub Free, plusieurs réglages de
sécurité n'existent que sur un dépôt public : ils sont activés au passage par le
propriétaire, et la liste est à revérifier si la visibilité change. La décision et
les commandes appliquées relèvent de #13.

- [x] **Signalement privé de vulnérabilités** (*Private Vulnerability Reporting*) :
  c'est le seul canal de signalement de [`SECURITY.md`](../../SECURITY.md) (#28). Désactivé, il retire le bouton
  « Report a vulnerability » et ne laisse plus que l'issue publique. Vérification,
  en lecture seule :

  ```sh
  gh api repos/yakohhhh/amnesia/private-vulnerability-reporting --jq .enabled   # true
  ```

- [ ] **Canal testé** : un signalement de test envoyé depuis un autre compte GitHub
  est bien notifié au propriétaire, puis fermé sans publication (#28).
- [ ] **Commits sans adresse personnelle** : l'adresse d'auteur et de committer de
  chaque commit poussé est publique, y compris dans les commits d'une PR
  (`refs/pull/<n>/head`), qu'un merge squash ne réécrit pas. Le propriétaire
  active sur GitHub « Keep my email addresses private » et « Block command line
  pushes that expose my email », puis commite avec son adresse
  `users.noreply.github.com`. Les commits déjà poussés gardent leur adresse :
  l'historique publié n'est pas réécrit. Vérification avant chaque push :
  `git log --format='%ae%n%ce' origin/main..HEAD | sort -u` ne montre que
  l'adresse `users.noreply.github.com`.
- [x] Secret scanning et protection des pushes.
- [x] Alertes et mises à jour de sécurité Dependabot.
- [x] Protection de `main` : PR obligatoire, check `ci-ok` requis, ni push forcé ni
  suppression (#13).
- [ ] **Formulaires d'issues obligatoires** (#29) : un formulaire « Bug » envoyé
  sans la case d'anonymisation cochée est refusé par GitHub (`required: true`,
  appliqué seulement sur un dépôt public).
- [ ] **Pas d'issue vierge** (#29) : pour un compte en lecture ou triage, « New
  issue » propose « Nouveau check », « Bug » et « Fonctionnalité », le lien
  « Signaler une vulnérabilité », et aucune issue vierge ; pour un rôle Write ou
  au-delà, l'option vierge n'apparaît que libellée « Maintainers only ».
- [ ] **Modèle de PR** (#29) : une nouvelle PR ouverte depuis l'interface web
  affiche la checklist du modèle.

Vérification groupée, en lecture seule :
`gh api repos/yakohhhh/amnesia --jq '.visibility, .security_and_analysis'`.

## Formulaires d'issues et modèle de PR

Le parcours du contributeur est décrit dans
[`CONTRIBUTING.md`](../../CONTRIBUTING.md). Côté GitHub :

- `.github/ISSUE_TEMPLATE/` : trois formulaires, « Nouveau check »
  (`nouveau-check.yml`), « Bug » (`bug.yml`) et « Fonctionnalité »
  (`fonctionnalite.yml`), et `config.yml`, qui désactive l'issue vierge
  (`blank_issues_enabled: false`) et ajoute un lien de contact vers
  [`SECURITY.md`](../../SECURITY.md) (#28). Les rôles Write et au-delà voient
  encore l'option vierge, que GitHub libelle « Maintainers only ».
- Chaque formulaire pose un label `type:*`, qui doit exister dans
  `.github/labels.yml`.
- `required: true` (champs et cases) n'est appliqué par GitHub que sur un dépôt
  public : c'est le cas depuis le 29/10/2026. Si le dépôt redevenait privé, ces
  obligations ne seraient plus que des indications.
- `.github/pull_request_template.md` pré-remplit toute PR ouverte depuis
  l'interface web. `gh pr create --body-file` le remplace : y recopier la
  checklist.
- Formulaires et modèle ne s'appliquent qu'une fois sur `main`. Leur effet sur
  GitHub se vérifie avec les cases #29 de la checklist « Passage en public ».

Garde-fous : `check-jsonschema` valide les formulaires (schéma
`vendor.github-issue-forms`) et `config.yml` (`vendor.github-issue-config`) en
pre-commit (hooks `formulaires-issues` et `config-issues`) et en CI (job
`workflow-lint`) ; `tests/test_contribution.py` vérifie les champs obligatoires,
les labels, les renvois et le modèle de PR.

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
- il renvoyait vers un guide de mise en ligne inexistant, et ses 5 labels, aux
  descriptions sans accents, ne couvraient pas la taxonomie du backlog.

Les issues du backlog ont depuis été créées hors de ce script ; la création
d'issues en masse n'est pas reprise dans `sync_github.py`.
