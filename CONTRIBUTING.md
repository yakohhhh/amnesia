# Contribuer à amnesia

Merci de l'intérêt que tu portes à amnesia. Ce guide suffit pour passer de
`git clone` à une suite de tests verte, puis pour proposer un changement selon les
conventions du dépôt : outillage, style, workflow Git, labels et CHANGELOG.

Deux règles passent avant tout le reste :

- **Aucune donnée client**, nulle part : ni dans le dépôt, ni dans une issue, une
  PR, un commit ou un commentaire (section
  [« Aucune donnée client »](#aucune-donnée-client)).
- **Une vulnérabilité ne se signale jamais publiquement** : signalement privé,
  selon la politique de sécurité,
  [`SECURITY.md`](https://github.com/yakohhhh/amnesia/blob/main/SECURITY.md).

## Aucune donnée client

Le dépôt est public, et un rapport amnesia est la carte des angles morts d'un
client. Rien de ce qui vient d'un audit réel n'entre dans le dépôt, les issues ou
les PR :

- ni nom d'hôte, domaine, adresse IP, compte, GUID ou identifiant de tenant ;
- ni rapport, collecte, export brut, journal ou capture d'écran d'un client ;
- ni secret (mot de passe, jeton, clé, certificat), même expiré.

Les exemples et les fixtures utilisent des valeurs fictives : noms en `.invalid`
ou `.example` (RFC 2606, RFC 6761), adresses de documentation `192.0.2.0/24`
(RFC 5737), noms d'hôtes génériques (`SRV-FILE`, `DC01`). Les règles des fixtures
sont dans [`tests/fixtures/README.md`](tests/fixtures/README.md) ; les exports bruts
vont dans un répertoire `raw/`, ignoré par git.

Les hooks pre-commit et la CI refusent les sorties d'amnesia (`amnesia-report*`,
`amnesia-bundle*`, `reports/`, PDF hors de `docs/`) et les fichiers de secrets
(`.env`, `.pfx`, `.p12`, `.key`) ; gitleaks cherche les secrets dans les fichiers
et dans tout l'historique. Ces garde-fous ne remplacent pas une relecture : en cas
de doute, ne pas commiter.

## Signaler une vulnérabilité

Jamais d'issue, de PR ni de discussion publique : le canal est le signalement
privé de GitHub, décrit dans
[`SECURITY.md`](https://github.com/yakohhhh/amnesia/blob/main/SECURITY.md), avec
les délais de traitement et les règles de divulgation.

## Issues

« New issue » propose trois formulaires, et aucune issue vierge :

| Formulaire | Label posé | Pour |
|---|---|---|
| **Nouveau check** | `type:feature` | une question d'enquête qu'un défaut de journalisation rendrait impossible |
| **Bug** | `type:bug` | un comportement incorrect, avec une sortie anonymisée |
| **Fonctionnalité** | `type:feature` | toute autre amélioration (CLI, rapport, collecte, documentation) |

Un check part d'une question d'enquête (« Qui s'est connecté en RDP sur SRV-FILE
il y a trois semaines ? »). Le formulaire « Nouveau check » demande donc la
question, la source de télémétrie (journal, Event IDs, API), la méthode de
collecte en lecture seule et les privilèges minimaux, puis le seuil et la
sévérité (grille de [`docs/severite.md`](docs/severite.md)). Le formulaire
« Bug » exige de cocher que noms d'hôtes, domaines, IP et identifiants de tenant
ont été retirés.

Pour écrire le code d'un check : section « Écrire un check » de
[`docs/dev/faits.md`](docs/dev/faits.md), en attendant le guide complet (#81).

## Environnement de développement

### Prérequis

- **git** ;
- **[uv](https://docs.astral.sh/uv/)**, version 0.13.0 ou plus récente (la CI
  utilise la 0.13.0).

Rien d'autre : uv télécharge l'interpréteur Python fixé par `.python-version`
(3.11, plancher du projet) et installe les outils à l'identique de `uv.lock`
(versions exactes et empreintes vérifiées). Au premier lancement, pre-commit
télécharge aussi la chaîne Go qui compile les hooks gitleaks et actionlint.
L'installation demande donc un accès à PyPI, à GitHub et à go.dev.

Installer uv, par exemple avec l'installeur officiel de la version de la CI
(autres méthodes : [documentation d'uv](https://docs.astral.sh/uv/getting-started/installation/)) :

```sh
# Linux, macOS
curl -LsSf https://astral.sh/uv/0.13.0/install.sh | sh
# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/0.13.0/install.ps1 | iex"
```

### De `git clone` à une suite verte

```sh
git clone https://github.com/yakohhhh/amnesia.git
cd amnesia
uv sync --locked                          # Python 3.11, projet et groupe dev depuis uv.lock
uv run pre-commit install                 # hooks lancés à chaque commit
uv run nox -s lint typecheck tests-3.11   # ruff, mypy --strict, pytest et couverture
```

`--locked` fait échouer `uv sync` si `uv.lock` ne correspond plus à
`pyproject.toml`, au lieu de le régénérer en silence.

La suite est verte quand nox termine par `Session tests-3.11 was successful.`,
couverture d'au moins 80 % comprise. Des tests SKIPPED sont normaux : ils
demandent Windows, un binaire gitleaks dans le `PATH`, des droits administrateur,
le lab Active Directory, un tenant cloud ou le réseau (marqueurs `windows`,
`admin`, `lab`, `cloud` et `network`, options `--run-*` de
[`tests/conftest.py`](tests/conftest.py)).

### Sessions nox et commandes de la CI

```sh
uv run nox -l                       # liste des sessions
uv run nox                          # lint, typecheck et tests de Python 3.11 à 3.15
uv run nox -s lint typecheck tests build   # comme la CI, build du paquet compris
```

nox télécharge par uv les interpréteurs absents. Les mêmes vérifications, une à
une, comme les jobs de la CI :

```sh
uv run ruff check .
uv run ruff format --check .
uv run mypy
PYTHONWARNDEFAULTENCODING=1 PYTEST_ADDOPTS='-W error::EncodingWarning' uv run pytest -q --cov
```

Sous Windows, passer par `uv run nox -s tests-3.11`, qui pose lui-même les deux
variables d'environnement.

### Hooks pre-commit

`uv run pre-commit install` installe les hooks : ruff (lint et format), fichiers
volumineux, YAML et TOML valides, fins de ligne, gitleaks, actionlint, schémas
des formulaires d'issues, refus des données client et des fichiers de secrets.
Pour les rejouer sur tout le dépôt : `uv run pre-commit run --all-files`.

- Ne jamais les contourner (`git commit --no-verify`) : la CI rejoue les mêmes
  contrôles côté serveur, sur tout l'historique.
- Quand un hook corrige un fichier (format, fin de ligne), le commit échoue :
  relire la correction, l'indexer (`git add`) et recommiter.

## Conventions de code

- **Python 3.11 ou plus récent** : aucune construction plus récente que le
  plancher de `requires-python` ([`docs/PAQUET.md`](docs/PAQUET.md)).
- **ruff** : règles et exceptions dans `pyproject.toml`, aucun `noqa` sans code.
- **Typage strict** : `uv run mypy` lance `mypy --strict` sur `src/` et `tests/` ;
  les tests sont annotés eux aussi.
- **Encodage** ([`docs/dev/encodage.md`](docs/dev/encodage.md)) :
  - fichiers en UTF-8 sans BOM, fins de ligne LF (sauf PowerShell et batch) ;
  - docstrings et textes visibles (CLI, checks, rapports) accentués ;
  - commentaires de code en français, sans accents, comme l'existant ;
  - `encoding=` explicite sur tout `open()`, `read_text()`, `write_text()` et
    tout `subprocess` en mode texte : la suite tourne avec `EncodingWarning` en
    erreur.
- **Lecture seule** : un check lit des configurations, il ne modifie jamais la
  cible auditée.
- **Tests** ([`tests/conftest.py`](tests/conftest.py)) : tests unitaires dans
  `tests/unit/`, un fichier par module ; vrais processus dans
  `tests/integration/` ; tests d'outillage à la racine de `tests/`. Le réseau est
  coupé, les marqueurs sont déclarés (`--strict-markers`), et aucun test n'écrit
  dans le dépôt (répertoire courant isolé dans `tmp_path`, vérifié en CI).
- **Dépendances** ([`docs/dev/dependances.md`](docs/dev/dependances.md)) :
  version exacte (`==`) dans `pyproject.toml`, publiée depuis plus de 7 jours
  (`exclude-newer`), lock régénéré avec la version d'uv de la CI, puis `uv.lock`
  commité dans la même PR :

  ```sh
  uvx uv@0.13.0 lock
  ```

- Imiter le style des fichiers voisins (nommage, docstrings, commentaires), et
  n'ajouter une dépendance qu'en cas de nécessité.

## Workflow Git

### Une issue, une branche, une PR

- Tout changement part d'une issue, et chaque issue a sa branche et sa PR. Un
  correctif repéré en chemin fait l'objet d'une autre issue.
- La branche part de `main` à jour et se nomme `<type>/<numéro>-<sujet>`, en
  minuscules et sans accents, par exemple `docs/29-contributing` ou
  `feat/22-rapport-json`. Types : `feat`, `fix`, `docs`, `chore`, `test`,
  `security`, `ci`.
- Une branche poussée n'est jamais réécrite (ni rebase, ni push forcé). Pour la
  mettre à jour, fusionner `main` :

  ```sh
  git fetch origin
  git merge origin/main
  git push
  ```

### Messages de commit

En français : un titre court qui dit ce que fait le commit, une ligne vide, puis
un corps qui explique le pourquoi et ce qui n'est pas évident dans le diff. Par
exemple :

```text
Validation stricte de --target

Une cible invalide devient une erreur d'usage (code 2). Le message ne reprend
jamais la saisie, qui peut contenir un nom d'hôte ou un identifiant.
```

**Aucune attribution à un outil d'IA**, ni dans les commits ni dans les PR ni dans
les fichiers : pas de trailer de co-auteur ni de mention « généré par » désignant
un assistant. L'auteur d'un commit est la personne qui le signe et en répond.

### Pull requests

- Titre : celui de l'issue. Description en français, pré-remplie par le modèle
  de PR : contexte en une phrase, `## Changements`, `## Vérifications` (commandes
  lancées et résultats), `## Reporté` si un point dépend d'un autre ticket ou
  d'une action du propriétaire, puis la checklist et `Closes #<numéro>` en
  dernière ligne.
- `main` est protégée : pas de push direct, PR obligatoire, check `ci-ok` requis
  (il agrège tous les jobs de la CI) et branche à jour avec `main` avant le merge.
- Merge en **squash** une fois `ci-ok` vert : un commit par PR sur `main`, titré
  par le titre de la PR suivi de son numéro.

### Labels

La taxonomie est déclarée dans [`.github/labels.yml`](.github/labels.yml)
([`docs/dev/github.md`](docs/dev/github.md)). Chaque issue porte :

- **1 type** (`type:feature`, `type:bug`, `type:docs`…), posé par le formulaire ;
- **1 priorité** (`priority:high`, `priority:medium` ou `priority:low`) ;
- **1 à 2 domaines** (`area:windows`, `area:core`…).

La priorité et les domaines sont posés au tri par un mainteneur.

## CHANGELOG

[`CHANGELOG.md`](CHANGELOG.md) suit Keep a Changelog, selon les règles de
[`docs/RELEASING.md`](docs/RELEASING.md) : toute PR qui change ce que voit un
utilisateur ou un intégrateur y ajoute une entrée dans `[Unreleased]`, en une
phrase et avec le numéro de la PR. Les changements purement internes (CI,
outillage, refactorisation sans effet visible) n'y figurent pas.

## Licence des contributions

La politique de licence des contributions (DCO ou CLA) n'est pas encore fixée :
elle dépend du choix de licence du projet (#11) et sera définie par #30, qui
complétera cette section. D'ici là, ouvre une issue pour en discuter avant
d'engager une contribution importante.
