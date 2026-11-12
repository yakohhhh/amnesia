# amnesia

[![ci](https://github.com/yakohhhh/amnesia/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/yakohhhh/amnesia/actions/workflows/ci.yml)

**Ce que ton SI aura *oublié* le jour de l'incident.**

La pire surprise en réponse à incident, c'est de découvrir que les logs
n'existaient pas, ou qu'ils ont déjà été écrasés. `amnesia` audite ta
télémétrie **avant** l'incident (endpoints Windows, Active Directory, cloud) et
te rend la liste des questions d'enquête auxquelles tu ne pourras **pas**
répondre.

> Exemple de sortie : *« Qui s'est connecté en RDP sur SRV-FILE il y a trois
> semaines ? → Impossible : le journal Security fait 20 Mo et a été écrasé il y
> a 4 jours. »*

## Ce qu'il vérifie (cible)

- **Windows** : politique d'audit avancée, Sysmon, logging PowerShell, taille et
  rétention des journaux, synchronisation NTP.
- **Active Directory** : audit des objets sensibles, Kerberos, modifications de GPO.
- **Cloud** : rétention des logs Microsoft 365 / Entra ID, AWS CloudTrail.
- **Pipeline** : les événements partent-ils vraiment vers le SIEM ?

## État

Squelette fonctionnel : moteur de checks + CLI. Les checks listent déjà leur
intention et les faits qu'ils lisent ; leur `evaluate()` est à implémenter — voir
[`docs/dev/faits.md`](https://github.com/yakohhhh/amnesia/blob/main/docs/dev/faits.md)
et
[`docs/ROADMAP.md`](https://github.com/yakohhhh/amnesia/blob/main/docs/ROADMAP.md).

## Démarrer

Avec [uv](https://docs.astral.sh/uv/) (environnement virtuel créé et géré
automatiquement) :

```bash
uv sync
uv run amnesia list-checks
uv run amnesia audit --target winrm://dc01
uv run amnesia render rapport.json --format md   # rendu d'un rapport archivé
```

Sans uv, toujours dans un environnement virtuel :

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e .
amnesia --help
```

`amnesia audit` écrit le rapport JSON dans `--out` (`amnesia-report.json` par
défaut, jamais écrasé sans `--overwrite` ; `--out -` l'envoie sur stdout et le
rendu texte sur stderr) et affiche les questions d'enquête sans réponse
(`--format text`, ou `json` pour le rapport lui-même ; `--no-color` et
`NO_COLOR` coupent les couleurs).

## Codes de sortie

Lancé depuis un RMM, une tâche planifiée ou une CI, un audit qui trouve des
angles morts ou qui n'a rien pu vérifier ne doit jamais paraître vert. Le code
de sortie traduit donc le contenu du rapport (`amnesia audit --help` reprend la
table ; constantes dans `amnesia.exitcodes`) :

| Code | Signification |
| --- | --- |
| `0` | Audit complet, aucun angle mort de sévérité >= `--fail-on`. |
| `1` | Au moins un angle mort de sévérité >= `--fail-on` (prioritaire sur 3). |
| `2` | Erreur d'usage ou de configuration (option, cible invalide, rapport déjà présent sans `--overwrite`). |
| `3` | Audit incomplet : un check en erreur, non exécuté ou en délai dépassé, sans angle mort au-dessus du seuil. « Pas pu vérifier » n'est pas « conforme » ; un check sans objet (`not_applicable`) ne rend pas l'audit incomplet. |
| `4` | Erreur fatale : aucune cible exploitable, rapport impossible à écrire ou à lire. |
| `130` | Interruption (Ctrl-C) : un rapport partiel est écrit, avec `run.interrupted = true`. |

`--fail-on {critical,high,medium,low,info,never}` (`low` par défaut) fixe le
seuil du code 1 ; `never` le neutralise, jamais le code 3. `amnesia render
<rapport.json> --fail-on <seuil>` applique la même table à un rapport archivé,
pour une CI qui ne refait pas l'audit ; sans `--fail-on`, un rendu réussi vaut
0. La table est stable : le sens d'un code ne change jamais et un code retiré
n'est jamais réattribué
([`docs/RELEASING.md`](https://github.com/yakohhhh/amnesia/blob/main/docs/RELEASING.md)).

## Développement

Pour contribuer (environnement, conventions, workflow Git, formulaires
d'issues) :
[`CONTRIBUTING.md`](https://github.com/yakohhhh/amnesia/blob/main/CONTRIBUTING.md).

Les outils (ruff, mypy, pytest, nox) sont épinglés dans `pyproject.toml` et figés
avec leurs empreintes dans `uv.lock`.

```bash
uv sync                             # installe le projet et le groupe dev depuis uv.lock
uv run nox -l                       # liste des sessions
uv run nox -s lint typecheck tests  # lint, typage + tests (toutes versions)
uv run nox -s build                 # sdist + wheel contrôlés, wheel installé dans un venv vierge
uv run mypy                         # typage strict de src et tests
uv run pytest                       # tests sur l'interpréteur de .python-version
```

La version n'est écrite qu'à un endroit : `__version__` dans
`src/amnesia/__init__.py`. Ce README est publié tel quel sur PyPI : liens absolus
uniquement. Choix de paquet (version minimale de Python, nom d'import) :
[`docs/PAQUET.md`](https://github.com/yakohhhh/amnesia/blob/main/docs/PAQUET.md).

Après une modification des dépendances : `uv lock`, et commiter `uv.lock`.

`uv.lock` applique un délai de carence de 7 jours (`exclude-newer` dans
`pyproject.toml`) : une version publiée trop récemment n'est jamais installée, le
temps qu'une éventuelle release compromise soit détectée. Dependabot propose
chaque semaine les mises à jour des actions et des outils, et le job CI
`pip-audit` bloque toute vulnérabilité connue dans `uv.lock` :
[`docs/dev/dependances.md`](https://github.com/yakohhhh/amnesia/blob/main/docs/dev/dependances.md).

Hooks avant commit (ruff, gitleaks, actionlint, refus des données client et des
fichiers de secrets) :

```bash
uv run pre-commit install
uv run pre-commit run --all-files
```

Un rapport amnesia est la carte des angles morts d'un client. Les sorties
(`amnesia-report*`, `amnesia-bundle*`, `amnesia-out/`, `reports/`, PDF hors de
`docs/`) et les fichiers de secrets (`.env`, `.pfx`, `.p12`, `.key`) sont ignorés
par git. Les hooks refusent aussi de les commiter, même avec `git add -f` et quelle
que soit la casse. Ces hooks sont une protection locale (`git commit --no-verify` les contourne) : la
CI rejoue les mêmes contrôles côté serveur, sur tout l'historique (job `gitleaks`).

## Versions et changements

Les changements notables de chaque version sont consignés dans
[`CHANGELOG.md`](https://github.com/yakohhhh/amnesia/blob/main/CHANGELOG.md).
[`docs/RELEASING.md`](https://github.com/yakohhhh/amnesia/blob/main/docs/RELEASING.md)
fixe le versionnage (SemVer, versions par milestone), les surfaces stables sur
lesquelles s'appuyer pour automatiser amnesia (ids de checks, `question_id`,
schéma du rapport JSON, codes de sortie, options de la CLI), leurs règles de
dépréciation et la procédure de release.

## Pourquoi Python

Les SDK dont le projet a besoin sont tous là et matures : Microsoft Graph,
boto3, WinRM, génération de rapports. On va vite, et les checks s'écrivent comme
des plugins indépendants.

## Vendable

C'est une **prestation de conseil que des cabinets facturent déjà** (digital
forensic readiness assessment). `amnesia` la transforme en produit : licence aux
MSP et aux cabinets d'audit, rapport client en marque blanche. Tu peux même le
facturer comme prestation dès la v0.

> Nom PyPI : le paquet s'appelle `amnesia-dfr` (le nom `amnesia` est pris), mais
> la commande reste `amnesia`. Il n'est pas encore publié (#33) : installe-le
> depuis les sources, jamais par son nom depuis PyPI.

## Scope & légal

Lecture seule, sur un périmètre que tu es autorisé à auditer. `amnesia` lit des
configurations, pas des données métier.

Un rapport est confidentiel : les règles de stockage, de transmission et de
conservation des données client, et le canal de signalement des vulnérabilités,
sont dans
[`SECURITY.md`](https://github.com/yakohhhh/amnesia/blob/main/SECURITY.md).

## Licence

MIT.
