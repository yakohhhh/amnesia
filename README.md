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

## Confidentialité

Un rapport amnesia est la carte des angles morts d'un client : rien n'en sort
sans que tu le décides. amnesia est **hors ligne par défaut** :

- il ne contacte que les cibles et les API que tu désignes (`--target`, un
  connecteur cloud explicitement demandé) ; aucune donnée ne part vers l'éditeur,
  un CDN ou un service tiers ;
- pas de télémétrie, pas de vérification de mise à jour, pas de rapport de
  plantage ni d'envoi de rapport : une erreur interne est journalisée sur
  stderr, et c'est tout ;
- il fonctionne entièrement sans accès Internet, hors connecteurs cloud
  explicitement demandés ; `list-checks`, `render`, `schema` et `audit --target
  local` n'ouvrent aucune connexion ;
- ses rendus (texte, Markdown) ne chargent aucune ressource externe : ni image,
  ni feuille de style, ni script, ni police ; les liens de référence restent du
  texte ;
- tout sous-processus lancé par un collecteur reçoit
  `POWERSHELL_TELEMETRY_OPTOUT=1` et `POWERSHELL_UPDATECHECK=Off` dans son
  environnement : PowerShell 7 envoie sinon une télémétrie au démarrage puis
  pendant la session, et vérifie ses mises à jour ; la variable n'a d'effet que
  posée avant le lancement du processus.

Ces engagements sont tenus par le code, pas seulement par ce texte : seuls les
collecteurs (`src/amnesia/facts/collectors.py`, liste explicite dans
`pyproject.toml`) peuvent ouvrir une connexion, la règle ruff `TID251` interdit
`socket`, `urllib.request`, `http.client`, `requests` et `httpx` partout
ailleurs, et la suite de tests tourne avec le réseau coupé, sous-processus
compris. Le futur contrôle de licence (#154) restera vérifiable hors ligne. Une
dépendance qui enfreindrait cette règle est une vulnérabilité à signaler
([`SECURITY.md`](https://github.com/yakohhhh/amnesia/blob/main/SECURITY.md)).

## Scope & légal

Lecture seule, sur un périmètre que tu es autorisé à auditer. `amnesia` lit des
configurations, pas des données métier.

Un rapport est confidentiel : les règles de stockage, de transmission et de
conservation des données client, et le canal de signalement des vulnérabilités,
sont dans
[`SECURITY.md`](https://github.com/yakohhhh/amnesia/blob/main/SECURITY.md).

## Licence

MIT.
