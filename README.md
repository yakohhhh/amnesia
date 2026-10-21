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
intention ; leur `run()` est à implémenter — voir [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Démarrer

Avec [uv](https://docs.astral.sh/uv/) (environnement virtuel créé et géré
automatiquement) :

```bash
uv sync
uv run amnesia list-checks
uv run amnesia audit --target dc01
```

Sans uv, toujours dans un environnement virtuel :

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e .
amnesia --help
```

## Développement

Les outils (ruff, pytest, nox) sont épinglés dans `pyproject.toml` et figés
avec leurs empreintes dans `uv.lock`.

```bash
uv sync                    # installe le projet et le groupe dev depuis uv.lock
uv run nox -l              # liste des sessions
uv run nox -s lint tests   # lint + tests sur toutes les versions supportées
uv run pytest              # tests sur l'interpréteur de .python-version
```

Après une modification des dépendances : `uv lock`, et commiter `uv.lock`.

`uv.lock` applique un délai de carence de 7 jours (`exclude-newer` dans
`pyproject.toml`) : une version publiée trop récemment n'est jamais installée, le
temps qu'une éventuelle release compromise soit détectée.

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
> la commande reste `amnesia`.

## Scope & légal

Lecture seule, sur un périmètre que tu es autorisé à auditer. `amnesia` lit des
configurations, pas des données métier.

## Licence

MIT.
