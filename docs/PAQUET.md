# Paquet et distribution — décisions

Choix de packaging et leur justification. Les tests de `tests/test_paquet.py` et la
session `uv run nox -s build` (jobs CI `build` et `nox-windows`) les vérifient.

## Version : une seule source

`__version__` dans `src/amnesia/__init__.py` est la seule occurrence du numéro de
version dans le dépôt. `pyproject.toml` la déclare dynamique et setuptools
la lit statiquement (`[tool.setuptools.dynamic]`, lecture de l'AST, sans importer
le paquet). Conséquences :

- `amnesia --version`, `PYTHONPATH=src python -m amnesia --version` et
  `importlib.metadata.version("amnesia-dfr")` affichent la même version ;
- `uv.lock` n'enregistre plus la version du projet : une montée de version ne le
  périme pas.

La politique de versionnage, le CHANGELOG et la procédure de release sont décrits
dans [`RELEASING.md`](RELEASING.md) (#31). La version reste écrite à la main, sans
setuptools-scm, et le tag de release est créé d'après elle.

## Version minimale de Python : 3.11

`requires-python = ">=3.11"` (décision appliquée dans #170) :

- Python 3.10 est en fin de vie depuis le 1er octobre 2026 (PEP 619) : plus aucun
  correctif de sécurité. Un outil d'audit de sécurité ne doit pas s'installer sur
  un interpréteur qui n'en reçoit plus ;
- 3.11 apporte `enum.StrEnum` (statuts de résultat, #15) et `tomllib` (catalogue en
  TOML sans dépendance tierce, #46).

Ce plancher pilote la matrice CI, la liste `PYTHONS` du `noxfile.py`, la version
cible de ruff (déduite de `requires-python`) et les classifiers
`Programming Language :: Python :: 3.x` ; un test vérifie leur concordance. Le
`METADATA` du wheel porte `Requires-Python: >=3.11`.

## Nom de distribution et nom d'import

Le nom `amnesia` est pris sur PyPI : la distribution s'appelle `amnesia-dfr`.

Archive du projet `amnesia` 0.2.0 inspectée sans l'exécuter (sdist
`amnesia-0.2.0.tar.gz`, SHA-256 `872488421bf785100dc154da56caa142e0dafed04ed6c237f884f750e1f6d8ea`
conforme à PyPI, contenu listé avec `tar -t` puis lu en texte) :

- publié le 17 mai 2010, jamais mis à jour, sdist seul (aucun wheel) ;
- `setup.py` à base de `distutils` (retiré de Python 3.12) qui importe le module
  pendant l'installation ;
- installe un module de premier niveau `amnesia.py` (`py_modules`) **et** un script
  `amnesia` (`scripts`) : il entre en collision avec notre nom d'import comme avec
  notre commande.

**Décision : le nom d'import reste `amnesia`, la commande aussi.**

- La collision n'existe que si les deux distributions sont installées dans le même
  environnement. `amnesia-dfr` est une CLI, à installer dans un environnement
  dédié (`uv tool install`, `pipx`) ; l'autre projet est abandonné depuis 2010.
- Passer à `amnesia_dfr` ne réglerait pas la collision de commande, qui est celle
  que voit l'utilisateur, et rendrait `python -m amnesia_dfr` incohérent avec la
  commande.
- Le vrai risque est `pip install amnesia` par erreur : il installe le projet de
  2010 et exécute son `setup.py`. La documentation donne donc toujours le nom
  complet `amnesia-dfr`, jamais `amnesia` seul.

**Le nom `amnesia-dfr` n'est pas encore réservé sur PyPI** (404 sur
`https://pypi.org/pypi/amnesia-dfr/json`, vérifié le 26 octobre 2026). N'importe
qui peut l'enregistrer, et une installation par le nom seul (`uv tool install`,
`pipx`) installerait alors un paquet tiers. C'est le risque de `pip install amnesia`,
reporté sur le nom recommandé. Jusqu'à la première publication (#33, Trusted
Publishing ; un publisher « pending » ne réserve pas le nom) :

- installer uniquement depuis les sources (voir le README) ou depuis un wheel
  construit localement avec `uv build` :
  `uv tool install dist/amnesia_dfr-<version>-py3-none-any.whl` ;
- aucune commande de la documentation n'installe `amnesia-dfr` par son nom depuis
  un index. Un test parcourt `README.md` et `docs/` et échoue sinon ; #33 le retire
  quand il ajoute la ligne d'installation PyPI, une fois le nom publié ;
- le message d'un extra manquant, affiché par la CLI et repris dans les rapports,
  n'installe pas non plus par le nom : il donne la commande depuis les sources
  (`amnesia.deps.install_command`, vérifiée par un test). #33 y rétablit une
  commande par le nom qui vise l'environnement d'amnesia (`uv tool`, `pipx`)
  plutôt qu'un `pip` quelconque, et retire ce test avec le précédent.

À réexaminer si `amnesia` expose une API importable par des tiers (plugins), ou si
une collision est signalée.

## Métadonnées publiées

- **Description** accentuée, **keywords**, **classifiers** (`Typing :: Typed`
  arrive avec #9) et **`[project.urls]`**.
- **Licence** au format de la PEP 639 (#30) : `license = "MIT"` (expression SPDX,
  publiée en `License-Expression: MIT`) et `license-files = ["LICENSE"]` (fichier
  copié sous `.dist-info/licenses/` du wheel). Aucun classifier `License ::` :
  setuptools refuse de les combiner avec l'expression, d'où `setuptools>=77` dans
  `build-system.requires`. Modèle de licence :
  [ADR 0001](adr/0001-modele-de-licence.md).
- Le dépôt est public depuis le 29 octobre 2026 (#13) : les URL sont
  accessibles à tous. Le lien Changelog vise `CHANGELOG.md` (#31).
- Le `README.md` est la long_description publiée : liens absolus uniquement, un
  lien relatif pointerait vers pypi.org (test automatisé).

## Données du paquet

`[tool.setuptools.package-data]` déclare les données embarquées dans le wheel :
`schemas/*.json` (#22), le catalogue de questions (#46 : `catalog/VERSION`,
`catalog/ids.lock` et `catalog/*/*.toml`, soit `questions/` et `sources/`) et
`templates/**/*` (#77), sous `src/amnesia/`. Un test construit le wheel avec un
fichier placé à chacun de ces emplacements et vérifie sa présence ; un autre
compare les fichiers du catalogue du wheel à ceux du dépôt
([`catalogue.md`](catalogue.md)).

## Contrôles du paquet construit

`uv run nox -s build`, en CI sous Linux (job `build`) et Windows (job
`nox-windows`) :

1. `uv build` : sdist, puis wheel construit depuis le sdist, avec le setuptools
   figé par `build-constraint-dependencies` ;
2. `validate-pyproject pyproject.toml` (classifiers vérifiés hors ligne) ;
3. `twine check --strict` sur le sdist et le wheel ;
4. `check-wheel-contents` sur le wheel ;
5. wheel installé sans index dans un venv vierge, où il doit être le seul
   paquet (socle sans dépendance tierce) : `amnesia --version` doit afficher
   `importlib.metadata.version("amnesia-dfr")`, `amnesia list-checks` et
   `amnesia catalog validate` doivent sortir en code 0 (le catalogue de
   questions se lit depuis le wheel installé et reste cohérent avec le registre
   des checks), et `PYTHONPATH=src python -m amnesia --version` doit afficher la
   même version.

## Dépendances d'exécution : extras optionnels

Le paquet n'a aucune dépendance tierce d'exécution : chaque SDK (WinRM, LDAP,
Microsoft Graph, boto3...) entre par un extra de domaine, importé à la demande,
et l'extra `all` les agrège (#44). Convention, import paresseux, bornes de
version et politique d'acceptation :
[`docs/dev/dependances.md`](dev/dependances.md). Le message d'un extra manquant
donne la commande d'installation depuis les sources (`uv sync --inexact --extra
<extra>`, ou `pip install -e ".[<extra>]"`), jamais par le nom tant qu'il n'est
pas publié.

Hors périmètre : publication (#33).
