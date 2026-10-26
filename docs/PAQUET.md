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

La politique de versionnage (tags, setuptools-scm éventuel, CHANGELOG) relève de
#31.

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

À réexaminer si `amnesia` expose une API importable par des tiers (plugins), ou si
une collision est signalée.

## Métadonnées publiées

- **Description** accentuée, **keywords**, **classifiers** (aucun `License ::`,
  PEP 639 : #30 ; `Typing :: Typed` arrive avec #9) et **`[project.urls]`**.
- Le dépôt est privé : les URL renvoient une 404 aux visiteurs tant que la
  visibilité n'est pas tranchée (#11, #13), et `CHANGELOG.md` arrive avec #31.
- Le `README.md` est la long_description publiée : liens absolus uniquement, un
  lien relatif pointerait vers pypi.org (test automatisé).

## Données du paquet

`[tool.setuptools.package-data]` déclare les répertoires embarqués dans le wheel :
`schemas/*.json` (#22), `catalog/*.toml` (#46) et `templates/**/*` (#77), sous
`src/amnesia/`. Un test construit le wheel avec un fichier placé dans chacun d'eux
et vérifie sa présence.

## Contrôles du paquet construit

`uv run nox -s build`, en CI sous Linux (job `build`) et Windows (job
`nox-windows`) :

1. `uv build` : sdist, puis wheel construit depuis le sdist, avec le setuptools
   figé par `build-constraint-dependencies` ;
2. `validate-pyproject pyproject.toml` (classifiers vérifiés hors ligne) ;
3. `twine check --strict` sur le sdist et le wheel ;
4. `check-wheel-contents` sur le wheel ;
5. wheel installé sans index dans un venv vierge : `amnesia --version` doit
   afficher `importlib.metadata.version("amnesia-dfr")`, `amnesia list-checks`
   doit sortir en code 0, et `PYTHONPATH=src python -m amnesia --version` doit
   afficher la même version.

Hors périmètre : champ `license` et PEP 639 (#30), publication (#33), extras
optionnels (#44).
