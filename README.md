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

`amnesia audit` écrit le rapport JSON dans `--out` et affiche les questions
d'enquête sans réponse (`--format text`, ou `json` pour le rapport lui-même ;
`--no-color` et `NO_COLOR` coupent les couleurs). Le rapport est la carte des
angles morts du client, d'où ces règles d'écriture :

- sans `--out`, il va dans `amnesia-out/amnesia-report.json` : dossier créé en
  0700 et doté d'un `.gitignore` réduit à `*`, pour qu'un audit lancé dans un
  clone ne finisse pas commité ; un `amnesia-out` qui est un lien symbolique
  (ou une jonction), qui appartient à un autre compte, ou qui reste ouvert en
  écriture à d'autres comptes est refusé avant l'audit (code 2) ;
- le fichier est lisible du seul compte courant : 0600 sous Linux et macOS quel
  que soit l'umask, ACL réduite au compte courant et sans héritage sous Windows ;
- l'écriture est atomique : un audit interrompu ou une erreur ne laissent ni
  fichier partiel ni temporaire ;
- un rapport existant n'est jamais écrasé sans `--overwrite` (code 2), et une
  destination qui est un lien symbolique ou qui n'est pas un fichier ordinaire
  (dossier, FIFO, périphérique comme `/dev/null`) est refusée, même avec
  `--overwrite` ;
- une destination située dans un dépôt git sans y être ignorée déclenche un
  avertissement sur stderr ;
- `--out -` envoie le JSON sur stdout et le rendu texte sur stderr.

## Codes de sortie

Lancé depuis un RMM, une tâche planifiée ou une CI, un audit qui trouve des
angles morts ou qui n'a rien pu vérifier ne doit jamais paraître vert. Le code
de sortie traduit donc le contenu du rapport (`amnesia audit --help` reprend la
table ; constantes dans `amnesia.exitcodes`) :

| Code | Signification |
| --- | --- |
| `0` | Audit complet, aucun angle mort de sévérité >= `--fail-on`. |
| `1` | Au moins un angle mort de sévérité >= `--fail-on` (prioritaire sur 3). |
| `2` | Erreur d'usage ou de configuration (option, cible invalide, rapport déjà présent sans `--overwrite`, destination refusée : lien symbolique, fichier spécial, `amnesia-out` d'un autre compte). |
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
uv sync --all-extras                # projet, extras et groupe dev depuis uv.lock
uv run nox -l                       # liste des sessions
uv run nox -s lint typecheck tests  # lint, typage + tests (toutes versions)
uv run nox -s build                 # sdist + wheel contrôlés, wheel installé dans un venv vierge
uv run nox -s lowest-direct         # tests avec les bornes basses des extras
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

Ces SDK restent optionnels : le paquet de base n'installe aucune dépendance
tierce. Chaque domaine apporte les siennes par un extra (`.[<extra>]`, ou
`.[all]` pour tous), importé seulement au moment de s'en servir ; sans lui, les
checks concernés sont « non évalués » et le message donne la commande
d'installation depuis les sources. `amnesia list-checks` indique l'extra requis
par chaque check.
Politique d'acceptation d'une dépendance :
[`docs/dev/dependances.md`](https://github.com/yakohhhh/amnesia/blob/main/docs/dev/dependances.md).

## Vendable

C'est une **prestation de conseil que des cabinets facturent déjà** (digital
forensic readiness assessment). Le modèle retenu est l'**open core**
([ADR 0001](https://github.com/yakohhhh/amnesia/blob/main/docs/adr/0001-modele-de-licence.md)) :

- **le cœur**, ce dépôt, reste sous licence MIT, gratuit pour tous, cabinets et
  MSP compris : moteur et catalogue de checks, collecte, collecteur PowerShell
  déposé chez le client, CLI, rapports JSON, texte, Markdown et HTML sans
  marque. Il reste utilisable seul, de bout en bout, pour auditer son propre SI
  ou celui d'un client ;
- **les éditions commerciales** (rapport client en marque blanche, export PDF,
  scoring de maturité, fonctionnalités MSP multi-clients) sont des composants
  séparés, sous licence propriétaire, développés hors de ce dépôt.

Tu peux même facturer l'audit comme prestation dès la v0, avec le cœur seul.

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
- tout sous-processus lancé par amnesia, `pwsh` compris, reçoit
  `POWERSHELL_TELEMETRY_OPTOUT=1` et `POWERSHELL_UPDATECHECK=Off` dans son
  environnement : PowerShell 7 envoie sinon une télémétrie au démarrage puis
  pendant la session, et vérifie ses mises à jour ; la variable n'a d'effet que
  posée avant le lancement du processus.

Ces engagements sont tenus par le code, pas seulement par ce texte :

- seuls les collecteurs (`src/amnesia/facts/collectors.py`, liste explicite
  dans `pyproject.toml`) peuvent ouvrir une connexion : la règle ruff `TID251`
  interdit partout ailleurs `socket.socket`, `socket.create_connection`,
  `asyncio.open_connection`, `asyncio.start_server`, `http.client`,
  `urllib.request`, `urllib3`, `requests`, `httpx` et les handlers de
  journalisation réseau (`logging.handlers.HTTPHandler`, `SysLogHandler`,
  `SocketHandler`…), et un test refuse hors des collecteurs tout import d'un
  module réseau ou d'un SDK de connexion (`importlib.import_module` compris) et
  toute méthode de connexion d'une boucle asyncio ;
- un test vérifie que chaque sous-processus lancé par amnesia reçoit
  l'environnement de `amnesia.facts.subprocess_env()` ;
- les tests coupent le réseau, et chaque commande (`--help`, `--version`,
  `list-checks`, `schema`, `render`, `audit`) est aussi lancée dans un
  processus dont le réseau est coupé avant le moindre import d'amnesia.

Le futur contrôle de licence (#154) restera vérifiable hors ligne. Une
dépendance qui enfreindrait ces règles est une vulnérabilité à signaler
([`SECURITY.md`](https://github.com/yakohhhh/amnesia/blob/main/SECURITY.md)).

## Scope & légal

Lecture seule, sur un périmètre que tu es autorisé à auditer. `amnesia` lit des
configurations, pas des données métier. Ce que ses collecteurs ont le droit
d'exécuter sur une cible est listé, opération par opération, dans
[`docs/READ-ONLY.md`](https://github.com/yakohhhh/amnesia/blob/main/docs/READ-ONLY.md) :
tout le reste est refusé avant exécution.

Un rapport est confidentiel : les règles de stockage, de transmission et de
conservation des données client, et le canal de signalement des vulnérabilités,
sont dans
[`SECURITY.md`](https://github.com/yakohhhh/amnesia/blob/main/SECURITY.md).

## Licence

Tout le contenu de ce dépôt est sous licence MIT
([`LICENSE`](https://github.com/yakohhhh/amnesia/blob/main/LICENSE)) ; aucune édition commerciale n'y est
publiée. Chaque fichier déclare sa licence en en-tête SPDX ou dans `REUSE.toml`,
et la conformité [REUSE](https://reuse.software/) est vérifiée en CI. Les
contributions sont acceptées sous DCO (`Signed-off-by` sur chaque commit, pas de
CLA) : voir
[`CONTRIBUTING.md`](https://github.com/yakohhhh/amnesia/blob/main/CONTRIBUTING.md#licence-des-contributions).
