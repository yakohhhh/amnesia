# amnesia

[![ci](https://github.com/yakohhhh/amnesia/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/yakohhhh/amnesia/actions/workflows/ci.yml)

**Ce que votre SI aura *oublié* le jour de l'incident.**

La pire surprise en réponse à incident, c'est de découvrir que les logs
n'existaient pas, ou qu'ils ont déjà été écrasés. `amnesia` est un outil d'audit
de *forensic readiness* : son but est d'auditer la télémétrie **avant**
l'incident (endpoints Windows, Active Directory, cloud) et de rendre la liste
des questions d'enquête qui resteraient **sans réponse**.

> Exemple de rendu, sur un rapport fictif : *« Qui s'est connecté en RDP sur
> SRV-FILE il y a trois semaines ? → Impossible : le journal Security fait 20 Mo
> et a été écrasé il y a 4 jours. »*

Le projet est en cours de développement : le socle fonctionne, mais **aucun
check n'est encore évalué** et rien n'est publié sur PyPI (section « État »).

## Périmètre visé

Cette liste décrit la cible, pas l'existant : aucun de ces contrôles n'est
encore évalué (section « État »).

- **Windows** ([M1](https://github.com/yakohhhh/amnesia/milestone/2)) :
  politique d'audit avancée, Sysmon, logging PowerShell, taille et rétention
  des journaux, synchronisation NTP.
- **Active Directory** ([M1](https://github.com/yakohhhh/amnesia/milestone/2)) :
  audit des objets sensibles, NTLM, modifications de GPO, autorités de
  certification.
- **Cloud** ([M2](https://github.com/yakohhhh/amnesia/milestone/3)) : rétention
  des logs Microsoft 365 / Entra ID, AWS CloudTrail.
- **Pipeline** ([M2](https://github.com/yakohhhh/amnesia/milestone/3)) : les
  événements partent-ils vraiment vers le SIEM ?
- **Linux et virtualisation**
  ([M3](https://github.com/yakohhhh/amnesia/milestone/6)) : journald, rsyslog,
  auditd, vSphere.

## État

Version de développement, jamais publiée. Sont fusionnés sur `main` le socle
([M0 — Scaffold](https://github.com/yakohhhh/amnesia/milestone/1)) et, premier
élément de [M1](https://github.com/yakohhhh/amnesia/milestone/2), le catalogue
des questions d'enquête :

- la commande `amnesia` et ses sous-commandes `audit`, `catalog`,
  `list-checks`, `render` et `schema` ;
- le catalogue embarqué des questions d'enquête : 31 questions (Windows et
  Active Directory), chacune avec les sources de télémétrie qui permettent d'y
  répondre ; il se consulte par `amnesia catalog list` et `amnesia catalog
  show <id>`, et se contrôle par `amnesia catalog validate`
  ([`docs/catalogue.md`](https://github.com/yakohhhh/amnesia/blob/main/docs/catalogue.md)) ;
- le moteur d'audit : il lance les checks sur une cible, isole un check en
  échec ou bloqué, et ne compte jamais conforme ce qui n'a pas été évalué ;
- le rapport JSON versionné et son JSON Schema, affiché par `amnesia schema`
  ([`docs/format-rapport.md`](https://github.com/yakohhhh/amnesia/blob/main/docs/format-rapport.md)) ;
- les rendus texte et Markdown d'un rapport, où chaque angle mort est formulé
  comme une question d'enquête ;
- des codes de sortie stables et une écriture protégée du rapport (sections
  « Démarrer » et « Codes de sortie ») ;
- un fonctionnement hors ligne, sans télémétrie (section « Confidentialité »).

Ce qui n'existe pas encore :

- **l'évaluation des checks** : les cinq checks Windows enregistrés déclarent
  leur intention et les faits qu'ils lisent, sans rien évaluer
  (`amnesia list-checks` les affiche « à implémenter » ;
  [`docs/dev/faits.md`](https://github.com/yakohhhh/amnesia/blob/main/docs/dev/faits.md)) ;
- **la collecte des faits** : ni sur la machine locale, ni à distance par
  WinRM, ni depuis un bundle hors ligne. `--target` accepte déjà
  `winrm://<hôte>` et `bundle:<chemin>`, mais rien n'y est collecté ;
- les checks Active Directory, cloud et Linux, et le rendu HTML.

Un audit ne détecte donc **aucun angle mort** aujourd'hui, et son résultat ne
dit rien de la télémétrie de la machine auditée : sous Windows, les cinq checks
sont « non exécutés » et l'audit se termine en code 3 (audit incomplet) ; sous
Linux et macOS, ils sont « sans objet » et le code est 0. Ce code 0 n'est pas
un audit réussi : le rendu annonce « tous les checks ont été évalués » alors
qu'aucun ne l'a été, un défaut suivi par
[#217](https://github.com/yakohhhh/amnesia/issues/217).

L'avancement se lit dans les
[milestones GitHub](https://github.com/yakohhhh/amnesia/milestones) : elles
seules font foi. Du M0, il reste la publication sur PyPI
([#33](https://github.com/yakohhhh/amnesia/issues/33)), qui attend le nom
définitif du projet ([#12](https://github.com/yakohhhh/amnesia/issues/12)), et
des réglages du dépôt ([#13](https://github.com/yakohhhh/amnesia/issues/13)).
Viennent ensuite
[M1 — MVP (Windows + AD)](https://github.com/yakohhhh/amnesia/milestone/2),
[M2 — Cloud](https://github.com/yakohhhh/amnesia/milestone/3) et
[M3 — Linux & virtualisation](https://github.com/yakohhhh/amnesia/milestone/6) ;
la vision de chaque milestone est dans
[`docs/ROADMAP.md`](https://github.com/yakohhhh/amnesia/blob/main/docs/ROADMAP.md).

## Démarrer

amnesia n'est pas encore publié sur PyPI
([#33](https://github.com/yakohhhh/amnesia/issues/33)) : il s'installe depuis
les sources, jamais par son nom depuis un index. Le paquet s'appelle
`amnesia-dfr` et sa commande, `amnesia` ; le paquet nommé `amnesia` sur PyPI
est un projet sans rapport, à ne pas installer.

Prérequis : git, et Python 3.11 ou plus récent (uv le télécharge au besoin).
Toutes les commandes se lancent depuis la racine du clone, sous macOS, Linux
ou Windows PowerShell ; une variante PowerShell est donnée quand la syntaxe
diffère.

```bash
git clone https://github.com/yakohhhh/amnesia.git
cd amnesia
```

### Avec uv

[uv](https://docs.astral.sh/uv/) crée et gère l'environnement virtuel
(installation vérifiée d'uv :
[`CONTRIBUTING.md`](https://github.com/yakohhhh/amnesia/blob/main/CONTRIBUTING.md#prérequis)) :

```bash
uv sync --locked
uv run amnesia list-checks
uv run amnesia audit
uv run amnesia render amnesia-out/amnesia-report.json --format md
```

`audit` audite la machine locale (`--target local`, la valeur par défaut),
écrit le rapport dans `amnesia-out/amnesia-report.json` et se termine en code 3
sous Windows, 0 sous Linux et macOS (section « État »). Relancé, il refuse
d'écraser ce rapport : ajouter `--overwrite`, ou choisir une autre destination
avec `--out`. `render` re-rend un rapport archivé, sans refaire l'audit.

Pour voir un rendu qui contient des angles morts, un rapport fictif sert aux
tests du dépôt :

```bash
uv run amnesia render tests/fixtures/report-min.json
```

### Sans uv, dans un environnement virtuel

Hors d'un environnement virtuel, un Python géré par le système (Homebrew,
Debian, Ubuntu) refuse `pip install`
([PEP 668](https://peps.python.org/pep-0668/)). Sous macOS et Linux (sous
Debian et Ubuntu, le paquet système `python3-venv` est requis) :

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/amnesia --help
```

Sous Windows PowerShell (sans le lanceur `py`, remplacer `py` par `python`) :

```powershell
py -m venv .venv
.\.venv\Scripts\python -m pip install -e .
.\.venv\Scripts\amnesia --help
```

### Sans installation

Le paquet de base n'a aucune dépendance tierce : il se lance depuis les
sources, avec Python 3.11 ou plus récent.

```bash
PYTHONPATH=src python3 -m amnesia --help
```

Sous Windows PowerShell, la variable vaut pour toute la session : la retirer
ensuite. Laissé en place, ce chemin relatif vaudrait pour tout Python lancé
depuis un autre dossier : les modules d'un dossier `src` qui s'y trouverait
passeraient avant ceux de la bibliothèque standard.

```powershell
$env:PYTHONPATH = "src"
py -m amnesia --help
Remove-Item Env:PYTHONPATH
```

### Le rapport

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

Les SDK dont le projet a besoin existent et sont matures : Microsoft Graph,
boto3, WinRM, génération de rapports. Les checks s'écrivent comme des plugins
indépendants.

Ces SDK restent optionnels : le paquet de base n'installe aucune dépendance
tierce. Chaque domaine apportera les siennes par un extra (`.[<extra>]`, ou
`.[all]` pour tous), importé seulement au moment de s'en servir : sans lui, les
checks concernés sont « non évalués » et le message donne la commande
d'installation depuis les sources. Le mécanisme est en place, mais aucun extra
de domaine n'existe encore : `all` est vide, et `amnesia list-checks` indique
l'extra requis par chaque check (`-` : aucun).
Politique d'acceptation d'une dépendance :
[`docs/dev/dependances.md`](https://github.com/yakohhhh/amnesia/blob/main/docs/dev/dependances.md).

## Confidentialité

Un rapport amnesia est la carte des angles morts d'un client : rien n'en sort
sans une décision explicite de l'utilisateur. amnesia est **hors ligne par
défaut** :

- il ne contacte que les cibles et les API désignées par l'utilisateur
  (`--target`, un connecteur cloud explicitement demandé) ; aucune donnée ne
  part vers l'éditeur, un CDN ou un service tiers ;
- pas de télémétrie, pas de vérification de mise à jour, pas de rapport de
  plantage ni d'envoi de rapport : une erreur interne est journalisée sur
  stderr, et c'est tout ;
- il fonctionne entièrement sans accès Internet, hors connecteurs cloud
  explicitement demandés ; `catalog`, `list-checks`, `render`, `schema` et
  `audit --target local` n'ouvrent aucune connexion ;
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
  `list-checks`, `schema`, `catalog`, `render`, `audit`) est aussi lancée dans
  un processus dont le réseau est coupé avant le moindre import d'amnesia.

Le futur contrôle de licence (#154) restera vérifiable hors ligne. Une
dépendance qui enfreindrait ces règles est une vulnérabilité à signaler
([`SECURITY.md`](https://github.com/yakohhhh/amnesia/blob/main/SECURITY.md)).

## Scope & légal

amnesia ne s'utilise que sur un périmètre que l'on est autorisé à auditer, par
un mandat écrit du propriétaire du système. Trois engagements de conception
encadrent la collecte :

- **lecture seule** : rien n'est écrit ni modifié sur la cible auditée
  ([ADR 0006](https://github.com/yakohhhh/amnesia/blob/main/docs/adr/0006-garantie-lecture-seule.md)) ;
  les opérations admises sont listées, une par une, dans
  [`docs/READ-ONLY.md`](https://github.com/yakohhhh/amnesia/blob/main/docs/READ-ONLY.md),
  et tout le reste est refusé avant exécution ;
- **périmètre autorisé** : aucune cible hors du périmètre déclaré n'est
  jointe ;
- **minimisation** : seules des configurations et des métadonnées de journaux
  sortent de la cible, jamais le contenu des événements ni des données métier ;
  l'inventaire des données traitées, avec leur finalité et leur lieu de
  stockage, est dans
  [`docs/DONNEES.md`](https://github.com/yakohhhh/amnesia/blob/main/docs/DONNEES.md).

Aucune collecte n'existe encore (section « État ») : ces engagements guident la
conception. L'allowlist des opérations de lecture
([#39](https://github.com/yakohhhh/amnesia/issues/39)) est livrée, et les
collecteurs à venir passeront par elle. Les contrôles de minimisation
([#41](https://github.com/yakohhhh/amnesia/issues/41)) le sont aussi : un fait,
une preuve ou un script qui porterait le contenu d'un événement est refusé.
Reste à livrer le fichier de périmètre vérifié avant toute connexion
([#37](https://github.com/yakohhhh/amnesia/issues/37)).

Un rapport est confidentiel : les règles de stockage, de transmission et de
conservation des données client, et le canal de signalement des vulnérabilités,
sont dans
[`SECURITY.md`](https://github.com/yakohhhh/amnesia/blob/main/SECURITY.md).

## Licence

Tout le contenu de ce dépôt est sous licence MIT
([`LICENSE`](https://github.com/yakohhhh/amnesia/blob/main/LICENSE)) ; aucune édition commerciale n'y est
publiée. Le modèle retenu est l'**open core**
([ADR 0001](https://github.com/yakohhhh/amnesia/blob/main/docs/adr/0001-modele-de-licence.md)) :
le cœur, ce dépôt, reste sous licence MIT et utilisable seul, de bout en bout ;
les éditions commerciales sont des composants séparés, sous licence
propriétaire, développés hors de ce dépôt.

Chaque fichier déclare sa licence en en-tête SPDX ou dans `REUSE.toml`,
et la conformité [REUSE](https://reuse.software/) est vérifiée en CI. Les
contributions sont acceptées sous DCO (`Signed-off-by` sur chaque commit, pas de
CLA) : voir
[`CONTRIBUTING.md`](https://github.com/yakohhhh/amnesia/blob/main/CONTRIBUTING.md#licence-des-contributions).
