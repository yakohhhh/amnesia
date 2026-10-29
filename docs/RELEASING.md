# Versionnage et procédure de release

Ce document fixe la numérotation des versions d'amnesia, les surfaces publiques à
garder stables et la procédure de release, du changement de version au push du
tag signé. L'historique des changements est tenu dans
[`CHANGELOG.md`](../CHANGELOG.md). La publication automatisée (workflow de
release, PyPI, release GitHub) relève de #33 : ce document décrit ce qui la
précède et ce qu'elle doit appliquer.

**État.** Rien n'a encore été publié : aucun tag, aucune release GitHub, aucun
paquet sur PyPI. La version déclarée aujourd'hui dans `src/amnesia/__init__.py`,
`0.1.0.dev0`, est une version de développement, jamais publiée ni taguée. La
première version publiée sera la 0.1.0 (milestone M0), par le workflow de #33.

Les tests de `tests/test_versionnage.py` vérifient la forme de ce document et du
CHANGELOG (table des milestones, surfaces publiques, catégories, renvois du
README), pas la justesse des règles.

## Numéros de version

| Numéro | Où on le lit | Règle | Ticket |
|---|---|---|---|
| Version du paquet | `__version__` dans `src/amnesia/__init__.py`, seule source ; `amnesia --version`, métadonnées du wheel, tag `vX.Y.Z` | SemVer, notation PEP 440 (section suivante) | #4 |
| `schema_version` du rapport | rapport JSON, schéma `report-vN.schema.json` | SemVer propre au schéma, indépendant de la version du paquet | #22 |
| `catalog_version` | fichier `VERSION` du catalogue, `tool.catalog_version` du rapport | CalVer (`2026.11.0`) | #46 |
| `version` d'un check | métadonnées du registre, `check_version` des résultats | entier incrémenté quand la logique du check change | #17 |

Ces numéros évoluent indépendamment. Une version du paquet peut ne changer ni le
schéma ni le catalogue ; une montée MAJEURE du schéma est en revanche un
changement incompatible du paquet.

**Version écrite à la main, sans setuptools-scm.** La version reste lisible sans
git (sdist, `python -m amnesia` depuis les sources), le build n'ajoute aucune
dépendance, et le changement de version est relu dans la PR de release. Le tag
est créé d'après `__version__`, jamais l'inverse ; le workflow de #33 refuse un
tag qui ne lui correspond pas.

Entre deux releases, `__version__` porte une version de développement PEP 440,
jamais publiée : `0.2.0.dev0` après la 0.1.0. Un rapport produit par du code non
publié ne se confond ainsi jamais avec un rapport d'une release (#142, menace
M14). `__version__` ne prend une version publiable (`X.Y.Z` ou `X.Y.ZrcN`) que
dans la PR de release, et revient à une version de développement juste après le
tag.

## SemVer

Les versions suivent le format `MAJEUR.MINEUR.CORRECTIF` de
[SemVer 2.0.0](https://semver.org/lang/fr/). Les pré-versions prennent la notation
PEP 440, que PyPI et pip normalisent : `0.1.0rc1` (et non `0.1.0-rc.1`), tag
`v0.1.0rc1`.

**En 0.x** (jusqu'à 1.0.0 exclue) :

- une **mineure** (0.2.0 → 0.3.0) apporte des nouveautés et peut casser la
  compatibilité. Chaque changement incompatible est signalé « Incompatible » dans
  le CHANGELOG, avec la marche à suivre ;
- un **correctif** (0.2.0 → 0.2.1) ne contient que des correctifs : bug, faille,
  documentation, mise à jour de dépendance. Aucune nouvelle fonctionnalité, aucun
  changement incompatible.

**À partir de 1.0.0**, SemVer strict sur les surfaces publiques :

- **majeure** : tout changement incompatible d'une surface publique ;
- **mineure** : ajout compatible (check, option, champ optionnel du rapport, code
  de sortie) ;
- **correctif** : correctifs seulement.

Un nouveau check peut faire apparaître de nouveaux Gaps, donc un code de sortie 1
là où l'audit passait : c'est le comportement attendu d'une mineure. Un check dont
la logique change incrémente sa `version` (#17) et figure dans « Modifié ».

## Milestones et versions

| Milestone | Version | Contenu |
|---|---|---|
| M0 — Scaffold | 0.1.0 | Socle : outillage, modèles, rapport JSON, commande `audit` réelle, première publication (#33) |
| M1 — MVP (Windows + AD) | 0.2.0 | Checks endpoints et Active Directory, rapport des angles morts |
| M2 — Cloud | 0.3.0 | Microsoft 365 / Entra ID, CloudTrail, forwarding SIEM |
| M3 — Linux & virtualisation | 0.4.0 | Cibles Linux et virtualisation |
| Offre v0 — prestation pilote | — | Piste commerciale et juridique, sans version du paquet |
| Backlog | — | Non planifié : un ticket rejoint une milestone versionnée avant sa release |

- Une milestone versionnée est livrée par la mineure qui la clôt. Les correctifs
  publiés entre-temps sont des versions correctives (0.2.1, 0.2.2…).
- Si une mineure doit sortir avant la clôture prévue, la table est mise à jour
  dans la même PR que la release, avec `.github/milestones.yml`.
- Les descriptions des milestones dans `.github/milestones.yml` reprennent leur
  version (« Version 0.1.0 — … »). `scripts/sync_github.py` les applique sur
  GitHub ([`docs/dev/github.md`](dev/github.md)) ; un test vérifie la concordance
  avec cette table.
- **1.0.0** n'est rattachée à aucune milestone : elle sort quand le format de
  rapport est stable, au plus tôt après une mineure entière sans changement
  incompatible du schéma (#22). La décision revient au mainteneur. Elle engage
  ensuite SemVer strict sur toutes les surfaces publiques.

## Surfaces publiques

Les MSP et les cabinets comparent des rapports dans le temps (#142) et
automatisent amnesia : les éléments ci-dessous forment son API publique. Les
règles s'appliquent à partir de la première publication (0.1.0). Avant, ces
éléments peuvent changer sans alias ni dépréciation : #17 renomme ainsi
`win.security_log_size` sans alias, puisqu'aucun id n'a été publié.

| Surface | Où on la trouve | Règle de stabilité | Dépréciation et retrait |
|---|---|---|---|
| Ids de checks (`win.audit_policy`) | registre (#17), `amnesia list-checks`, `check_id` du rapport, sélection (#74), exceptions (#143) | Jamais renommé sans alias ; un id retiré n'est jamais réattribué à un autre contrôle | Alias de dépréciation, durée minimale commune (section « Dépréciation »), illustré plus bas |
| `question_id` (`Q-WIN-RDP-LOGON`) | catalogue (#46), `question_id` des Gaps du rapport | Immuable, jamais réutilisé, consigné dans `catalog/ids.lock` | La question passe en `status = "deprecated"` avec `replaced_by` et reste dans le catalogue : son id n'est jamais retiré |
| Schéma du rapport JSON (`schema_version`) | `report-vN.schema.json`, `amnesia schema` (#22) | Versionné indépendamment du paquet : MAJEURE pour une suppression, un renommage ou un changement de type ; MINEURE pour un champ optionnel ajouté. Les consommateurs ignorent les champs inconnus | Champ marqué `deprecated` (mot-clé de JSON Schema 2020-12) pendant la durée minimale commune, puis retiré dans une MAJEURE du schéma |
| Codes de sortie | `amnesia/exitcodes.py`, section « Codes de sortie » du README (#24) | Stables : le sens d'un code ne change jamais et un code retiré n'est jamais réattribué. Un nouveau code n'arrive que dans une mineure, jamais à la place de 0 : ce qui échouait reste en échec | Pas de dépréciation : changer le sens d'un code est un changement incompatible (mineure signalée « Incompatible » en 0.x, majeure ensuite) |
| Options CLI et sous-commandes (`--target`, `--out`, `--fail-on`, `-v`) | `amnesia --help`, `amnesia <commande> --help` | Stables : nom, forme des valeurs et sens. Une valeur par défaut ne change que dans une mineure, signalée dans « Modifié » | Une option dépréciée fonctionne encore et émet un avertissement pendant au moins une version mineure (durée minimale commune) avant sa suppression |

**Hors des surfaces publiques**, donc susceptibles de changer dans n'importe quelle
version, à signaler dans le CHANGELOG quand l'utilisateur le voit :

- le rendu texte et Markdown (#23) et la formulation des messages : un script
  lit le rapport JSON, jamais la sortie lisible ;
- le journal de diagnostic (stderr, `--log-file`, y compris `--log-format json`) ;
- l'API Python (`amnesia.*`) : seule l'interface des checks tiers que définira
  #149 deviendra publique, avec ses propres règles.

## Dépréciation

Règles communes à toutes les surfaces publiques :

- **Durée minimale.** Un élément déprécié dans la mineure N reste utilisable dans
  toute la série N et dans toute la mineure suivante : il disparaît au plus tôt
  en N+2. Déprécié en 0.3.0, il fonctionne en 0.3.x et en 0.4.x, et peut être
  retiré en 0.5.0. À partir de 1.0.0, le retrait n'a lieu que dans une majeure,
  après ce même préavis.
- **Avertissement.** Chaque usage de l'élément déprécié émet un avertissement sur
  stderr, jamais sur stdout, qui porte le JSON avec `--out -` (#24).
  L'avertissement nomme le remplaçant et la version de retrait au plus tôt.
- **CHANGELOG.** L'annonce figure dans « Déprécié » de la version N, le retrait
  dans « Supprimé » de la version qui l'applique, marqué « Incompatible ».
- **Jamais de réattribution.** Un identifiant retiré (id de check, code de
  sortie, option) ne désigne jamais autre chose.
- Une dépréciation n'entre jamais dans un correctif : elle attend la mineure
  suivante.

## Alias de dépréciation des ids de checks

Un id de check publié n'est jamais renommé sans alias.

- L'alias associe l'ancien id au nouveau ; il est déclaré dans le registre des
  checks (#17), avec la version qui l'introduit et la version de retrait au plus
  tôt.
- Partout où l'utilisateur saisit un id (sélection `--check` et `--skip` de #74,
  exceptions de #143, profils de #47), l'ancien id est accepté, traduit vers le
  nouveau, et déclenche l'avertissement de dépréciation.
- Le rapport ne porte que le nouvel id. La comparaison de deux rapports (#142)
  traduit les anciens ids par les alias, pour qu'un renommage n'apparaisse pas
  comme un check retiré suivi d'un check ajouté.
- L'alias vit au moins la durée minimale commune : annoncé dans la mineure N, il
  est retiré au plus tôt en N+2. L'ancien id n'est ensuite jamais réattribué.
- Scinder un check en deux n'est pas un renommage : l'ancien id est déprécié, sans
  alias, et les deux nouveaux sont annoncés dans « Ajouté ».

### Exemple (fictif)

En 0.3.0, le check `win.time_sync` vérifie aussi le fuseau horaire et devient
`win.clock_sync`.

Le CHANGELOG de la 0.3.0 l'annonce :

```markdown
### Déprécié

- Id de check `win.time_sync` renommé `win.clock_sync` : l'ancien id reste
  accepté comme alias en 0.3.x et en 0.4.x, retrait au plus tôt en 0.5.0 (#NNN).
```

En 0.3.x et en 0.4.x, une sélection par l'ancien id fonctionne encore et avertit
sur stderr ; le rapport ne porte que `win.clock_sync` :

```console
$ amnesia audit --target winrm://dc01 --skip win.time_sync
avertissement : l'id de check « win.time_sync » est déprécié, utiliser « win.clock_sync » (retrait au plus tôt en 0.5.0)
```

En 0.5.0 (ou plus tard), l'alias est retiré :

```markdown
### Supprimé

- **Incompatible** : alias `win.time_sync` retiré, utiliser `win.clock_sync`
  (déprécié depuis la 0.3.0) (#NNN).
```

`win.time_sync` ne désignera plus jamais un autre check.

## CHANGELOG

[`CHANGELOG.md`](../CHANGELOG.md) suit
[Keep a Changelog 1.1.0](https://keepachangelog.com/fr/1.1.0/), rédigé en
français.

- La section `[Unreleased]` est toujours en tête. Chaque PR qui change ce que voit
  un utilisateur ou un intégrateur y ajoute son entrée, dans la même PR.
- Les catégories de Keep a Changelog, que sa traduction française garde en
  anglais, sont traduites une fois pour toutes et apparaissent dans cet ordre :

  | Keep a Changelog | amnesia |
  |---|---|
  | Added | Ajouté |
  | Changed | Modifié |
  | Deprecated | Déprécié |
  | Removed | Supprimé |
  | Fixed | Corrigé |
  | Security | Sécurité |

- Une catégorie vide n'apparaît pas.
- **Changement incompatible** : l'entrée commence par `**Incompatible** :` et
  donne la marche à suivre. Elle se range dans sa catégorie (souvent « Modifié »
  ou « Supprimé »), jamais dans un correctif.
- Une entrée tient en une phrase, du point de vue de l'utilisateur, avec le numéro
  de la PR : `(#123)`.
- « Sécurité » liste les failles corrigées, avec leur avis (GHSA, CVE) une fois
  publié, selon les règles de `SECURITY.md` (#28).
- Les changements purement internes (CI, outillage de développement,
  refactorisation sans effet visible) n'y figurent pas : l'historique git les
  garde.
- Une version publiée prend le titre `## [X.Y.Z] - AAAA-MM-JJ` (date UTC du tag,
  ISO 8601) et un lien de comparaison en bas du fichier. Seule une version finale
  est datée, jamais une pré-version ni une version de développement.
- Les versions sont rangées par numéro décroissant. Les dates ne décroissent
  qu'au sein d'une série `MAJEUR.MINEUR` : un correctif d'une série ancienne
  (0.1.1) peut sortir après une mineure plus récente (0.2.0), et se range sous
  elle.
- Les entrées sont écrites à la main, sans Conventional Commits. Un générateur de
  notes (git-cliff, release-drafter) pourra être ajouté plus tard sans imposer de
  format de commit ; la release GitHub reprend la section de la version (#33).

## Procédure de release

### Prérequis

- **Workflow de release (#33) mergé** et publishers PyPI configurés. Tant que ce
  n'est pas le cas, aucun tag n'est poussé : un tag poussé ne doit plus jamais
  être déplacé, et la 0.1.0 inaugure le workflow.
- **Réglages du dépôt** de la section « Protections côté GitHub » en place.
- **Clé de signature** SSH (recommandée) ou GPG, configurée dans git, déclarée sur
  GitHub comme clé de signature pour que le tag apparaisse « Verified », et
  inscrite par une PR relue dans `.github/allowed_signers`. Ce fichier, au format
  `allowed_signers` de git (une ligne `<e-mail> <clé publique>`, l'e-mail étant
  celui de `user.email`), est la liste des clés autorisées à signer une release :
  #33 vérifie le tag contre lui. Sans lui, `git tag -v` échoue sur un tag SSH
  pourtant bien signé (« gpg.ssh.allowedSignersFile needs to be configured »).

  ```sh
  git config --global user.signingkey <clé>   # chemin de la clé SSH publique, ou empreinte GPG
  git config --global gpg.format ssh          # seulement pour une clé SSH
  git config --global tag.gpgSign true        # tout tag annoté est signé
  git config gpg.ssh.allowedSignersFile .github/allowed_signers   # dans le clone du dépôt
  ```

  Avec une clé GPG, `git tag -v` s'appuie sur le trousseau local ; la clé publique
  est alors versionnée à côté de `.github/allowed_signers` pour que #33 puisse
  l'importer avant la vérification.

### Checklist

1. **Vérifier `main`.** Plus aucune issue ouverte dans la milestone (sinon,
   reportée explicitement), CI verte (`ci-ok`), section `[Unreleased]` complète et
   relue : chaque changement incompatible y est marqué « Incompatible ».
2. **Branche de release**, depuis `main` à jour :

   ```sh
   git fetch origin
   git switch -c release/vX.Y.Z origin/main
   ```

3. **Changer la version unique** : `__version__ = "X.Y.Z"` dans
   `src/amnesia/__init__.py`, seule occurrence du numéro dans le code et la
   configuration (#4) : ni `pyproject.toml` ni `uv.lock` ne changent.
4. **Dater le CHANGELOG** :
   - le contenu de `## [Unreleased]` passe sous `## [X.Y.Z] - AAAA-MM-JJ` ;
   - une section `## [Unreleased]` vide reste en tête ;
   - les liens du bas sont mis à jour :

     ```markdown
     [Unreleased]: https://github.com/yakohhhh/amnesia/compare/vX.Y.Z...HEAD
     [X.Y.Z]: https://github.com/yakohhhh/amnesia/compare/vPRÉCÉDENTE...vX.Y.Z
     ```

     Pour la 0.1.0, sans version précédente :
     `[0.1.0]: https://github.com/yakohhhh/amnesia/releases/tag/v0.1.0`.
5. **Contrôles locaux** :

   ```sh
   uv sync --locked
   uv run nox -s lint typecheck tests build
   uv run amnesia --version                    # amnesia X.Y.Z
   ```

6. **PR « Version X.Y.Z »**, qui ne contient que la version et le CHANGELOG.
   Mergée une fois la CI verte.
7. **Tag signé** sur le commit de merge, depuis `main` à jour :

   ```sh
   git fetch origin
   git switch --detach origin/main
   git log -1 --format='%H %s'                 # le merge de la PR de release
   uv run amnesia --version                    # amnesia X.Y.Z
   git tag -s vX.Y.Z -m "amnesia X.Y.Z"
   git tag -v vX.Y.Z                           # signature valide
   ```

8. **Push du tag**, qui déclenche la publication (#33) :

   ```sh
   git push origin vX.Y.Z                      # ce seul tag, jamais --tags
   ```

9. **Après la publication** : vérifier la release GitHub (sdist, wheel, extrait du
   CHANGELOG) et la page PyPI avec ses attestations (#33), puis fermer la
   milestone (`state: closed` dans `.github/milestones.yml`, puis
   `scripts/sync_github.py`).
10. **Retour en développement** : PR qui passe `__version__` à la version de
    développement suivante, jamais publiée. Après une version finale X.Y.Z, c'est
    `__version__ = "X.Y+1.0.dev0"` sur `main` (`0.2.0.dev0` après la 0.1.0) et
    `X.Y.Z+1.dev0` sur une branche de maintenance ; après une pré-version,
    `X.Y.Z.devN` avec N incrémenté. Le test du CHANGELOG exige que cette version
    suive la dernière version datée.

### Ce que la publication (#33) doit garantir

- déclenchement par le push d'un tag `v*`, et par lui seul ;
- échec avant toute publication si le tag diffère de `v` + `__version__`, ou si
  c'est une version de développement (`.devN`), qui n'est jamais publiée ;
- échec avant toute publication si le tag n'est pas un tag annoté signé par une
  clé de la liste autorisée (`git verify-tag "$GITHUB_REF_NAME"`), liste lue
  depuis `origin/main` (`git show origin/main:.github/allowed_signers`) et non
  depuis le commit taggé ;
- échec si le commit taggé n'est ancêtre ni de `origin/main` ni d'une branche
  `maint/*` protégée (`git merge-base --is-ancestor`) ;
- job de publication dans l'environnement `pypi` (section « Protections côté
  GitHub ») ;
- pré-version (`rcN`) publiée sur TestPyPI, version finale sur PyPI, par Trusted
  Publishing avec attestations, sans jeton stocké ;
- release GitHub avec le sdist, le wheel et la section du CHANGELOG de la
  version.

### Pré-versions

`vX.Y.ZrcN` suit la même checklist, avec `__version__ = "X.Y.ZrcN"` ; le
CHANGELOG ne date pas de pré-version, il ne date que la version finale. Le test
du CHANGELOG accepte une pré-version tant que la dernière version datée précède
X.Y.Z. La 0.1.0 passe par `v0.1.0rc1` sur TestPyPI avant PyPI (#33).

### Correctifs

Une version corrective (X.Y.Z+1) suit la même checklist. Si `main` contient déjà
des changements destinés à la mineure suivante, le correctif part d'une branche de
maintenance créée depuis le tag par un mainteneur (`git switch -c maint/X.Y.x
vX.Y.Z`), protégée comme `main` (section « Protections côté GitHub »). Chaque
report y arrive par une PR (`git cherry-pick` sur une branche de travail), relue
et avec la CI verte, jamais par un push direct ; le tag est posé sur le merge de
la PR de release de cette branche. L'entrée du CHANGELOG est aussi reportée dans
`main`, rangée par numéro de version : la 0.1.1 publiée après la 0.2.0 se place
sous la 0.2.0.

### Interdits

- Déplacer, supprimer ou réutiliser un tag publié ; `git push --tags` ;
  `--force` sur un tag.
- Republier un numéro : PyPI refuse un fichier déjà publié, même supprimé. Une
  version défectueuse est retirée (« yank ») sur PyPI et remplacée par un
  correctif.
- Publier depuis un poste (`twine upload`, `uv publish`) : seul le workflow de
  #33 publie.
- Tagger un commit qui n'est pas sur `main` ou sur une branche `maint/*`
  protégée, ou dont `__version__` est une version de développement.
- Pousser un commit directement sur une branche `maint/*`.

### Protections côté GitHub

Réglages du dépôt, à la main du propriétaire (#13), à mettre en place avant le
premier tag :

- un ruleset sur les tags `v*` qui réserve leur création aux mainteneurs et
  interdit leur mise à jour et leur suppression ;
- un ruleset sur les branches `maint/*` équivalent à la protection de `main` :
  PR obligatoire, `ci-ok` requis, ni push forcé ni suppression, création réservée
  aux mainteneurs ;
- un environnement `pypi` limité aux tags `v*`, avec approbation obligatoire d'un
  mainteneur, et le Trusted Publisher PyPI lié à cet environnement. Le workflow
  d'un tag s'exécute depuis le commit taggé : un tag posé sur un commit hors de
  `main` peut neutraliser les contrôles du workflow, pas l'approbation de
  l'environnement.

Ensemble, la signature du tag vérifiée par #33 contre `.github/allowed_signers`,
ces réglages et le Trusted Publishing répondent à la menace M22 du
[modèle de menace](threat-model.md) (chaîne de publication compromise). Pris
isolément, un tag signé ne protège de rien : tant que rien ne vérifie la
signature, un jeton de mainteneur volé suffit à pousser un tag non signé.
