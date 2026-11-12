# Changelog

Tous les changements notables d'amnesia sont consignés dans ce fichier.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le
projet applique le [versionnage sémantique](https://semver.org/lang/fr/), selon
les règles de [`docs/RELEASING.md`](docs/RELEASING.md) : catégories traduites
(Ajouté, Modifié, Déprécié, Supprimé, Corrigé, Sécurité), changements
incompatibles signalés par « **Incompatible** : ». Rien n'a encore été publié :
la première version sera la 0.1.0 (milestone M0).

## [Unreleased]

### Ajouté

- Paquet `amnesia-dfr`, commande `amnesia`, pour Python 3.11 ou plus récent ; une
  seule version, affichée par `amnesia --version` (#181).
- Commandes `amnesia list-checks` et `amnesia audit` (squelette) : cinq checks
  Windows enregistrés, dont l'évaluation reste à écrire.
- Registre des checks : métadonnées validées à l'import (domaine, version,
  cibles), ids `domaine.nom` uniques ; `amnesia list-checks` affiche id,
  domaine, état et titre sans instancier de check (#187).
- Cible `--target` validée strictement (`local`, `winrm://<hôte>[:port]` ou
  `bundle:<chemin>`) : une cible invalide est une erreur d'usage (code 2), sans
  écho de la saisie (#179).
- Statuts de résultat des checks (`pass`, `gap`, `error`, `skipped`,
  `not_applicable`) et leurs motifs : ce qui n'a pas été évalué n'est jamais
  compté conforme (#178).
- Journalisation : options `-v`, `-vv`, `-q`, `--debug`, `--log-file` (fichier
  créé en 0600) et `--log-format text|json`, horodatage UTC, diagnostics sur
  stderr, secrets expurgés (clés, jetons, mots de passe) (#180).
- Textes accentués, et sortie lisible sous Windows (cp1252, cp850) comme en UTF-8
  strict : un caractère impossible à encoder ne fait pas planter la commande
  (#182).
- Annotations de type publiées avec le paquet (marqueur `py.typed`) (#177).
- Moteur d'audit, utilisable comme API Python (`from amnesia import run_audit,
  AuditResult`) : faits collectés une fois par audit, délai par check (120 s par
  défaut), un check en échec ou bloqué n'arrête pas les autres, résultats triés
  par sévérité avec comptes par statut et par sévérité ; un Ctrl+C rend un
  audit partiel marqué interrompu (#195).
- Politique de sécurité `SECURITY.md` : signalement privé des vulnérabilités par
  GitHub, délais de traitement, périmètre, divulgation coordonnée, et règles de
  manipulation des rapports et des données client (#196).
- Rapport JSON versionné (`schema_version` 1.0.0) et son JSON Schema
  draft 2020-12, embarqué dans le paquet et affiché par `amnesia schema` :
  un résultat par check et par cible, Gaps triés par sévérité, comptes par
  statut et par sévérité, sérialisation déterministe, valeurs de `--password`,
  `--token`, `--secret` et `--client-secret` masquées dans `run.argv`. Format et
  compatibilité : `docs/format-rapport.md` (#22).
- Commande `amnesia render <rapport.json> --format text|md` : re-rend un rapport
  archivé sans refaire l'audit, chaque angle mort formulé comme une question
  (« → Impossible : … »), de critical à info, avec `--group-by
  severity|domain|target` et `--min-severity`. Section « Non vérifié »
  obligatoire pour les checks en erreur ou non exécutés, résumé chiffré, couleurs
  seulement sur un terminal sans `NO_COLOR` ni `--no-color`, repli ASCII (`->`)
  selon l'encodage de sortie. Les valeurs du rapport sont neutralisées (séquences
  ANSI, contrôles, bidi) et échappées en Markdown ; un rapport d'une autre
  version majeure de format est refusé (code 4) (#23).
- `amnesia audit` lance réellement les checks : rapport JSON écrit dans `--out`
  (jamais écrasé sans `--overwrite` ; un lien planté à cet emplacement n'est
  jamais suivi, même en écrasant ; `--out -` : JSON sur stdout, rendu texte
  sur stderr), rendu texte ou JSON sur stdout (`--format`, `--no-color`,
  `NO_COLOR`). Codes de sortie stables (`amnesia.exitcodes`, table dans
  `amnesia audit --help` et le README) : 0 audit complet sans angle mort au
  seuil, 1 angle mort de sévérité >= `--fail-on` (`low` par défaut, `never` ne
  neutralise que ce code), 2 usage, 3 audit incomplet (check en erreur ou non
  exécuté : « pas pu vérifier » n'est pas « conforme »), 4 erreur fatale, 130
  interruption avec rapport partiel. `amnesia render --fail-on` applique la
  même table à un rapport archivé. Sans sous-commande, l'aide part sur stderr
  (#24).

[Unreleased]: https://github.com/yakohhhh/amnesia/commits/main
