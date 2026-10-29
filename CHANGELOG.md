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

[Unreleased]: https://github.com/yakohhhh/amnesia/commits/main
