# 0004. Séparation de la collecte et de l'évaluation

- Statut : accepté
- Date : 2026-10-29
- Décideurs : mainteneur
- Tickets : #20, #21, #15

## Contexte et problème

Dans le squelette initial, un check faisait tout : il joignait la cible,
lançait des commandes et jugeait leur sortie dans la même méthode `run()`.
Impossible de le tester sans un Windows et des droits, impossible de l'exécuter
sur un bundle hors ligne, et une collecte coûteuse (`auditpol`, registre) était
relancée par chaque check qui en avait besoin. Surtout, un check qui n'arrivait
pas à lire la cible pouvait rendre une liste de Gaps vide, indiscernable d'un
« rien à signaler » : exactement le faux sentiment de sécurité qu'amnesia doit
dissiper.

## Facteurs de décision

- tester chaque check sur la CI Linux, avec des faits enregistrés ;
- un même check pour le local, WinRM, SSH et le mode hors ligne ;
- ne jamais confondre « non configuré » (un fait observé, qui peut donner un
  Gap) et « non lisible » (accès refusé, fait absent, qui n'en donne jamais) ;
- une collecte par cible et par audit, quel que soit le nombre de checks.

## Options envisagées

1. Deux couches : des **collecteurs** produisent des faits nommés (`FactSet`),
   les **checks** déclarent les faits qu'ils lisent (`requires_facts`) et les
   évaluent dans une fonction pure (`evaluate(facts, ctx)`).
2. Garder `run()` dans le check, avec un objet « connexion » injecté et
   remplaçable par un faux dans les tests.
3. Un check par transport (`SysmonWinRM`, `SysmonBundle`...).

## Décision

Option 1, mise en œuvre par #20 et #21 :

- `amnesia.facts` porte le modèle (`Fact`, `FactSet`, enveloppe JSON versionnée
  `amnesia.facts/1` avec son JSON Schema) et les collecteurs (`Collector`,
  `CachingCollector`, `FixtureCollector`, `LocalCollector`) ;
- un check déclare `requires_facts` et implémente `evaluate(facts, ctx)` sans
  aucune I/O : ni processus, ni réseau, ni fichier, ni horloge système
  (`ctx.clock`) ;
- le moteur (`amnesia.runner.run_audit`) collecte les faits requis par un
  `CachingCollector` propre à l'audit, puis `resolve()` traduit tout fait
  indisponible en `error`, `skipped` ou `not_applicable` **avant** d'appeler
  `evaluate()` : un check n'est évalué que si tous ses faits sont observés ;
- le doute penche toujours vers « non évalué » : plusieurs faits manquants
  donnent une erreur avant un saut, un saut avant un `not_applicable`.

### Conséquences

- Bien : les checks se testent avec `FixtureCollector` et des fichiers de faits
  anonymisés ; la CI ubuntu les exécute tous.
- Bien : un nouveau transport est un collecteur de plus, sans toucher aux
  checks ([ADR 0007](0007-transports.md)).
- Bien : la garantie de lecture seule se concentre dans les collecteurs, seuls
  à joindre la cible ([ADR 0006](0006-garantie-lecture-seule.md)).
- Mal : deux schémas à tenir (faits et rapport) et un vocabulaire de clés de
  faits à stabiliser (#48) ; un check ne peut pas « demander un fait de plus »
  en cours d'évaluation.
- Mal : un fait est collecté même si le check, au vu des autres faits, n'en
  aurait pas eu besoin ; le coût est accepté pour garder `evaluate()` pure.

### Confirmation

- `tests/test_architecture.py` : aucun module de `amnesia.checks.<domaine>`
  n'importe de module d'I/O ni de collecteur (table des dépendances de
  `docs/architecture.md`).
- `tests/unit/test_collecte.py`, `test_resultats_checks.py`,
  `test_runner.py` : `resolve()` ne rend jamais de Gap, un fait indisponible
  donne le statut attendu, un fait n'est collecté qu'une fois par audit.
- `docs/dev/faits.md` : exemple complet, testé.

## Avantages et inconvénients des options

### Option 1 : collecteurs et checks purs

- Bien : testabilité, multi-transport, mémoïsation, statuts honnêtes.
- Mal : indirection supplémentaire, deux schémas.

### Option 2 : connexion injectée

- Bien : changement minimal du squelette.
- Mal : chaque check reste libre de lancer n'importe quelle commande ; la
  lecture seule et la mémoïsation dépendent de la discipline de chaque auteur ;
  le mode hors ligne exige de simuler une connexion.

### Option 3 : un check par transport

- Bien : aucun modèle de faits à définir.
- Mal : la logique d'évaluation est dupliquée par transport, et diverge.

## Pour aller plus loin

- [`docs/dev/faits.md`](../dev/faits.md) : enveloppe, collecteurs, écriture
  d'un check.
- `src/amnesia/facts/`, `src/amnesia/checks/base.py`, `src/amnesia/runner.py`.
- Statuts de résultat : #15 ; modèle Gap : #16.
