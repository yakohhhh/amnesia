# 0005. Versionnage du schéma de rapport

- Statut : accepté
- Date : 2026-10-29
- Décideurs : mainteneur
- Tickets : #22, #31

## Contexte et problème

Le rapport JSON est le contrat machine d'amnesia : les rendus lisibles (#23,
#77), le diff entre deux audits (#142), le scoring (#139), la marque blanche
(#141) et les intégrations des MSP le lisent. Un rapport est aussi conservé des
mois chez un client et comparé à un rapport plus récent. Sans règle, un champ
renommé casse en silence un script d'intégration ou une comparaison.

## Facteurs de décision

- un consommateur doit savoir, à la lecture du seul rapport, s'il peut le
  traiter ;
- la version du rapport ne doit pas suivre celle du paquet : la plupart des
  releases ne changent pas le format ;
- le format doit être vérifiable mécaniquement, pas seulement documenté ;
- deux audits identiques doivent produire deux fichiers identiques
  (comparaison, tests golden).

## Options envisagées

1. Un champ `schema_version` SemVer propre au schéma, un JSON Schema par version
   majeure (`report-vN.schema.json`) embarqué dans le paquet et affiché par
   `amnesia schema`.
2. Le rapport porte la version du paquet (`tool.version`) et rien d'autre.
3. Pas de versionnage : les consommateurs s'adaptent.

## Décision

Option 1, mise en œuvre par #22 et reprise dans la politique de versionnage
(#31, `docs/RELEASING.md`) :

- `schema_version` suit SemVer indépendamment du paquet : **MAJEURE** pour une
  suppression, un renommage, un changement de type ou de sens, une nouvelle
  valeur d'énumération ou un champ rendu obligatoire ; **MINEURE** pour un
  champ optionnel ajouté ; **CORRECTIVE** pour une précision sans effet sur les
  rapports produits ;
- un consommateur refuse une MAJEURE inconnue et ignore les champs inconnus :
  le schéma v1 ne déclare pas `additionalProperties: false` et valide tout
  rapport `1.x.y` ; les tests vérifient en revanche qu'amnesia n'écrit aucun
  champ absent du schéma ;
- le schéma est embarqué (`src/amnesia/schemas/report-v1.schema.json`, draft
  2020-12) et publié tel quel par `amnesia schema` ;
- la sérialisation est déterministe (ordre des clés, tri des résultats et des
  Gaps, horodatages UTC `Z`, UTF-8 sans BOM) et un golden la fige ;
- les rendus lisibles (terminal, Markdown, HTML, PDF) lisent le rapport JSON,
  jamais les objets Python, et restent hors des surfaces publiques ;
- un champ déprécié est marqué `deprecated` (mot-clé JSON Schema) pendant la
  durée minimale commune de `docs/RELEASING.md` avant d'être retiré dans une
  MAJEURE.

Le même principe s'applique à l'enveloppe des faits (`amnesia.facts/1`, #20),
avec une version entière : un bundle d'une version inconnue est refusé avec un
message explicite.

### Conséquences

- Bien : un script d'intégration teste `schema_version` une fois ; un rapport
  de 2026 reste lisible par un amnesia de 2028 tant que la MAJEURE ne change
  pas.
- Bien : tout changement du golden est un changement du format, visible en
  revue.
- Mal : ajouter un champ demande de toucher le schéma, la documentation, le
  golden et `schema_version` ; c'est voulu.
- Mal : une MAJEURE du schéma est un changement incompatible du paquet, à
  éviter : préférer ajouter un champ à en changer le sens.

### Confirmation

- `tests/unit/test_rapport.py` : rapport validé par le schéma, golden
  `tests/golden/report.json`, aucun champ hors schéma, déterminisme.
- `tests/test_versionnage.py` : le schéma figure dans les surfaces publiques
  de `docs/RELEASING.md`.
- `docs/format-rapport.md`, section « Compatibilité ».

## Avantages et inconvénients des options

### Option 1 : `schema_version` et JSON Schema embarqué

- Bien : vérifiable hors ligne, indépendant du paquet, contrat lisible.
- Mal : un fichier de schéma à tenir.

### Option 2 : version du paquet seule

- Bien : rien à ajouter.
- Mal : chaque release oblige les consommateurs à vérifier si le format a
  changé ; une correction sans effet sur le format change quand même la
  version lue.

### Option 3 : aucun versionnage

- Bien : aucun travail.
- Mal : casse silencieuse des intégrations et des comparaisons d'audits ;
  inacceptable pour un livrable conservé des mois.

## Pour aller plus loin

- [`docs/format-rapport.md`](../format-rapport.md) : champs, déterminisme,
  compatibilité, exemple complet.
- [`docs/RELEASING.md`](../RELEASING.md) : surfaces publiques, dépréciation.
- [ADR 0004](0004-separation-collecte-evaluation.md) : l'enveloppe des faits.
