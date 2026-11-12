# Registre des décisions (ADR)

Ce répertoire garde le « pourquoi » des choix structurants d'amnesia, un fichier
par décision, au format [MADR](https://adr.github.io/madr/) traduit en français.
Le code dit ce qui est fait, [`docs/architecture.md`](../architecture.md) dit
comment c'est assemblé, et un ADR dit pourquoi on l'a voulu ainsi, quelles
options ont été écartées et ce que la décision coûte.

La règle du registre lui-même est l'[ADR 0003](0003-registre-des-decisions.md).

## Index

| N° | Décision | Statut | Date | Tickets |
|---|---|---|---|---|
| 0001 | Modèle de licence | proposé | 2026-10-29 | #11, #30 |
| 0002 | Nom et marque | proposé | 2026-10-29 | #12 |
| [0003](0003-registre-des-decisions.md) | Tenir un registre de décisions | accepté | 2026-10-29 | #34 |
| [0004](0004-separation-collecte-evaluation.md) | Séparation de la collecte et de l'évaluation | accepté | 2026-10-29 | #20, #21, #15 |
| [0005](0005-versionnage-du-schema-de-rapport.md) | Versionnage du schéma de rapport | accepté | 2026-10-29 | #22, #31 |
| [0006](0006-garantie-lecture-seule.md) | Garantie de lecture seule | accepté | 2026-10-29 | #27, #39, #37, #64 |
| [0007](0007-transports.md) | Transports : WinRM, SSH par le client OpenSSH, bundles hors ligne | accepté | 2026-10-29 | #63, #64, #119, #48, #52 |

Les ADR 0001 et 0002 sont en cours d'écriture dans les PR de #11 et de #12 ;
leurs numéros sont réservés ici pour que le registre reste dans l'ordre :

- **0001, modèle de licence** : le modèle *open core* a été retenu le
  29/10/2026 (cœur sous licence libre, modules commerciaux à part) ; les termes
  exacts et la politique de contribution (DCO ou CLA, #30) sont fixés par l'ADR.
  Tant qu'il n'est pas mergé, la licence déclarée reste MIT.
- **0002, nom et marque** : le changement de nom est décidé, le nouveau nom
  n'est pas choisi. Tant que l'ADR n'est pas mergé, le projet, le paquet
  (`amnesia-dfr`) et la commande (`amnesia`) gardent leur nom.

## Statuts

| Statut | Sens |
|---|---|
| proposé | décision non tranchée, ou tranchée mais ADR en cours de rédaction : rien ne s'appuie encore dessus |
| accepté | décision en vigueur : le code et les PR la suivent |
| déprécié | décision abandonnée sans successeur |
| remplacé par ADR-NNNN | décision remplacée : l'ADR reste, et renvoie à son successeur |
| rejeté | option étudiée et écartée, gardée pour mémoire |

Un ADR accepté ne se réécrit pas : une décision qui change donne un nouvel ADR,
et l'ancien passe en « remplacé ». Seuls le statut, la date et les liens d'un
ADR existant se mettent à jour.

## Quand écrire un ADR

Quand une PR change ce qu'un autre contributeur ne pourrait pas deviner en
lisant le code, et qu'on regretterait d'avoir oublié :

- une frontière entre modules ou une dépendance autorisée
  (`docs/architecture.md`) ;
- un transport, un connecteur ou un mode d'accès à la cible ;
- un format ou une surface publique (rapport, faits, codes de sortie, options) ;
- une garantie de sécurité, ou une exception à une garantie ;
- un choix de produit (licence, nom, modèle commercial).

Le modèle de PR pose la question : « Cette PR nécessite-t-elle un ADR ? ». Si
oui, l'ADR fait partie de la PR, ou la PR cite le numéro d'un ADR existant. Un
changement d'implémentation qui ne touche à aucune de ces frontières n'en a pas
besoin.

## Écrire un ADR

1. Prendre le numéro suivant de l'index (quatre chiffres) et nommer le fichier
   `NNNN-sujet-en-minuscules.md`, sans accents.
2. Partir du gabarit ci-dessous : chaque section est présente, même courte.
3. Ajouter la ligne de l'index, avec le statut « proposé » tant que la PR n'est
   pas mergée, « accepté » ensuite.
4. Aucune donnée client ni secret, comme partout dans le dépôt.

`tests/test_architecture.py` vérifie la forme : numéros uniques et continus,
sections obligatoires, statut connu, ligne d'index pour chaque fichier.

### Gabarit

```markdown
# NNNN. Titre de la décision

- Statut : proposé
- Date : AAAA-MM-JJ
- Décideurs : mainteneur
- Tickets : #N

## Contexte et problème

Le problème à résoudre, en deux ou trois phrases, et ce qui le rend
structurant.

## Facteurs de décision

- ce qui pèse dans le choix : sécurité, testabilité, coût, compatibilité...

## Options envisagées

1. Option A
2. Option B

## Décision

Option retenue, parce que...

### Conséquences

- Bien : ...
- Mal : ...

### Confirmation

Comment on vérifie que la décision est appliquée (test, revue, CI).

## Avantages et inconvénients des options

### Option A

- Bien : ...
- Mal : ...

### Option B

- Bien : ...
- Mal : ...

## Pour aller plus loin

Liens vers les tickets, la documentation et les ADR liés.
```
