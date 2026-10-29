# 0003. Tenir un registre de décisions

- Statut : accepté
- Date : 2026-10-29
- Décideurs : mainteneur
- Tickets : #34

## Contexte et problème

Les décisions structurantes d'amnesia sont dispersées dans des tickets :
séparation collecte/évaluation (#20), statuts de résultat (#15), modèle Gap
(#16), schéma de rapport (#22), garantie lecture seule (#39), licence (#11),
bundles hors ligne (#52). Un ticket dit ce qu'on a fait ; il ne garde ni les
options écartées ni ce que le choix coûte, et il se perd dans un backlog de
plus de 150 issues. Le dépôt est public : contributeurs (#29), partenaires
licenciés et relecteurs du modèle de menace (#27) ont besoin d'un endroit
stable où lire le « pourquoi ».

## Facteurs de décision

- lisible sans outil, dans le dépôt, revu dans les PR comme le code ;
- un format connu des contributeurs, pas une convention maison ;
- léger : un ADR doit coûter moins qu'une heure, sinon il ne sera pas écrit ;
- stable : un lien vers une décision doit rester valable.

## Options envisagées

1. Fichiers Markdown au format MADR dans `docs/adr/`, un par décision, index
   dans un README.
2. Décisions consignées dans les tickets GitHub, avec un label `decision`.
3. Un document unique `docs/DECISIONS.md` tenu à jour.
4. Un wiki GitHub.

## Décision

Option 1 : `docs/adr/`, un fichier par décision, numéroté à quatre chiffres,
au format [MADR](https://adr.github.io/madr/) traduit en français (sections
« Contexte et problème », « Facteurs de décision », « Options envisagées »,
« Décision », « Conséquences », « Confirmation », « Avantages et inconvénients
des options »). Le README du répertoire tient l'index et définit les statuts
(proposé, accepté, déprécié, remplacé, rejeté). Un ADR accepté est immuable :
une décision qui change donne un nouvel ADR, l'ancien passe en « remplacé ».

Une décision pas encore tranchée, ou tranchée mais dont l'ADR est en cours,
figure dans l'index avec le statut « proposé » : le registre dit aussi ce qui
reste ouvert.

Le modèle de PR demande « Cette PR nécessite-t-elle un ADR ? », et
`CONTRIBUTING.md` renvoie vers l'architecture et le registre.

### Conséquences

- Bien : le « pourquoi » est versionné, relu, lié aux tickets et aux PR, et
  survit à la clôture des issues.
- Bien : un partenaire ou un auditeur externe lit cinq fichiers plutôt que
  150 tickets.
- Mal : une décision de plus à prendre à chaque PR (« faut-il un ADR ? ») ; la
  question dans le modèle de PR rend ce coût explicite et borné.
- Mal : un ADR peut vieillir sans que personne ne le marque « remplacé » ; la
  revue d'une PR qui change une frontière doit y penser.

### Confirmation

`tests/test_architecture.py` vérifie la forme du registre : fichiers
`NNNN-sujet.md`, numéros uniques et continus, sections obligatoires, statut
connu, ligne d'index pour chaque fichier, et question de l'ADR dans le modèle
de PR. La justesse d'une décision reste affaire de revue.

## Avantages et inconvénients des options

### Option 1 : MADR dans `docs/adr/`

- Bien : format connu, relu dans les PR, liens stables, lisible hors ligne.
- Mal : un fichier de plus par décision.

### Option 2 : tickets labellisés

- Bien : rien à créer, tout est déjà dans les tickets.
- Mal : un ticket mélange discussion et décision, se ferme, se renomme ; les
  options écartées sont dans des commentaires ; invisible hors de GitHub.

### Option 3 : un document unique

- Bien : une seule page à lire.
- Mal : conflits de merge sur chaque PR, pas d'immuabilité par décision, et
  une page qui grossit jusqu'à ne plus être lue.

### Option 4 : wiki GitHub

- Bien : édition rapide.
- Mal : hors du dépôt, sans revue de PR ni CI, et un wiki d'un dépôt public est
  éditable par défaut par tout compte GitHub.

## Pour aller plus loin

- [`docs/adr/README.md`](README.md) : index, statuts, gabarit.
- [`docs/architecture.md`](../architecture.md) : ce que les ADR expliquent.
- MADR : <https://adr.github.io/madr/>.
