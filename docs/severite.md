# Grille de sévérité des angles morts

Chaque `Gap` porte une sévérité (`Severity`, dans `src/amnesia/checks/base.py`)
parmi cinq niveaux, du plus grave au moins grave :

`critical` > `high` > `medium` > `low` > `info`

La sévérité mesure ce que l'angle mort coûte à l'enquête le jour de l'incident :
quelle question reste sans réponse, sur quelle partie du périmètre. Elle ne
mesure ni l'effort de remédiation, ni la probabilité d'une attaque.

| Valeur     | Niveau   | Rang | En une phrase                                              |
| ---------- | -------- | ---- | ---------------------------------------------------------- |
| `critical` | critique | 4    | question d'accès initial ou de périmètre sans réponse sur un actif critique |
| `high`     | élevée   | 3    | question clé sans réponse sur une partie du périmètre      |
| `medium`   | moyenne  | 2    | réponse partielle                                          |
| `low`      | faible   | 1    | enquête possible, mais ralentie                            |
| `info`     | info     | 0    | constat sans impact direct sur l'enquête                   |

## `critical` — critique

Une question d'accès initial ou de périmètre (qui est entré, par où, jusqu'où)
reste sans réponse sur un actif critique : contrôleur de domaine, bastion,
serveur d'authentification, console d'administration du SI.

Ex. : le journal Security d'un contrôleur de domaine couvre moins de 7 jours ;
une compromission découverte au bout de deux semaines ne laisse aucune trace
des authentifications initiales.

## `high` — élevée

Une question clé reste sans réponse sur une partie du périmètre, ou la fenêtre
observée est inférieure à 50 % de la fenêtre exigée.

Ex. : le journal Security de SRV-FILE fait 20 Mo et a été écrasé il y a
4 jours, pour 90 jours exigés ; « qui s'est connecté en RDP il y a trois
semaines ? » reste sans réponse.

## `medium` — moyenne

La question trouve une réponse partielle : l'événement existe, mais il lui
manque un élément nécessaire à l'enquête.

Ex. : l'événement 4688 (création de processus) est journalisé sans la ligne de
commande ; on sait qu'un `powershell.exe` a été lancé, pas ce qu'il a exécuté.

## `low` — faible

L'enquête reste possible, mais elle est ralentie ou demande des recoupements
manuels.

Ex. : les horloges de deux serveurs divergent de quelques secondes ; la
corrélation de leurs journaux reste possible, mais demande de recaler les
horodatages à la main.

## `info` — info

Constat sans impact direct sur la capacité d'enquête, utile au client pour
d'autres raisons (conformité, coût, hygiène).

Ex. : des journaux sont conservés au-delà de la durée recommandée par la CNIL ;
l'enquête n'en souffre pas, mais la conservation doit être justifiée.

## Règles d'usage

- **Ordre** : les comparaisons suivent le rang (`Severity.MEDIUM <
  Severity.HIGH`), jamais l'ordre alphabétique des valeurs, qui donnerait
  `critical` < `high` < `info` < `low` < `medium`. Une `Severity` ne se compare
  qu'à une autre `Severity`.
- **Saisie** : `Severity.parse("high")` donne `Severity.HIGH` ; une valeur
  inconnue (`"hihg"`, `"HIGH"`) lève une `ValueError` qui liste les cinq valeurs
  valides. Le constructeur de `Gap` applique la même conversion.
- **Tri des Gaps** : sévérité décroissante, puis question (ordre alphabétique,
  sans tenir compte des accents ni de la casse), puis cible.
- **Indice de compromission** : `compromise_indicator` est indépendant de la
  sévérité. Un journal effacé (#59) est un indice à investiguer, quelle que soit
  la sévérité de l'angle mort qu'il crée.
- **Certitude de la preuve** : la sévérité décrit l'angle mort ; la certitude
  de sa mesure est portée à part par `Evidence.confidence` (`measured`,
  `estimated`, `assumed`).
