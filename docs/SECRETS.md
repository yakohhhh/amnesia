# Secrets d'authentification

amnesia s'authentifie auprès du SI audité avec des comptes privilégiés : mot de
passe WinRM aujourd'hui, secrets cloud ensuite (#95). Ce document fixe d'où un
secret peut venir, dans quel ordre, et ce que chaque source ne protège pas.
Code : [`src/amnesia/secrets.py`](../src/amnesia/secrets.py). Menaces
couvertes : M15 et M17 du [modèle de menace](threat-model.md) ; risque
résiduel RR4.

## Règle : jamais de secret sur la ligne de commande

Aucune option d'amnesia ne prend une valeur secrète : pas de `--password`, de
`--token`, de `--secret` ni de `--client-secret`. Un argument est lisible par
tous les comptes du poste dans `ps` et `/proc/<pid>/cmdline`, reste dans
l'historique du shell et, si l'audit de la ligne de commande est actif, dans
les événements 4688 du poste de l'auditeur.

Seules sont admises les options qui **désignent une source**, comme
`--password-file CHEMIN`. Cette option s'écrit en entier : son abréviation
`--password`, qu'argparse accepterait, est refusée (code 2) sans que la valeur
soit lue ni affichée, pour qu'un mot de passe tapé par erreur ne soit pas pris
pour un chemin. Un test parcourt toutes les options de toutes les
sous-commandes et refuse celle dont le nom contient `password`, `secret`,
`token` ou `key` et qui prend une valeur, sauf si elle finit par `-file` et
désigne un chemin (`tests/unit/test_cli_secrets.py`).

## Les quatre sources, par ordre de priorité

La première source qui fournit le secret l'emporte, de la plus explicite à la
plus implicite. Une source désignée mais refusée (fichier trop ouvert,
trousseau en clair) arrête la commande : amnesia ne se rabat pas en silence sur
la suivante.

| Ordre | Source | Comment | Refus |
|---|---|---|---|
| 1 | Fichier | `--password-file CHEMIN` : une ligne, UTF-8 | droits plus larges que `0600`, autre propriétaire, fichier vide, sur plusieurs lignes ou de plus de 4096 octets |
| 2 | Variable d'environnement | `AMNESIA_WINRM_PASSWORD` | variable vide |
| 3 | Trousseau du système | entrée `amnesia/<mission>/<nom>`, lue par le module `keyring` | backend qui n'est pas un trousseau du système (`keyrings.alt`, dont `PlaintextKeyring`) |
| 4 | Saisie au terminal | invite `getpass`, sans écho | pas de terminal, écho impossible à couper, saisie vide |

Un refus est une erreur d'usage : code de sortie 2, avant que l'audit ne
commence, avec un message qui nomme la source et jamais la valeur.

### 1. Fichier (`--password-file`)

```console
$ umask 077
$ $EDITOR ~/.config/amnesia/winrm.txt     # une ligne : le mot de passe
$ amnesia audit --target winrm://<hôte> --password-file ~/.config/amnesia/winrm.txt
```

- Sous POSIX, le fichier doit appartenir au compte courant et n'accorder aucun
  droit au groupe ni aux autres (`0600` ou `0400`), comme une clé privée pour
  `ssh`. Un fichier en `0644` est refusé (code 2) : `chmod 600` le corrige. Les
  droits sont lus sur le fichier ouvert, liens symboliques suivis.
- Sous Windows, le mode ne décrit pas l'ACL : amnesia avertit de vérifier que
  seul ton compte peut lire le fichier (`icacls <fichier>`). La lecture de
  l'ACL elle-même n'est pas encore faite.
- La fin de ligne finale (`\n` ou `\r\n`) et un BOM UTF-8 sont retirés ; les
  espaces sont gardés.
- Dans le rapport, `run.argv` ne garde que le nom du fichier, pas son
  répertoire.

**Limites** : le secret est en clair sur le disque. Il est lisible par `root`,
par tout processus de ton compte, par une sauvegarde ou une synchronisation du
dossier, et par qui obtient le disque s'il n'est pas chiffré (M15). Supprime le
fichier à la fin de la mission ; ne le place jamais dans un dépôt git.

### 2. Variable d'environnement

```console
$ read -rs AMNESIA_WINRM_PASSWORD && export AMNESIA_WINRM_PASSWORD
$ amnesia audit --target winrm://<hôte>
```

amnesia retire la variable de son environnement dès qu'il l'a lue (et même
quand `--password-file` l'emporte, ou que la cible ne s'authentifie pas) :
aucun processus qu'il lance n'en hérite.

**Limites** : la variable reste définie dans le shell qui a lancé amnesia, et
tout processus lancé depuis ce shell en hérite : `unset AMNESIA_WINRM_PASSWORD`
après l'audit. L'environnement d'un processus est lisible par les autres
processus du même compte et par `root` (`/proc/<pid>/environ`, `ps e`).
`export AMNESIA_WINRM_PASSWORD=...` tapé tel quel finit dans l'historique du
shell : préfère `read -rs`, ou le mécanisme de secrets de ta CI.

### 3. Trousseau du système

Le secret est lu dans le Gestionnaire d'identifiants Windows, le Trousseau
macOS ou Secret Service (GNOME Keyring, KWallet) par le module Python
[`keyring`](https://pypi.org/project/keyring/), sous le service
`amnesia/<mission>` et le compte `<nom>` (`winrm-password`) : un jeu
d'identifiants par mission, sans croisement entre clients (M18).

```console
$ keyring set amnesia/<mission> winrm-password
```

- Seuls les backends fournis par `keyring` lui-même, qui s'appuient sur un
  trousseau chiffré du système, sont admis. Tout autre backend est refusé avec
  un message explicite, y compris au sein d'une chaîne de backends :
  `keyrings.alt` fournit `PlaintextKeyring`, qui écrit les secrets en clair
  dans un fichier.
- Sans module `keyring`, sans trousseau disponible (serveur sans session
  graphique) ou sans entrée à ce nom, la source est ignorée et la suivante est
  consultée.
- Le message d'erreur d'un backend n'est jamais recopié.

**Limites** : un trousseau déverrouillé rend le secret à tout processus de ta
session, sans nouvelle demande sur la plupart des systèmes. `keyring` est une
dépendance optionnelle qu'amnesia n'installe pas : elle doit être présente dans
le même environnement Python. La commande `amnesia audit` ne consulte pas
encore le trousseau : elle le fera quand la notion de mission existera (#148) ;
la fonction `amnesia.secrets.from_keyring()` est prête.

### 4. Saisie au terminal

En dernier recours, quand un mot de passe est requis et qu'aucune autre source
ne le fournit, amnesia le demande par `getpass`, sans écho.

- Sans terminal (CI, tube, tâche planifiée), la commande échoue tout de suite,
  code 2, avec la liste des sources consultées : elle n'attend jamais une
  saisie qui ne viendra pas.
- Si l'écho ne peut pas être coupé, la saisie est refusée plutôt que d'afficher
  le mot de passe.

**Limites** : une saisie se regarde par-dessus l'épaule, s'enregistre dans une
session partagée (`script`, enregistrement d'écran, multiplexeur de terminal
partagé) et se capture par un enregistreur de frappe (RR1).

## Ce qu'amnesia fait d'un secret

- La valeur est enveloppée dans le type `Secret` : `repr()`, `str()` et les
  f-strings rendent `***` ; `json.dumps`, `pickle`, `copy` et
  `dataclasses.asdict` échouent. Seule `reveal()` rend la valeur, au moment de
  la remettre au transport.
- Chaque secret lu est enregistré auprès du filtre d'expurgation
  (`amnesia.log`) : sa valeur, brute ou encodée dans une URL, est remplacée par
  `***` dans les journaux, dans les messages d'erreur et dans toute chaîne du
  rapport JSON.
- Aucun secret n'est écrit dans le rapport, dans les faits collectés ni dans
  `run.argv`.

**Limites communes** : le secret vit en clair dans la mémoire du processus le
temps de l'audit, et Python ne permet pas de l'effacer de façon fiable (RR4).
Le masquage porte sur la valeur exacte : une forme transformée par un tiers
(hachée, encodée en base64) n'est reconnue que par les motifs génériques du
journal. Un mot de passe très court, ou égal à un mot courant du rapport,
serait masqué partout où ce mot apparaît : c'est une raison de plus d'en
choisir un long. Sur un poste compromis, aucune de ces mesures ne tient (RR1).

## Pour qui ajoute un transport ou un connecteur

- Reçois un `Secret`, jamais une `str` ; appelle `reveal()` au dernier moment
  et ne garde pas le résultat dans un attribut.
- Ne mets jamais la valeur dans une exception, un fait, une preuve ou un
  message : le masquage est un filet, pas une permission.
- Une nouvelle source se déclare par une option qui la désigne
  (`--client-secret-file`), jamais par une option qui porte la valeur.
- Déclare dans `amnesia.cli.TRANSPORTS_A_MOT_DE_PASSE` le transport qui exige
  un mot de passe : la CLI le demandera au terminal faute d'autre source.
