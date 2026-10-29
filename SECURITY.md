# Politique de sécurité

amnesia s'exécute chez des clients avec des comptes privilégiés (WinRM, LDAP,
Microsoft Graph, AWS) et produit des rapports qui dressent la carte de ce qu'un SI
ne journalise pas. Ce document dit comment signaler une vulnérabilité, ce que le
projet fait d'un signalement, et comment manipuler les données d'un client. Il
s'appuie sur le [modèle de menace][modele], dont il reprend les identifiants
(menaces `M`, risques résiduels `RR`).

## Versions supportées

En 0.x, seule la dernière version publiée reçoit les correctifs de sécurité. Une
faille est corrigée par une version corrective de la dernière série (0.2.0 →
0.2.1), jamais dans une série plus ancienne : pour une version antérieure, la
seule mesure est de mettre à jour.

| Version | Correctifs de sécurité |
|---|---|
| Dernière version 0.x publiée | Oui |
| Versions 0.x antérieures | Non : mettre à jour |
| `main` | Oui : tout correctif y arrive d'abord |

Rien n'est encore publié ([`CHANGELOG.md`][changelog]) : d'ici la 0.1.0, un
signalement porte sur `main`. Cette politique sera revue avant la 1.0.0, avec les
règles de stabilité de [`docs/RELEASING.md`][releasing].

## Signaler une vulnérabilité

**Jamais d'issue, de PR ni de discussion pour signaler une vulnérabilité** : le
dépôt est public, et tout ce qui y est écrit l'est aussi.

Le seul canal est le signalement privé de vulnérabilités de GitHub (*Private
Vulnerability Reporting*) :

1. onglet **Security** du dépôt, bouton **Report a vulnerability**, ou directement
   <https://github.com/yakohhhh/amnesia/security/advisories/new> (compte GitHub
   requis) ;
2. le signalement ouvre un brouillon d'avis de sécurité, visible uniquement de son
   auteur, des mainteneurs du dépôt et des personnes qu'ils y invitent ; toute la
   suite s'y déroule : questions, correctif, publication.

Le projet ne publie ni adresse e-mail ni clé de chiffrement : le signalement reste
dans GitHub, qui en restreint l'accès. Si le formulaire est indisponible, ouvrir
une issue qui demande seulement un canal de contact privé, sans aucun détail sur la
faille.

Un signalement utile indique :

- la version (`amnesia --version`) ou le commit, le système d'exploitation et la
  version de Python ;
- la faille, son impact et, si elle est identifiée, la menace du modèle de menace
  qu'elle touche ;
- les étapes de reproduction, avec des données fictives : jamais de rapport, de
  collecte ni d'identifiant d'un client (section « Données manipulées »).

## Délais

Le projet a un mainteneur unique. Les délais courent en jours calendaires à partir
du signalement :

| Étape | Délai |
|---|---|
| Accusé de réception | 72 h |
| Évaluation : faille confirmée ou non, gravité (score CVSS de l'avis), versions touchées | 7 jours |
| Correctif publié et divulgation coordonnée | 90 jours au plus |

- 90 jours est un plafond : une faille grave ou déjà exploitée est corrigée au plus
  vite. Un délai plus long n'est possible qu'avec l'accord de l'auteur du
  signalement, si le correctif l'exige.
- L'auteur est tenu informé dans l'avis à chaque étape, et de tout retard.
- Un signalement écarté (hors périmètre, non reproductible, comportement
  documenté) l'est par écrit, avec sa raison.

## Périmètre

**Dans le périmètre :**

- le code de ce dépôt : CLI, checks, collecte, transports et connecteurs,
  collecteur PowerShell hors ligne, rendus de rapport ;
- la chaîne de release : workflows GitHub Actions, construction et publication du
  paquet `amnesia-dfr`, artefacts publiés (#33) ;
- les mesures du modèle de menace déjà en place : une mesure contournable est une
  vulnérabilité.

Exemples : secret visible dans un journal ou dans la ligne de commande
([M17][menaces]), injection de script ou de séquences de terminal dans un rendu
([M01][menaces], [M02][menaces]), bundle importé qui écrit hors de son dossier
([M03][menaces]), validation TLS contournable ([M07][menaces]), opération en
écriture sur une cible ([M11][menaces]), données envoyées à un tiers
([M19][menaces]).

**Hors périmètre :**

- les environnements des clients et les systèmes audités : une lacune qu'amnesia
  y détecte est un constat d'audit, à traiter avec le client ;
- les failles propres à une dépendance, à signaler à son projet ; leur
  exploitation à travers amnesia reste dans le périmètre ;
- GitHub, PyPI et leurs infrastructures, qui ont leurs propres programmes ;
- les [risques résiduels][residuels] acceptés par le modèle de menace : un
  signalement qui en aggrave l'impact ou en révèle un nouveau reste bienvenu ;
- l'ingénierie sociale et le déni de service contre des services tiers.

## Recherche de bonne foi

Le projet considère comme autorisée, et ne poursuivra pas, une recherche menée de
bonne foi dans le respect de cette politique, c'est-à-dire :

- sur sa propre installation, ses propres systèmes ou un laboratoire, jamais
  sur un SI ou un tenant sans mandat écrit de son propriétaire ;
- sans accéder, modifier ou conserver plus de données que nécessaire pour
  démontrer la faille, et en supprimant le reste ;
- signalée par le canal ci-dessus, sans publication avant la fin de la
  divulgation coordonnée ;
- sans ingénierie sociale ni dégradation d'un service.

Cet engagement ne vaut que pour le projet amnesia : il n'autorise aucun test sur
un système tiers et n'engage ni GitHub, ni PyPI, ni les clients des utilisateurs
d'amnesia.

## Divulgation et correctifs

- **Divulgation coordonnée** : la faille reste confidentielle jusqu'à la
  publication du correctif, dans la limite de 90 jours. Passé ce délai sans
  correctif, l'avis est publié avec les contournements connus, et l'auteur du
  signalement est libre de publier.
- **Correctif** : préparé dans la fourche privée temporaire de l'avis, puis publié
  dans une version corrective ([`docs/RELEASING.md`, « Correctifs »][correctifs]).
  Il n'est jamais mergé depuis l'avis : GitHub n'exécute pas la CI dans la
  fourche privée, et ce merge n'applique pas la protection de `main`. Le
  mainteneur relit chaque commit et rejoue les contrôles de la CI en local avant
  que rien n'atteigne le dépôt public, puis le correctif arrive dans `main` par
  une PR ordinaire, avec `ci-ok` requis.
- **Avis de sécurité** : publié sur GitHub (identifiant GHSA) avec la version
  corrigée. Un CVE est demandé à GitHub, autorité d'attribution (CNA), dès que la
  faille touche une version publiée.
- **CHANGELOG** : la catégorie « Sécurité » de la version corrigée cite la faille,
  son avis et son CVE.
- **Crédit** : l'auteur du signalement est crédité dans l'avis, sauf s'il préfère
  rester anonyme.

## Vérifier les artefacts

Rien n'est encore publié sur PyPI, et le nom `amnesia-dfr` n'y est pas réservé :
un paquet de ce nom installé depuis un index peut être une usurpation
([M25][menaces]). Installer amnesia uniquement depuis les sources ou depuis un
wheel construit localement ([`docs/PAQUET.md`][paquet]).

À partir de la 0.1.0 (#33) :

- le paquet est publié par Trusted Publishing, sans jeton stocké, avec des
  attestations de provenance vérifiables sur PyPI ; #33 documentera leur
  vérification ([M22][menaces], [M25][menaces]) ;
- chaque version correspond à un tag signé, dont la signature est vérifiée avant
  toute publication ([`docs/RELEASING.md`][releasing]).

## Données manipulées

Ces règles valent pour quiconque exécute amnesia ou manipule ses sorties :
consultant, opérateur MSP, administrateur du client, mainteneur. Chacune répond à
une menace du [modèle de menace][menaces]. Plusieurs des mesures techniques
citées sont encore à venir (modèle de menace, « État des mesures ») : tant que
leur ticket n'est pas mergé, la règle repose sur l'opérateur seul.

### Ce que lit amnesia

amnesia travaille en lecture seule ([M11][menaces]), avec des comptes limités à ce
que les checks lisent ([M06][menaces]). Il lit des configurations (politique
d'audit, Sysmon, journalisation PowerShell, taille et rétention des journaux,
synchronisation horaire, paramètres d'audit d'Active Directory, de Microsoft 365
et d'AWS) et des métadonnées de journaux, jamais de contenu métier : ni fichiers,
ni messages, ni bases de données.

### Ce que contient un rapport

Un rapport liste ce qu'un attaquant peut faire chez le client sans laisser de
trace : journaux absents, trop courts ou jamais transmis au SIEM. Il contient
aussi des noms d'hôtes, de comptes et de domaines, des adresses IP, des
identifiants de tenant, parfois des données personnelles (#41). C'est un document
confidentiel, à traiter comme un rapport de test d'intrusion ([M20][menaces]). Les
collectes brutes, les bundles du collecteur hors ligne et le journal d'exécution
contiennent les mêmes données et suivent les mêmes règles.

### Règles

- **Mandat.** Ne collecter que sur une cible couverte par un mandat écrit du
  client, dans la période et hors des exclusions qu'il fixe (#37) : une collecte
  hors mandat est un accès non autorisé. Menace [M10][menaces].
- **Stockage.** Rapports, collectes, bundles et journaux d'exécution ne sont
  stockés que sur un disque chiffré, dans le répertoire de la mission, lisibles du
  seul opérateur (fichiers en 0600, dossiers en 0700, #25) ; jamais sur un support
  amovible non chiffré, un partage ouvert ou un service de synchronisation
  personnel. Menace [M15][menaces].
- **Jamais dans git.** Aucune sortie d'amnesia n'est commitée, dans ce dépôt ou
  ailleurs. Les sorties par défaut sont ignorées par git et refusées par les hooks
  de ce dépôt, que `--no-verify` contourne ; la CI rejoue les contrôles (#6, #7).
  Menace [M16][menaces].
- **Une mission, un client.** Chaque mission a son répertoire, son périmètre, ses
  identifiants et ses sorties : rien d'un client ne sert ni ne reste dans la
  mission d'un autre (#148). Menace [M18][menaces].
- **Transmission.** Un rapport ne quitte le poste que par un canal chiffré et
  authentifié (partage à accès nominatif, messagerie chiffrée de bout en bout), ou
  chiffré pour des destinataires nommés (#145). Il porte son marquage de diffusion
  (#79), et une diffusion large reçoit la version expurgée (#144). Menace
  [M20][menaces].
- **Rétention.** La durée de conservation est fixée par le cadre de la mission
  (#89). À la clôture, les collectes brutes et les bundles sont supprimés ; seul le
  rapport remis est conservé, le temps prévu. Menaces [M15][menaces] et
  [M18][menaces].
- **Identifiants.** Jamais persistés en clair, jamais passés en argument de ligne
  de commande (visibles dans `ps` et l'historique du shell), jamais copiés dans un
  rapport, un journal ou un ticket : variables d'environnement ou trousseau du
  système (#38). Un jeu d'identifiants par mission, révoqué à sa clôture. Menaces
  [M17][menaces] et [M05][menaces].
- **Support et signalements.** Ne jamais coller un rapport, une collecte, un
  bundle, un journal d'exécution ni aucune sortie produite chez un client dans une
  issue, une PR, une discussion, un signalement de vulnérabilité ou un échange de
  support : reproduire avec des données fictives ou anonymisées, selon les
  [règles des fixtures de test][fixtures]. Le dépôt est public : ce qui y est
  collé l'est aussi. Menaces [M16][menaces] et [M20][menaces].
- **Aucune télémétrie.** amnesia n'envoie rien à personne : ni télémétrie, ni
  vérification de mise à jour, ni ressource externe dans ses rendus. Ses seules
  connexions réseau sont celles de la collecte, vers les cibles (#26, #77). Une
  dépendance qui enfreint cette règle est une vulnérabilité à signaler. Menace
  [M19][menaces].

[modele]: https://github.com/yakohhhh/amnesia/blob/main/docs/threat-model.md
[menaces]: https://github.com/yakohhhh/amnesia/blob/main/docs/threat-model.md#menaces-et-mesures
[residuels]: https://github.com/yakohhhh/amnesia/blob/main/docs/threat-model.md#risques-résiduels
[changelog]: https://github.com/yakohhhh/amnesia/blob/main/CHANGELOG.md
[releasing]: https://github.com/yakohhhh/amnesia/blob/main/docs/RELEASING.md
[correctifs]: https://github.com/yakohhhh/amnesia/blob/main/docs/RELEASING.md#correctifs
[paquet]: https://github.com/yakohhhh/amnesia/blob/main/docs/PAQUET.md
[fixtures]: https://github.com/yakohhhh/amnesia/blob/main/tests/fixtures/README.md
