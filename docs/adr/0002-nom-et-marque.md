# ADR 0002 — Nom et marque

| | |
|---|---|
| Statut | **Accepté partiellement** le 29/10/2026 par le propriétaire du dépôt : le changement de nom est acté, le nouveau nom reste **en attente** de son choix (voir [En attente](#en-attente)) |
| Décideur | Ayman Mazroui, propriétaire du dépôt |
| Ticket | #12 ; bloqués par cet ADR : #33 (publication PyPI), #93 (landing page) ; indépendant de #11 (licence) |
| Supplante | — |

## Contexte

Le projet s'appelle « amnesia » depuis son premier commit. Le nom dit bien ce
que le produit vend (« ce que ton SI aura *oublié* le jour de l'incident »),
mais il cumule quatre handicaps, dont le premier est rédhibitoire pour le
propriétaire :

- **Connotation stupéfiants en français.** « Amnesia » (ou « amnésia ») est le
  nom courant d'une variété de cannabis, et c'est le premier sens que le mot
  évoque à une partie du public francophone visé (RSSI, DSI, cabinets, MSP).
  Un rapport d'audit livré à un comité de direction sous ce nom part avec un
  handicap que ne compense aucune autre qualité du nom.
- **Nom chargé dans le secteur.** Tails s'appelait « amnesia » à ses débuts
  (2009) ; AMNESIA:33 (Forescout, 2020) désigne 33 vulnérabilités de piles
  TCP/IP ; « Amnesia » est aussi un outil d'anonymisation de données (OpenAIRE,
  dépôt `dTsitsigkos/Amnesia`, 176 étoiles). Les recherches « amnesia security »
  ne renverraient pas vers ce projet avant longtemps.
- **Nom PyPI occupé.** `amnesia` est pris par un rechargeur WSGI abandonné
  (version unique 0.2.0 du 17/05/2010). La PEP 541 ne permet un transfert
  qu'à un projet déjà publié et notable, après tentatives de contact prouvées :
  irréaliste avant une première release. D'où l'écart actuel entre le paquet
  `amnesia-dfr` et la commande `amnesia`.
- **Domaines pris.** amnesia.com (1995), amnesia.fr (2009) et amnesia.io (2016)
  sont enregistrés.

Rien n'a encore été réservé ni publié sous ce nom : `amnesia-dfr` n'existe pas
sur PyPI, aucun domaine n'est réservé, aucune marque n'est déposée. Changer de
nom maintenant ne coûte que le renommage dans le dépôt ; après la première
release (#33) et la landing page (#93), chaque semaine ajouterait un coût.

## Décision

**Changer de nom.** « amnesia » n'est pas conservé comme nom commercial, ni
comme nom de paquet, ni comme nom de commande.

Le nouveau nom n'est pas choisi dans cet ADR : l'étude ci-dessous propose six
candidats vérifiés et un classement argumenté, et le choix final revient au
propriétaire (voir [En attente](#en-attente)). Jusqu'à ce choix :

1. Le dépôt, le paquet `amnesia-dfr`, la commande `amnesia` et le README
   gardent le nom actuel : un renommage provisoire vers un candidat non retenu
   coûterait deux fois (voir [Écart avec le code](#écart-avec-le-code)).
2. Aucune publication sur PyPI (#33) ni de landing page (#93) sous l'ancien
   nom.
3. Aucun domaine n'est acheté et aucune marque n'est déposée pour « amnesia ».

Une fois le nom choisi, cet ADR passe au statut « Accepté » avec le nom
retenu, le domaine réservé, l'adresse de contact et, le cas échéant, le numéro
du dépôt de marque ; le renommage du code se fait dans une PR dédiée.

## Candidats

Six candidats en rapport avec le positionnement (forensic readiness, angles
morts, mémoire et journaux), en français ou en latin pour rester prononçables
en anglais :

| Nom | Sens et lien avec le produit | Prononciation en anglais |
|---|---|---|
| **lacune** | Ce qui manque : le produit rend la liste des *lacunes* de télémétrie, et chaque `Gap` du rapport en est une. Mot français courant, cognat de *lacuna* en anglais. | « la-KOON » ; *lacuna* est un mot anglais savant |
| **souvenance** | Vieux mot français pour « souvenir, mémoire de ce qui s'est passé » : ce que l'audit garantit au SI. | « soo-ve-NANCE » ; quatre syllabes |
| **remanence** | *Rémanence* : persistance d'une trace après la disparition de sa cause ; la *rémanence des données* est un terme établi en sécurité. | identique en anglais (*remanence*) |
| **oubliette** | Cachot où l'on jette ce que l'on veut oublier : là où finissent les journaux non conservés. Mot français passé tel quel en anglais. | « oo-blee-ET », connu des anglophones |
| **vestige** | Trace qui subsiste : ce que l'analyste trouve, ou non, après l'incident. Même mot dans les deux langues. | identique |
| **memento** | « Souviens-toi » (latin) ; le film du même nom traite précisément d'amnésie. | identique |

Trois autres noms ont été écartés dès la première vérification, sans entrer
dans les tableaux : **oubli** (PyPI occupé par un projet actif de 2026,
organisation GitHub prise, .com/.fr/.io enregistrés), **lethe** (PyPI occupé,
906 dépôts GitHub, .com/.fr/.io enregistrés) et **lacunae** (PyPI occupé depuis
le 02/03/2026 par un outil d'analyse d'écarts réglementaires, et trop proche de
« lacune » pour cohabiter).

## Vérifications datées

Toutes les vérifications ci-dessous datent du **29/10/2026** et ont été faites
depuis ce dépôt, sans compte ni réservation. Méthode, reproductible à la main :

- **PyPI** : `https://pypi.org/pypi/<nom>/json` ; 404 = nom libre, sinon
  version, nombre de versions et dates des dépôts lus dans la réponse. La
  normalisation PEP 503 (`-`, `_`, `.`, casse) est appliquée par PyPI : la
  réponse vaut pour les variantes.
- **GitHub** : `GET /search/repositories?q=<nom>+in:name` (total approximatif
  et nombre de dépôts dont le nom est exactement `<nom>`, casse ignorée, parmi
  les 100 premiers) et `GET /users/<nom>` (compte ou organisation).
- **Domaines** : RDAP du registre (Verisign pour .com, Afnic pour .fr, Identity
  Digital pour .io ; serveurs trouvés via `https://data.iana.org/rdap/dns.json`,
  .io n'y figurant pas) : 200 = enregistré, 404 = libre. Un domaine libre en
  RDAP peut être réservé ou mis en vente premium par le registre : la
  disponibilité réelle se confirme au moment de l'achat.
- **Gestionnaires de paquets** : Homebrew (`formulae.brew.sh/api/formula/` et
  `/cask/`), winget (recherche de code dans `microsoft/winget-pkgs`, chemin des
  manifestes), Chocolatey (`community.chocolatey.org/packages/<nom>`, 404 =
  libre) et Debian (`sources.debian.org/api/src/<nom>/`).
- **Homonymes en sécurité** : recherche web « `<nom>` security OR forensics
  tool », en anglais et en français.
- **Marques** : data.inpi.fr et TMview (EUIPO) sont des applications sans API
  publique documentée ; les seuls accès automatisés trouvés sont des scrapers
  tiers, écartés. Chaque cellule donne l'URL de la recherche à faire à la main,
  en classes de Nice 9 (logiciels) et 42 (services informatiques et conseil en
  sécurité).

### Disponibilité

| Nom | PyPI | GitHub (dépôts au nom exact / compte) | .com | .fr | .io | Homebrew / winget / Chocolatey / Debian | Date |
|---|---|---|---|---|---|---|---|
| amnesia | occupé : 0.2.0, 1 version du 17/05/2010, rechargeur WSGI | 31 dépôts (`meh/amnesia` 707 étoiles, `dTsitsigkos/Amnesia` 176) / compte pris | enregistré | enregistré | enregistré | libre / libre / libre / libre | 29/10/2026 |
| amnesia-dfr | libre | aucun / libre | libre | libre | libre | libre / libre / libre / libre | 29/10/2026 |
| lacune | libre | 1 dépôt (`alesr/lacune`, 1 étoile) / compte pris | enregistré | enregistré | **libre** (.dev, .app, .net, .org et .tech libres aussi) | libre / libre / libre / libre | 29/10/2026 |
| souvenance | libre | 2 dépôts sans étoile / compte pris | enregistré | enregistré | **libre** (.dev, .net et .tech libres ; .app et .org enregistrés) | libre / libre / libre / libre | 29/10/2026 |
| remanence | occupé : 0.1.0a1, 9 versions du 30/07 au 24/08/2026, bibliothèque d'analyse d'images disque | 23 dépôts (3 étoiles au plus) / compte pris | enregistré | enregistré | enregistré (.dev, .app, .net et .org enregistrés ; .tech libre) | libre / libre / libre / libre | 29/10/2026 |
| oubliette | occupé : 0.0.1 du 27/06/2020, jeu | 41 dépôts (3 étoiles au plus) / compte pris | enregistré | libre | enregistré | libre / libre / libre / libre | 29/10/2026 |
| vestige | occupé : 0.1.0 sans fichier publié | 53 dépôts (`samvallad33/vestige` 658 étoiles) / compte pris | enregistré | enregistré | libre | libre / libre / libre / libre | 29/10/2026 |
| memento | occupé : 0.2, 3 versions de 2006, middleware WSGI | 42 dépôts (`Memento-Teams/Memento` 2 663 étoiles) / compte pris | enregistré | enregistré | enregistré | libre / libre / occupé / libre | 29/10/2026 |

Le compte GitHub n'est bloquant pour aucun candidat : le dépôt reste
`yakohhhh/<nom>`, sans organisation à créer.

### Marques et homonymes

| Nom | INPI (classes 9 et 42) | EUIPO / TMview (classes 9 et 42) | Homonymes dans le secteur sécurité | Date |
|---|---|---|---|---|
| amnesia | à vérifier manuellement : <https://data.inpi.fr/search?q=amnesia&type=marques> | à vérifier manuellement : <https://www.tmdn.org/tmview/#/tmview/results?basicSearch=amnesia> | Tails (« amnesia », 2009), AMNESIA:33 (Forescout, 2020), Amnesia (anonymisation, OpenAIRE) ; variété de cannabis | 29/10/2026 |
| lacune | à vérifier manuellement : <https://data.inpi.fr/search?q=lacune&type=marques> | à vérifier manuellement : <https://www.tmdn.org/tmview/#/tmview/results?basicSearch=lacune> | aucun produit trouvé ; « Lacuna » est un prototype de recherche anti-forensique (UT Austin, 2012) et LacunaLog un projet SourceForge inactif | 29/10/2026 |
| souvenance | à vérifier manuellement : <https://data.inpi.fr/search?q=souvenance&type=marques> | à vérifier manuellement : <https://www.tmdn.org/tmview/#/tmview/results?basicSearch=souvenance> | aucun | 29/10/2026 |
| remanence | à vérifier manuellement : <https://data.inpi.fr/search?q=remanence&type=marques> ; une société de cosmétiques « Remanence » (Lille, 1992) existe, probablement en classe 3 | à vérifier manuellement : <https://www.tmdn.org/tmview/#/tmview/results?basicSearch=remanence> | bibliothèque PyPI `remanence` d'analyse forensique d'images disque (2026), active | 29/10/2026 |
| oubliette | à vérifier manuellement : <https://data.inpi.fr/search?q=oubliette&type=marques> | à vérifier manuellement : <https://www.tmdn.org/tmview/#/tmview/results?basicSearch=oubliette> | `oubliette-suite` (PyPI, pare-feu pour LLM, 2026), Oubliette (gestionnaire de mots de passe Windows, SourceForge) | 29/10/2026 |
| vestige | à vérifier manuellement : <https://data.inpi.fr/search?q=vestige&type=marques> | à vérifier manuellement : <https://www.tmdn.org/tmview/#/tmview/results?basicSearch=vestige> | Vestige Digital Investigations, cabinet de forensique américain (2004, groupe ArcherHall depuis 2024) | 29/10/2026 |
| memento | à vérifier manuellement : <https://data.inpi.fr/search?q=memento&type=marques> | à vérifier manuellement : <https://www.tmdn.org/tmview/#/tmview/results?basicSearch=memento> | Memento (gestion de la fraude, racheté par FIS en 2012) ; nom très répandu (5 653 dépôts GitHub) | 29/10/2026 |

Deux points valent pour tous les candidats : un mot courant (« lacune »,
« vestige », « memento ») est faiblement distinctif s'il décrit le service, ce
qui limite la protection d'une marque en classe 42 sans l'empêcher ; et les
coûts indicatifs sont de 190 € à l'INPI pour une classe (40 € par classe
supplémentaire) et de 850 € à l'EUIPO pour une classe en ligne, à reconfirmer
au dépôt.

## Classement

1. **lacune** (recommandé). Seul candidat dont le sens *est* la sortie du
   produit : un rapport de lacunes de télémétrie. Nom PyPI libre, donc paquet
   et commande peuvent enfin porter le même nom ; lacune.io, .dev, .app, .net,
   .org et .tech libres ; aucun homonyme en sécurité ; prononçable en anglais
   et porté par le cognat *lacuna*. Faiblesses : lacune.com et lacune.fr pris ;
   terme descriptif, donc marque faible ; `lacunae` déjà pris sur PyPI par un
   outil voisin (analyse d'écarts réglementaires), source possible de confusion.
2. **souvenance**. Aucune collision : PyPI libre, souvenance.io, .dev, .net et
   .tech libres, aucun homonyme. Évoque la mémoire plutôt que le manque, ce qui
   est moins direct ; quatre syllabes et une finale française qui se prononce
   moins naturellement en anglais.
3. **remanence**. Le meilleur ancrage dans le vocabulaire de la sécurité
   (rémanence des données), mais `remanence` est pris sur PyPI par une
   bibliothèque forensique active (2026), tous les domaines usuels sont
   enregistrés et une société française porte déjà ce nom. Ne serait viable
   qu'avec un suffixe (`remanence-audit`), ce qui recrée l'écart actuel entre
   paquet et commande.
4. **memento**. Nom trop répandu (5 653 dépôts, un projet à 2 663 étoiles,
   PyPI pris, Chocolatey pris, domaines pris) : invisible dans les recherches.
5. **oubliette**. Image forte mais deux homonymes en sécurité, dont une suite
   publiée sur PyPI en 2026 (`oubliette-suite`), et PyPI pris.
6. **vestige**. Homonyme direct d'un cabinet de forensique (Vestige Digital
   Investigations), exactement le secteur visé : à exclure.

## Risques résiduels

- **Homonymes en sécurité.** Nuls pour « lacune » et « souvenance » au
  29/10/2026 ; un acteur peut apparaître entre cette étude et la publication.
  La recherche de marque (INPI, EUIPO) reste à faire à la main avant tout
  dépôt.
- **Nom PyPI.** Un nom libre sur PyPI n'est réservé qu'à la première
  publication (#33). Entre le choix du nom et cette publication, rien n'empêche
  un tiers de le prendre ; la parade est de publier la première version sans
  attendre une fois le nom choisi, pas de squatter le nom avec un paquet vide
  (pratique que PyPI décourage et que la PEP 541 permet de contester).
- **Nom descriptif.** « lacune » décrit le service rendu : la marque verbale
  serait faible en classe 42 ; un logo ou une marque semi-figurative, ou un
  usage « lacune » accolé à une déclinaison distinctive, limite ce risque.
- **Ancien nom.** Les commits, issues et PR déjà publics gardent « amnesia »
  dans leur historique ; GitHub redirige l'ancienne URL du dépôt après un
  renommage, mais l'ancien nom reste visible dans l'historique.

## Écart avec le code

Au 29/10/2026, le code porte encore l'ancien nom et l'écart entre paquet et
commande subsiste :

- `pyproject.toml` : `name = "amnesia-dfr"`, script `amnesia` ;
- `src/amnesia/cli.py` : `prog="amnesia"` ;
- `README.md` : titre `# amnesia`, commandes `uv run amnesia …`.

Cet écart est volontaire : renommer le paquet, la commande, le module, les
journaux `amnesia.check.<id>`, les schémas (`amnesia.facts/1`) et la
documentation vers un candidat non encore retenu obligerait à tout refaire si
le propriétaire en choisit un autre. Le renommage se fera en une seule PR, une
fois le nom choisi, avant toute publication (#33). Tant qu'il n'est pas fait,
`amnesia-dfr` reste non publié : aucun nom n'est réservé sous l'ancienne
identité.

## En attente

Actions qui reviennent au propriétaire, sans lesquelles l'ADR reste
« Accepté partiellement » :

- **Choix final** du nom parmi les candidats (recommandation : « lacune »).
- **Réservation d'au moins un domaine** (.com, plus .fr si la cible est
  française ; à défaut .io ou .dev, libres pour « lacune » et « souvenance » au
  29/10/2026), à consigner ici. Aucun domaine n'est réservé à ce jour.
- **Adresse de contact projet.** Le propriétaire a désigné le 29/10/2026 une
  boîte personnelle, hors de tout domaine projet, comme adresse de contact
  provisoire ; elle n'est pas reproduite dans ce dépôt public, et aucun message
  de test n'a encore été vérifié. L'adresse définitive, sur le domaine réservé,
  sera notée ici et réutilisée par SECURITY.md (#28, qui garde le formulaire
  GitHub comme canal) et la landing page (#93).
- **Recherche de marque** à la main sur data.inpi.fr et TMview (URL dans le
  tableau), puis **décision de dépôt** : numéro à consigner ici, ou raison du
  report. Au 29/10/2026, aucun dépôt n'est fait : le nom n'étant pas choisi, il
  n'y a rien à déposer.
- **Ticket de renommage** du code (paquet, commande, module, schémas,
  documentation), à ouvrir après le choix.

## Conséquences

- #33 (publication PyPI) et #93 (landing page) attendent le choix du nom ; #30
  (métadonnées de licence) et #11 ne sont pas affectés.
- Aucun changement de code dans cette PR : le renommage suivra dans la sienne.
- Le nom « amnesia » et le paquet `amnesia-dfr` ne sont ni réservés ni
  promus nulle part ; aucune dépense engagée.
- Cet ADR est à compléter (nom, domaine, adresse, marque) puis à passer en
  « Accepté » ; ses vérifications datées sont à refaire le jour du choix si
  plus de quelques semaines se sont écoulées.

## Références

- #12 (ce ticket), #33, #93, #28, #11
- <https://pypi.org/pypi/amnesia/json> : amnesia 0.2.0, version unique du
  17/05/2010
- <https://pypi.org/pypi/remanence/json>, <https://pypi.org/pypi/lacunae/json>,
  <https://pypi.org/pypi/oubliette-suite/json> : occupants relevés le 29/10/2026
- <https://peps.python.org/pep-0541/> : conditions de réutilisation d'un nom
- <https://data.iana.org/rdap/dns.json> : annuaire des serveurs RDAP
- <https://tails.net/news/celebrating_10_years/> : première version
  d'« amnesia » en 2009
- <https://www.forescout.com/research-labs/amnesia33/> : AMNESIA:33
- <https://www.vestigeltd.com/about/our-history/> : Vestige Digital
  Investigations
- <https://data.inpi.fr> et <https://www.tmdn.org/tmview/> : recherche
  d'antériorité de marque
- [docs/dev/github.md](../dev/github.md) : passage en public du dépôt
