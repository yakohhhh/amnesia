# ADR 0001 — Modèle de licence

| | |
|---|---|
| Statut | **Accepté** le 29/10/2026 par le propriétaire du dépôt ; avis juridique en attente (voir [Avis d'un avocat IP/IT](#avis-dun-avocat-ipit)) |
| Décideur | Ayman Mazroui, auteur et titulaire des droits |
| Ticket | #11 ; applique la décision : #30 ; bloqués par cet ADR : #13, #33 |
| Supplante | — (premier ADR) |

## Contexte

Le dépôt annonce deux choses contradictoires : une licence MIT (`LICENSE`,
`pyproject.toml`, section « Licence » du README) et un modèle commercial fondé
sur une licence vendue aux MSP et aux cabinets d'audit, avec un rapport en
marque blanche (section « Vendable » du README). Sous MIT, n'importe qui, cabinet
concurrent ou MSP compris, peut utiliser, modifier, rebrander et revendre amnesia
sans rien payer.

Deux faits fixent le cadre de la décision :

- **Un seul auteur.** Chaque commit de l'historique est de la même personne
  physique. Aucune contribution externe n'a été fusionnée : il n'y a aucun
  accord à recueillir pour changer la licence de ce qui n'a pas encore été
  publié.
- **Le dépôt a été rendu public le 29/10/2026, avant la fusion de cet ADR**
  (#13, [docs/dev/github.md](../dev/github.md), section « Passage en public »).
  La licence MIT accordée sur le code publié est **irrévocable** : quiconque a
  obtenu une copie de l'état du dépôt à cette date, ou de tout commit poussé
  depuis sous MIT, conserve les droits MIT sur cette copie, quelle que soit la
  licence des versions futures. Les conséquences sont détaillées dans
  [Publication avant la fusion de l'ADR](#publication-avant-la-fusion-de-ladr).

Le second fait a déjà écarté, de fait, les options qui supposaient de
relicencier le cœur avant toute publication. Il n'a cependant pas tranché la
question principale, qui reste ouverte pour tout ce qui n'existe pas encore :
quelles fonctionnalités seront publiées sous licence libre, et lesquelles seront
vendues.

Cette décision bloque la publication sur PyPI (#33), la mise en forme des
métadonnées de licence (#30), le mécanisme de contrôle de licence (#154) et la
première contribution externe (#29). Le nom commercial (#12) et la recherche
d'antériorité de marque sont hors périmètre : la décision ci-dessous vaut quel
que soit le nom retenu pour le cœur ou pour les éditions commerciales.

## Décision

**Modèle open core.**

1. **Le cœur** (ce dépôt : moteur, collecte, checks, modèles `Gap` et `Fact`,
   rapport JSON et rendus texte et Markdown, CLI, documentation) **reste sous
   licence MIT**, sans changement de licence ni de titulaire.
2. **Les éditions commerciales** (rapport en marque blanche, scoring et export
   PDF, fonctionnalités MSP multi-tenant, connecteurs premium, voir le
   [tableau des fonctionnalités par édition](#fonctionnalités-par-édition))
   sont développées **dans des composants séparés, sous licence propriétaire**,
   dans un ou plusieurs dépôts privés. Elles s'installent par-dessus le cœur et
   l'utilisent par ses surfaces stables (ids de checks, `question_id`, schéma du
   rapport JSON, codes de sortie, options de la CLI, voir
   [docs/RELEASING.md](../RELEASING.md)) ou par le mécanisme de plugins (#149).
3. **Le titulaire des droits** sur le cœur et sur les éditions commerciales est
   le propriétaire du dépôt, personne physique, jusqu'à la création d'une
   structure (voir [Titulaire des droits](#titulaire-des-droits)).
4. **Les contributions externes au cœur** sont acceptées sous **DCO**
   (*Developer Certificate of Origin*, `Signed-off-by`), pas sous CLA (voir
   [CLA ou DCO](#cla-ou-dco)). Les éditions commerciales ne reçoivent aucune
   contribution externe.
5. **Aucun contenu de ce dépôt ne dépend d'un composant commercial** : le cœur
   doit rester utilisable seul, de bout en bout, pour auditer son propre SI ou
   celui d'un client. Un check, un fait ou un rendu déjà publié sous MIT ne
   migre jamais vers une édition commerciale.

## Options comparées

Les six options de #11 sont regroupées en quatre familles. Pour chacune : effet
sur les MSP et cabinets, sur la marque blanche et sur les contributions, et
raison de son rejet ou de son choix.

### Option A — MIT pur (« MIT + services », statu quo)

Tout est MIT ; les revenus viennent uniquement de la prestation (diagnostic
#90, pilote #92, formation #91).

- **MSP et cabinets** : utilisation, modification et revente libres, sans
  contrepartie. Un concurrent peut livrer un rapport amnesia à sa marque dès la
  première version.
- **Marque blanche** : incluse de fait, impossible à vendre.
- **Contributions** : maximales (licence OSI, aucune formalité au-delà du DCO).
- **Rejetée** : incompatible avec le modèle annoncé, un seul levier de revenu
  (le temps du consultant), aucune différenciation entre l'auteur et un
  revendeur. C'est en revanche la licence **de fait** de tout ce qui a été
  publié jusqu'ici, et l'option A reste la base de l'option B.

### Option B — Open core (retenue)

Cœur MIT dans ce dépôt, éditions commerciales propriétaires dans des composants
séparés. L'option 6 de #11 (code MIT, catalogue de questions et de remédiations
sous licence commerciale) en est une variante : elle est écartée parce que le
catalogue est ce qui rend le cœur utile seul, et qu'un cœur vide n'attire ni
utilisateurs ni contributeurs. Les mises à jour premium du catalogue (profils de
référence #135, mapping ATT&CK #147) peuvent en revanche faire partie d'une
édition commerciale sans retirer le catalogue de base.

- **MSP et cabinets** : le cœur suffit pour auditer et remettre un rapport brut.
  Pour un rapport à sa marque, un PDF présentable, un score suivi dans le temps
  ou un audit de dizaines de tenants, il faut une édition commerciale. Un
  concurrent peut réimplémenter ces fonctionnalités au-dessus du cœur MIT : la
  frontière entre éditions est une position commerciale, pas une protection
  juridique, et elle doit être tenue dans la durée.
- **Marque blanche** : vendue, dans un composant propriétaire.
- **Contributions** : bonnes sur le cœur (MIT, DCO) ; nulles sur les éditions
  commerciales, par construction.
- **Retenue** : seule option compatible à la fois avec la publication MIT déjà
  faite, avec le modèle annoncé et avec une mise en œuvre immédiate, sans avocat
  ni CLA. Son coût est la discipline de la frontière (voir
  [Conséquences](#conséquences)).

### Option C — Copyleft fort ou source-available : AGPL-3.0 + licence commerciale, BUSL-1.1, FSL-1.1-MIT, Elastic License 2.0, PolyForm Internal Use (option 4 de #11, précédent PingCastle)

Le cœur reçoit une licence dissuasive pour l'usage commercial par des tiers, et
une licence commerciale lève la restriction.

- **MSP et cabinets** :
  - **AGPL** : un consultant qui lance la CLI sur son poste n'a ni distribué le
    logiciel ni offert un service réseau ; l'AGPL ne l'oblige probablement pas à
    acheter (à confirmer par l'avocat). La double licence ne capte donc pas le
    cas d'usage principal.
  - **BUSL-1.1, FSL-1.1-MIT, Elastic 2.0** : la « Competing Use » de la FSL
    autorise explicitement l'usage dans le cadre de services professionnels
    rendus à un licencié, formulation ambiguë pour un cabinet ; Elastic 2.0
    n'interdit pas l'usage par des consultants ; BUSL exige de rédiger soi-même
    l'« Additional Use Grant », sans modèle sectoriel. Dans les trois cas, le
    respect de la licence par un cabinet n'est ni vérifiable ni opposable sans
    procédure.
  - **PolyForm Internal Use + contrat** (gratuit pour son propre SI, payant pour
    auditer des tiers) : colle le mieux à la cible et fait des clients finaux
    des prospects ; mais licence non OSI, donc peu de contributions et refus
    probable par des distributions et des politiques d'achat.
- **Marque blanche** : possible sous licence commerciale uniquement.
- **Contributions** : faibles (AGPL rebute les entreprises ; les licences
  source-available ne sont pas OSI). Une double licence exige un CLA pour
  chaque contribution.
- **Rejetée** : **inapplicable à l'existant**, publié sous MIT le 29/10/2026
  (un fork MIT de l'état actuel resterait disponible et légal), et le cas
  d'usage principal (consultant depuis son poste) passe entre les mailles de
  chaque variante. Elle imposerait en outre un CLA et un avis juridique avant
  toute contribution.

### Option D — Propriétaire (code fermé, licence commerciale seule)

- **MSP et cabinets** : seul le licencié utilise amnesia. Capture maximale des
  revenus sur le papier ; adoption nulle sans force de vente, et aucune
  confiance possible d'un client qui doit exécuter un collecteur sur ses
  contrôleurs de domaine sans pouvoir le lire.
- **Marque blanche** : vendue.
- **Contributions** : aucune.
- **Rejetée** : contraire à la lisibilité du collecteur (#48), argument de
  vente et exigence de sécurité (lecture seule, vérifiable par l'admin du
  client), et contraire à la publication MIT déjà faite.

## Critères pondérés

Note de 0 (mauvais) à 3 (bon) par critère, pondérée. Les poids reflètent la
situation d'un projet à un seul auteur, sans force de vente, dont le premier
revenu est la prestation ; ils sont à réexaminer si une structure est créée.

| Critère | Poids | A · MIT pur | B · Open core | C · Copyleft / source-available | D · Propriétaire |
|---|---|---|---|---|---|
| Revenus captés auprès des MSP et cabinets | 3 | 0 | 2 | 2 | 3 |
| Adoption (installation, essai, bouche-à-oreille) | 3 | 3 | 3 | 1 | 0 |
| Contributions externes | 2 | 3 | 2 | 1 | 0 |
| Capacité à faire respecter la licence | 2 | 3 (rien à faire respecter) | 2 (composants non publiés) | 0 (usage interne invérifiable) | 2 |
| Compatibilité avec la marque blanche vendue | 2 | 0 | 3 | 2 | 3 |
| Simplicité juridique (sans avocat pour démarrer) | 2 | 3 | 3 | 0 | 1 |
| Compatibilité avec les licences des dépendances et contenus tiers (#83) | 1 | 3 | 2 | 1 | 1 |
| Applicable à l'existant publié sous MIT | 3 | 3 | 3 | 0 | 0 |
| **Total pondéré** (sur 54) | | **39** | **46** | **16** | **22** |

Lecture : A et B sont à égalité partout sauf sur les revenus et la marque
blanche, qui sont précisément l'objet de la décision ; C et D sont disqualifiés
par la publication MIT déjà faite, indépendamment de leurs autres mérites.

## Trois cas d'usage

Pour chaque option, les trois situations demandées par #11.

| Cas | A · MIT pur | B · Open core | C · Copyleft / source-available | D · Propriétaire |
|---|---|---|---|---|
| **1. Un cabinet ou un MSP lance amnesia depuis son poste pour auditer un client** | Libre et gratuit, rapport brut ou rebrandé par ses soins. | Libre et gratuit avec le cœur (rapport JSON, texte, Markdown). Édition commerciale requise pour la marque blanche, le PDF, le score, le multi-tenant et l'isolation par mission. | AGPL : pas de distribution ni de service réseau, donc probablement aucune obligation (à confirmer par l'avocat). FSL / Elastic : usage par un prestataire ambigu ou permis. PolyForm Internal Use : interdit sans contrat, mais invérifiable. | Interdit sans licence. |
| **2. Le collecteur (#48) est déposé sur les machines du client** | Le client reçoit un script MIT : il peut le lire, le garder, le modifier. | Identique : le collecteur fait partie du cœur, **par choix** ; il reste lisible et vérifiable par l'admin du client, ce qui est un argument de vente et une exigence du modèle de menace (Z2, [docs/threat-model.md](../threat-model.md)). | AGPL : déposer le script est une transmission (« convey », section 0) : le client reçoit le code avec les droits de l'AGPL, sans obligation d'achat pour autant. Source-available : le client est lié par une licence qu'il n'a pas choisie. | Le client exécute un script qu'il n'a pas le droit de lire : refus prévisible des DSI et des RSSI. |
| **3. Marque blanche (rapport au nom et au logo du prestataire)** | Incluse de fait, invendable. | Composant commercial (#141) ; le rapport brut du cœur porte le nom du projet, sans logo ni nom de prestataire. | Vendue sous licence commerciale uniquement ; un fork MIT de l'existant la reproduit légalement. | Vendue sous licence commerciale. |

## Fonctionnalités par édition

Frontière établie à partir du backlog réel (milestones « Backlog » et « Offre
v0 — prestation pilote »). Règle de partage : **tout ce qui sert à constater et
à expliquer un angle mort est dans le cœur ; ce qui sert à livrer, vendre et
industrialiser une mission est commercial.** Les noms « Pro » et « MSP » sont
provisoires (#169 fixe l'offre partenaire ; #12 le nom).

| Fonctionnalité | Ticket | Cœur (MIT) | Pro (cabinet) | MSP (multi-clients) |
|---|---|---|---|---|
| Moteur de checks, collecte, modèles `Gap` et `Fact` | #20, #21, #16 | oui | oui | oui |
| Catalogue de checks Windows, AD, cloud (M1, M2, M3) | M1, M2, M3 | oui | oui | oui |
| Rapport JSON versionné et schéma | #22 | oui | oui | oui |
| Rendus texte et Markdown « questions sans réponse » | #23 | oui | oui | oui |
| Rapport HTML autonome, sans marque | #77 | oui | oui | oui |
| Collecteur PowerShell déposé chez le client, bundle hors ligne | #48, #52 | oui | oui | oui |
| Collecte distante WinRM | #63 | oui | oui | oui |
| Import d'exports natifs Windows (gpresult, auditpol, wevtutil) | #136 | oui | oui | oui |
| Mapping MITRE ATT&CK de base (références des Gaps) | #16, #147 | oui | oui | oui |
| Plugins de checks tiers via entry points | #149 | oui | oui | oui |
| Rapport client en marque blanche (nom, logo, modèle) | #141 | — | oui | oui |
| Export PDF du rapport client | #140 | — | oui | oui |
| Scoring de maturité par domaine et par scénario | #139 | — | oui | oui |
| Comparaison de deux audits (`amnesia diff`) | #142 | — | oui | oui |
| Exceptions acceptées (waivers) avec justification et expiration | #143 | — | oui | oui |
| Pack de preuves de mission (archive signée, empreintes) | #146 | — | oui | oui |
| Version expurgée et pseudonymisée du rapport | #144 | — | oui | oui |
| Calque Navigator ATT&CK et profils de référence ANSSI / Microsoft | #147, #135 | — | oui | oui |
| Isolation par mission (usage multi-clients) | #148 | — | — | oui |
| Audit multi-tenant Microsoft 365 pour MSP (GDAP) | #162 | — | — | oui |
| Connecteurs SIEM premium (Elastic, test canari de bout en bout) | #156, #155 | — | — | oui |
| Mécanisme de licence (fichier signé, hors ligne) | #154 | — | oui | oui |
| Offre partenaire, formation, support, co-marquage | #169, #91, #168 | — | contrat | contrat |

Choix volontaires à retenir :

- **Chiffrement du rapport (#145), internationalisation FR/EN (#138),
  signature des scripts (#151), SBOM (#153)** restent dans le cœur : ce sont des
  exigences de sécurité ou d'accessibilité, pas des arguments de vente.
- **Le mapping ATT&CK** est scindé : les références techniques portées par
  chaque `Gap` (#16) sont dans le cœur ; le calque Navigator et sa tenue à jour
  par version d'ATT&CK sont commerciaux.
- **Les connecteurs SIEM** « lecture seule » (vérifier que les événements
  partent) relèvent du cœur quand ils constatent un angle mort (M2) ; le test
  canari actif (#155) et les connecteurs spécifiques à un éditeur (#156) sont
  commerciaux.
- Une fonctionnalité listée « commerciale » peut passer dans le cœur plus tard
  (le sens inverse est interdit, voir la décision, point 5).

## Titulaire des droits

- **Titulaire** : Ayman Mazroui, personne physique, auteur de l'intégralité de
  l'historique à ce jour (`LICENSE`, ligne « Copyright (c) 2026 Ayman
  Mazroui »). Les éditions commerciales, développées par la même personne dans
  des dépôts privés, lui appartiennent de même.
- **Structure à créer** : si une société est constituée pour porter l'offre
  (#169), une cession ou une licence exclusive des droits sur le cœur et sur les
  éditions commerciales, de la personne physique vers la société, sera rédigée
  avec l'avocat. La mention de copyright de `LICENSE` sera alors complétée, sans
  retirer la mention d'origine. Rien dans le présent ADR n'en dépend.
- **Contributions externes** : sous DCO, chaque contributeur reste titulaire de
  ses droits et accorde au projet la licence MIT sur sa contribution. Le projet
  ne détient donc pas « tous les droits » sur le cœur une fois des
  contributions fusionnées : c'est précisément ce qui rend une relicence future
  coûteuse (voir ci-dessous), et ce qui est accepté.

## CLA ou DCO

**Décision : DCO** (`Signed-off-by` sur chaque commit, vérifié par un check sur
les PR ; mise en place dans #30 et #29).

| | CLA (cession ou licence large) | DCO (retenu) |
|---|---|---|
| Ce que le projet obtient | Le droit de relicencier la contribution, y compris sous licence commerciale | Une contribution sous MIT, avec attestation d'origine |
| Suffit pour l'open core | Oui | **Oui** : le cœur reste MIT, et MIT permet d'intégrer le code du cœur dans les composants commerciaux comme dans n'importe quel produit |
| Suffit pour une double licence (option C) | Oui, obligatoire | Non |
| Friction pour le contributeur | Signature d'un contrat, bot CLA Assistant, obstacle pour les salariés dont l'employeur doit signer | Une ligne dans le message de commit |
| Confiance des contributeurs | Faible : un CLA signale que le projet se réserve le droit de fermer le code | Bonne |

Conséquences sur une future relicence :

- Tant que le cœur reste MIT, le DCO suffit : le projet peut utiliser, inclure
  et vendre toute contribution avec le cœur, comme n'importe quel utilisateur de
  code MIT.
- Si une relicence du cœur vers une licence copyleft ou source-available était
  envisagée plus tard, il faudrait l'accord de chaque contributeur dont le code
  serait encore présent, ou réécrire ce code. Ce coût est accepté : il ne porte
  que sur un scénario déjà rejeté (option C), et il est de toute façon
  dominé par le fait que l'existant restera disponible sous MIT quoi qu'il
  arrive.
- **À réexaminer** si le projet reçoit des contributions substantielles et
  qu'une relicence redevient une option : passer au CLA à ce moment ne couvrira
  que les contributions postérieures.

## Conséquences

Positives :

- Aucun changement de licence, de titulaire ni de métadonnées à faire dans
  l'urgence : #30 se réduit à la forme PEP 639 (expression SPDX `MIT`,
  `license-files`, en-têtes SPDX) et à la mise en place du DCO ; #33 et #13 ne
  sont plus bloqués par une question de licence.
- Le collecteur déposé chez le client reste lisible, ce qui est cohérent avec le
  modèle de menace et la politique de sécurité ([SECURITY.md](../../SECURITY.md)).
- Les contributions externes restent possibles sans contrat.

Négatives et obligations :

- **Tenir la frontière.** Chaque nouveau ticket doit être rangé dans le cœur ou
  dans une édition commerciale avant d'être commencé ; le tableau ci-dessus est
  la référence, et une fonctionnalité du cœur n'en sort jamais. Un label
  `edition:commerciale` sur les tickets concernés et un renvoi vers cet ADR dans
  leur description sont demandés à #30.
- **Surfaces stables.** Les éditions commerciales dépendent des surfaces
  stables du cœur ([docs/RELEASING.md](../RELEASING.md)) et du mécanisme de
  plugins (#149) : ces surfaces deviennent un contrat interne, à faire évoluer
  avec dépréciation.
- **Rien de commercial dans ce dépôt.** Ni code, ni clé, ni contrat, ni nom de
  client, ni grille tarifaire : le dépôt est public. Les documents d'offre
  (#169, #90, #89) qui contiennent des éléments commerciaux sensibles sont à
  tenir hors du dépôt ; ceux qui peuvent être publics y restent.
- **Dépendances.** Le cœur ne peut dépendre que de licences compatibles MIT
  (registre #83) ; les éditions commerciales ne peuvent dépendre d'aucune
  licence copyleft (PyMuPDF AGPL exclu, WeasyPrint BSD-3 admis pour #140).
- **Contrôle de licence** (#154) : uniquement dans les composants commerciaux,
  hors ligne, sans télémétrie (#26), jamais dans le cœur.
- **Un concurrent peut reconstruire les éditions commerciales au-dessus du
  cœur.** La protection réelle est l'avance fonctionnelle, le catalogue tenu à
  jour, la méthodologie (#91) et le support, pas la licence.
- Le nom commercial des éditions dépend de #12 ; le présent ADR n'en préjuge
  pas.

## Publication avant la fusion de l'ADR

Le dépôt est public depuis le **29/10/2026**, décision prise dans #13 avant la
fusion de cet ADR, alors que #11 demandait l'inverse (« aucune publication
avant sa fusion »). Conséquences, constatées et acceptées :

- Tout commit poussé sur `main` jusqu'à présent est publié sous MIT, de façon
  irrévocable pour qui en détient une copie. Aucune relicence rétroactive n'est
  possible ; le cœur ne pouvait donc plus recevoir qu'une licence permissive,
  ce qui est cohérent avec la décision.
- Aucun paquet n'a été publié sur PyPI ni sur TestPyPI, aucun tag ni aucune
  release GitHub : la portée de la publication est celle du dépôt git.
- Aucune contribution externe n'a été reçue entre la mise en public et la
  fusion de cet ADR : aucun droit tiers n'est en jeu.
- Aucun composant commercial n'existait dans le dépôt à cette date : rien de ce
  qui doit rester propriétaire n'a été publié.
- La checklist « Passage en public » de [docs/dev/github.md](../dev/github.md)
  reste la référence pour les réglages du dépôt.

## Avis d'un avocat IP/IT

**À obtenir** (section vide au 29/10/2026). L'avis sera consigné ici avec sa
date et son périmètre, sans reproduire son contenu confidentiel.

| | |
|---|---|
| Date de l'avis | à obtenir |
| Périmètre demandé | validité de l'open core avec un cœur MIT et des composants propriétaires distincts ; formulation du contrat de licence commerciale ; cession ou licence exclusive de la personne physique vers une structure ; portée du DCO ; qualification de l'exécution du collecteur chez le client ; conformité du registre de licences tierces (#83) |
| Conclusions retenues | — |
| Effet sur cet ADR | — |

Cet ADR est applicable sans attendre cet avis pour ce qui ne crée aucun
engagement nouveau : le cœur reste sous la licence qu'il a déjà. **Aucun contrat
de licence commerciale n'est signé et aucun composant commercial n'est livré à
un client avant que l'avis soit consigné ici.**

## Références

- #11 (ce ticket), #30 (application : LICENSE, pyproject, README, DCO), #13
  (visibilité du dépôt), #33 (publication PyPI), #29 (CONTRIBUTING), #12 (nom),
  #83 (registre des licences tierces), #154 (mécanisme de licence), #169 (offre
  partenaire).
- `LICENSE` : MIT, « Copyright (c) 2026 Ayman Mazroui ».
- <https://developercertificate.org/> : texte du DCO.
- <https://www.gnu.org/licenses/agpl-3.0.html> : sections 0 (« convey ») et 13
  (interaction à distance).
- <https://fsl.software/FSL-1.1-MIT.template.md> : « Competing Use » et
  « Permitted Purpose ».
- <https://polyformproject.org/licenses/internal-use/1.0.0/>.
- <https://www.netwrix.com/en/products/pingcastle/pingcastle-comparison/> :
  précédent « gratuit pour son propre SI, payant pour auditer des tiers ».
- [docs/threat-model.md](../threat-model.md), [docs/RELEASING.md](../RELEASING.md),
  [docs/dev/github.md](../dev/github.md), [SECURITY.md](../../SECURITY.md).
