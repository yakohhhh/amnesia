# Lecture seule : ce qu'amnesia exécute sur une cible

<!-- Fichier généré depuis `src/amnesia/readonly.py` par
`uv run python scripts/generer_read_only.py` : ne pas le modifier à la
main (`tests/unit/test_readonly.py` vérifie qu'il est à jour). -->

amnesia ne modifie jamais une cible auditée. Cette page liste, opération
par opération, tout ce que ses collecteurs ont le droit d'exécuter :
une opération absente de cette liste est refusée avant exécution
(`ReadOnlyViolation`). La décision et ses limites sont dans
[l'ADR 0006](adr/0006-garantie-lecture-seule.md) : c'est un garde-fou
contre une erreur de code ou d'usage, pas une isolation ; contre du code
hostile, seule une contrainte côté cible tient (endpoint JEA, rôle en
lecture seule, compte d'audit à droits réduits).

Version de l'allowlist : 1.

## Exécutables Windows

Appelés par leur chemin complet (`<lecteur>:\...\System32\<programme>`),
sans shell, avec un délai, et seulement sous l'une de ces formes : un
argument de plus, de moins ou différent est refusé.

| Commande | Ce qu'elle lit |
|---|---|
| `auditpol.exe /get /category:* /r` | politique d'audit effective, en CSV ; seule la colonne des GUID de sous-catégorie est exploitable, les libellés sont traduits |
| `auditpol.exe /list /subcategory:* /r` | liste des sous-catégories d'audit et de leurs GUID |
| `wevtutil.exe gl <canal>` | configuration d'un journal d'événements |
| `wevtutil.exe gl <canal> /f:xml` | configuration d'un journal d'événements, en XML |
| `wevtutil.exe gli <canal>` | état d'un journal : taille, nombre d'événements, plus ancien événement |
| `w32tm.exe /query /status` | état de la synchronisation NTP |
| `w32tm.exe /query /configuration` | configuration du service de temps |
| `w32tm.exe /query /source` | source de temps courante |
| `reg.exe query <clé de configuration>` | valeurs d'une clé de configuration du registre HKLM |
| `reg.exe query <clé> /v <valeur>` | une valeur d'une clé de registre |
| `sc.exe query <service>` | état d'un service |
| `sc.exe qc <service>` | configuration d'un service |

Valeurs admises pour les arguments variables :

- `<canal>` : `[A-Za-z0-9][A-Za-z0-9 _./-]{0,254}`
- `<clé de configuration>` : `(?:HKLM|HKEY_LOCAL_MACHINE)\\(?i:SOFTWARE\\Policies|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies|SYSTEM\\CurrentControlSet\\Services\\EventLog|SYSTEM\\CurrentControlSet\\Control\\Lsa)(?:\\[A-Za-z0-9 _.{}()-]{1,255}){0,28}`
- `<clé>` : `(?:HKLM|HKEY_LOCAL_MACHINE)(?!\\(?i:SAM|SECURITY)(?:\\|$))(?:\\[A-Za-z0-9 _.{}()-]{1,255}){1,32}`
- `<valeur>` : `(?!(?i:DefaultPassword)$)[A-Za-z0-9][A-Za-z0-9 _.-]{0,254}`
- `<service>` : `[A-Za-z0-9][A-Za-z0-9_.$-]{0,255}`

Formes qui n'entreront jamais dans l'allowlist :

| Forme | Pourquoi |
|---|---|
| `auditpol /set, /clear, /remove, /restore` | modifient la politique d'audit |
| `auditpol /backup` | écrit un fichier CSV sur la cible |
| `wevtutil cl, sl, im, um, al` | effacent un journal (ATT&CK T1070.001) ou modifient sa configuration |
| `wevtutil qe` | lit le contenu des événements, pas une configuration |
| `wevtutil epl` | écrit un fichier d'export sur la cible |
| `reg add, delete, import` | modifient le registre |
| `reg query sur les ruches SAM et SECURITY` | lit la base des comptes locaux et les secrets LSA |
| `reg export` | écrit un fichier sur la cible |
| `w32tm /config, /resync` | modifient ou forcent la synchronisation |

## Scripts PowerShell

Un script vit dans `src/amnesia/ps/`, jamais dans une chaîne du code
Python, et n'est exécuté que s'il est inscrit au registre avec son
empreinte SHA-256 : un script inconnu ou modifié est refusé.

Aucun script n'est encore livré (collecteur PowerShell : #48).

La CI analyse l'AST de chaque script (`Parser::ParseFile`) et refuse
toute commande, méthode .NET ou type absent des tables ci-dessous, tout
alias (seul le nom complet d'une cmdlet est admis), toute commande au nom
calculé à l'exécution, toute affectation à autre chose qu'une variable
simple et toute redirection vers un fichier. Un type compte autant
qu'une méthode : une conversion (`[Type]$valeur`, `[Type]@{...}`,
`-as`) appelle un constructeur ou des accesseurs.

| Cmdlet | Usage | Exception |
|---|---|---|
| `Get-WinEvent` | configuration des journaux (-ListLog) et événements les plus anciens (-Oldest) |  |
| `Get-ItemProperty` | valeurs d'une clé de registre |  |
| `Get-ItemPropertyValue` | une valeur d'une clé de registre |  |
| `Get-Item` | existence et métadonnées d'une clé ou d'un fichier |  |
| `Get-ChildItem` | énumération de sous-clés de registre |  |
| `Test-Path` | existence d'une clé de registre ou d'un fichier |  |
| `Get-Service` | état et mode de démarrage des services |  |
| `Get-Date` | horodatage de la collecte |  |
| `Where-Object` | filtrage en mémoire |  |
| `Select-Object` | projection en mémoire |  |
| `Sort-Object` | tri en mémoire |  |
| `ConvertTo-Json` | sérialisation de la sortie |  |
| `Write-Output` | émission de la sortie |  |
| `Set-StrictMode` | règle d'analyse de la session PowerShell du script : n'écrit rien sur la cible | verbe interdit, admis |

| Méthode .NET | Usage |
|---|---|
| `.ToString()` | conversion en texte |
| `.ToUniversalTime()` | conversion d'un horodatage en UTC |
| `.ToXml()` | XML d'un événement (EventData), indépendant de la langue |
| `[System.Security.Principal.WindowsIdentity]::GetCurrent()` | identité du compte d'audit, pour nommer un privilège manquant |

| Type | Usage |
|---|---|
| `[ordered]` | dictionnaire ordonné de la sortie, en mémoire |
| `[pscustomobject]` | objet de sortie, en mémoire |
| `[string]` | conversion en texte |
| `[int]` | conversion en entier |
| `[long]` | conversion en entier long |
| `[bool]` | conversion en booléen |
| `[datetime]` | conversion en horodatage |
| `[System.Security.Principal.WindowsIdentity]` | type de la méthode statique `GetCurrent()` ci-dessus |

Verbes interdits, sauf exception nommée ci-dessus : `Set-`, `New-`, `Remove-`, `Clear-`, `Add-`, `Enable-`, `Disable-`, `Start-`, `Stop-`, `Restart-`, `Register-`.

Cmdlets interdites : `Limit-EventLog`, `Invoke-Expression`, `Invoke-Command`, `Invoke-CimMethod`, `Invoke-WmiMethod`, `Start-Process`, `Write-EventLog`, `Clear-EventLog`.

Paramètres interdits sur toute cmdlet, abréviations comprises, parce
qu'ils joignent un autre hôte que la cible : `-ComputerName`, `-Cn`, `-CimSession`. Des paramètres étalés (`@variable`) sont refusés : l'analyse ne les
voit pas.

## LDAP

La connexion est enveloppée : seules ces opérations passent. `modify`, `add`, `delete`, `modrdn`, `modify_dn` et toute autre méthode sont refusées avant la moindre requête.

| Opération | Usage |
|---|---|
| `bind` | authentification de la session |
| `search` | recherche et lecture d'entrées de l'annuaire |

## AWS

Un crochet `before-call` posé sur chaque client refuse, avant tout envoi,
une opération qui ne correspond à aucun de ces motifs
(`service:Opération`).

| Opérations | Usage | Statut |
|---|---|---|
| `*:Describe*` | description de ressources et de configurations | admis par défaut |
| `*:Get*` | lecture d'une configuration | admis par défaut |
| `*:List*` | énumération de ressources | admis par défaut |
| `*:LookupEvents*` | recherche d'événements CloudTrail | admis par défaut |
| `sts:AssumeRole` | rôle d'audit d'un autre compte de l'organisation (#109) | opt-in `aws-assume-role` |

Lectures refusées malgré leur préfixe (liste de refus, incomplète par
nature : le collecteur AWS nommera ses services, #95) :

| Opérations | Pourquoi |
|---|---|
| `secretsmanager:GetSecretValue` | renvoie un secret en clair |
| `s3:GetObject` | renvoie le contenu d'un objet : une donnée métier |
| `ssm:GetParameter*` | renvoie des paramètres, dont des secrets déchiffrés |
| `ec2:GetPasswordData` | renvoie le mot de passe administrateur d'une instance |
| `sts:GetSessionToken` | émet des identifiants temporaires |
| `sts:GetFederationToken` | émet des identifiants temporaires |
| `sso:GetRoleCredentials` | émet des identifiants temporaires |
| `cognito-identity:Get*` | crée une identité (`GetId`) ou émet des identifiants et des jetons |
| `redshift:GetClusterCredentials*` | émet des identifiants de base de données et peut créer l'utilisateur (`AutoCreate`) |
| `redshift-serverless:GetCredentials` | émet des identifiants de base de données |
| `ecr:GetAuthorizationToken` | émet un jeton d'accès au registre |
| `ecr-public:GetAuthorizationToken` | émet un jeton d'accès au registre |
| `codeartifact:GetAuthorizationToken` | émet un jeton d'accès au dépôt |
| `lightsail:GetRelationalDatabaseMasterUserPassword` | renvoie le mot de passe maître d'une base de données |
| `lightsail:GetInstanceAccessDetails` | renvoie des identifiants d'accès à une instance |
| `glue:GetConnection*` | renvoie les propriétés d'une connexion, dont son mot de passe |
| `apigateway:GetApiKey*` | renvoie des clés d'API |
| `dynamodb:GetItem` | renvoie un élément d'une table : une donnée métier |
| `kinesis:GetRecords` | renvoie les enregistrements d'un flux |
| `codecommit:GetFile` | renvoie le contenu d'un fichier d'un dépôt |
| `codecommit:GetBlob` | renvoie le contenu d'un fichier d'un dépôt |
| `glacier:GetJobOutput` | renvoie le contenu d'une archive |

## HTTP (Microsoft Graph, Log Analytics, Splunk)

HTTPS seulement, vers la seule adresse de base de l'API auditée. GET est
le verbe par défaut ; tout autre verbe n'est admis que sur un endpoint
nommé ici.

| API | Requête | Usage | Statut |
|---|---|---|---|
| `graph` | `GET /**` | lecture de la configuration du tenant | admis par défaut |
| `graph` | `POST /{version}/security/auditLog/queries` | recherche dans le journal d'audit unifié | opt-in `graph-audit-log-query` |
| `log-analytics` | `GET /**` | métadonnées de l'espace de travail | admis par défaut |
| `log-analytics` | `POST /v1/workspaces/{id}/query` | requête KQL : un POST qui ne fait que lire | admis par défaut |
| `splunk` | `GET /**` | lecture de la configuration et des index | admis par défaut |
| `splunk` | `POST /services/search/jobs` | recherche SPL | opt-in `splunk-search-job` |

Chemins refusés quel que soit le verbe, où qu'ils se trouvent dans
l'URL (`**` vaut tout préfixe ou toute suite) :

| API | Chemin | Pourquoi |
|---|---|---|
| `graph` | `**/deviceLocalCredentials/**` | renvoie les mots de passe d'administrateur local (LAPS) |
| `graph` | `**/recoveryKeys/**` | renvoie les clés de récupération BitLocker |
| `graph` | `**/messages/**` | contenu d'une boîte aux lettres ou d'un espace de fichiers |
| `graph` | `**/mailFolders/**` | contenu d'une boîte aux lettres ou d'un espace de fichiers |
| `graph` | `**/drive/**` | contenu d'une boîte aux lettres ou d'un espace de fichiers |
| `graph` | `**/drives/**` | contenu d'une boîte aux lettres ou d'un espace de fichiers |
| `splunk` | `**/jobs/export/**` | lance une recherche SPL par un simple GET, hors de l'opt-in `splunk-search-job` |

## Exceptions désactivées par défaut

Ces opérations ne modifient aucune configuration, mais elles laissent une
trace ou consomment une ressource chez le client : elles sont refusées
tant que l'auditeur ne les a pas activées explicitement, une par une.

| Opt-in | Ce qu'il coûte |
|---|---|
| `aws-assume-role` | `sts:AssumeRole` émet des identifiants temporaires pour le rôle d'un autre compte et laisse un événement dans son CloudTrail |
| `graph-audit-log-query` | `POST /security/auditLog/queries` crée un objet `auditLogQuery` dans le tenant et consomme des quotas quotidiens de requêtes dont le client peut avoir besoin en pleine crise |
| `splunk-search-job` | `POST /services/search/jobs` crée un job de recherche sur le serveur Splunk et compte dans le quota de recherches de son compte |
