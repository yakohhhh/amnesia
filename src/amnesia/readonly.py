# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Garantie de lecture seule : allowlist des opérations des collecteurs.

``ALLOWED_OPERATIONS`` est la source unique de ce qu'un collecteur a le droit
d'exécuter sur une cible (ADR 0006) : exécutables Windows à arguments figés,
commandes et méthodes .NET admises dans les scripts PowerShell, opérations
LDAP, opérations AWS et endpoints HTTP. Tout le reste est refusé **avant**
exécution par ``ReadOnlyViolation`` :

- ``check_command(argv)`` : exécutable appelé par son chemin complet, arguments
  conformes à une forme figée ; ``amnesia.facts.collectors.run_command`` est le
  seul point de lancement d'un collecteur ;
- ``load_script(nom)`` : script de ``src/amnesia/ps/`` inscrit dans ``SCRIPTS``
  avec son empreinte SHA-256 ; ``check_script_inventory()`` juge l'inventaire
  de son AST (commandes, méthodes, affectations, redirections), dressé en CI
  par ``scripts/inventaire_ps.ps1`` ;
- ``ReadOnlyLdap`` : enveloppe d'une connexion LDAP, bind et search seulement ;
- ``aws_guard()`` et ``protect_aws_client()`` : crochet botocore
  ``before-call`` ;
- ``HttpGuard`` : allowlist par API, verbe et chemin, GET par défaut.

Ces gardes n'importent aucun SDK : les collecteurs cloud, LDAP et SIEM (#66,
#95, #112, #113) les branchent sur leurs clients. Ce sont des garde-fous
contre une erreur de code ou d'usage, pas une isolation : contre du code
hostile dans le processus, seule une contrainte côté cible tient (ADR 0006).

Une ``ReadOnlyViolation`` signale un bug d'amnesia, pas un échec de collecte :
un collecteur la laisse remonter, hors de tout ``except Exception``. Son
message ne reprend jamais les arguments reçus.

``docs/READ-ONLY.md`` est généré par ``render_markdown()``
(``scripts/generer_read_only.py``) ; un test vérifie qu'il est à jour.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase
from importlib.resources import files
from pathlib import Path, PureWindowsPath
from types import MappingProxyType
from typing import Any, Final, TypeVar
from urllib.parse import unquote, urlsplit

ALLOWLIST_VERSION: Final = 1
"""Version de l'allowlist, incrémentée à chaque opération ajoutée ou retirée."""


class ReadOnlyViolation(Exception):
    """Opération absente de l'allowlist, refusée avant toute exécution."""


# --- modele ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Param:
    """Argument variable d'une commande, borné par une expression régulière."""

    name: str
    pattern: str

    def accepts(self, value: str) -> bool:
        return re.fullmatch(self.pattern, value) is not None


@dataclass(frozen=True, slots=True)
class Executable:
    """Forme figée d'un exécutable Windows : programme, puis arguments exacts.

    ``program`` est le nom du fichier dans ``System32`` ; l'appel se fait par
    son chemin complet. Un argument est un littéral, comparé tel quel, ou un
    ``Param``.
    """

    program: str
    args: tuple[str | Param, ...]
    reads: str

    @property
    def label(self) -> str:
        mots = [a if isinstance(a, str) else f"<{a.name}>" for a in self.args]
        return " ".join([self.program, *mots])

    def accepts(self, args: Sequence[str]) -> bool:
        if len(args) != len(self.args):
            return False
        return all(
            attendu == recu if isinstance(attendu, str) else attendu.accepts(recu)
            for attendu, recu in zip(self.args, args, strict=True)
        )


@dataclass(frozen=True, slots=True)
class PsCommand:
    """Cmdlet admise dans un script PowerShell, par son nom complet.

    ``exception`` : le verbe est interdit, mais la cmdlet est admise pour la
    raison donnée par ``reads``.
    """

    name: str
    reads: str
    exception: bool = False

    @property
    def label(self) -> str:
        return self.name


@dataclass(frozen=True, slots=True)
class PsMethod:
    """Méthode .NET admise dans un script PowerShell.

    ``type`` est le nom complet du type pour une méthode statique, ``None``
    pour une méthode d'instance (le type du receveur n'est pas connu de l'AST).
    """

    name: str
    type: str | None
    reads: str

    @property
    def label(self) -> str:
        return f"[{self.type}]::{self.name}()" if self.type else f".{self.name}()"


@dataclass(frozen=True, slots=True)
class PsType:
    """Type .NET admis dans un script PowerShell, par son nom tel qu'il est écrit.

    Une conversion (``[Type]$valeur``, ``[Type]@{...}``, ``-as [Type]``) appelle
    un constructeur ou des accesseurs : le type compte autant qu'une méthode.
    """

    name: str
    reads: str

    @property
    def label(self) -> str:
        return f"[{self.name}]"


@dataclass(frozen=True, slots=True)
class LdapOperation:
    """Opération LDAP admise, par le nom de la méthode du client."""

    name: str
    reads: str

    @property
    def label(self) -> str:
        return self.name


@dataclass(frozen=True, slots=True)
class AwsOperation:
    """Opérations AWS admises : motif ``service:Opération`` (``*`` permis)."""

    pattern: str
    reads: str
    opt_in: str | None = None

    @property
    def label(self) -> str:
        return self.pattern


@dataclass(frozen=True, slots=True)
class HttpEndpoint:
    """Endpoint HTTP admis : API, verbe et gabarit de chemin.

    Dans ``path``, ``{nom}`` vaut un segment et ``**``, en dernier, le reste du
    chemin.
    """

    api: str
    method: str
    path: str
    reads: str
    opt_in: str | None = None

    @property
    def label(self) -> str:
        return f"{self.method} {self.path}"


@dataclass(frozen=True, slots=True)
class HttpDenied:
    """Chemins refusés quel que soit le verbe : suite de segments consécutifs.

    La suite est cherchée partout dans le chemin, sans tenir compte de la casse
    ni d'une clé OData accolée au segment (``drives('...')``).
    """

    api: str
    segments: tuple[str, ...]
    reason: str

    @property
    def label(self) -> str:
        return "/".join(["**", *self.segments, "**"])


Operation = (
    Executable
    | PsCommand
    | PsMethod
    | PsType
    | LdapOperation
    | AwsOperation
    | HttpEndpoint
)

# --- allowlist ------------------------------------------------------------------

# une valeur ne commence jamais par « / » ni « - » : elle serait lue comme une
# option (wevtutil /r:<hote>, reg query \\<hote>\...)
_CANAL = Param("canal", r"[A-Za-z0-9][A-Za-z0-9 _./-]{0,254}")
_RACINE = r"(?:HKLM|HKEY_LOCAL_MACHINE)"
_SOUS_CLE = r"(?:\\[A-Za-z0-9 _.{}()-]{1,255})"
# une cle lue en entier : seulement sous les racines de configuration que les
# checks consultent ; ailleurs, une cle peut porter un secret parmi ses valeurs
# (DefaultPassword de Winlogon) et se lit valeur par valeur
_CLE_ENTIERE = Param(
    "clé de configuration",
    _RACINE
    + r"\\(?i:SOFTWARE\\Policies"
    + r"|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies"
    + r"|SYSTEM\\CurrentControlSet\\Services\\EventLog"
    + r"|SYSTEM\\CurrentControlSet\\Control\\Lsa)"
    + _SOUS_CLE
    + "{0,28}",
)
# ruches SAM et SECURITY de HKLM (comptes locaux, secrets LSA) : jamais lues
_CLE = Param(
    "clé",
    _RACINE + r"(?!\\(?i:SAM|SECURITY)(?:\\|$))" + _SOUS_CLE + "{1,32}",
)
_VALEUR = Param("valeur", r"(?!(?i:DefaultPassword)$)[A-Za-z0-9][A-Za-z0-9 _.-]{0,254}")
_SERVICE = Param("service", r"[A-Za-z0-9][A-Za-z0-9_.$-]{0,255}")

_WINDOWS: tuple[Operation, ...] = (
    Executable(
        "auditpol.exe",
        ("/get", "/category:*", "/r"),
        "politique d'audit effective, en CSV ; seule la colonne des GUID de "
        "sous-catégorie est exploitable, les libellés sont traduits",
    ),
    Executable(
        "auditpol.exe",
        ("/list", "/subcategory:*", "/r"),
        "liste des sous-catégories d'audit et de leurs GUID",
    ),
    Executable(
        "wevtutil.exe", ("gl", _CANAL), "configuration d'un journal d'événements"
    ),
    Executable(
        "wevtutil.exe",
        ("gl", _CANAL, "/f:xml"),
        "configuration d'un journal d'événements, en XML",
    ),
    Executable(
        "wevtutil.exe",
        ("gli", _CANAL),
        "état d'un journal : taille, nombre d'événements, plus ancien événement",
    ),
    Executable("w32tm.exe", ("/query", "/status"), "état de la synchronisation NTP"),
    Executable(
        "w32tm.exe", ("/query", "/configuration"), "configuration du service de temps"
    ),
    Executable("w32tm.exe", ("/query", "/source"), "source de temps courante"),
    Executable(
        "reg.exe",
        ("query", _CLE_ENTIERE),
        "valeurs d'une clé de configuration du registre HKLM",
    ),
    Executable(
        "reg.exe", ("query", _CLE, "/v", _VALEUR), "une valeur d'une clé de registre"
    ),
    Executable("sc.exe", ("query", _SERVICE), "état d'un service"),
    Executable("sc.exe", ("qc", _SERVICE), "configuration d'un service"),
    PsCommand(
        "Get-WinEvent",
        "configuration des journaux (-ListLog) et événements les plus anciens "
        "(-Oldest)",
    ),
    PsCommand("Get-ItemProperty", "valeurs d'une clé de registre"),
    PsCommand("Get-ItemPropertyValue", "une valeur d'une clé de registre"),
    PsCommand("Get-Item", "existence et métadonnées d'une clé ou d'un fichier"),
    PsCommand("Get-ChildItem", "énumération de sous-clés de registre"),
    PsCommand("Test-Path", "existence d'une clé de registre ou d'un fichier"),
    PsCommand("Get-Service", "état et mode de démarrage des services"),
    PsCommand("Get-Date", "horodatage de la collecte"),
    PsCommand("Where-Object", "filtrage en mémoire"),
    PsCommand("Select-Object", "projection en mémoire"),
    PsCommand("Sort-Object", "tri en mémoire"),
    PsCommand("ConvertTo-Json", "sérialisation de la sortie"),
    PsCommand("Write-Output", "émission de la sortie"),
    PsCommand(
        "Set-StrictMode",
        "règle d'analyse de la session PowerShell du script : n'écrit rien sur "
        "la cible",
        exception=True,
    ),
    PsMethod("ToString", None, "conversion en texte"),
    PsMethod("ToUniversalTime", None, "conversion d'un horodatage en UTC"),
    PsMethod("ToXml", None, "XML d'un événement (EventData), indépendant de la langue"),
    PsMethod(
        "GetCurrent",
        "System.Security.Principal.WindowsIdentity",
        "identité du compte d'audit, pour nommer un privilège manquant",
    ),
    PsType("ordered", "dictionnaire ordonné de la sortie, en mémoire"),
    PsType("pscustomobject", "objet de sortie, en mémoire"),
    PsType("string", "conversion en texte"),
    PsType("int", "conversion en entier"),
    PsType("long", "conversion en entier long"),
    PsType("bool", "conversion en booléen"),
    PsType("datetime", "conversion en horodatage"),
    PsType(
        "System.Security.Principal.WindowsIdentity",
        "type de la méthode statique `GetCurrent()` ci-dessus",
    ),
)

_LDAP: tuple[Operation, ...] = (
    LdapOperation("bind", "authentification de la session"),
    LdapOperation("search", "recherche et lecture d'entrées de l'annuaire"),
)

_AWS: tuple[Operation, ...] = (
    AwsOperation("*:Describe*", "description de ressources et de configurations"),
    AwsOperation("*:Get*", "lecture d'une configuration"),
    AwsOperation("*:List*", "énumération de ressources"),
    AwsOperation("*:LookupEvents*", "recherche d'événements CloudTrail"),
    AwsOperation(
        "sts:AssumeRole",
        "rôle d'audit d'un autre compte de l'organisation (#109)",
        opt_in="aws-assume-role",
    ),
)

_HTTP: tuple[Operation, ...] = (
    HttpEndpoint("graph", "GET", "/**", "lecture de la configuration du tenant"),
    HttpEndpoint(
        "graph",
        "POST",
        "/{version}/security/auditLog/queries",
        "recherche dans le journal d'audit unifié",
        opt_in="graph-audit-log-query",
    ),
    HttpEndpoint("log-analytics", "GET", "/**", "métadonnées de l'espace de travail"),
    HttpEndpoint(
        "log-analytics",
        "POST",
        "/v1/workspaces/{id}/query",
        "requête KQL : un POST qui ne fait que lire",
    ),
    HttpEndpoint("splunk", "GET", "/**", "lecture de la configuration et des index"),
    HttpEndpoint(
        "splunk",
        "POST",
        "/services/search/jobs",
        "recherche SPL",
        opt_in="splunk-search-job",
    ),
)

ALLOWED_OPERATIONS: Final[Mapping[str, tuple[Operation, ...]]] = MappingProxyType(
    {"windows": _WINDOWS, "ldap": _LDAP, "aws": _AWS, "http": _HTTP}
)
"""Source unique : opérations admises, par famille de collecteurs."""

OPT_INS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "aws-assume-role": (
            "`sts:AssumeRole` émet des identifiants temporaires pour le rôle "
            "d'un autre compte et laisse un événement dans son CloudTrail"
        ),
        "graph-audit-log-query": (
            "`POST /security/auditLog/queries` crée un objet `auditLogQuery` "
            "dans le tenant et consomme des quotas quotidiens de requêtes dont "
            "le client peut avoir besoin en pleine crise"
        ),
        "splunk-search-job": (
            "`POST /services/search/jobs` crée un job de recherche sur le "
            "serveur Splunk et compte dans le quota de recherches de son "
            "compte"
        ),
    }
)
"""Exceptions désactivées par défaut : nom de l'opt-in, puis ce qu'il coûte."""

PS_FORBIDDEN_VERBS: Final = (
    "Set",
    "New",
    "Remove",
    "Clear",
    "Add",
    "Enable",
    "Disable",
    "Start",
    "Stop",
    "Restart",
    "Register",
)
"""Verbes PowerShell interdits, sauf exception nommée dans l'allowlist."""

PS_FORBIDDEN_COMMANDS: Final = (
    "Limit-EventLog",
    "Invoke-Expression",
    "Invoke-Command",
    "Invoke-CimMethod",
    "Invoke-WmiMethod",
    "Start-Process",
    "Write-EventLog",
    "Clear-EventLog",
)
"""Cmdlets interdites, jamais admises dans l'allowlist."""

PS_FORBIDDEN_PARAMETERS: Final = ("ComputerName", "Cn", "CimSession")
"""Paramètres interdits sur toute cmdlet, abréviations comprises : ils joignent
un autre hôte que la cible du script."""

AWS_DENIED: Final[Mapping[str, str]] = MappingProxyType(
    {
        "secretsmanager:GetSecretValue": "renvoie un secret en clair",
        "s3:GetObject": "renvoie le contenu d'un objet : une donnée métier",
        "ssm:GetParameter*": "renvoie des paramètres, dont des secrets déchiffrés",
        "ec2:GetPasswordData": "renvoie le mot de passe administrateur d'une instance",
        "sts:GetSessionToken": "émet des identifiants temporaires",
        "sts:GetFederationToken": "émet des identifiants temporaires",
        "sso:GetRoleCredentials": "émet des identifiants temporaires",
        "cognito-identity:Get*": (
            "crée une identité (`GetId`) ou émet des identifiants et des jetons"
        ),
        "redshift:GetClusterCredentials*": (
            "émet des identifiants de base de données et peut créer "
            "l'utilisateur (`AutoCreate`)"
        ),
        "redshift-serverless:GetCredentials": (
            "émet des identifiants de base de données"
        ),
        "ecr:GetAuthorizationToken": "émet un jeton d'accès au registre",
        "ecr-public:GetAuthorizationToken": "émet un jeton d'accès au registre",
        "codeartifact:GetAuthorizationToken": "émet un jeton d'accès au dépôt",
        "lightsail:GetRelationalDatabaseMasterUserPassword": (
            "renvoie le mot de passe maître d'une base de données"
        ),
        "lightsail:GetInstanceAccessDetails": (
            "renvoie des identifiants d'accès à une instance"
        ),
        "glue:GetConnection*": (
            "renvoie les propriétés d'une connexion, dont son mot de passe"
        ),
        "apigateway:GetApiKey*": "renvoie des clés d'API",
        "dynamodb:GetItem": "renvoie un élément d'une table : une donnée métier",
        "kinesis:GetRecords": "renvoie les enregistrements d'un flux",
        "codecommit:GetFile": "renvoie le contenu d'un fichier d'un dépôt",
        "codecommit:GetBlob": "renvoie le contenu d'un fichier d'un dépôt",
        "glacier:GetJobOutput": "renvoie le contenu d'une archive",
    }
)
"""Lectures AWS refusées malgré leur préfixe : elles renvoient un secret ou du
contenu, émettent des identifiants ou créent un objet. Liste de refus, donc
incomplète par nature : le collecteur AWS (#95) nommera ses services."""

_CONTENU = "contenu d'une boîte aux lettres ou d'un espace de fichiers"
HTTP_DENIED: Final[tuple[HttpDenied, ...]] = (
    HttpDenied(
        "graph",
        ("deviceLocalCredentials",),
        "renvoie les mots de passe d'administrateur local (LAPS)",
    ),
    HttpDenied(
        "graph", ("recoveryKeys",), "renvoie les clés de récupération BitLocker"
    ),
    HttpDenied("graph", ("messages",), _CONTENU),
    HttpDenied("graph", ("mailFolders",), _CONTENU),
    HttpDenied("graph", ("drive",), _CONTENU),
    HttpDenied("graph", ("drives",), _CONTENU),
    HttpDenied(
        "splunk",
        ("jobs", "export"),
        "lance une recherche SPL par un simple GET, hors de l'opt-in "
        "`splunk-search-job`",
    ),
)
"""Chemins HTTP refusés malgré la règle ``GET /**`` : ils renvoient un secret
ou du contenu, ou lancent une recherche. Liste de refus, incomplète par
nature : chaque collecteur (#112, #113) nommera ses endpoints."""

LDAP_FORBIDDEN: Final = ("modify", "add", "delete", "modrdn", "modify_dn")
"""Opérations LDAP d'écriture, citées par la documentation ; toute méthode hors
allowlist est refusée de la même façon."""

NEVER_ALLOWED: Final[Mapping[str, str]] = MappingProxyType(
    {
        "auditpol /set, /clear, /remove, /restore": "modifient la politique d'audit",
        "auditpol /backup": "écrit un fichier CSV sur la cible",
        "wevtutil cl, sl, im, um, al": (
            "effacent un journal (ATT&CK T1070.001) ou modifient sa configuration"
        ),
        "wevtutil qe": "lit le contenu des événements, pas une configuration",
        "wevtutil epl": "écrit un fichier d'export sur la cible",
        "reg add, delete, import": "modifient le registre",
        "reg query sur les ruches SAM et SECURITY": (
            "lit la base des comptes locaux et les secrets LSA"
        ),
        "reg export": "écrit un fichier sur la cible",
        "w32tm /config, /resync": "modifient ou forcent la synchronisation",
    }
)
"""Formes d'exécutables qui n'entreront jamais dans l'allowlist, et pourquoi."""

_T = TypeVar(
    "_T",
    Executable,
    PsCommand,
    PsMethod,
    PsType,
    LdapOperation,
    AwsOperation,
    HttpEndpoint,
)


def _operations(collector: str, kind: type[_T]) -> tuple[_T, ...]:
    return tuple(op for op in ALLOWED_OPERATIONS[collector] if isinstance(op, kind))


def _opt_ins(
    demandes: Collection[str], operations: Sequence[Operation]
) -> frozenset[str]:
    """Opt-in demandés, vérifiés : un nom inconnu est une erreur de programmation."""
    if isinstance(demandes, str):
        raise TypeError("opt_in : collection de noms attendue, pas une chaîne")
    connus = {
        op.opt_in
        for op in operations
        if isinstance(op, AwsOperation | HttpEndpoint) and op.opt_in is not None
    }
    inconnus = sorted(set(demandes) - connus)
    if inconnus:
        raise ValueError(f"opt-in inconnu : {', '.join(inconnus)}")
    return frozenset(demandes)


# --- executables ----------------------------------------------------------------


def _programme(chemin: str) -> str:
    """Nom du programme d'un chemin complet ``<lecteur>:\\...\\System32\\<nom>``."""
    fichier = PureWindowsPath(chemin)
    if (
        "\0" in chemin
        or re.fullmatch(r"[A-Za-z]:", fichier.drive) is None
        or fichier.root != "\\"
        or ".." in fichier.parts
        or fichier.parent.name.lower() != "system32"
    ):
        raise ReadOnlyViolation(
            "exécutable refusé : chemin complet attendu "
            r"(<lecteur>:\...\System32\<programme>), jamais un nom seul"
        )
    return fichier.name.lower()


def check_command(argv: Sequence[str]) -> tuple[str, ...]:
    """Vérifie ``argv`` contre l'allowlist et rend l'argv validé, figé.

    Lève ``ReadOnlyViolation`` si le programme n'est pas appelé par son chemin
    complet, s'il est hors allowlist ou si ses arguments diffèrent de toutes
    ses formes figées.
    """
    if isinstance(argv, str | bytes) or not isinstance(argv, Sequence):
        raise ReadOnlyViolation(
            "commande refusée : liste d'arguments attendue, pas une ligne de commande"
        )
    fige = tuple(argv)
    if not fige or not all(isinstance(arg, str) for arg in fige):
        raise ReadOnlyViolation("commande refusée : arguments textuels attendus")
    programme = _programme(fige[0])
    formes = [
        op for op in _operations("windows", Executable) if op.program == programme
    ]
    if not formes:
        raise ReadOnlyViolation("exécutable refusé : programme hors allowlist")
    if not any(forme.accepts(fige[1:]) for forme in formes):
        raise ReadOnlyViolation(
            f"{programme} : arguments hors des formes figées de l'allowlist"
        )
    return fige


# --- scripts PowerShell ---------------------------------------------------------

SCRIPTS: Final[Mapping[str, str]] = MappingProxyType({})
"""Registre des scripts de ``src/amnesia/ps/`` : nom du fichier, puis empreinte
SHA-256 (``script_digest``). Vide tant que le collecteur PowerShell (#48) n'a
pas livré son premier script."""

_NOM_DE_SCRIPT = re.compile(r"[a-z0-9][a-z0-9_]*\.ps1")


def script_digest(content: bytes) -> str:
    """Empreinte SHA-256 d'un script, fins de ligne ramenées à LF.

    Les scripts sont en CRLF dans une copie de travail (``.gitattributes``) ;
    l'empreinte ne dépend pas de la façon dont le fichier a été extrait.
    """
    return hashlib.sha256(content.replace(b"\r\n", b"\n")).hexdigest()


def load_script(
    name: str,
    *,
    directory: Path | None = None,
    registry: Mapping[str, str] | None = None,
) -> str:
    """Texte du script ``name``, après vérification du registre et de l'empreinte.

    Lève ``ReadOnlyViolation`` si le script est absent du registre, illisible
    ou si son empreinte diffère de celle figée. Le texte rendu est celui dont
    l'empreinte a été vérifiée : c'est lui qu'un collecteur exécute, jamais le
    fichier relu. ``directory`` et ``registry`` valent par défaut le paquet
    ``amnesia/ps`` et ``SCRIPTS``.
    """
    registre = SCRIPTS if registry is None else registry
    attendue = registre.get(name) if isinstance(name, str) else None
    if attendue is None or _NOM_DE_SCRIPT.fullmatch(name) is None:
        raise ReadOnlyViolation("script PowerShell refusé : absent du registre")
    try:
        if directory is None:
            contenu = files("amnesia").joinpath("ps", name).read_bytes()
        else:
            contenu = (directory / name).read_bytes()
    except OSError as exc:
        raise ReadOnlyViolation(f"script PowerShell {name} : illisible") from exc
    if script_digest(contenu) != attendue:
        raise ReadOnlyViolation(
            f"script PowerShell {name} : empreinte différente de celle du registre"
        )
    return contenu.replace(b"\r\n", b"\n").decode("utf-8-sig")


def _parametres_ps(element: Mapping[str, Any]) -> str | None:
    """Motif du refus des paramètres d'une cmdlet admise."""
    parametres, etale = element.get("parameters"), element.get("splat")
    if (
        not isinstance(parametres, list)
        or not all(isinstance(p, str) and p for p in parametres)
        or not isinstance(etale, bool)
    ):
        return "élément d'inventaire inconnu"
    if etale:
        return "paramètres étalés (@variable), hors de vue de l'analyse"
    for parametre in parametres:
        # PowerShell admet tout debut non ambigu d'un nom de parametre
        if any(
            interdit.lower().startswith(parametre.lower())
            for interdit in PS_FORBIDDEN_PARAMETERS
        ):
            return f"paramètre qui joint un autre hôte : -{parametre}"
    return None


def _commande_ps(element: Mapping[str, Any]) -> str | None:
    nom = element.get("name")
    if not isinstance(nom, str) or not nom:
        return "commande au nom calculé à l'exécution"
    admises = {op.name.lower() for op in _operations("windows", PsCommand)}
    if nom.lower() in admises:
        return _parametres_ps(element)
    if nom.lower() in {c.lower() for c in PS_FORBIDDEN_COMMANDS}:
        return f"cmdlet interdite : {nom}"
    verbe, tiret, _ = nom.partition("-")
    if tiret and verbe.lower() in {v.lower() for v in PS_FORBIDDEN_VERBS}:
        return f"verbe interdit ({verbe}-) : {nom}"
    if not tiret:
        return f"alias ou exécutable (nom complet de cmdlet attendu) : {nom}"
    return f"commande hors allowlist : {nom}"


def _methode_ps(element: Mapping[str, Any]) -> str | None:
    nom, type_ = element.get("name"), element.get("type")
    if not isinstance(nom, str) or not nom:
        return "méthode au nom calculé à l'exécution"
    statique = element.get("static")
    for op in _operations("windows", PsMethod):
        if op.name.lower() != nom.lower():
            continue
        if statique is False and op.type is None:
            return None
        if (
            statique is True
            and isinstance(type_, str)
            and op.type is not None
            and op.type.lower() == type_.lower()
        ):
            return None
    if statique is True:
        return f"méthode statique hors allowlist : [{type_}]::{nom}()"
    return f"méthode hors allowlist : .{nom}()"


def _type_ps(nom: object) -> str | None:
    if not isinstance(nom, str) or not nom:
        return "type calculé à l'exécution"
    if nom.lower() in {op.name.lower() for op in _operations("windows", PsType)}:
        return None
    return f"type hors allowlist : [{nom}]"


def _element_ps(element: Mapping[str, Any]) -> str | None:
    """Motif du refus d'un élément de l'inventaire, ``None`` s'il est admis."""
    genre = element.get("kind")
    if genre == "command":
        return _commande_ps(element)
    if genre == "method":
        return _methode_ps(element)
    if genre == "type":
        return _type_ps(element.get("name"))
    if genre == "assignment":
        # $objet.Propriete = ... peut ecrire sur la cible (EventLog.MaximumKilobytes),
        # ${C:\fichier} = ... ecrit un fichier : seule une variable simple est admise
        if element.get("target") == "VariableExpressionAst" and (
            element.get("drive") is False
        ):
            return None
        return "affectation à autre chose qu'une variable simple"
    if genre == "redirection":
        if str(element.get("name")).lower() == "$null":
            return None
        return "redirection vers un fichier"
    if genre == "using":
        if element.get("name") == "Namespace":
            return None
        return "instruction using autre que « using namespace »"
    return "élément d'inventaire inconnu"


def check_script_inventory(inventory: Mapping[str, Any]) -> list[str]:
    """Écarts d'un script PowerShell à l'allowlist, d'après l'inventaire de son AST.

    ``inventory`` est une entrée de la sortie de ``scripts/inventaire_ps.ps1`` :
    ``errors`` (erreurs d'analyse) et ``items`` (commandes et leurs paramètres,
    appels de méthodes, types, affectations, redirections, ``using``). Rend un
    message par écart, liste
    vide si le script ne fait que des lectures admises. Tout ce qui n'est pas
    reconnu est un écart.
    """
    erreurs, elements = inventory.get("errors"), inventory.get("items")
    if not isinstance(erreurs, list) or not isinstance(elements, list):
        return ["inventaire illisible"]
    ecarts = ["erreur d'analyse du script" for _ in erreurs]
    for element in elements:
        if not isinstance(element, Mapping):
            ecarts.append("élément d'inventaire inconnu")
            continue
        motif = _element_ps(element)
        if motif is not None:
            ecarts.append(f"ligne {element.get('line')} : {motif}")
    return ecarts


# --- LDAP -----------------------------------------------------------------------


class ReadOnlyLdap:
    """Enveloppe d'une connexion LDAP : seules les opérations de l'allowlist passent.

    Toute autre méthode (``modify``, ``add``, ``delete``, ``modrdn``, opération
    étendue...) lève ``ReadOnlyViolation`` dès l'accès à l'attribut, donc avant
    toute requête. L'enveloppe ne dépend d'aucun SDK : le collecteur AD (#66)
    lui remet la connexion de son client et ne garde que l'enveloppe.
    """

    __slots__ = ("_connection",)

    def __init__(self, connection: object) -> None:
        object.__setattr__(self, "_connection", connection)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        if name not in {op.name for op in _operations("ldap", LdapOperation)}:
            raise ReadOnlyViolation(f"opération LDAP hors allowlist : {name}")
        return getattr(self._connection, name)

    def __setattr__(self, name: str, value: object) -> None:
        raise ReadOnlyViolation("enveloppe LDAP en lecture seule : attribut figé")


# --- AWS ------------------------------------------------------------------------


AWS_EVENT: Final = "before-call.*.*"
"""Événement botocore de la garde : émis pour chaque opération, après la
construction de la requête et avant sa signature et son envoi."""


def check_aws(service: str, operation: str, *, opt_in: Collection[str] = ()) -> None:
    """Refuse l'opération AWS ``service:operation`` si elle sort de l'allowlist.

    ``operation`` est le nom d'API (``DescribeTrails``), ``service`` le nom du
    client botocore (``cloudtrail``). La liste ``AWS_DENIED`` l'emporte sur
    l'allowlist.
    """
    regles = _operations("aws", AwsOperation)
    actifs = _opt_ins(opt_in, regles)
    if (
        not isinstance(service, str)
        or not isinstance(operation, str)
        or re.fullmatch(r"[a-z0-9-]+", service) is None
        or re.fullmatch(r"[A-Za-z0-9]+", operation) is None
    ):
        raise ReadOnlyViolation("opération AWS refusée : service ou nom illisible")
    appel = f"{service}:{operation}"
    if any(fnmatchcase(appel, motif) for motif in AWS_DENIED):
        raise ReadOnlyViolation(f"opération AWS refusée (secret ou contenu) : {appel}")
    for regle in regles:
        if fnmatchcase(appel, regle.pattern) and (
            regle.opt_in is None or regle.opt_in in actifs
        ):
            return
    raise ReadOnlyViolation(f"opération AWS hors allowlist : {appel}")


def aws_guard(*, opt_in: Collection[str] = ()) -> Callable[..., None]:
    """Crochet botocore ``before-call`` : refuse avant tout envoi.

    botocore appelle le crochet avec ``model`` (``OperationModel``) ; une
    exception levée ici interrompt l'appel avant la signature et l'envoi de la
    requête. Un modèle illisible est refusé.
    """
    actifs = _opt_ins(opt_in, _operations("aws", AwsOperation))

    def avant_appel(model: Any = None, **_autres: object) -> None:
        try:
            service, operation = model.service_model.service_name, model.name
        except AttributeError:
            raise ReadOnlyViolation(
                "opération AWS refusée : modèle d'opération illisible"
            ) from None
        check_aws(service, operation, opt_in=actifs)

    return avant_appel


def protect_aws_client(client: Any, *, opt_in: Collection[str] = ()) -> None:
    """Branche ``aws_guard()`` sur un client boto3 ou botocore (#95).

    À appeler sur chaque client créé, avant tout autre crochet. botocore émet
    ``before-call`` jusqu'à la première réponse, en commençant par les crochets
    les plus spécifiques ; ``register_first`` place la garde avant les crochets
    ordinaires du niveau ``before-call.*.*``, mais après un crochet déjà posé
    par ``register_first`` ou sur un événement plus spécifique. Un tel crochet
    qui répond à la place du service passe avant la garde : aucune requête ne
    part alors vers AWS.

    Le dernier appel fait foi : protéger de nouveau un client remplace la
    garde et ses ``opt_in``, au lieu de laisser les anciens actifs en silence.
    """
    # botocore ignore un second enregistrement sous le meme unique_id
    client.meta.events.unregister(AWS_EVENT, unique_id="amnesia-readonly")
    client.meta.events.register_first(
        AWS_EVENT, aws_guard(opt_in=opt_in), unique_id="amnesia-readonly"
    )


# --- HTTP -----------------------------------------------------------------------

_SEGMENT = re.compile(r"[A-Za-z0-9._~-]+")
_ENCODAGE_AMBIGU = re.compile(r"%(?:2e|2f|5c)", re.IGNORECASE)


def _decouper(url: object) -> tuple[str, int, tuple[str, ...]]:
    """Hôte, port et segments de chemin d'une URL HTTPS, ou ``ReadOnlyViolation``."""
    # urlsplit retire en silence tabulations et sauts de ligne, et les clients
    # HTTP ne lisent pas tous « \ » de la meme facon : refus plutot que
    # deux lectures differentes d'une meme URL
    if not isinstance(url, str) or re.search(r"[\x00-\x20\x7f\\]", url):
        raise ReadOnlyViolation("requête HTTP refusée : URL illisible")
    try:
        parties = urlsplit(url)
        port = parties.port
    except ValueError:
        raise ReadOnlyViolation("requête HTTP refusée : URL illisible") from None
    hote = (parties.hostname or "").lower()
    if parties.scheme.lower() != "https" or not hote:
        raise ReadOnlyViolation("requête HTTP refusée : URL https absolue attendue")
    if parties.username is not None or parties.password is not None:
        raise ReadOnlyViolation("requête HTTP refusée : identifiants dans l'URL")
    chemin = parties.path.removesuffix("/")
    segments = tuple(chemin.split("/")[1:]) if chemin else ()
    if (
        (chemin and not chemin.startswith("/"))
        or _ENCODAGE_AMBIGU.search(chemin)
        or any(segment in {"", ".", ".."} for segment in segments)
    ):
        raise ReadOnlyViolation("requête HTTP refusée : chemin ambigu")
    return hote, port or 443, segments


def _chemin_conforme(gabarit: str, segments: tuple[str, ...]) -> bool:
    attendus = tuple(gabarit.strip("/").split("/"))
    if attendus[-1] == "**":
        attendus = attendus[:-1]
        segments = segments[: len(attendus)]
    if len(attendus) != len(segments):
        return False
    return all(
        _SEGMENT.fullmatch(recu) is not None
        if attendu.startswith("{") and attendu.endswith("}")
        else attendu == recu
        for attendu, recu in zip(attendus, segments, strict=True)
    )


def _chemin_refuse(api: str, segments: tuple[str, ...]) -> HttpDenied | None:
    """Règle de ``HTTP_DENIED`` que le chemin enfreint, ``None`` sinon."""
    # le serveur decode « %6d » en « m » et lit users('x') comme users/x :
    # comparaison sur le nom decode du segment, sans casse ni cle accolee
    noms = tuple(unquote(s).partition("(")[0].lower() for s in segments)
    for refus in HTTP_DENIED:
        attendus = tuple(s.lower() for s in refus.segments)
        if refus.api == api and any(
            noms[i : i + len(attendus)] == attendus for i in range(len(noms))
        ):
            return refus
    return None


class HttpGuard:
    """Garde d'un client HTTP : allowlist par verbe et par chemin, pour une API.

    ``api`` nomme l'API (``graph``, ``log-analytics``, ``splunk``) et
    ``base_url`` l'adresse que le collecteur a le droit de joindre : toute
    requête vers un autre hôte, un autre port ou hors du chemin de base est
    refusée, comme tout verbe autre que GET hors des endpoints nommés et tout
    chemin de ``HTTP_DENIED``, quel que soit le verbe. Une exception désactivée
    par défaut ne passe qu'avec son ``opt_in``.

    L'instance est appelable avec un objet requête (``.method``, ``.url``) :
    elle se branche comme crochet d'avant-envoi d'un client HTTP (#95, #112,
    #113).
    """

    def __init__(
        self, api: str, base_url: str, *, opt_in: Collection[str] = ()
    ) -> None:
        self._endpoints = tuple(
            op for op in _operations("http", HttpEndpoint) if op.api == api
        )
        if not self._endpoints:
            raise ValueError(f"API HTTP inconnue : {api}")
        self.api = api
        self._opt_in = _opt_ins(opt_in, self._endpoints)
        try:
            self._base = _decouper(base_url)
        except ReadOnlyViolation:
            raise ValueError("base_url : URL https absolue attendue") from None

    def check(self, method: str, url: str) -> None:
        """Lève ``ReadOnlyViolation`` si la requête sort de l'allowlist."""
        hote, port, segments = _decouper(url)
        base_hote, base_port, base_segments = self._base
        if (hote, port) != (base_hote, base_port) or (
            segments[: len(base_segments)] != base_segments
        ):
            raise ReadOnlyViolation(
                f"requête HTTP refusée ({self.api}) : hors de l'adresse de base"
            )
        verbe = method.upper() if isinstance(method, str) else ""
        relatifs = segments[len(base_segments) :]
        # chemin entier : une adresse de base ne met pas un chemin refuse a l'abri
        refus = _chemin_refuse(self.api, segments)
        if refus is not None:
            raise ReadOnlyViolation(
                f"requête HTTP refusée ({self.api}) : {refus.label} "
                "(secret, contenu ou recherche)"
            )
        for endpoint in self._endpoints:
            if endpoint.method != verbe or not _chemin_conforme(
                endpoint.path, relatifs
            ):
                continue
            if endpoint.opt_in is None or endpoint.opt_in in self._opt_in:
                return
            raise ReadOnlyViolation(
                f"requête HTTP refusée ({self.api}) : {endpoint.label} exige "
                f"l'opt-in {endpoint.opt_in}"
            )
        raise ReadOnlyViolation(
            f"requête HTTP refusée ({self.api}) : verbe ou chemin hors allowlist"
        )

    def __call__(self, request: Any) -> None:
        try:
            methode, url = request.method, str(request.url)
        except AttributeError:
            raise ReadOnlyViolation(
                "requête HTTP refusée : requête illisible"
            ) from None
        self.check(methode, url)


# --- documentation --------------------------------------------------------------


def _table(entetes: tuple[str, ...], lignes: Sequence[tuple[str, ...]]) -> list[str]:
    rendu = ["| " + " | ".join(entetes) + " |", "|" + "---|" * len(entetes)]
    rendu += ["| " + " | ".join(ligne) + " |" for ligne in lignes]
    return [*rendu, ""]


def _code(texte: str) -> str:
    return f"`{texte}`"


def _opt_in(op: AwsOperation | HttpEndpoint) -> str:
    return "admis par défaut" if op.opt_in is None else f"opt-in `{op.opt_in}`"


def render_markdown() -> str:
    """Texte de ``docs/READ-ONLY.md``, généré depuis ``ALLOWED_OPERATIONS``."""
    lignes = [
        "# Lecture seule : ce qu'amnesia exécute sur une cible",
        "",
        "<!-- Fichier généré depuis `src/amnesia/readonly.py` par",
        "`uv run python scripts/generer_read_only.py` : ne pas le modifier à la",
        "main (`tests/unit/test_readonly.py` vérifie qu'il est à jour). -->",
        "",
        "amnesia ne modifie jamais une cible auditée. Cette page liste, opération",
        "par opération, tout ce que ses collecteurs ont le droit d'exécuter :",
        "une opération absente de cette liste est refusée avant exécution",
        "(`ReadOnlyViolation`). La décision et ses limites sont dans",
        "[l'ADR 0006](adr/0006-garantie-lecture-seule.md) : c'est un garde-fou",
        "contre une erreur de code ou d'usage, pas une isolation ; contre du code",
        "hostile, seule une contrainte côté cible tient (endpoint JEA, rôle en",
        "lecture seule, compte d'audit à droits réduits).",
        "",
        f"Version de l'allowlist : {ALLOWLIST_VERSION}.",
        "",
        "## Exécutables Windows",
        "",
        "Appelés par leur chemin complet (`<lecteur>:\\...\\System32\\<programme>`),",
        "sans shell, avec un délai, et seulement sous l'une de ces formes : un",
        "argument de plus, de moins ou différent est refusé.",
        "",
    ]
    lignes += _table(
        ("Commande", "Ce qu'elle lit"),
        [(_code(op.label), op.reads) for op in _operations("windows", Executable)],
    )
    lignes += ["Valeurs admises pour les arguments variables :", ""]
    lignes += [
        f"- `<{p.name}>` : `{p.pattern}`"
        for p in dict.fromkeys(
            arg
            for op in _operations("windows", Executable)
            for arg in op.args
            if isinstance(arg, Param)
        )
    ]
    lignes += ["", "Formes qui n'entreront jamais dans l'allowlist :", ""]
    lignes += _table(
        ("Forme", "Pourquoi"),
        [(_code(forme), motif) for forme, motif in NEVER_ALLOWED.items()],
    )
    lignes += [
        "## Scripts PowerShell",
        "",
        "Un script vit dans `src/amnesia/ps/`, jamais dans une chaîne du code",
        "Python, et n'est exécuté que s'il est inscrit au registre avec son",
        "empreinte SHA-256 : un script inconnu ou modifié est refusé.",
        "",
    ]
    if SCRIPTS:
        lignes += _table(
            ("Script", "SHA-256"),
            [(_code(nom), _code(empreinte)) for nom, empreinte in SCRIPTS.items()],
        )
    else:
        lignes += ["Aucun script n'est encore livré (collecteur PowerShell : #48).", ""]
    lignes += [
        "La CI analyse l'AST de chaque script (`Parser::ParseFile`) et refuse",
        "toute commande, méthode .NET ou type absent des tables ci-dessous, tout",
        "alias (seul le nom complet d'une cmdlet est admis), toute commande au nom",
        "calculé à l'exécution, toute affectation à autre chose qu'une variable",
        "simple et toute redirection vers un fichier. Un type compte autant",
        "qu'une méthode : une conversion (`[Type]$valeur`, `[Type]@{...}`,",
        "`-as`) appelle un constructeur ou des accesseurs.",
        "",
    ]
    lignes += _table(
        ("Cmdlet", "Usage", "Exception"),
        [
            (_code(op.label), op.reads, "verbe interdit, admis" if op.exception else "")
            for op in _operations("windows", PsCommand)
        ],
    )
    lignes += _table(
        ("Méthode .NET", "Usage"),
        [(_code(op.label), op.reads) for op in _operations("windows", PsMethod)],
    )
    lignes += _table(
        ("Type", "Usage"),
        [(_code(op.label), op.reads) for op in _operations("windows", PsType)],
    )
    lignes += [
        "Verbes interdits, sauf exception nommée ci-dessus : "
        + ", ".join(f"`{v}-`" for v in PS_FORBIDDEN_VERBS)
        + ".",
        "",
        "Cmdlets interdites : "
        + ", ".join(_code(c) for c in PS_FORBIDDEN_COMMANDS)
        + ".",
        "",
        "Paramètres interdits sur toute cmdlet, abréviations comprises, parce",
        "qu'ils joignent un autre hôte que la cible : "
        + ", ".join(_code(f"-{p}") for p in PS_FORBIDDEN_PARAMETERS)
        + ". Des paramètres étalés (`@variable`) sont refusés : l'analyse ne les",
        "voit pas.",
        "",
        "## LDAP",
        "",
        "La connexion est enveloppée : seules ces opérations passent. "
        + ", ".join(_code(nom) for nom in LDAP_FORBIDDEN)
        + " et toute autre méthode sont refusées avant la moindre requête.",
        "",
    ]
    lignes += _table(
        ("Opération", "Usage"),
        [(_code(op.label), op.reads) for op in _operations("ldap", LdapOperation)],
    )
    lignes += [
        "## AWS",
        "",
        "Un crochet `before-call` posé sur chaque client refuse, avant tout envoi,",
        "une opération qui ne correspond à aucun de ces motifs",
        "(`service:Opération`).",
        "",
    ]
    lignes += _table(
        ("Opérations", "Usage", "Statut"),
        [
            (_code(op.label), op.reads, _opt_in(op))
            for op in _operations("aws", AwsOperation)
        ],
    )
    lignes += [
        "Lectures refusées malgré leur préfixe (liste de refus, incomplète par",
        "nature : le collecteur AWS nommera ses services, #95) :",
        "",
    ]
    lignes += _table(
        ("Opérations", "Pourquoi"),
        [(_code(motif), raison) for motif, raison in AWS_DENIED.items()],
    )
    lignes += [
        "## HTTP (Microsoft Graph, Log Analytics, Splunk)",
        "",
        "HTTPS seulement, vers la seule adresse de base de l'API auditée. GET est",
        "le verbe par défaut ; tout autre verbe n'est admis que sur un endpoint",
        "nommé ici.",
        "",
    ]
    lignes += _table(
        ("API", "Requête", "Usage", "Statut"),
        [
            (_code(op.api), _code(op.label), op.reads, _opt_in(op))
            for op in _operations("http", HttpEndpoint)
        ],
    )
    lignes += [
        "Chemins refusés quel que soit le verbe, où qu'ils se trouvent dans",
        "l'URL (`**` vaut tout préfixe ou toute suite) :",
        "",
    ]
    lignes += _table(
        ("API", "Chemin", "Pourquoi"),
        [(_code(r.api), _code(r.label), r.reason) for r in HTTP_DENIED],
    )
    lignes += [
        "## Exceptions désactivées par défaut",
        "",
        "Ces opérations ne modifient aucune configuration, mais elles laissent une",
        "trace ou consomment une ressource chez le client : elles sont refusées",
        "tant que l'auditeur ne les a pas activées explicitement, une par une.",
        "",
    ]
    lignes += _table(
        ("Opt-in", "Ce qu'il coûte"),
        [(_code(nom), cout) for nom, cout in OPT_INS.items()],
    )
    return "\n".join(lignes)
