# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Garantie de lecture seule : allowlist des operations (amnesia.readonly, #39).

Les gardes cloud, LDAP et HTTP n'importent aucun SDK : elles sont exercees ici
avec des doublures qui reproduisent le point de branchement de chaque client
(emetteur d'evenements de botocore, crochet d'avant-envoi d'un client HTTP).
L'analyse des scripts PowerShell par le vrai pwsh est dans
tests/integration/test_scripts_powershell.py.
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from fnmatch import fnmatchcase
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from amnesia import readonly
from amnesia.readonly import (
    ALLOWED_OPERATIONS,
    AWS_DENIED,
    AWS_EVENT,
    OPT_INS,
    PS_FORBIDDEN_COMMANDS,
    PS_FORBIDDEN_VERBS,
    SCRIPTS,
    AwsOperation,
    Executable,
    HttpEndpoint,
    HttpGuard,
    LdapOperation,
    Param,
    PsCommand,
    PsMethod,
    ReadOnlyLdap,
    ReadOnlyViolation,
    aws_guard,
    check_aws,
    check_command,
    check_script_inventory,
    load_script,
    protect_aws_client,
    render_markdown,
    script_digest,
)

RACINE = Path(__file__).resolve().parent.parent.parent
SRC = RACINE / "src" / "amnesia"
DOCUMENT = RACINE / "docs" / "READ-ONLY.md"
SYSTEM32 = "C:\\Windows\\System32\\"
# valeur d'exemple de chaque argument variable (donnees fictives)
EXEMPLES = {
    "canal": "Microsoft-Windows-Sysmon/Operational",
    "clé": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell",
    "valeur": "EnableScriptBlockLogging",
    "service": "Sysmon64",
}
GUID = "00000000-0000-0000-0000-000000000000"


def _toutes() -> list[readonly.Operation]:
    return [op for ops in ALLOWED_OPERATIONS.values() for op in ops]


def _executables() -> list[Executable]:
    return [op for op in _toutes() if isinstance(op, Executable)]


def _argv(forme: Executable) -> list[str]:
    arguments = [a if isinstance(a, str) else EXEMPLES[a.name] for a in forme.args]
    return [SYSTEM32 + forme.program, *arguments]


# --- registre -------------------------------------------------------------------


def test_registre_source_unique_et_fige() -> None:
    assert set(ALLOWED_OPERATIONS) == {"windows", "ldap", "aws", "http"}
    with pytest.raises(TypeError):
        ALLOWED_OPERATIONS["windows"] = ()  # type: ignore[index]
    for op in _toutes():
        # chaque operation dit ce qu'elle lit : c'est sa justification
        assert op.reads.strip(), op.label
        with pytest.raises(AttributeError):
            op.reads = ""  # type: ignore[misc]


def test_opt_in_declares_et_tous_utilises() -> None:
    utilises = {
        op.opt_in
        for op in _toutes()
        if isinstance(op, AwsOperation | HttpEndpoint) and op.opt_in is not None
    }
    assert utilises == set(OPT_INS)
    assert all(cout.strip() for cout in OPT_INS.values())


# --- executables ----------------------------------------------------------------


@pytest.mark.parametrize("forme", _executables(), ids=lambda forme: forme.label)
def test_chaque_forme_figee_est_admise(forme: Executable) -> None:
    argv = _argv(forme)
    assert check_command(argv) == tuple(argv)


def test_argument_variable_sans_exemple_oublie() -> None:
    noms = {
        a.name for forme in _executables() for a in forme.args if isinstance(a, Param)
    }
    assert noms == set(EXEMPLES)


@pytest.mark.parametrize(
    "commande",
    [
        "auditpol.exe /set /subcategory:Logon /success:disable",
        "auditpol.exe /clear /y",
        "auditpol.exe /remove /allusers",
        "auditpol.exe /restore /file:C:\\politique.csv",
        "auditpol.exe /backup /file:C:\\politique.csv",
        "wevtutil.exe cl Security",
        "wevtutil.exe sl Security /ms:1048576",
        "wevtutil.exe im C:\\manifeste.man",
        "wevtutil.exe um C:\\manifeste.man",
        "wevtutil.exe al C:\\archive.evtx",
        "wevtutil.exe qe Security",
        "wevtutil.exe epl Security C:\\export.evtx",
        "reg.exe add HKLM\\SOFTWARE\\Exemple /v Actif /d 0",
        "reg.exe delete HKLM\\SOFTWARE\\Exemple /f",
        "reg.exe import C:\\exemple.reg",
        "reg.exe export HKLM\\SOFTWARE\\Exemple C:\\exemple.reg",
        "w32tm.exe /config /update",
        "w32tm.exe /resync",
        "sc.exe stop EventLog",
        "sc.exe config EventLog start=disabled",
        "cmd.exe /c ver",
        "powershell.exe -Command Clear-EventLog",
    ],
)
def test_commande_interdite_refusee(commande: str) -> None:
    programme, *arguments = commande.split(" ")
    with pytest.raises(ReadOnlyViolation):
        check_command([SYSTEM32 + programme, *arguments])


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["/get"],
        ["/get", "/category:*"],
        ["/get", "/category:*", "/r", "/r"],
        ["/get", "/category:*", "/r", "/backup"],
        ["/get", "/subcategory:*", "/r"],
        ["/GET", "/category:*", "/r"],
        ["/get", "/category:Logon", "/r"],
        ["/r", "/category:*", "/get"],
        ["/get /category:* /r"],
    ],
)
def test_auditpol_hors_de_sa_forme_figee_refuse(arguments: list[str]) -> None:
    with pytest.raises(ReadOnlyViolation, match=r"auditpol\.exe : arguments hors"):
        check_command([SYSTEM32 + "auditpol.exe", *arguments])


@pytest.mark.parametrize(
    "programme",
    [
        "wevtutil",
        "wevtutil.exe",
        "System32\\wevtutil.exe",
        "C:wevtutil.exe",
        "C:\\Temp\\wevtutil.exe",
        "C:\\Windows\\System32\\..\\System32\\wevtutil.exe",
        "\\\\srv-file\\partage\\System32\\wevtutil.exe",
        "/usr/bin/wevtutil.exe",
        "C:\\Windows\\System32\\wevtutil.exe:flux",
        "C:\\Windows\\System32\\wevtutil.exe ",
        "C:\\Windows\\System32\\wevtutil.exe\0",
        "",
    ],
)
def test_programme_sans_chemin_complet_refuse(programme: str) -> None:
    with pytest.raises(ReadOnlyViolation):
        check_command([programme, "gl", "Security"])


def test_chemin_complet_insensible_a_la_casse_et_au_lecteur() -> None:
    assert check_command(["D:\\WINNT\\system32\\WEVTUTIL.EXE", "gl", "Security"])
    assert check_command(["C:/Windows/System32/wevtutil.exe", "gl", "Security"])


@pytest.mark.parametrize(
    "arguments",
    [
        # une valeur lue comme une option viserait un autre hote ou un fichier
        ["gl", "/r:srv-file"],
        ["gl", "-r:srv-file"],
        ["gl", "Security", "/r:srv-file"],
        ["gl", ""],
        ["gl", "Security\n"],
        ["gl", "Security;cl"],
    ],
)
def test_canal_wevtutil_borne(arguments: list[str]) -> None:
    with pytest.raises(ReadOnlyViolation):
        check_command([SYSTEM32 + "wevtutil.exe", *arguments])


@pytest.mark.parametrize(
    "arguments",
    [
        ["query", "\\\\srv-file\\HKLM\\SOFTWARE"],
        ["query", "HKCU\\Software"],
        ["query", "HKLM"],
        ["query", "HKLM\\SOFTWARE", "/v"],
        ["query", "HKLM\\SOFTWARE", "/v", "/s"],
        ["query", "HKLM\\SOFTWARE", "/s"],
    ],
)
def test_cle_de_registre_bornee(arguments: list[str]) -> None:
    with pytest.raises(ReadOnlyViolation):
        check_command([SYSTEM32 + "reg.exe", *arguments])


@pytest.mark.parametrize(
    "argv", ["wevtutil.exe gl Security", b"wevtutil.exe", [], [None], [1, 2], None, 3]
)
def test_argv_mal_forme_refuse(argv: Any) -> None:
    with pytest.raises(ReadOnlyViolation):
        check_command(argv)


def test_message_sans_echo_des_arguments() -> None:
    with pytest.raises(ReadOnlyViolation) as refus:
        check_command([SYSTEM32 + "wevtutil.exe", "cl", "JOURNAL-DU-CLIENT"])
    assert "JOURNAL-DU-CLIENT" not in str(refus.value)
    with pytest.raises(ReadOnlyViolation) as refus:
        check_command(["C:\\Dossier-Du-Client\\outil.exe"])
    assert "Dossier-Du-Client" not in str(refus.value)


# --- un seul point de lancement -------------------------------------------------

LANCEURS = {"run", "Popen", "call", "check_call", "check_output"}


class _Lancements(ast.NodeVisitor):
    """Fonction englobante de chaque reference a un lanceur de subprocess."""

    def __init__(self) -> None:
        self.pile: list[str] = []
        self.trouves: list[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.pile.append(node.name)
        self.generic_visit(node)
        self.pile.pop()

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "subprocess":
            self.trouves.append("from subprocess import")

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if (
            isinstance(node.value, ast.Name)
            and node.value.id == "subprocess"
            and node.attr in LANCEURS
        ):
            self.trouves.append(self.pile[-1] if self.pile else "<module>")
        self.generic_visit(node)


def _lancements(source: str) -> list[str]:
    visiteur = _Lancements()
    visiteur.visit(ast.parse(source))
    return visiteur.trouves


def test_detection_des_lancements() -> None:
    source = (
        "import subprocess\n"
        "def run_command():\n    subprocess.run([])\n"
        "def autre():\n    subprocess.Popen([])\n"
        "X = subprocess.check_output\n"
    )
    assert _lancements(source) == ["run_command", "autre", "<module>"]
    assert _lancements("from subprocess import run\n") == ["from subprocess import"]


def test_la_collecte_ne_lance_un_processus_que_par_run_command() -> None:
    # tout processus d'un collecteur passe par l'allowlist (ADR 0006, point 2)
    fichiers = sorted((SRC / "facts").rglob("*.py"))
    assert fichiers
    trouves = {
        f"{fichier.name}:{fonction}"
        for fichier in fichiers
        for fonction in _lancements(fichier.read_text(encoding="utf-8"))
    }
    assert trouves == {"collectors.py:run_command"}


# --- scripts PowerShell ---------------------------------------------------------

SCRIPT = b"\xef\xbb\xbfGet-WinEvent -ListLog 'Security'\r\n"


def _depot(tmp_path: Path, contenu: bytes = SCRIPT) -> tuple[Path, dict[str, str]]:
    (tmp_path / "journaux.ps1").write_bytes(contenu)
    return tmp_path, {"journaux.ps1": script_digest(SCRIPT)}


def test_script_inscrit_et_intact_charge(tmp_path: Path) -> None:
    dossier, registre = _depot(tmp_path)
    texte = load_script("journaux.ps1", directory=dossier, registry=registre)
    # sans BOM, fins de ligne LF : le texte dont l'empreinte a ete verifiee
    assert texte == "Get-WinEvent -ListLog 'Security'\n"


def test_empreinte_independante_des_fins_de_ligne(tmp_path: Path) -> None:
    dossier, registre = _depot(tmp_path, SCRIPT.replace(b"\r\n", b"\n"))
    assert load_script("journaux.ps1", directory=dossier, registry=registre)


def test_script_absent_du_registre_refuse(tmp_path: Path) -> None:
    dossier, registre = _depot(tmp_path)
    (dossier / "inconnu.ps1").write_bytes(SCRIPT)
    with pytest.raises(ReadOnlyViolation, match="absent du registre"):
        load_script("inconnu.ps1", directory=dossier, registry=registre)
    # le registre du paquet ne connait pas davantage ce nom
    with pytest.raises(ReadOnlyViolation, match="absent du registre"):
        load_script("inconnu.ps1")


def test_script_a_l_empreinte_modifiee_refuse(tmp_path: Path) -> None:
    dossier, registre = _depot(tmp_path, SCRIPT + b"Clear-EventLog -LogName Security\n")
    with pytest.raises(ReadOnlyViolation, match="empreinte"):
        load_script("journaux.ps1", directory=dossier, registry=registre)


def test_script_inscrit_mais_absent_refuse(tmp_path: Path) -> None:
    registre = {"journaux.ps1": script_digest(SCRIPT)}
    with pytest.raises(ReadOnlyViolation, match="illisible"):
        load_script("journaux.ps1", directory=tmp_path, registry=registre)
    # sans dossier : le paquet amnesia/ps, qui ne contient pas ce script
    with pytest.raises(ReadOnlyViolation, match="illisible"):
        load_script("journaux.ps1", registry=registre)


@pytest.mark.parametrize("nom", ["../journaux.ps1", "sous/journaux.ps1", "x.psm1", ""])
def test_nom_de_script_hors_du_dossier_refuse(tmp_path: Path, nom: str) -> None:
    # le fichier existe et son empreinte concorde : seul le nom motive le refus
    dossier = tmp_path / "ps"
    (dossier / "sous").mkdir(parents=True)
    for fichier in ("journaux.ps1", "ps/sous/journaux.ps1", "ps/x.psm1"):
        (tmp_path / fichier).write_bytes(SCRIPT)
    registre = {nom: script_digest(SCRIPT)}
    with pytest.raises(ReadOnlyViolation, match="absent du registre"):
        load_script(nom, directory=dossier, registry=registre)


def test_scripts_du_paquet_tous_inscrits_avec_leur_empreinte() -> None:
    dossier = SRC / "ps"
    presents = {f.name for f in dossier.glob("*")} if dossier.is_dir() else set()
    assert presents == set(SCRIPTS)
    for nom in SCRIPTS:
        assert load_script(nom)


def _ecarts(*elements: dict[str, Any]) -> list[str]:
    return check_script_inventory({"errors": [], "items": list(elements)})


def _commande(nom: str | None) -> dict[str, Any]:
    return {"kind": "command", "name": nom, "line": 2}


def _methode(nom: str | None, type_: str | None = None) -> dict[str, Any]:
    return {
        "kind": "method",
        "name": nom,
        "static": type_ is not None,
        "type": type_,
        "line": 3,
    }


def test_inventaire_d_un_script_conforme() -> None:
    assert (
        _ecarts(
            _commande("Set-StrictMode"),
            _commande("Get-WinEvent"),
            _commande("get-itemproperty"),
            _methode("ToXml"),
            _methode("GetCurrent", "System.Security.Principal.WindowsIdentity"),
            {
                "kind": "assignment",
                "target": "VariableExpressionAst",
                "drive": False,
                "line": 4,
            },
            {"kind": "redirection", "name": "$null", "line": 5},
            {"kind": "using", "name": "Namespace", "line": 1},
        )
        == []
    )


@pytest.mark.parametrize(
    ("element", "motif"),
    [
        (_commande("Set-ItemProperty"), "verbe interdit (Set-) : Set-ItemProperty"),
        (_commande("sc"), "alias ou exécutable"),
        (_commande("Limit-EventLog"), "cmdlet interdite : Limit-EventLog"),
        (_commande("clear-eventlog"), "cmdlet interdite"),
        (_commande("Invoke-Expression"), "cmdlet interdite"),
        (_commande("New-Object"), "verbe interdit (New-)"),
        (_commande("Add-Type"), "verbe interdit (Add-)"),
        (_commande("ForEach-Object"), "commande hors allowlist"),
        (_commande("Get-Content"), "commande hors allowlist"),
        (_commande("wevtutil.exe"), "alias ou exécutable"),
        (_commande("%"), "alias ou exécutable"),
        (_commande(None), "nom calculé à l'exécution"),
        (_commande(""), "nom calculé à l'exécution"),
        (_methode("ClearLog"), "méthode hors allowlist : .ClearLog()"),
        (_methode("Clear"), "méthode hors allowlist"),
        (_methode("SaveChanges"), "méthode hors allowlist"),
        (_methode("Invoke"), "méthode hors allowlist"),
        (_methode(None), "nom calculé à l'exécution"),
        (_methode("Create", "scriptblock"), "méthode statique hors allowlist"),
        (_methode("GetCurrent", "Exemple.AutreType"), "méthode statique hors"),
        # une methode d'instance admise ne vaut pas pour un appel statique
        (_methode("ToString", "System.IO.File"), "méthode statique hors"),
        (
            {"kind": "method", "name": "GetCurrent", "static": False, "type": None},
            "méthode hors allowlist",
        ),
        (
            {"kind": "method", "name": "GetCurrent", "static": True, "type": None},
            "méthode statique hors",
        ),
        (
            {"kind": "assignment", "target": "MemberExpressionAst", "drive": False},
            "affectation",
        ),
        (
            {"kind": "assignment", "target": "VariableExpressionAst", "drive": True},
            "affectation",
        ),
        ({"kind": "assignment", "target": "VariableExpressionAst"}, "affectation"),
        ({"kind": "redirection", "name": "'C:\\sortie.txt'"}, "redirection"),
        ({"kind": "using", "name": "Module"}, "using"),
        ({"kind": "autre"}, "inconnu"),
        ({}, "inconnu"),
    ],
)
def test_ecart_de_l_inventaire_detecte(element: dict[str, Any], motif: str) -> None:
    (ecart,) = _ecarts(element)
    assert motif in ecart


def test_inventaire_illisible_ou_en_erreur_refuse() -> None:
    assert check_script_inventory({}) == ["inventaire illisible"]
    assert check_script_inventory({"errors": [], "items": None}) != []
    assert check_script_inventory({"errors": ["x"], "items": []}) == [
        "erreur d'analyse du script"
    ]
    assert check_script_inventory({"errors": [], "items": ["x"]}) != []


def test_allowlist_powershell_coherente() -> None:
    commandes = [op for op in _toutes() if isinstance(op, PsCommand)]
    verbes = {v.lower() for v in PS_FORBIDDEN_VERBS}
    interdites = {c.lower() for c in PS_FORBIDDEN_COMMANDS}
    for op in commandes:
        verbe, tiret, nom = op.name.partition("-")
        # nom complet Verbe-Nom : un alias ne se resout pas sur l'AST
        assert tiret and verbe and nom, op.name
        assert op.name.lower() not in interdites
        # un verbe interdit n'est admis que par une exception nommee
        assert (verbe.lower() in verbes) is op.exception, op.name
    assert {op.name for op in commandes if op.exception} == {"Set-StrictMode"}
    # appel d'une methode par son nom, hors de vue de l'analyse (-MemberName)
    assert "foreach-object" not in {op.name.lower() for op in commandes}
    methodes = {op.name for op in _toutes() if isinstance(op, PsMethod)}
    assert not methodes & {"ClearLog", "Clear", "SaveChanges", "Delete", "Invoke"}


# --- LDAP -----------------------------------------------------------------------


class _ConnexionLdap:
    """Connexion factice : note chaque requete qui serait emise."""

    def __init__(self) -> None:
        self.requetes: list[str] = []
        self.entries = ["entree fictive"]

    def _noter(self, nom: str) -> Callable[..., bool]:
        def operation(*_args: object, **_options: object) -> bool:
            self.requetes.append(nom)
            return True

        return operation

    def __getattr__(self, nom: str) -> Callable[..., bool]:
        return self._noter(nom)


def test_ldap_bind_et_search_passent() -> None:
    connexion = _ConnexionLdap()
    annuaire = ReadOnlyLdap(connexion)
    assert annuaire.bind()
    assert annuaire.search("dc=exemple,dc=invalid", "(objectClass=computer)")
    assert connexion.requetes == ["bind", "search"]
    assert {op.name for op in _toutes() if isinstance(op, LdapOperation)} == {
        "bind",
        "search",
    }


@pytest.mark.parametrize(
    "operation",
    [*readonly.LDAP_FORBIDDEN, "extended", "compare", "entries", "unbind", "extend"],
)
def test_ldap_ecriture_refusee_sans_requete(operation: str) -> None:
    connexion = _ConnexionLdap()
    annuaire = ReadOnlyLdap(connexion)
    with pytest.raises(ReadOnlyViolation, match="LDAP hors allowlist"):
        getattr(annuaire, operation)("cn=srv-file,dc=exemple,dc=invalid", {})
    assert connexion.requetes == []


def test_ldap_enveloppe_figee() -> None:
    connexion = _ConnexionLdap()
    annuaire = ReadOnlyLdap(connexion)
    with pytest.raises(ReadOnlyViolation):
        annuaire.search = connexion.modify
    # un attribut special absent reste une AttributeError : hasattr, copy...
    assert not hasattr(annuaire, "__enter__")
    assert connexion.requetes == []


# --- AWS ------------------------------------------------------------------------


class _Evenements:
    """Émetteur factice, à la façon de botocore : ``before-call`` s'arrête à la
    première réponse, crochets ``register_first`` d'abord."""

    def __init__(self) -> None:
        self.premiers: list[tuple[str, Callable[..., Any], str | None]] = []
        self.suivants: list[tuple[str, Callable[..., Any], str | None]] = []

    def register_first(
        self, nom: str, crochet: Callable[..., Any], unique_id: str | None = None
    ) -> None:
        self.premiers.insert(0, (nom, crochet, unique_id))

    def register(
        self, nom: str, crochet: Callable[..., Any], unique_id: str | None = None
    ) -> None:
        self.suivants.append((nom, crochet, unique_id))

    def emit_until_response(self, evenement: str, **arguments: Any) -> Any:
        for motif, crochet, _ in [*self.premiers, *self.suivants]:
            if fnmatchcase(evenement, motif):
                reponse = crochet(event_name=evenement, **arguments)
                if reponse is not None:
                    return reponse
        return None


class _ClientAws:
    """Client factice : émet ``before-call`` comme botocore, puis « envoie »."""

    def __init__(self, service: str) -> None:
        self.service = service
        self.meta = SimpleNamespace(events=_Evenements())
        self.envoyees: list[str] = []

    def appeler(self, operation: str) -> None:
        modele = SimpleNamespace(
            name=operation, service_model=SimpleNamespace(service_name=self.service)
        )
        reponse = self.meta.events.emit_until_response(
            f"before-call.{self.service}.{operation}",
            model=modele,
            params={"body": b""},
            request_signer=object(),
            context={},
        )
        if reponse is None:
            self.envoyees.append(operation)


def _client_protege(service: str, **options: Any) -> _ClientAws:
    client = _ClientAws(service)
    protect_aws_client(client, **options)
    return client


@pytest.mark.parametrize(
    ("service", "operation"),
    [
        ("cloudtrail", "DescribeTrails"),
        ("cloudtrail", "GetEventSelectors"),
        ("cloudtrail", "LookupEvents"),
        ("s3", "GetBucketLogging"),
        ("s3", "GetObjectLockConfiguration"),
        ("s3", "ListBuckets"),
        ("sts", "GetCallerIdentity"),
        ("ssm", "GetInventory"),
    ],
)
def test_aws_lecture_admise(service: str, operation: str) -> None:
    client = _client_protege(service)
    client.appeler(operation)
    assert client.envoyees == [operation]


@pytest.mark.parametrize(
    ("service", "operation"),
    [
        ("s3", "PutBucketPolicy"),
        ("s3", "DeleteBucket"),
        ("cloudtrail", "StopLogging"),
        ("cloudtrail", "UpdateTrail"),
        ("ec2", "RunInstances"),
        ("iam", "CreateAccessKey"),
        ("sts", "AssumeRole"),
        ("kms", "Decrypt"),
        # lectures qui renvoient un secret ou du contenu
        ("secretsmanager", "GetSecretValue"),
        ("ec2", "GetPasswordData"),
        ("s3", "GetObject"),
        ("ssm", "GetParameter"),
        ("ssm", "GetParameters"),
        ("ssm", "GetParametersByPath"),
    ],
)
def test_aws_ecriture_ou_secret_refuse_sans_requete(
    service: str, operation: str
) -> None:
    client = _client_protege(service)
    with pytest.raises(ReadOnlyViolation, match=f"{service}:{operation}"):
        client.appeler(operation)
    assert client.envoyees == []


def test_aws_garde_posee_avant_un_crochet_qui_repond() -> None:
    # un bouchon (Stubber de botocore) repond a la place du service : la garde
    # doit passer avant lui, sinon l'emission s'arrete sans l'avoir appelee
    client = _ClientAws("s3")
    bouchon: list[str] = []

    def repondre(**arguments: Any) -> dict[str, str]:
        bouchon.append(arguments["event_name"])
        return {"reponse": "fictive"}

    client.meta.events.register(AWS_EVENT, repondre)
    client.meta.events.register_first(AWS_EVENT, lambda **_: None)
    protect_aws_client(client)
    nom, _, identifiant = client.meta.events.premiers[0]
    assert (nom, identifiant) == ("before-call.*.*", "amnesia-readonly")
    with pytest.raises(ReadOnlyViolation):
        client.appeler("PutBucketPolicy")
    assert bouchon == []
    client.appeler("GetBucketPolicyStatus")
    assert bouchon == ["before-call.s3.GetBucketPolicyStatus"]
    assert client.envoyees == []


def test_aws_assume_role_seulement_avec_opt_in() -> None:
    client = _client_protege("sts", opt_in={"aws-assume-role"})
    client.appeler("AssumeRole")
    assert client.envoyees == ["AssumeRole"]
    # l'opt-in n'ouvre rien d'autre, et ne leve aucun refus de AWS_DENIED
    with pytest.raises(ReadOnlyViolation):
        client.appeler("AssumeRoleWithSAML")
    with pytest.raises(ReadOnlyViolation):
        check_aws("secretsmanager", "GetSecretValue", opt_in={"aws-assume-role"})


@pytest.mark.parametrize("opt_in", [{"sts:AssumeRole"}, {"splunk-search-job"}, {"*"}])
def test_aws_opt_in_inconnu_est_une_erreur(opt_in: set[str]) -> None:
    with pytest.raises(ValueError, match="opt-in inconnu"):
        aws_guard(opt_in=opt_in)
    with pytest.raises(ValueError, match="opt-in inconnu"):
        check_aws("sts", "GetCallerIdentity", opt_in=opt_in)
    with pytest.raises(TypeError):
        aws_guard(opt_in="aws-assume-role")


@pytest.mark.parametrize(
    "modele",
    [None, object(), SimpleNamespace(name="ListBuckets"), SimpleNamespace(name=None)],
)
def test_aws_modele_illisible_refuse(modele: object) -> None:
    with pytest.raises(ReadOnlyViolation):
        aws_guard()(model=modele)
    with pytest.raises(ReadOnlyViolation):
        aws_guard()()


@pytest.mark.parametrize(
    ("service", "operation"),
    [("", "ListBuckets"), ("s3", ""), ("s3:x", "ListBuckets"), ("s3", "List*")],
)
def test_aws_nom_illisible_refuse(service: str, operation: str) -> None:
    with pytest.raises(ReadOnlyViolation):
        check_aws(service, operation)


def test_aws_refus_sont_des_lectures_par_leur_prefixe() -> None:
    # sans AWS_DENIED, chacune passerait : la liste n'a pas d'entree inutile
    for motif in AWS_DENIED:
        operation = motif.partition(":")[2]
        assert operation.startswith(("Get", "Describe", "List")), motif


# --- HTTP -----------------------------------------------------------------------

GRAPH = "https://graph.microsoft.com"
JOURNAUX = "https://api.loganalytics.io"
SPLUNK = "https://splunk.exemple.invalid:8089"


class _ClientHttp:
    """Client factice : appelle ses crochets d'avant-envoi, puis « envoie »."""

    def __init__(self, *crochets: Callable[[Any], None]) -> None:
        self.crochets = crochets
        self.envoyees: list[str] = []

    def request(self, methode: str, url: str) -> None:
        requete = SimpleNamespace(method=methode, url=SimpleNamespace(__str__=None))
        requete.url = _Url(url)
        for crochet in self.crochets:
            crochet(requete)
        self.envoyees.append(f"{methode} {url}")


class _Url:
    """URL qui n'est pas une chaîne, comme celle d'un client HTTP."""

    def __init__(self, texte: str) -> None:
        self.texte = texte

    def __str__(self) -> str:
        return self.texte


@pytest.mark.parametrize(
    ("api", "base", "methode", "chemin"),
    [
        ("graph", GRAPH, "GET", "/v1.0/auditLogs/directoryAudits?$top=1"),
        ("graph", GRAPH, "get", "/beta/security/auditLog/queries"),
        ("graph", GRAPH, "GET", "/v1.0/organization/"),
        ("graph", GRAPH, "GET", ""),
        ("log-analytics", JOURNAUX, "POST", f"/v1/workspaces/{GUID}/query"),
        ("log-analytics", JOURNAUX, "GET", f"/v1/workspaces/{GUID}/metadata"),
        ("splunk", SPLUNK, "GET", "/services/data/indexes?output_mode=json"),
    ],
)
def test_http_lecture_admise(api: str, base: str, methode: str, chemin: str) -> None:
    client = _ClientHttp(HttpGuard(api, base))
    client.request(methode, base + chemin)
    assert len(client.envoyees) == 1


@pytest.mark.parametrize(
    ("api", "base", "methode", "url"),
    [
        ("graph", GRAPH, "POST", GRAPH + "/v1.0/users"),
        ("graph", GRAPH, "POST", GRAPH + "/v1.0/$batch"),
        ("graph", GRAPH, "PATCH", GRAPH + "/v1.0/organization"),
        ("graph", GRAPH, "PUT", GRAPH + "/v1.0/organization"),
        ("graph", GRAPH, "DELETE", GRAPH + "/v1.0/users/exemple"),
        ("graph", GRAPH, "HEAD", GRAPH + "/v1.0/users"),
        ("graph", GRAPH, "", GRAPH + "/v1.0/users"),
        # exception desactivee par defaut
        ("graph", GRAPH, "POST", GRAPH + "/v1.0/security/auditLog/queries"),
        ("splunk", SPLUNK, "POST", SPLUNK + "/services/search/jobs"),
        ("log-analytics", JOURNAUX, "POST", JOURNAUX + f"/v1/workspaces/{GUID}"),
        ("log-analytics", JOURNAUX, "POST", JOURNAUX + "/v1/workspaces/a/b/query"),
        ("log-analytics", JOURNAUX, "POST", JOURNAUX + "/v1/workspaces/%41/query"),
        # autre hote, autre port, autre schema : hors de la cible designee
        ("graph", GRAPH, "GET", "https://graph.microsoft.com.exemple.invalid/v1.0/"),
        ("graph", GRAPH, "GET", "https://exemple.invalid/v1.0/users"),
        ("graph", GRAPH, "GET", "https://graph.microsoft.com:8443/v1.0/users"),
        ("graph", GRAPH, "GET", "http://graph.microsoft.com/v1.0/users"),
        ("graph", GRAPH, "GET", "https://compte:mdp@graph.microsoft.com/v1.0"),
        ("graph", GRAPH, "GET", "/v1.0/users"),
        ("graph", GRAPH, "GET", "https://graph.microsoft.com:port/v1.0"),
        # chemins ambigus
        ("graph", GRAPH, "GET", GRAPH + "/v1.0/../beta/users"),
        ("graph", GRAPH, "GET", GRAPH + "/v1.0/%2e%2e/users"),
        ("graph", GRAPH, "GET", GRAPH + "/v1.0//users"),
        ("graph", GRAPH, "GET", GRAPH + "/v1.0\\users"),
        ("graph", GRAPH, "GET", GRAPH + "/v1.0/a%2Fb"),
        # caracteres que deux analyseurs d'URL ne lisent pas de la meme facon
        ("graph", GRAPH, "GET", "https://graph.microsoft.com\\@exemple.invalid/"),
        ("graph", GRAPH, "GET", "https://exemple.invalid\\@graph.microsoft.com/"),
        ("graph", GRAPH, "GET", "https://graph.microsoft.com/v1.0/\tusers"),
        ("graph", GRAPH, "GET", "https://graph.microsoft.com/v1.0/users\n"),
        ("graph", GRAPH, "GET", " https://graph.microsoft.com/v1.0/users"),
        ("graph", GRAPH, "GET", "https://graph.microsoft.com./v1.0/users"),
    ],
)
def test_http_requete_refusee_sans_envoi(
    api: str, base: str, methode: str, url: str
) -> None:
    client = _ClientHttp(HttpGuard(api, base))
    with pytest.raises(ReadOnlyViolation):
        client.request(methode, url)
    assert client.envoyees == []


def test_http_requete_d_audit_graph_seulement_avec_opt_in() -> None:
    url = GRAPH + "/v1.0/security/auditLog/queries"
    with pytest.raises(ReadOnlyViolation, match="opt-in graph-audit-log-query"):
        HttpGuard("graph", GRAPH).check("POST", url)
    garde = HttpGuard("graph", GRAPH, opt_in={"graph-audit-log-query"})
    garde.check("POST", url)
    garde.check("POST", GRAPH + "/beta/security/auditLog/queries")
    # l'opt-in n'ouvre que son endpoint
    with pytest.raises(ReadOnlyViolation):
        garde.check("POST", url + "/exemple/records")
    with pytest.raises(ReadOnlyViolation):
        garde.check("POST", GRAPH + "/v1.0/users")


def test_http_job_de_recherche_splunk_seulement_avec_opt_in() -> None:
    garde = HttpGuard("splunk", SPLUNK + "/fr-FR/", opt_in={"splunk-search-job"})
    garde.check("POST", SPLUNK + "/fr-FR/services/search/jobs")
    # hors du chemin de base, meme hote
    with pytest.raises(ReadOnlyViolation, match="adresse de base"):
        garde.check("POST", SPLUNK + "/services/search/jobs")
    with pytest.raises(ReadOnlyViolation, match="adresse de base"):
        garde.check("GET", SPLUNK + "/services/data/indexes")


def test_http_configuration_invalide_est_une_erreur() -> None:
    with pytest.raises(ValueError, match="API HTTP inconnue"):
        HttpGuard("autre", GRAPH)
    with pytest.raises(ValueError, match="base_url"):
        HttpGuard("graph", "http://graph.microsoft.com")
    with pytest.raises(ValueError, match="opt-in inconnu"):
        HttpGuard("graph", GRAPH, opt_in={"splunk-search-job"})
    with pytest.raises(TypeError):
        HttpGuard("graph", GRAPH, opt_in="graph-audit-log-query")


@pytest.mark.parametrize("requete", [None, object(), SimpleNamespace(method="GET")])
def test_http_requete_illisible_refusee(requete: object) -> None:
    with pytest.raises(ReadOnlyViolation):
        HttpGuard("graph", GRAPH)(requete)
    with pytest.raises(ReadOnlyViolation):
        HttpGuard("graph", GRAPH).check("GET", None)  # type: ignore[arg-type]


def test_http_tout_verbe_d_ecriture_nomme_est_justifie() -> None:
    for op in _toutes():
        if isinstance(op, HttpEndpoint) and op.method != "GET":
            # un POST n'entre dans l'allowlist que nomme, sur un chemin sans « ** »
            assert op.method == "POST"
            assert "**" not in op.path


# --- documentation --------------------------------------------------------------


def test_document_genere_a_jour() -> None:
    # regenerer : uv run python scripts/generer_read_only.py
    assert DOCUMENT.read_text(encoding="utf-8") == render_markdown()


def test_document_cite_chaque_operation() -> None:
    document = render_markdown()
    for op in _toutes():
        assert f"`{op.label}`" in document, op.label
    for nom in (*OPT_INS, *AWS_DENIED, *PS_FORBIDDEN_COMMANDS):
        assert f"`{nom}`" in document
    assert document.endswith("|\n")
    assert "adr/0006-garantie-lecture-seule.md" in document


def test_readme_renvoie_a_la_liste_des_operations() -> None:
    readme = (RACINE / "README.md").read_text(encoding="utf-8")
    (_, section) = readme.split("\n## Scope & légal\n")
    section = section.split("\n## ")[0]
    assert "/blob/main/docs/READ-ONLY.md)" in section
