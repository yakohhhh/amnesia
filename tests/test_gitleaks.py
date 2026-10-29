"""Regles de .gitleaks.toml verifiees avec le vrai binaire gitleaks.

Le binaire est pris dans GITLEAKS_BIN ou dans le PATH ; le job CI gitleaks
fournit celui dont il a verifie l'empreinte. Sans binaire, ces tests sont ignores.
Les faux secrets sont assembles a l'execution pour ne jamais figurer tels quels
dans le depot.
"""

import json
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parent.parent
# chaine vide si absent : subprocess.run n'accepte pas None dans ses arguments
GITLEAKS = os.environ.get("GITLEAKS_BIN") or shutil.which("gitleaks") or ""

pytestmark = pytest.mark.skipif(not GITLEAKS, reason="binaire gitleaks absent")

GUID = "3f2b8c1d-4e5a-4b6c-9d7e-8f9a0b1c2d3e"
MDP = "Hiver" + "2026!Acme"


def _regles_declenchees(
    tmp_path: Path, nom: str, contenu: str, *options: str
) -> set[str]:
    fichier = tmp_path / nom
    if not fichier.exists():
        fichier.write_text(contenu, encoding="utf-8")
    rapport = tmp_path / "rapport.json"
    # binaire designe par le developpeur ou la CI (GITLEAKS_BIN), pas de shell
    subprocess.run(  # noqa: S603
        [
            GITLEAKS,
            "dir",
            "--no-banner",
            "--config",
            str(RACINE / ".gitleaks.toml"),
            "--report-format",
            "json",
            "--report-path",
            str(rapport),
            "--exit-code",
            "0",
            *options,
            str(fichier),
        ],
        check=True,
        capture_output=True,
    )
    return {
        fuite["RuleID"] for fuite in json.loads(rapport.read_text(encoding="utf-8"))
    }


@pytest.mark.parametrize(
    ("nom", "contenu"),
    [
        (".env", f"TENANT_ID={GUID}\nWINRM_USER=audit\nWINRM_PASSWORD={MDP}\n"),
        ("graph.yml", f"graph:\n  tenant_id: {GUID}\n  client_secret: '{MDP}'\n"),
        (
            "connexion.ps1",
            f'Connect-Graph -TenantId {GUID} `\n    -ClientSecret "{MDP}"\n',
        ),
        ("tenant.yml", f"azure:\n  tenant: {GUID}\n  password: '{MDP}'\n"),
        (
            "msal.py",
            f'AUTHORITY = "https://login.microsoftonline.com/{GUID}"\n'
            f'PASSWORD = "{MDP}"\n',
        ),
        ("az.sh", f"az login --tenant {GUID} -u audit --password '{MDP}'\n"),
        ("azure.env", f"AZURE_TENANT_ID={GUID}\nAZURE_PASSWORD={MDP}\n"),
    ],
    ids=["env", "yaml", "powershell", "tenant", "autorite-msal", "az-cli", "azure-env"],
)
def test_secret_pres_d_un_identifiant_entra(
    tmp_path: Path, nom: str, contenu: str
) -> None:
    assert "secret-pres-d-un-guid-entra" in _regles_declenchees(tmp_path, nom, contenu)


@pytest.mark.parametrize(
    ("nom", "contenu"),
    [
        (
            "client.py",
            f'TENANT_ID = "{GUID}"\n'
            "credential = ClientSecretCredential(TENANT_ID, CLIENT_ID, secret)\n"
            'motdepasse = keyring.get_password("amnesia", "winrm")\n',
        ),
        (
            "graph_users.json",
            f'{{"id": "{GUID}", "passwordPolicies": "DisablePasswordExpiration"}}\n',
        ),
        ("sans_guid.env", f"WINRM_PASSWORD={MDP}\n"),
        ("gabarit.py", 'URL = f"winrm://{compte}:{mdp}@{hote}:5986/wsman"\n'),
    ],
    ids=["code-azure-identity", "fixture-graph", "sans-identifiant", "gabarit-url"],
)
def test_pas_de_faux_positif(tmp_path: Path, nom: str, contenu: str) -> None:
    assert _regles_declenchees(tmp_path, nom, contenu) == set()


def test_identifiants_dans_une_url(tmp_path: Path) -> None:
    url = "winrm://audit:" + "P@ssw0rd!2026" + "@dc01.acme.local"
    regles = _regles_declenchees(tmp_path, "cible.txt", url + "\n")
    assert "identifiants-dans-une-url" in regles


def _cle_aws() -> str:
    # forme valide (AKIA + 16 caracteres base32), assemblee a l'execution
    return "AKIA" + "Q4ZT7XK2MBV5NR3W"


def test_archive_ouverte_avec_max_archive_depth(tmp_path: Path) -> None:
    with zipfile.ZipFile(tmp_path / "bundle.zip", "w") as archive:
        archive.writestr("config/.env", f"AWS_ACCESS_KEY_ID={_cle_aws()}\n")
    sans = _regles_declenchees(tmp_path, "bundle.zip", "")
    avec = _regles_declenchees(tmp_path, "bundle.zip", "", "--max-archive-depth=2")
    assert sans == set()
    assert "aws-access-token" in avec


def test_gitleaks_allow_ignore_cote_serveur(tmp_path: Path) -> None:
    ligne = f'cle = "{_cle_aws()}"  # gitleaks:allow\n'
    assert _regles_declenchees(tmp_path, "a.py", ligne) == set()
    regles = _regles_declenchees(tmp_path, "a.py", ligne, "--ignore-gitleaks-allow")
    assert "aws-access-token" in regles
