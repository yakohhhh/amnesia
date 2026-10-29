"""Frontière réseau (#26) : seuls les collecteurs listés peuvent se connecter.

Trois garde-fous, indépendants :
- la règle ruff TID251 (banned-api) interdit les API réseau hors des chemins
  de ``per-file-ignores`` (vérifiée sur cas dans tests/test_regles_ruff.py) ;
- ce fichier parcourt l'AST de ``src/`` : aucun import d'un module réseau
  (bibliothèque standard ou SDK) hors de MODULES_RESEAU, et cette liste est
  exactement celle des ``per-file-ignores`` de TID251 dans pyproject.toml ;
- l'engagement écrit : README (section « Confidentialité ») et docs.
"""

from __future__ import annotations

import ast
import re
import tomllib
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import pytest

RACINE = Path(__file__).resolve().parent.parent
SRC = RACINE / "src"
PYPROJECT = RACINE / "pyproject.toml"
README = RACINE / "README.md"

MODULES_RESEAU = (
    # collecteurs (#20) : les seuls a joindre une cible, et seulement celle
    # que l'utilisateur a designee ; WinRM (#63) et cloud (#95) iront dans le
    # paquet collectors/
    "src/amnesia/facts/collectors.py",
    "src/amnesia/facts/collectors/**",
)
"""Chemins de ``src/`` autorisés à ouvrir une connexion (motifs ruff)."""

# modules dont l'import, hors de MODULES_RESEAU, trahit un acces reseau :
# bibliotheque standard, puis SDK prevus par les collecteurs (#44, #63, #95)
MODULES_INTERDITS = (
    "socket",
    "ssl",
    "http.client",
    "http.server",
    "urllib.request",
    "ftplib",
    "smtplib",
    "poplib",
    "imaplib",
    "xmlrpc.client",
    "urllib3",
    "requests",
    "httpx",
    "aiohttp",
    "websocket",
    "websockets",
    "winrm",
    "pypsrp",
    "psrp",
    "spnego",
    "ldap3",
    "msal",
    "msgraph",
    "azure",
    "boto3",
    "botocore",
)

API_RESEAU = {
    "socket.socket",
    "socket.create_connection",
    "asyncio.open_connection",
    "http.client",
    "urllib.request",
    "urllib3",
    "requests",
    "httpx",
}
"""API que la règle TID251 doit interdire (issue #26)."""


def _ruff_lint() -> dict[str, Any]:
    with PYPROJECT.open("rb") as fichier:
        outil: dict[str, Any] = tomllib.load(fichier)["tool"]["ruff"]["lint"]
    return outil


def _fichiers_src() -> list[Path]:
    fichiers = sorted(SRC.rglob("*.py"))
    assert fichiers
    return fichiers


def _autorise(fichier: Path) -> bool:
    chemin = fichier.relative_to(RACINE).as_posix()
    return any(fnmatch(chemin, motif) for motif in MODULES_RESEAU)


def _interdit(nom: str) -> bool:
    return any(nom == m or nom.startswith(m + ".") for m in MODULES_INTERDITS)


def _imports(arbre: ast.AST) -> list[tuple[int, str]]:
    # (ligne, module importe) : « import a.b », « from a.b import c » (c compris
    # quand a.b est un paquet : « from http import client »)
    trouves: list[tuple[int, str]] = []
    for noeud in ast.walk(arbre):
        if isinstance(noeud, ast.Import):
            trouves.extend((noeud.lineno, alias.name) for alias in noeud.names)
        elif isinstance(noeud, ast.ImportFrom) and noeud.module and noeud.level == 0:
            trouves.append((noeud.lineno, noeud.module))
            trouves.extend(
                (noeud.lineno, f"{noeud.module}.{alias.name}") for alias in noeud.names
            )
    return trouves


def test_outils_du_test() -> None:
    assert _interdit("socket")
    assert _interdit("urllib.request")
    assert _interdit("http.client")
    assert not _interdit("urllib.parse")
    assert not _interdit("http")
    assert not _interdit("socketserver")
    arbre = ast.parse("import socket\nfrom http import client\nfrom . import x\n")
    assert _imports(arbre) == [(1, "socket"), (2, "http"), (2, "http.client")]
    assert _autorise(SRC / "amnesia" / "facts" / "collectors.py")
    assert _autorise(SRC / "amnesia" / "facts" / "collectors" / "winrm.py")
    assert not _autorise(SRC / "amnesia" / "cli.py")


def test_aucun_import_reseau_hors_des_collecteurs() -> None:
    trouves = [
        f"{fichier.relative_to(RACINE).as_posix()}:{ligne} {nom}"
        for fichier in _fichiers_src()
        if not _autorise(fichier)
        for ligne, nom in _imports(ast.parse(fichier.read_text(encoding="utf-8")))
        if _interdit(nom)
    ]
    assert not trouves


def test_aucun_import_reseau_meme_dans_les_collecteurs_actuels() -> None:
    # aujourd'hui aucun collecteur reseau n'existe : la derogation est posee
    # pour #63 et #95, pas encore utilisee. A retirer quand elle le sera.
    trouves = [
        f"{fichier.relative_to(RACINE).as_posix()}:{ligne} {nom}"
        for fichier in _fichiers_src()
        if _autorise(fichier)
        for ligne, nom in _imports(ast.parse(fichier.read_text(encoding="utf-8")))
        if _interdit(nom)
    ]
    assert not trouves


def test_liste_des_collecteurs_reseau_identique_a_pyproject() -> None:
    # une seule liste : les per-file-ignores de TID251, hors tests/
    ignores = _ruff_lint()["per-file-ignores"]
    assert isinstance(ignores, dict)
    avec_tid251 = {motif for motif, regles in ignores.items() if "TID251" in regles}
    assert avec_tid251 == {*MODULES_RESEAU, "tests/**"}
    # aucune derogation plus large (src/**, *.py...) ni fichier inexistant
    for motif in MODULES_RESEAU:
        assert motif.startswith("src/amnesia/")
        if "*" not in motif:
            assert (RACINE / motif).is_file(), motif


def test_tid251_active_et_api_interdites() -> None:
    lint = _ruff_lint()
    assert "TID251" in lint["select"]
    bannies = lint["flake8-tidy-imports"]["banned-api"]
    assert set(bannies) >= API_RESEAU
    for api in API_RESEAU:
        assert "#26" in bannies[api]["msg"]


# --- engagement ecrit -----------------------------------------------------------


def _section(texte: str, titre: str) -> str:
    for morceau in re.split(r"^## ", texte, flags=re.MULTILINE)[1:]:
        entete, _, corps = morceau.partition("\n")
        if entete.strip() == titre:
            return " ".join(corps.split())
    raise AssertionError(f"section {titre!r} absente")


def test_readme_section_confidentialite() -> None:
    corps = _section(README.read_text(encoding="utf-8"), "Confidentialité")
    for engagement in (
        "télémétrie",
        "vérification de mise à jour",
        "rapport de plantage",
        "sans accès Internet",
        "cibles",
        "`POWERSHELL_TELEMETRY_OPTOUT=1`",
        "ressource externe",
        "hors ligne",
    ):
        assert engagement in corps, engagement


@pytest.mark.parametrize(
    ("document", "attendu"),
    [
        ("SECURITY.md", "README.md#confidentialité"),
        ("docs/dev/faits.md", "TID251"),
        ("docs/dev/faits.md", "subprocess_env()"),
        ("docs/dev/faits.md", "tests/test_reseau.py"),
    ],
)
def test_docs_renvoient_a_la_frontiere_reseau(document: str, attendu: str) -> None:
    assert attendu in (RACINE / document).read_text(encoding="utf-8")
