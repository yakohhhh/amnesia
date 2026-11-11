"""Extras optionnels (#44) : imports paresseux, job lowest-direct, politique écrite.

Métadonnées du wheel (aucune dépendance hors extra, ``all`` complet) et bornes
de version : tests/test_paquet.py. ``require_extra`` et « non évalué » :
tests/unit/test_deps.py.
"""

import ast
import re
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest
import yaml

from amnesia import deps
from amnesia.deps import Package

RACINE = Path(__file__).resolve().parent.parent
SOURCES = RACINE / "src" / "amnesia"
CI = RACINE / ".github" / "workflows" / "ci.yml"
POLITIQUE = RACINE / "docs" / "dev" / "dependances.md"

# extras d'essai : aucun n'est encore declare dans amnesia.deps.EXTRAS
EXTRAS_ESSAI: Mapping[str, tuple[Package, ...]] = {
    "aws": (Package("boto3", "boto3"),),
    "cloud-m365": (
        Package("msgraph-sdk", "msgraph"),
        Package("azure-identity", "azure.identity"),
    ),
    "azure": (Package("azure-monitor-query", "azure.monitor.query"),),
}


# --- imports executes au chargement d'un module --------------------------------


def _type_checking(test: ast.expr) -> bool:
    """``if TYPE_CHECKING:`` ou ``if typing.TYPE_CHECKING:``."""
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


class _ImportsAuChargement(ast.NodeVisitor):
    """Imports absolus exécutés à l'import du module.

    Corps de classe, ``try`` et ``if`` compris ; ni les fonctions, exécutées plus
    tard, ni la branche ``if TYPE_CHECKING:``, que seul mypy lit.
    """

    def __init__(self) -> None:
        self.imports: list[tuple[str, int]] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        pass

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        pass

    def visit_If(self, node: ast.If) -> None:
        if not _type_checking(node.test):
            self.visit(node.test)
            for instruction in node.body:
                self.visit(instruction)
        for instruction in node.orelse:
            self.visit(instruction)

    def visit_Import(self, node: ast.Import) -> None:
        self.imports.extend((alias.name, node.lineno) for alias in node.names)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        # import relatif (from . import x) : module d'amnesia
        if node.level == 0 and node.module is not None:
            self.imports.append((node.module, node.lineno))


def _racine(module: str) -> str:
    return module.split(".")[0]


def _imports_interdits(
    source: str, extras: Mapping[str, tuple[Package, ...]], fichier: str = "<essai>"
) -> list[str]:
    """Imports tiers exécutés au chargement, avec l'extra qui fournit le module.

    Seuls la bibliothèque standard et amnesia sont permis : le socle n'a aucune
    dépendance tierce, et un SDK d'extra ne s'importe qu'à l'exécution, après
    ``require_extra()``.
    """
    visiteur = _ImportsAuChargement()
    visiteur.visit(ast.parse(source))
    interdits = []
    for module, ligne in visiteur.imports:
        racine = _racine(module)
        if racine in sys.stdlib_module_names or racine == "amnesia":
            continue
        fournisseurs = sorted(
            extra
            for extra, paquets in extras.items()
            if any(_racine(p.module) == racine for p in paquets)
        )
        origine = (
            f"extra {', '.join(fournisseurs)}"
            if fournisseurs
            else "paquet tiers hors socle"
        )
        interdits.append(
            f"{fichier}:{ligne} importe {module} au chargement ({origine}) : "
            "l'importer dans la fonction qui s'en sert, après require_extra()"
        )
    return interdits


def test_aucun_import_tiers_au_chargement_dans_amnesia() -> None:
    fichiers = sorted(SOURCES.rglob("*.py"))
    assert len(fichiers) >= 20
    interdits = [
        interdit
        for fichier in fichiers
        for interdit in _imports_interdits(
            fichier.read_text(encoding="utf-8"),
            deps.EXTRAS,
            fichier.relative_to(SOURCES).as_posix(),
        )
    ]
    assert interdits == []


@pytest.mark.parametrize(
    ("source", "extra"),
    [
        ("import boto3\n", "aws"),
        ("from boto3.session import Session\n", "aws"),
        ("import os, boto3 as b\n", "aws"),
        ("import msgraph.core\n", "cloud-m365"),
        ("from azure.identity import ClientSecretCredential\n", "azure, cloud-m365"),
        ("try:\n    import boto3\nexcept ImportError:\n    boto3 = None\n", "aws"),
        ("class C:\n    import boto3\n", "aws"),
        ("import sys\nif sys.platform == 'win32':\n    import boto3\n", "aws"),
        (
            "from typing import TYPE_CHECKING\n"
            "if TYPE_CHECKING:\n    pass\nelse:\n    import boto3\n",
            "aws",
        ),
    ],
    ids=[
        "import",
        "from",
        "liste",
        "sous-module",
        "racine-partagee",
        "try",
        "corps-de-classe",
        "if",
        "else-de-type-checking",
    ],
)
def test_sdk_d_extra_importe_au_chargement_detecte(source: str, extra: str) -> None:
    (interdit,) = _imports_interdits(source, EXTRAS_ESSAI)
    assert f"(extra {extra})" in interdit
    assert "require_extra()" in interdit


def test_paquet_tiers_hors_extra_detecte() -> None:
    (interdit,) = _imports_interdits("import yaml\n", EXTRAS_ESSAI, "a/b.py")
    assert interdit.startswith("a/b.py:1 importe yaml au chargement (paquet tiers")


@pytest.mark.parametrize(
    "source",
    [
        "def f():\n    import boto3\n",
        "async def f():\n    from boto3 import client\n",
        "class C:\n    def m(self):\n        import boto3\n",
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import boto3\n",
        "import typing\nif typing.TYPE_CHECKING:\n    from boto3 import Session\n",
        "from . import deps\nfrom ..checks import base\n",
        "import json\nfrom amnesia.deps import require_extra\n",
        "from __future__ import annotations\n",
    ],
    ids=[
        "fonction",
        "coroutine",
        "methode",
        "type-checking",
        "typing-type-checking",
        "relatif",
        "stdlib-et-amnesia",
        "future",
    ],
)
def test_import_paresseux_accepte(source: str) -> None:
    assert _imports_interdits(source, EXTRAS_ESSAI) == []


# --- job lowest-direct ---------------------------------------------------------


def test_job_lowest_direct_en_ci() -> None:
    doc = yaml.safe_load(CI.read_text(encoding="utf-8"))
    job = doc["jobs"]["lowest-direct"]
    assert job["runs-on"].startswith("ubuntu-")
    commandes = [etape.get("run", "") for etape in job["steps"]]
    assert "uv sync --locked" in commandes
    assert "uv run nox -s lowest-direct" in commandes
    # requis par ci-ok, donc par la protection de main
    assert "lowest-direct" in doc["jobs"]["ci-ok"]["needs"]


def test_session_lowest_direct_installe_les_bornes_basses() -> None:
    texte = (RACINE / "noxfile.py").read_text(encoding="utf-8")
    session = re.search(
        r'@nox\.session\(name="lowest-direct", python=PYTHONS\[0\]\)\n'
        r"def lowest_direct\(.*?(?=\n@nox\.session|\Z)",
        texte,
        re.DOTALL,
    )
    assert session, "session nox lowest-direct absente"
    # tous les extras, a leur borne basse, meme deja installes par les outils
    for option in (
        '"--resolution=lowest-direct"',
        '"--upgrade"',
        '"--editable=.[all]"',
    ):
        assert option in session[0], option
    assert '"pytest"' in session[0]


# --- politique ecrite -----------------------------------------------------------


def test_politique_d_acceptation_documentee() -> None:
    texte = POLITIQUE.read_text(encoding="utf-8")
    titres = set(re.findall(r"^#{2,3} (.+)$", texte, re.MULTILINE))
    assert {
        "Extras optionnels",
        "Import paresseux",
        "Bornes de version",
        "Accepter une dépendance d'exécution",
    } <= titres
    for critere in ("Licence", "Maintenance", "Surface d'attaque", "Stdlib"):
        assert f"**{critere}**" in texte, critere
    for licence in ("MIT", "BSD", "Apache-2.0", "ISC", "MPL-2.0", "PSF"):
        assert licence in texte, licence
    for refusee in ("GPL", "AGPL", "LGPL"):
        assert refusee in texte, refusee
    # le socle s'installe sans rien d'autre, et l'API d'import paresseux est citee
    for terme in ("require_extra", "MissingExtra", "lowest-direct", "`all`"):
        assert terme in texte, terme
