# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Architecture et registre des décisions (#34).

Ces tests verifient que docs/architecture.md et le code restent alignes (table
des dependances autorisees contre les imports reels de src/amnesia, lus par
AST) et la forme du registre docs/adr/ (numeros, sections, statuts, index),
pas la justesse des decisions : ce jugement reste celui de la revue.
"""

import ast
import itertools
import re
from collections.abc import Iterable, Mapping
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parent.parent
SRC = RACINE / "src" / "amnesia"
ARCHITECTURE = RACINE / "docs" / "architecture.md"
MODELE_MENACE = RACINE / "docs" / "threat-model.md"
ADR = RACINE / "docs" / "adr"
INDEX = ADR / "README.md"
CONTRIBUTING = RACINE / "CONTRIBUTING.md"
MODELE_PR = RACINE / ".github" / "pull_request_template.md"

PAQUET = "amnesia"
# ligne de la table des dependances : | `module` | deps |
LIGNE_DEPENDANCES = re.compile(r"^\| `(amnesia[^`]*)` \| ([^|]*) \|$", re.MULTILINE)
# garde-fou des modules de check (ADR 0006) : une liste blanche, pas une liste
# noire. Seuls ces modules de la bibliotheque standard (calcul pur : ni
# fichier, ni processus, ni reseau, ni chargement dynamique) sont importables.
STDLIB_PERMIS_CHECK = frozenset(
    {
        "__future__",
        "collections",
        "collections.abc",
        "dataclasses",
        "datetime",
        "enum",
        "functools",
        "ipaddress",
        "itertools",
        "math",
        "operator",
        "re",
        "typing",
    }
)
# fonctions integrees qui ouvrent un fichier ou executent du code arbitraire
BUILTINS_INTERDITS_CHECK = frozenset(
    {"open", "__import__", "exec", "eval", "compile", "breakpoint"}
)
# introspection qui rend un module non importe (os, subprocess) atteignable
INTROSPECTION_INTERDITE_CHECK = frozenset(
    {"__builtins__", "__globals__", "__import__", "__loader__", "__subclasses__"}
)
# exemples d'I/O que la liste blanche exclut, cites par docs/architecture.md
IO_EXCLUS_DOCUMENTES = (
    "subprocess",
    "socket",
    "os",
    "pathlib",
    "io",
    "tempfile",
    "asyncio",
    "importlib",
    "winreg",
    "ctypes",
    "winrm",
    "ldap3",
)
# identifiants du modele de menace : mesures sur deux chiffres (M01), pour ne
# pas confondre une mesure avec un jalon du projet (M1, M2, M3)
IDENTIFIANT_MENACE = re.compile(r"\b(?:Z\d+|F\d+|AC\d+|A\d+|M\d{2}|RR\d+|H\d+)\b")
ETAPES = [
    "CIBLE",
    "TRANSPORT",
    "COLLECTE",
    "EVALUATION",
    "RESULTATS",
    "RAPPORT",
    "RENDUS",
]

STATUTS = ("proposé", "accepté", "déprécié", "rejeté")
REMPLACE = re.compile(r"remplacé par ADR-\d{4}")
SECTIONS = (
    "## Contexte et problème",
    "## Facteurs de décision",
    "## Options envisagées",
    "## Décision",
    "### Conséquences",
    "### Confirmation",
    "## Avantages et inconvénients des options",
)
FICHIER_ADR = re.compile(r"(\d{4})-[a-z0-9-]+\.md")
TITRE_ADR = re.compile(r"# (\d{4})\. (.+)")
TICKETS = re.compile(r"#\d+(, #\d+)*")
# ADR anterieurs au gabarit MADR (#11, #12) : un ADR accepte ne se reecrit pas,
# ils gardent donc leur forme (titre « # ADR NNNN — Titre », en-tete en
# tableau), verifiee par tests/test_adr_licence.py et test_adr_nom_marque.py
ANTERIEURS = frozenset({"0001", "0002"})
TITRE_ANTERIEUR = re.compile(r"# ADR (\d{4}) — (.+)")
# | Statut | **Accepté** le 29/10/2026 ...  ;  | Ticket | #11 ; ...
STATUT_ANTERIEUR = re.compile(
    r"^\| Statut \| \*\*([^*]+)\*\* le (\d{2})/(\d{2})/(\d{4})\b", re.MULTILINE
)
TICKET_ANTERIEUR = re.compile(r"^\| Ticket \| (.+) \|$", re.MULTILINE)
# | [0003](fichier) | titre | statut | date | tickets |
LIGNE_INDEX = re.compile(
    r"^\| (?:\[(\d{4})\]\(([^)]+)\)|(\d{4})) \| ([^|]+) \| ([^|]+) \| "
    r"(\d{4}-\d{2}-\d{2}) \| ([^|]+) \|$",
    re.MULTILINE,
)
QUESTION_ADR = "Cette PR nécessite-t-elle un ADR ?"


def _texte(chemin: Path) -> str:
    return chemin.read_text(encoding="utf-8")


# Modules et imports


def _modules() -> dict[str, Path]:
    """Nom de module -> fichier, pour tout .py de src/amnesia (paquets compris)."""
    modules: dict[str, Path] = {}
    for chemin in sorted(SRC.rglob("*.py")):
        parties = chemin.relative_to(SRC.parent).with_suffix("").parts
        if parties[-1] == "__init__":
            parties = parties[:-1]
        modules[".".join(parties)] = chemin
    return modules


def _est_type_checking(test: ast.expr) -> bool:
    if isinstance(test, ast.Name):
        return test.id == "TYPE_CHECKING"
    return isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"


def _hors_type_checking(arbre: ast.AST) -> list[ast.AST]:
    """Nœuds exécutés à l'import : le corps des ``if TYPE_CHECKING:`` est exclu."""
    exclus: set[int] = set()
    for noeud in ast.walk(arbre):
        if isinstance(noeud, ast.If) and _est_type_checking(noeud.test):
            for corps in noeud.body:
                exclus.update(id(n) for n in ast.walk(corps))
    return [noeud for noeud in ast.walk(arbre) if id(noeud) not in exclus]


def _origine(module: str, noeud: ast.ImportFrom, *, paquet: bool) -> str:
    """Module absolu nommé par ``from <origine> import ...``."""
    if noeud.level == 0:
        assert noeud.module is not None
        return noeud.module
    # import relatif : un niveau = le paquet courant, deux = son parent
    base = (module if paquet else module.rpartition(".")[0]).split(".")
    racine = base[: len(base) - noeud.level + 1]
    assert racine, f"{module} : import relatif au-dessus du paquet"
    return ".".join([*racine, *([noeud.module] if noeud.module else [])])


def _imports(
    module: str, source: str, *, paquet: bool, connus: Iterable[str] = ()
) -> set[str]:
    """Modules importés à l'exécution (``if TYPE_CHECKING:`` exclu), absolus.

    ``from paquet import x`` dépend du sous-module ``paquet.x`` quand c'est un
    module de ``connus``, et du paquet sinon (``x`` est alors un nom).
    """
    connus = set(connus)
    importes: set[str] = set()
    for noeud in _hors_type_checking(ast.parse(source)):
        if isinstance(noeud, ast.Import):
            importes.update(alias.name for alias in noeud.names)
        elif isinstance(noeud, ast.ImportFrom):
            origine = _origine(module, noeud, paquet=paquet)
            for alias in noeud.names:
                sous_module = f"{origine}.{alias.name}"
                importes.add(sous_module if sous_module in connus else origine)
    return importes


def _imports_internes(module: str, chemin: Path) -> set[str]:
    importes = _imports(
        module,
        _texte(chemin),
        paquet=chemin.name == "__init__.py",
        connus=_modules(),
    )
    return {m for m in importes if m == PAQUET or m.startswith(f"{PAQUET}.")}


def test_resolution_des_imports_relatifs_et_type_checking() -> None:
    source = (
        "from typing import TYPE_CHECKING\n"
        "from . import __version__\n"
        "from .checks import REGISTRY\n"
        "from ..target import Target\n"
        "import amnesia.log\n"
        "import json\n"
        "if TYPE_CHECKING:\n"
        "    from ..facts import FactSet\n"
    )
    importes = _imports("amnesia.checks.base", source, paquet=False)
    assert importes == {
        "typing",
        "amnesia.checks",
        "amnesia.checks.checks",
        "amnesia.target",
        "amnesia.log",
        "json",
    }
    connus = _modules()
    # « from paquet import x » : si x est un sous-module, la dependance est x,
    # pas le paquet (sinon « amnesia » autorise laisserait passer tout amnesia.*)
    assert _imports(
        "amnesia.checks", "from . import base\n", paquet=True, connus=connus
    ) == {"amnesia.checks.base"}
    assert _imports(
        "amnesia.runner", "from . import cli\n", paquet=False, connus=connus
    ) == {"amnesia.cli"}
    assert _imports(
        "amnesia.runner",
        "from amnesia import report, __version__\n",
        paquet=False,
        connus=connus,
    ) == {"amnesia.report", "amnesia"}
    # et la table le refuse : le moteur n'importe ni la CLI ni le rapport
    autorises = _table()["amnesia.runner"]
    assert not _autorise("amnesia.cli", autorises)
    assert not _autorise("amnesia.report", autorises)
    assert _autorise("amnesia", autorises)


# Table des dependances autorisees


def _table() -> dict[str, set[str]]:
    table: dict[str, set[str]] = {}
    for module, deps in LIGNE_DEPENDANCES.findall(_texte(ARCHITECTURE)):
        assert module not in table, f"ligne en double : {module}"
        table[module] = (
            set() if deps.strip() == "aucune" else set(re.findall(r"`([^`]+)`", deps))
        )
    assert table, "table des dépendances absente de docs/architecture.md"
    return table


def _motif(cle: str) -> str:
    return re.escape(cle).replace(re.escape("<domaine>"), r"[a-z0-9_]+")


def _ligne_de(module: str, table: dict[str, set[str]]) -> str:
    """Clé de la table qui régit ``module`` : exacte, sinon ligne ``<domaine>``."""
    if module in table:
        return module
    candidates = [
        cle
        for cle in table
        if "<domaine>" in cle and re.fullmatch(_motif(cle) + r"(\.[a-z0-9_]+)*", module)
    ]
    assert candidates, f"{module} : aucune ligne dans la table des dépendances"
    assert len(candidates) == 1, f"{module} : lignes ambiguës {candidates}"
    return candidates[0]


def _autorise(importe: str, autorises: set[str]) -> bool:
    # « amnesia » designe le seul paquet racine, jamais ses sous-modules
    return any(
        importe == d or (d != PAQUET and importe.startswith(f"{d}.")) for d in autorises
    )


def test_chaque_module_a_sa_ligne_et_chaque_ligne_un_module() -> None:
    table = _table()
    modules = _modules()
    regies = {_ligne_de(module, table) for module in modules}
    assert regies == set(table), f"lignes sans module : {set(table) - regies}"
    # une dependance citee existe
    for cle, deps in table.items():
        for dep in deps:
            assert dep in modules, f"{cle} : dépendance inconnue {dep}"


@pytest.mark.parametrize("module", sorted(_modules()))
def test_imports_internes_conformes_a_la_table(module: str) -> None:
    table = _table()
    autorises = table[_ligne_de(module, table)]
    for importe in sorted(_imports_internes(module, _modules()[module])):
        assert _autorise(importe, autorises), (
            f"{module} importe {importe}, hors des dépendances autorisées "
            f"({', '.join(sorted(autorises)) or 'aucune'}) : docs/architecture.md"
        )


def _modules_de_checks() -> list[str]:
    table = _table()
    return sorted(m for m in _modules() if "<domaine>" in _ligne_de(m, table))


def _noms_publics(chemin: Path) -> set[str]:
    """Noms qu'un module expose : ``__all__``, sinon ce qu'il définit lui-même.

    Un nom importé par le module (``subprocess``, ``os`` dans
    ``amnesia.checks.base``) n'en fait pas partie : le réimporter depuis ce
    module contournerait la liste blanche.
    """
    definis: set[str] = set()
    for noeud in ast.parse(_texte(chemin)).body:
        if isinstance(noeud, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            definis.add(noeud.name)
        elif isinstance(noeud, ast.Assign):
            for cible in noeud.targets:
                if isinstance(cible, ast.Name) and cible.id == "__all__":
                    return set(ast.literal_eval(noeud.value))
                if isinstance(cible, ast.Name):
                    definis.add(cible.id)
        elif isinstance(noeud, ast.AnnAssign) and isinstance(noeud.target, ast.Name):
            definis.add(noeud.target.id)
    return {nom for nom in definis if not nom.startswith("_")}


def _ecarts_de_check(
    module: str, source: str, *, paquet: bool, modules: Mapping[str, Path]
) -> set[str]:
    """Ce qui, dans un module de check, sort du calcul pur (ADR 0006).

    Garde-fou contre l'erreur d'un check du dépôt, pas isolation : du code
    Python malveillant trouve toujours un chemin vers ``os``. Tout le module
    est parcouru, blocs ``if TYPE_CHECKING:`` compris.
    """
    ecarts: set[str] = set()
    for noeud in ast.walk(ast.parse(source)):
        if isinstance(noeud, ast.Import):
            ecarts.update(
                f"import {a.name}"
                for a in noeud.names
                if a.name not in STDLIB_PERMIS_CHECK
            )
        elif isinstance(noeud, ast.ImportFrom):
            origine = _origine(module, noeud, paquet=paquet)
            if origine != PAQUET and not origine.startswith(f"{PAQUET}."):
                if origine not in STDLIB_PERMIS_CHECK:
                    ecarts.add(f"from {origine}")
                continue
            # interne : des noms publics, jamais un module ni un nom reexporte
            publics = _noms_publics(modules[origine]) if origine in modules else set()
            ecarts.update(
                f"from {origine} import {a.name}"
                for a in noeud.names
                if a.name not in publics or f"{origine}.{a.name}" in modules
            )
        elif isinstance(noeud, ast.Name) and noeud.id in (
            BUILTINS_INTERDITS_CHECK | INTROSPECTION_INTERDITE_CHECK
        ):
            ecarts.add(noeud.id)
        elif (
            isinstance(noeud, ast.Attribute)
            and noeud.attr in INTROSPECTION_INTERDITE_CHECK
        ):
            ecarts.add(f".{noeud.attr}")
    return ecarts


def test_un_module_de_check_ne_fait_aucune_io() -> None:
    # evaluate() est pure : ni processus, ni reseau, ni fichier, ni SDK (ADR 0006)
    modules = _modules()
    checks = _modules_de_checks()
    assert checks
    for module in checks:
        chemin = modules[module]
        ecarts = _ecarts_de_check(
            module,
            _texte(chemin),
            paquet=chemin.name == "__init__.py",
            modules=modules,
        )
        assert not ecarts, f"{module} : {sorted(ecarts)} (ADR 0006)"


def test_garde_fou_des_checks_voit_les_contournements_connus() -> None:
    # chaque ligne contourne une liste noire de modules d'I/O
    piege = (
        "import io, posix, asyncio, importlib, tempfile\n"
        "import amnesia.checks.base\n"
        "from os import path\n"
        "from ..base import subprocess, Check\n"
        "from .. import base\n"
        "from ...target import Kind, Path\n"
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    import shutil\n"
        "open('x', 'w').write('x')\n"
        "f = __import__\n"
        "eval('1'), exec('1'), compile('1', 'x', 'eval'), breakpoint()\n"
        "().__class__.__subclasses__()\n"
        "Check.evaluate.__globals__\n"
    )
    ecarts = _ecarts_de_check(
        "amnesia.checks.windows.piege", piege, paquet=False, modules=_modules()
    )
    assert ecarts == {
        "import io",
        "import posix",
        "import asyncio",
        "import importlib",
        "import tempfile",
        "import amnesia.checks.base",
        "import shutil",
        "from os",
        "from amnesia.checks.base import subprocess",
        "from amnesia.checks import base",
        "from amnesia.target import Path",
        "open",
        "__import__",
        "eval",
        "exec",
        "compile",
        "breakpoint",
        ".__subclasses__",
        ".__globals__",
    }
    # un check ordinaire passe
    ordinaire = (
        "from __future__ import annotations\n"
        "import re\n"
        "from collections.abc import Mapping\n"
        "from ...target import Kind\n"
        "from ..base import Check\n"
        "from ..registry import Domain, register\n"
    )
    assert not _ecarts_de_check(
        "amnesia.checks.windows.ordinaire", ordinaire, paquet=False, modules=_modules()
    )


def test_interdictions_documentees() -> None:
    texte = _texte(ARCHITECTURE)
    for nom in sorted(
        STDLIB_PERMIS_CHECK | BUILTINS_INTERDITS_CHECK | set(IO_EXCLUS_DOCUMENTES)
    ):
        assert f"`{nom}`" in texte, nom


# Formats importes (#35)

# seul amnesia.inputs analyse un format importe : hors de lui, aucun module
# n'importe les analyseurs XML ni les modules d'archives de la bibliotheque
# standard. « xml » couvre xml.etree, xml.dom, xml.sax et xml.parsers.expat.
MODULE_D_ENTREE = "amnesia.inputs"
# pyexpat et _elementtree sont l'analyseur de xml.parsers.expat et de xml.etree
# sous un autre nom ; plistlib et xmlrpc l'appellent, zipimport lit une archive
FORMATS_RESERVES = (
    "xml",
    "pyexpat",
    "_elementtree",
    "plistlib",
    "xmlrpc",
    "zipfile",
    "zipimport",
    "tarfile",
)
# fonctions qui chargent un module par son nom, ou qui extraient une archive en
# appelant zipfile et tarfile a la place de l'appelant
CHARGEMENT_PAR_NOM = frozenset({"import_module", "__import__"})
EXTRACTION_INDIRECTE = frozenset({"unpack_archive", "make_archive"})


def _est_reserve(module: str) -> bool:
    return any(module == r or module.startswith(f"{r}.") for r in FORMATS_RESERVES)


def _nom_appele(appel: ast.Call) -> str:
    if isinstance(appel.func, ast.Name):
        return appel.func.id
    if isinstance(appel.func, ast.Attribute):
        return appel.func.attr
    return ""


def _formats_reserves(source: str) -> set[str]:
    """Imports d'un format réservé, ``if TYPE_CHECKING:`` et import par nom compris."""
    ecarts: set[str] = set()
    for noeud in ast.walk(ast.parse(source)):
        if isinstance(noeud, ast.Import):
            ecarts.update(a.name for a in noeud.names if _est_reserve(a.name))
        elif isinstance(noeud, ast.ImportFrom):
            if noeud.level == 0 and noeud.module and _est_reserve(noeud.module):
                ecarts.add(noeud.module)
            ecarts.update(a.name for a in noeud.names if a.name in EXTRACTION_INDIRECTE)
        elif isinstance(noeud, ast.Call) and _nom_appele(noeud) in CHARGEMENT_PAR_NOM:
            ecarts.update(
                arg.value
                for arg in noeud.args
                if isinstance(arg, ast.Constant)
                and isinstance(arg.value, str)
                and _est_reserve(arg.value)
            )
        elif isinstance(noeud, ast.Name) and noeud.id in EXTRACTION_INDIRECTE:
            ecarts.add(noeud.id)
        elif isinstance(noeud, ast.Attribute) and noeud.attr in EXTRACTION_INDIRECTE:
            ecarts.add(noeud.attr)
    return ecarts


def test_formats_importes_reserves_a_amnesia_inputs() -> None:
    # critere d'acceptation de #35 : ni xml.etree, xml.dom, xml.sax,
    # xml.parsers.expat, zipfile ou tarfile hors de amnesia.inputs
    modules = _modules()
    assert MODULE_D_ENTREE in modules
    for module, chemin in modules.items():
        if module == MODULE_D_ENTREE or module.startswith(f"{MODULE_D_ENTREE}."):
            continue
        ecarts = _formats_reserves(_texte(chemin))
        assert not ecarts, (
            f"{module} importe {sorted(ecarts)} : un format importé se lit par "
            f"{MODULE_D_ENTREE} (docs/architecture.md)"
        )
    # le garde-fou voit bien ces imports la ou ils sont permis
    assert _formats_reserves(_texte(modules[MODULE_D_ENTREE])) >= {
        "xml.etree",
        "xml.parsers",
        "zipfile",
    }


@pytest.mark.parametrize(
    ("source", "ecart"),
    [
        ("import xml.etree.ElementTree as ET\n", "xml.etree.ElementTree"),
        ("from xml.etree import ElementTree\n", "xml.etree"),
        ("from xml import etree\n", "xml"),
        ("import xml\n", "xml"),
        ("from xml.dom import minidom\n", "xml.dom"),
        ("import xml.sax\n", "xml.sax"),
        ("from xml.parsers import expat\n", "xml.parsers"),
        ("import xml.parsers.expat\n", "xml.parsers.expat"),
        ("import pyexpat\n", "pyexpat"),
        ("from pyexpat import ParserCreate\n", "pyexpat"),
        ("import _elementtree\n", "_elementtree"),
        ("import plistlib\n", "plistlib"),
        ("import xmlrpc.client\n", "xmlrpc.client"),
        ("import zipimport\n", "zipimport"),
        ("import zipfile\n", "zipfile"),
        ("from zipfile import ZipFile\n", "zipfile"),
        ("import os, tarfile\n", "tarfile"),
        ("def f():\n    import tarfile\n", "tarfile"),
        ("try:\n    import zipfile\nexcept ImportError:\n    pass\n", "zipfile"),
        (
            "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import zipfile\n",
            "zipfile",
        ),
        ("import importlib\nz = importlib.import_module('zipfile')\n", "zipfile"),
        ("x = __import__('xml.sax')\n", "xml.sax"),
        ("import shutil\nshutil.unpack_archive('a.zip', 'd')\n", "unpack_archive"),
        ("from shutil import unpack_archive\n", "unpack_archive"),
    ],
)
def test_garde_fou_des_formats_importes(source: str, ecart: str) -> None:
    assert ecart in _formats_reserves(source)


def test_garde_fou_des_formats_importes_sans_faux_positif() -> None:
    source = (
        "import json, tomllib, csv\n"
        "from amnesia.inputs import XmlElement, extract_zip, load_xml\n"
        "from . import xml_gpo\n"
        "import importlib\n"
        "m = importlib.import_module('amnesia.checks.windows')\n"
        "NOM = 'zipfile'\n"
    )
    assert _formats_reserves(source) == set()


def test_formats_reserves_documentes() -> None:
    texte = _texte(ARCHITECTURE)
    for nom in ("xml.etree", "xml.dom", "xml.sax", "xml.parsers.expat", "zipfile"):
        assert f"`{nom}`" in texte, nom
    for nom in ("tarfile", "pyexpat", "plistlib", "xmlrpc", "zipimport"):
        assert f"`{nom}`" in texte, nom
    assert "`amnesia.inputs.XmlElement`" in texte


# Flux et frontieres de confiance


def _schema() -> str:
    (schema,) = re.findall(r"```mermaid\n(.*?)```", _texte(ARCHITECTURE), re.DOTALL)
    assert isinstance(schema, str)
    return schema


def test_diagramme_mermaid_du_flux() -> None:
    schema = _schema()
    assert schema.startswith("flowchart ")
    noeuds = re.findall(r"^\s*([A-Z]+)\[", schema, flags=re.MULTILINE)
    assert len(noeuds) == len(set(noeuds)), "nœud déclaré deux fois"
    aretes = re.findall(
        r"^\s*([A-Z]+)\s*(?:-->|-\.->|-\.-)\s*(?:\|[^|]*\|\s*)?([A-Z]+)\s*$",
        schema,
        flags=re.MULTILINE,
    )
    assert aretes
    for origine, destination in aretes:
        assert origine in noeuds, origine
        assert destination in noeuds, destination
    # le flux cible -> transport -> collecte -> evaluation -> resultats ->
    # rapport -> rendus, dans cet ordre
    chaine = [(a, b) for a, b in aretes if a in ETAPES and b in ETAPES]
    assert chaine == list(itertools.pairwise(ETAPES))
    # un label n'embarque ni ticket ni entite : « #63 » et « #9829; » se
    # ressemblent pour mermaid
    assert "#" not in schema


def _identifiants_du_modele_de_menace() -> set[str]:
    return set(IDENTIFIANT_MENACE.findall(_texte(MODELE_MENACE)))


def test_un_jalon_n_est_pas_une_mesure() -> None:
    texte = "jalons M1, M2, M3 ; mesures M05 et M11 ; flux F1 ; risque RR10"
    assert set(IDENTIFIANT_MENACE.findall(texte)) == {"M05", "M11", "F1", "RR10"}


# fichiers d'ADR (index exclu, fichiers caches ignores : .DS_Store, .swp)
FICHIERS_ADR = sorted(
    p for p in ADR.glob("*.md") if p != INDEX and not p.name.startswith(".")
)


@pytest.mark.parametrize(
    "chemin",
    [ARCHITECTURE, *FICHIERS_ADR],
    ids=lambda p: str(p.relative_to(RACINE)),
)
def test_identifiants_du_modele_de_menace_cites_definis(chemin: Path) -> None:
    # zones, flux, menaces, risques et hypotheses cites existent (lien #27)
    cites = set(IDENTIFIANT_MENACE.findall(_texte(chemin)))
    assert cites <= _identifiants_du_modele_de_menace(), chemin.name


def test_frontieres_de_confiance_rattachees_au_modele_de_menace() -> None:
    texte = _texte(ARCHITECTURE)
    zones = set(re.findall(r"\bZ\d+\b", texte))
    assert zones >= {"Z1", "Z2", "Z3", "Z4", "Z5"}
    assert "](threat-model.md)" in texte
    assert "#41" in texte  # cycle de vie des donnees


# Registre des decisions


def _adrs(repertoire: Path = ADR) -> dict[str, Path]:
    adrs: dict[str, Path] = {}
    for chemin in sorted(repertoire.iterdir()):
        # .DS_Store du Finder, sauvegardes d'editeur (*.md~, .*.swp) : ignores ;
        # un .md mal nomme reste une erreur
        if (
            chemin.name == INDEX.name
            or not chemin.is_file()
            or chemin.name.startswith(".")
            or chemin.suffix != ".md"
        ):
            continue
        correspondance = FICHIER_ADR.fullmatch(chemin.name)
        assert correspondance, f"nom d'ADR invalide : {chemin.name}"
        numero = correspondance[1]
        assert numero not in adrs, f"numéro en double : {numero}"
        adrs[numero] = chemin
    assert adrs
    return adrs


def test_registre_ignore_les_fichiers_parasites(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("index\n", encoding="utf-8")
    (tmp_path / "0001-sujet.md").write_text("adr\n", encoding="utf-8")
    for parasite in (".DS_Store", "0001-sujet.md~", ".0001-sujet.md.swp"):
        (tmp_path / parasite).write_bytes(b"\x00")
    assert _adrs(tmp_path) == {"0001": tmp_path / "0001-sujet.md"}
    (tmp_path / "Sujet.md").write_text("adr\n", encoding="utf-8")
    with pytest.raises(AssertionError, match=r"nom d'ADR invalide : Sujet\.md"):
        _adrs(tmp_path)


def _entete(chemin: Path) -> dict[str, str]:
    """Titre et champs « - Clé : valeur » de l'en-tête MADR."""
    texte = _texte(chemin)
    titre = TITRE_ADR.fullmatch(texte.splitlines()[0])
    assert titre, f"{chemin.name} : titre « # NNNN. Titre » attendu"
    entete = {"numero": titre[1], "titre": titre[2].strip()}
    for cle, valeur in re.findall(r"^- (\w+) : (.+)$", texte.partition("## ")[0], re.M):
        entete[cle.lower()] = valeur.strip()
    return entete


def _entete_anterieur(chemin: Path) -> dict[str, str]:
    """Titre, statut, date et tickets d'un ADR antérieur au gabarit.

    « **Accepté partiellement** le 29/10/2026 » donne le statut « accepté » et
    la date 2026-10-29 ; la nuance reste dans l'ADR et sous l'index.
    """
    texte = _texte(chemin)
    titre = TITRE_ANTERIEUR.fullmatch(texte.splitlines()[0])
    assert titre, f"{chemin.name} : titre « # ADR NNNN — Titre » attendu"
    tete = texte.partition("\n## ")[0]
    statut = STATUT_ANTERIEUR.search(tete)
    assert statut, f"{chemin.name} : ligne « | Statut | **...** le JJ/MM/AAAA »"
    tickets = TICKET_ANTERIEUR.search(tete)
    assert tickets, f"{chemin.name} : ligne « | Ticket | #N ... | »"
    return {
        "numero": titre[1],
        "titre": titre[2].strip(),
        "statut": statut[1].split()[0].lower(),
        "date": f"{statut[4]}-{statut[3]}-{statut[2]}",
        "tickets": tickets[1],
    }


def test_numeros_uniques_et_continus() -> None:
    numeros = set(_adrs())
    assert numeros == {f"{n:04d}" for n in range(1, len(numeros) + 1)}
    assert numeros >= ANTERIEURS


@pytest.mark.parametrize("numero", sorted(ANTERIEURS))
def test_forme_des_adr_anterieurs_au_gabarit(numero: str) -> None:
    # forme minimale ; le detail est dans test_adr_licence.py et
    # test_adr_nom_marque.py, propres a chacun
    chemin = _adrs()[numero]
    entete = _entete_anterieur(chemin)
    assert entete["numero"] == numero, chemin.name
    assert entete["statut"] in STATUTS, chemin.name
    assert date.fromisoformat(entete["date"]) <= datetime.now(UTC).date()
    assert re.match(r"#\d+\b", entete["tickets"]), chemin.name
    texte = _texte(chemin)
    for section in ("## Contexte", "## Décision", "## Conséquences"):
        assert f"\n{section}\n" in texte, f"{chemin.name} : section {section!r}"


@pytest.mark.parametrize("numero", sorted(set(_adrs()) - ANTERIEURS))
def test_forme_madr_de_chaque_adr(numero: str) -> None:
    chemin = _adrs()[numero]
    entete = _entete(chemin)
    assert entete["numero"] == numero, chemin.name
    assert entete["statut"] in STATUTS or REMPLACE.fullmatch(entete["statut"])
    assert date.fromisoformat(entete["date"]) <= datetime.now(UTC).date()
    assert TICKETS.fullmatch(entete["tickets"]), chemin.name
    assert entete["décideurs"]
    texte = _texte(chemin)
    for section in SECTIONS:
        assert f"\n{section}\n" in texte, f"{chemin.name} : section {section!r}"
    # contexte, decision et consequences ont un contenu
    for section in ("## Contexte et problème", "## Décision", "### Conséquences"):
        # jusqu'au titre suivant (« #77 » en debut de ligne n'en est pas un)
        corps = re.split(r"\n#+ ", texte.partition(f"\n{section}\n")[2])[0]
        assert len(corps.strip()) > 80, f"{chemin.name} : {section} vide"


def _decision(chemin: Path) -> str:
    """Section « Décision » d'un ADR, espaces normalisés (lignes repliées)."""
    texte = _texte(chemin).partition("\n## Décision\n")[2]
    return " ".join(texte.partition("\n### Conséquences\n")[0].split())


def test_transports_pas_plus_permissifs_que_le_modele_de_menace() -> None:
    # un ADR accepte est la reference de #63 et #119 : il reprend M05 et M07
    decision = _decision(ADR / "0007-transports.md")
    for mesure in (
        "sans option pour la désactiver",
        "Basic et CredSSP refusés quel que soit le canal",
        "Kerberos seul par défaut, sans délégation",
        "NTLM seulement avec `--allow-ntlm`",
        "proxy ignoré",
    ):
        assert mesure in decision, mesure
    # SSH : ce que ~/.ssh/config donnerait a une cible compromise est coupe sur
    # la ligne de commande, et « -- » separe l'hote des options
    (invocation,) = re.findall(r"```text (ssh .*?)```", decision)
    for option in (
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ClearAllForwardings=yes",
        "PermitLocalCommand=no",
    ):
        assert f"-o {option} " in invocation, option
    assert re.search(r" -- <hôte> ", invocation)


def test_lecture_seule_sans_promesse_d_isolation() -> None:
    decision = _decision(ADR / "0006-garantie-lecture-seule.md")
    assert "pas une isolation" in decision
    # auditpol /backup ecrit un fichier sur la cible : jamais une lecture
    (allowlist,) = re.findall(r" 2\. un collecteur (.*?) 3\. ", decision)
    assert "auditpol" not in allowlist
    assert "`auditpol /backup /file:<fichier>` écrit" in decision
    assert "hérite de la garantie" not in _texte(ADR / "0006-garantie-lecture-seule.md")


def _index() -> dict[str, dict[str, str]]:
    lignes: dict[str, dict[str, str]] = {}
    for lien_num, lien, num, titre, statut, jour, tickets in LIGNE_INDEX.findall(
        _texte(INDEX)
    ):
        numero = lien_num or num
        assert numero not in lignes, f"index : {numero} en double"
        lignes[numero] = {
            "lien": lien,
            "titre": titre.strip(),
            "statut": statut.strip(),
            "date": jour,
            "tickets": tickets.strip(),
        }
    return lignes


def test_index_aligne_sur_les_fichiers() -> None:
    index = _index()
    adrs = _adrs()
    assert set(index) == set(adrs)
    for numero, chemin in adrs.items():
        ligne = index[numero]
        assert ligne["lien"] == chemin.name, numero
        if numero in ANTERIEURS:
            entete = _entete_anterieur(chemin)
            # l'index cite le ticket principal, et rien que l'en-tete ne cite
            cites = set(re.findall(r"#\d+", entete["tickets"]))
            assert TICKETS.fullmatch(ligne["tickets"]), numero
            assert set(re.findall(r"#\d+", ligne["tickets"])) <= cites, numero
            assert ligne["tickets"].startswith(entete["tickets"].split()[0]), numero
        else:
            entete = _entete(chemin)
            assert ligne["tickets"] == entete["tickets"], numero
        assert ligne["titre"] == entete["titre"], numero
        assert ligne["statut"] == entete["statut"], numero
        assert ligne["date"] == entete["date"], numero


def test_statuts_et_gabarit_dans_le_registre() -> None:
    texte = _texte(INDEX)
    for statut in (*STATUTS, "remplacé par ADR-NNNN"):
        assert f"| {statut} |" in texte, statut
    (gabarit,) = re.findall(r"```markdown\n(.*?)```", texte, flags=re.DOTALL)
    for section in SECTIONS:
        assert f"\n{section}\n" in gabarit, section
    assert "- Statut : proposé" in gabarit
    assert QUESTION_ADR in texte
    # ADR anterieurs au gabarit : le registre dit ou leur forme est verifiee,
    # et ce qui reste ouvert dans 0002 (le nouveau nom)
    assert "tests/test_adr_licence.py" in texte
    assert "tests/test_adr_nom_marque.py" in texte
    assert "nouveau nom" in texte


@pytest.mark.parametrize(
    "chemin",
    [ARCHITECTURE, INDEX, *FICHIERS_ADR],
    ids=lambda p: str(p.relative_to(RACINE)),
)
def test_liens_relatifs_valides(chemin: Path) -> None:
    cibles = re.findall(r"\]\(([^)\s]+)\)", _texte(chemin))
    assert cibles
    for cible in cibles:
        if cible.startswith(("https://", "#")):
            continue
        fichier = cible.partition("#")[0]
        assert (chemin.parent / fichier).exists(), f"{chemin.name} : {cible}"


# Renvois : CONTRIBUTING et modele de PR


def test_contributing_renvoie_vers_architecture_et_adr() -> None:
    texte = _texte(CONTRIBUTING)
    assert "](docs/architecture.md)" in texte
    assert "](docs/adr/README.md)" in texte
    assert "tests/test_architecture.py" in texte


def test_modele_de_pr_pose_la_question_de_l_adr() -> None:
    cases = [c for c in _texte(MODELE_PR).splitlines() if c.startswith("- [ ] ADR")]
    assert len(cases) == 1
    assert QUESTION_ADR in cases[0]
    assert "docs/adr/README.md" in cases[0]
