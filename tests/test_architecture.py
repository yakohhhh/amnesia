"""Architecture et registre des décisions (#34).

Ces tests verifient que docs/architecture.md et le code restent alignes (table
des dependances autorisees contre les imports reels de src/amnesia, lus par
AST) et la forme du registre docs/adr/ (numeros, sections, statuts, index),
pas la justesse des decisions : ce jugement reste celui de la revue.
"""

import ast
import itertools
import re
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
# modules d'I/O interdits dans un module de check (ADR 0006)
IO_INTERDITS = frozenset(
    {"subprocess", "socket", "os", "pathlib", "shutil", "urllib", "http", "winreg"}
)
SDK_INTERDITS = frozenset(
    {"ctypes", "winrm", "pypsrp", "ldap3", "boto3", "msgraph", "paramiko", "asyncssh"}
)
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
# numeros reserves a des ADR ecrits dans d'autres PR : dans l'index, sans fichier
RESERVES = {"0001": "#11", "0002": "#12"}
# | [0003](fichier) | titre | statut | date | tickets |  ou  | 0001 | ...
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


def _imports(module: str, source: str, *, paquet: bool) -> set[str]:
    """Modules importés à l'exécution (``if TYPE_CHECKING:`` exclu), absolus."""
    arbre = ast.parse(source)
    exclus: set[int] = set()
    for noeud in ast.walk(arbre):
        if isinstance(noeud, ast.If) and _est_type_checking(noeud.test):
            for corps in noeud.body:
                exclus.update(id(n) for n in ast.walk(corps))
    base = module if paquet else module.rpartition(".")[0]
    importes: set[str] = set()
    for noeud in ast.walk(arbre):
        if id(noeud) in exclus:
            continue
        if isinstance(noeud, ast.Import):
            importes.update(alias.name for alias in noeud.names)
        elif isinstance(noeud, ast.ImportFrom):
            if noeud.level == 0:
                assert noeud.module is not None
                importes.add(noeud.module)
                continue
            # import relatif : un niveau = le paquet courant, deux = son parent
            racine = base.split(".")[: len(base.split(".")) - noeud.level + 1]
            assert racine, f"{module} : import relatif au-dessus du paquet"
            importes.add(".".join([*racine, *([noeud.module] if noeud.module else [])]))
    return importes


def _imports_internes(module: str, chemin: Path) -> set[str]:
    importes = _imports(module, _texte(chemin), paquet=chemin.name == "__init__.py")
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
    # dans un __init__, « . » designe le paquet lui-meme ; « from . import x »
    # est une dependance sur le paquet (x peut etre un nom ou un sous-module)
    assert _imports("amnesia.checks", "from . import base\n", paquet=True) == {
        "amnesia.checks"
    }


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


def test_un_module_de_check_n_importe_aucune_io() -> None:
    # evaluate() est pure : ni processus, ni reseau, ni fichier, ni SDK (ADR 0006)
    modules = _modules_de_checks()
    assert modules
    for module in modules:
        chemin = _modules()[module]
        importes = _imports(module, _texte(chemin), paquet=chemin.name == "__init__.py")
        racines = {m.split(".")[0] for m in importes}
        assert not racines & (IO_INTERDITS | SDK_INTERDITS), module
        assert "amnesia.facts.collectors" not in importes, module


def test_interdictions_documentees() -> None:
    texte = _texte(ARCHITECTURE)
    for nom in sorted(IO_INTERDITS | {"ctypes", "winrm", "ldap3", "boto3"}):
        assert f"`{nom}`" in texte, nom


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
    return set(re.findall(r"\b(?:Z|F|AC|A|M|RR|H)\d+\b", _texte(MODELE_MENACE)))


@pytest.mark.parametrize(
    "chemin",
    [ARCHITECTURE, *sorted(p for p in ADR.glob("*.md") if p != INDEX)],
    ids=lambda p: str(p.relative_to(RACINE)),
)
def test_identifiants_du_modele_de_menace_cites_definis(chemin: Path) -> None:
    # zones, flux, menaces, risques et hypotheses cites existent (lien #27)
    cites = set(re.findall(r"\b(?:Z|F|AC|A|M|RR|H)\d+\b", _texte(chemin)))
    assert cites <= _identifiants_du_modele_de_menace(), chemin.name


def test_frontieres_de_confiance_rattachees_au_modele_de_menace() -> None:
    texte = _texte(ARCHITECTURE)
    zones = set(re.findall(r"\bZ\d+\b", texte))
    assert zones >= {"Z1", "Z2", "Z3", "Z4", "Z5"}
    assert "](threat-model.md)" in texte
    assert "#41" in texte  # cycle de vie des donnees


# Registre des decisions


def _adrs() -> dict[str, Path]:
    adrs: dict[str, Path] = {}
    for chemin in sorted(ADR.iterdir()):
        if chemin == INDEX or not chemin.is_file():
            continue
        correspondance = FICHIER_ADR.fullmatch(chemin.name)
        assert correspondance, f"nom d'ADR invalide : {chemin.name}"
        numero = correspondance[1]
        assert numero not in adrs, f"numéro en double : {numero}"
        adrs[numero] = chemin
    assert adrs
    return adrs


def _entete(chemin: Path) -> dict[str, str]:
    """Titre et champs « - Clé : valeur » de l'en-tête MADR."""
    texte = _texte(chemin)
    titre = TITRE_ADR.fullmatch(texte.splitlines()[0])
    assert titre, f"{chemin.name} : titre « # NNNN. Titre » attendu"
    entete = {"numero": titre[1], "titre": titre[2].strip()}
    for cle, valeur in re.findall(r"^- (\w+) : (.+)$", texte.partition("## ")[0], re.M):
        entete[cle.lower()] = valeur.strip()
    return entete


def test_numeros_continus_reserves_compris() -> None:
    numeros = set(_adrs()) | set(RESERVES)
    assert numeros == {f"{n:04d}" for n in range(1, len(numeros) + 1)}
    for numero in RESERVES:
        assert numero not in _adrs(), f"{numero} est réservé à une autre PR"


@pytest.mark.parametrize("numero", sorted(_adrs()))
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
    assert set(index) == set(adrs) | set(RESERVES)
    for numero, chemin in adrs.items():
        entete = _entete(chemin)
        ligne = index[numero]
        assert ligne["lien"] == chemin.name, numero
        assert ligne["titre"] == entete["titre"], numero
        assert ligne["statut"] == entete["statut"], numero
        assert ligne["date"] == entete["date"], numero
        assert ligne["tickets"] == entete["tickets"], numero
    # decisions en cours dans d'autres PR : proposees, sans lien, ticket cite
    for numero, ticket in RESERVES.items():
        assert index[numero]["statut"] == "proposé", numero
        assert index[numero]["lien"] == "", numero
        assert ticket in index[numero]["tickets"], numero


def test_statuts_et_gabarit_dans_le_registre() -> None:
    texte = _texte(INDEX)
    for statut in (*STATUTS, "remplacé par ADR-NNNN"):
        assert f"| {statut} |" in texte, statut
    (gabarit,) = re.findall(r"```markdown\n(.*?)```", texte, flags=re.DOTALL)
    for section in SECTIONS:
        assert f"\n{section}\n" in gabarit, section
    assert "- Statut : proposé" in gabarit
    assert QUESTION_ADR in texte
    # decisions prises mais ADR en cours : open core (#11), changement de nom (#12)
    assert "open core" in texte
    assert "nouveau nom" in texte


@pytest.mark.parametrize(
    "chemin",
    [ARCHITECTURE, INDEX, *sorted(p for p in ADR.glob("*.md") if p != INDEX)],
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
