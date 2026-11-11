"""Paquet construit : version unique, metadonnees publiees et donnees embarquees."""

import email.message
import email.parser
import email.policy
import os
import re
import runpy
import shutil
import subprocess
import sys
import tomllib
import zipfile
from collections.abc import Iterable, Iterator
from pathlib import Path

import pytest
import yaml

import amnesia
from amnesia import deps

RACINE = Path(__file__).resolve().parent.parent
PYPROJECT = tomllib.loads((RACINE / "pyproject.toml").read_text(encoding="utf-8"))
PROJET = PYPROJECT["project"]
# un fichier concret par motif de package-data (« ** » : un sous-repertoire)
SONDES = [
    motif.replace("**", "sous-dossier").replace("*", "sonde")
    for motif in PYPROJECT["tool"]["setuptools"]["package-data"]["amnesia"]
]


@pytest.fixture(scope="module")
def wheel(tmp_path_factory: pytest.TempPathFactory) -> Iterator[zipfile.ZipFile]:
    # Build dans une copie du projet (ni build/ ni egg-info dans le depot), avec
    # le setuptools du groupe dev : meme version que le backend fige, hors ligne.
    projet = tmp_path_factory.mktemp("projet")
    for nom in ("pyproject.toml", "README.md", "LICENSE"):
        shutil.copy2(RACINE / nom, projet / nom)
    shutil.copytree(
        RACINE / "src",
        projet / "src",
        ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"),
    )
    for sonde in SONDES:
        chemin = projet / "src" / "amnesia" / sonde
        if chemin.exists():  # fichier reel du paquet (py.typed) : laisse tel quel
            continue
        chemin.parent.mkdir(parents=True, exist_ok=True)
        chemin.write_text("sonde\n", encoding="utf-8")
    dist = tmp_path_factory.mktemp("dist")
    build = subprocess.run(  # noqa: S603 - interpreteur courant, code constant
        [
            sys.executable,
            "-c",
            "import sys; from setuptools import build_meta; "
            "build_meta.build_wheel(sys.argv[1])",
            str(dist),
        ],
        cwd=projet,
        capture_output=True,
        # messages de setuptools en UTF-8 ; replace : diagnostic seulement
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    assert build.returncode == 0, build.stderr
    (chemin,) = dist.glob("*.whl")
    with zipfile.ZipFile(chemin) as archive:
        yield archive


@pytest.fixture(scope="module")
def metadata(wheel: zipfile.ZipFile) -> email.message.Message:
    (nom,) = [n for n in wheel.namelist() if n.endswith(".dist-info/METADATA")]
    texte = wheel.read(nom).decode("utf-8")
    return email.parser.Parser(policy=email.policy.compat32).parsestr(texte)


def test_version_definie_une_seule_fois() -> None:
    # pyproject ne porte pas la version : setuptools la lit dans __init__.py
    assert "version" not in PROJET
    assert PROJET["dynamic"] == ["version"]
    dynamique = PYPROJECT["tool"]["setuptools"]["dynamic"]
    assert dynamique["version"] == {"attr": "amnesia.__version__"}


def test_metadata_version_et_requires_python(metadata: email.message.Message) -> None:
    assert metadata["Name"] == "amnesia-dfr"
    assert metadata["Version"] == amnesia.__version__
    assert metadata["Requires-Python"] == PROJET["requires-python"]


def test_version_depuis_les_sources(metadata: email.message.Message) -> None:
    # PYTHONPATH=src python -m amnesia --version, sans paquet installe (-S)
    sortie = subprocess.run(
        [sys.executable, "-S", "-m", "amnesia", "--version"],
        cwd=RACINE,
        env={
            **os.environ,
            "PYTHONPATH": str(RACINE / "src"),
            "PYTHONIOENCODING": "utf-8",
        },
        capture_output=True,
        encoding="utf-8",
        check=True,
    )
    assert sortie.stdout.strip() == f"amnesia {metadata['Version']}"


def test_metadata_publiees(metadata: email.message.Message) -> None:
    assert metadata["Summary"] == PROJET["description"]
    assert not metadata["Summary"].isascii(), "description sans accents"
    assert "DFIR" in metadata["Keywords"].split(",")
    classifiers = metadata.get_all("Classifier", [])
    assert len(classifiers) >= 10
    assert classifiers == PROJET["classifiers"]
    # PEP 639 : la licence ne passe pas par un classifier (#30)
    assert not [c for c in classifiers if c.startswith("License ::")]
    urls: dict[str, str] = {}
    for entree in metadata.get_all("Project-URL", []):
        nom, _, url = entree.partition(", ")
        urls[nom] = url
    assert set(urls) == {"Homepage", "Repository", "Issues", "Changelog"}
    for url in urls.values():
        assert url.startswith("https://"), url


def test_classifiers_suivent_la_matrice_ci() -> None:
    prefixe = "Programming Language :: Python :: 3."
    classees = [
        c.removeprefix("Programming Language :: Python :: ")
        for c in PROJET["classifiers"]
        if c.startswith(prefixe)
    ]
    nox_pythons = runpy.run_path(str(RACINE / "noxfile.py"))["PYTHONS"]
    ci = yaml.safe_load(
        (RACINE / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    matrice = ci["jobs"]["test"]["strategy"]["matrix"]["python-version"]
    assert classees == nox_pythons == matrice
    assert PROJET["requires-python"] == f">={matrice[0]}"


def test_long_description_sans_lien_relatif(metadata: email.message.Message) -> None:
    # sur PyPI, un lien relatif pointe vers pypi.org, pas vers le depot
    description = metadata.get_payload()
    assert isinstance(description, str)
    liens = re.findall(r"\]\(\s*<?([^)\s>]+)", description)
    liens += re.findall(r"^\s*\[[^\]]+\]:\s*<?(\S+?)>?$", description, re.MULTILINE)
    liens += re.findall(r"(?:href|src)\s*=\s*[\"']([^\"']+)", description)
    assert liens
    relatifs = [lien for lien in liens if not lien.startswith("https://")]
    assert not relatifs


# installation de amnesia-dfr par son nom depuis un index (pip, pipx, uv, uvx),
# nom normalise selon la PEP 503 ; un chemin de wheel (dist/amnesia_dfr-...) passe
INSTALLATION_PAR_NOM = re.compile(
    r"\b(?:pip3?\s+install|pipx\s+(?:install|run)|uvx"
    r"|uv\s+(?:tool\s+(?:install|run)|pip\s+install|add))\b"
    r"[^`\n]*?(?<![\w./\\-])amnesia[-_.]+dfr(?![\w./\\*-])",
    re.IGNORECASE,
)


def test_aucune_installation_par_nom_avant_publication() -> None:
    # amnesia-dfr n'est pas reserve sur PyPI : un tiers peut l'enregistrer. La
    # documentation installe depuis les sources ou le wheel local. A retirer par
    # #33 une fois le nom publie (docs/PAQUET.md).
    assert INSTALLATION_PAR_NOM.search("pipx install amnesia-dfr")
    assert INSTALLATION_PAR_NOM.search("uvx --from Amnesia_DFR==0.1.0 amnesia")
    assert not INSTALLATION_PAR_NOM.search(
        "uv tool install dist/amnesia_dfr-0.1.0-py3-none-any.whl"
    )
    documents = [RACINE / "README.md", *sorted((RACINE / "docs").rglob("*.md"))]
    trouvees = [
        f"{document.relative_to(RACINE)}:{numero}"
        for document in documents
        for numero, ligne in enumerate(
            document.read_text(encoding="utf-8").splitlines(), start=1
        )
        if INSTALLATION_PAR_NOM.search(ligne)
    ]
    assert not trouvees


def test_package_data_dans_le_wheel(wheel: zipfile.ZipFile) -> None:
    assert SONDES
    contenu = set(wheel.namelist())
    for sonde in SONDES:
        assert f"amnesia/{sonde}" in contenu


def test_schemas_json_dans_le_wheel(wheel: zipfile.ZipFile) -> None:
    # equivalent de « unzip -l » : les vrais schemas, pas seulement les sondes
    contenu = set(wheel.namelist())
    for nom in ("report-v1.schema.json", "facts-1.schema.json"):
        assert f"amnesia/schemas/{nom}" in contenu
        assert (
            wheel.read(f"amnesia/schemas/{nom}")
            == (RACINE / "src" / "amnesia" / "schemas" / nom).read_bytes()
        )


def test_setuptools_des_tests_aligne_sur_le_backend_fige() -> None:
    dev = [d for d in PYPROJECT["dependency-groups"]["dev"] if "setuptools" in d]
    contraintes = PYPROJECT["tool"]["uv"]["build-constraint-dependencies"]
    assert dev == [c for c in contraintes if c.startswith("setuptools")]


def test_ci_construit_le_paquet_sous_linux_et_windows() -> None:
    ci = yaml.safe_load(
        (RACINE / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    systemes: set[str] = set()
    for job in ci["jobs"].values():
        commandes = [e.get("run", "") for e in job.get("steps", [])]
        if any(re.search(r"\bnox -s\b.*\bbuild\b", c) for c in commandes):
            systemes.add(job["runs-on"].split("-")[0])
    assert systemes == {"ubuntu", "windows"}


# --- dependances d'execution : extras optionnels (#44) -------------------------

# Backports de la stdlib admis hors extra, seulement sous condition de version de
# Python (« tomli ; python_version < "3.11" ») : docs/dev/dependances.md
BACKPORTS = frozenset(
    {"exceptiongroup", "importlib-metadata", "importlib-resources", "tomli"}
)

# Bornes hautes admises (distribution normalisee -> incompatibilite connue) ;
# toute entree renvoie a la fiche de la dependance dans docs/dev/dependances.md
BORNES_HAUTES: dict[str, str] = {}

# nom [extras] specificateurs ; marqueur, forme des Requires-Dist de setuptools
EXIGENCE = re.compile(
    r"\s*(?P<nom>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*"
    r"(?:\[(?P<extras>[^\]]*)\])?\s*(?P<versions>[^;]*?)\s*(?:;\s*(?P<marqueur>.*))?"
)
# setuptools ajoute « and extra == "x" » au premier niveau du marqueur d'origine,
# mis entre parentheses s'il contient un « or »
MARQUEUR_EXTRA = re.compile(
    r"(?:(?P<condition>.*?)\s+and\s+)?extra\s*==\s*[\"'](?P<extra>[^\"']+)[\"']"
)
CONDITION_DE_VERSION = re.compile(
    r"python(?:_full)?_version\s*<\s*[\"'][0-9]+(?:\.[0-9]+)*[\"']"
)


def _normaliser(nom: str) -> str:
    """Nom de distribution normalisé (PEP 503)."""
    return re.sub(r"[-_.]+", "-", nom).lower()


def _exigence(texte: str) -> re.Match[str]:
    trouve = EXIGENCE.fullmatch(texte)
    assert trouve, f"exigence illisible : {texte!r}"
    return trouve


def _hors_parentheses(condition: str) -> str:
    """Condition sans ses chaînes ni ses groupes entre parenthèses."""
    texte = re.sub(r"\"[^\"]*\"|'[^']*'", '""', condition)
    while True:
        reduit = re.sub(r"\([^()]*\)", "", texte)
        if reduit == texte:
            return texte
        texte = reduit


def _extra_de(exigence: str) -> str | None:
    """Extra qui conditionne l'exigence, ou None si elle s'installe sans extra.

    Prudent : « a or b and extra == "x" » se lit « a or (b and extra == "x") »
    et s'installe sans extra ; tout marqueur non reconnu compte comme sans extra.
    """
    marqueur = _exigence(exigence)["marqueur"]
    if marqueur is None:
        return None
    trouve = MARQUEUR_EXTRA.fullmatch(marqueur.strip())
    if trouve is None:
        return None
    condition = trouve["condition"]
    if condition is not None and re.search(r"\bor\b", _hors_parentheses(condition)):
        return None
    return trouve["extra"]


def _backport_conditionnel(exigence: str) -> bool:
    """Backport de la stdlib installé seulement sous une version de Python."""
    trouve = _exigence(exigence)
    marqueur = trouve["marqueur"]
    return (
        _normaliser(trouve["nom"]) in BACKPORTS
        and marqueur is not None
        and CONDITION_DE_VERSION.fullmatch(marqueur.strip()) is not None
    )


def _hors_extra(exigences: Iterable[str]) -> list[str]:
    """Exigences installées sans extra, backports conditionnels exceptés."""
    return [
        e for e in exigences if _extra_de(e) is None and not _backport_conditionnel(e)
    ]


def _extras_references_par_all(exigences: Iterable[str]) -> set[str]:
    """Extras que « all » référence ; échoue s'il ajoute une autre dépendance."""
    references: set[str] = set()
    for exigence in exigences:
        if _extra_de(exigence) != deps.ALL:
            continue
        trouve = _exigence(exigence)
        # agregat auto-reference : amnesia-dfr[ad,aws], sans version ni SDK
        assert _normaliser(trouve["nom"]) == deps.DISTRIBUTION, exigence
        assert trouve["extras"], exigence
        assert not trouve["versions"], exigence
        references |= {e.strip() for e in trouve["extras"].split(",")}
    return references


@pytest.mark.parametrize(
    ("exigence", "extra"),
    [
        ('boto3>=1.34; extra == "aws"', "aws"),
        ("boto3 >=1.34 ; extra == 'aws'", "aws"),
        ('amnesia-dfr[ad,aws]; extra == "all"', "all"),
        ('pypsrp>=0.8; python_version < "3.13" and extra == "windows"', "windows"),
        (
            'x>=1; (sys_platform == "win32" or python_version < "3.12") '
            'and extra == "ad"',
            "ad",
        ),
        ("boto3>=1.34", None),
        ('boto3>=1.34; python_version >= "3.11"', None),
        (
            'x>=1; sys_platform == "win32" or python_version < "3.12" '
            'and extra == "ad"',
            None,
        ),
        ('x>=1; extra == "ad" or sys_platform == "win32"', None),
        ('x>=1; platform_release == "a or b" and extra == "ad"', "ad"),
    ],
    ids=[
        "extra",
        "espaces-apostrophes",
        "all",
        "condition-et-extra",
        "or-entre-parentheses",
        "sans-marqueur",
        "marqueur-sans-extra",
        "or-hors-parentheses",
        "extra-ou-autre",
        "or-dans-une-chaine",
    ],
)
def test_marqueur_extra_reconnu(exigence: str, extra: str | None) -> None:
    assert _extra_de(exigence) == extra


@pytest.mark.parametrize(
    ("exigence", "admise"),
    [
        ('tomli>=2; python_version < "3.11"', True),
        ('exceptiongroup>=1.2; python_full_version < "3.11.4"', True),
        ('Importlib_Metadata>=6; python_version < "3.12"', True),
        ("tomli>=2", False),
        ('requests>=2; python_version < "3.11"', False),
        ('tomli>=2; sys_platform == "win32"', False),
        ('tomli>=2; python_version >= "3.11"', False),
    ],
    ids=[
        "tomli",
        "full-version",
        "nom-non-normalise",
        "sans-condition",
        "pas-un-backport",
        "condition-de-plateforme",
        "condition-inversee",
    ],
)
def test_backport_conditionnel(exigence: str, admise: bool) -> None:
    assert _backport_conditionnel(exigence) is admise
    assert (_hors_extra([exigence]) == []) is admise


def test_aucune_dependance_d_execution_hors_extra(
    metadata: email.message.Message,
) -> None:
    # le socle s'installe sans aucun paquet tiers : chaque SDK passe par un extra
    assert _hors_extra(metadata.get_all("Requires-Dist", [])) == []
    assert not PROJET.get("dependencies"), "dependances du socle : extra attendu"


def test_extra_all_reference_tous_les_extras(metadata: email.message.Message) -> None:
    fournis = set(metadata.get_all("Provides-Extra", []))
    assert deps.ALL in fournis
    references = _extras_references_par_all(metadata.get_all("Requires-Dist", []))
    assert references == fournis - {deps.ALL}


def test_all_incomplet_detecte() -> None:
    exigences = [
        'boto3>=1.34; extra == "aws"',
        'pypsrp>=0.8; extra == "windows"',
        'amnesia-dfr[aws]; extra == "all"',
    ]
    assert _hors_extra(exigences) == []
    assert _extras_references_par_all(exigences) == {"aws"}
    # « all » n'agrege que des extras, sans dependance propre
    with pytest.raises(AssertionError):
        _extras_references_par_all(['boto3>=1.34; extra == "all"'])


def test_extras_concordent_avec_amnesia_deps() -> None:
    # nom PyPI dans pyproject.toml, module importe dans amnesia.deps.EXTRAS :
    # require_extra() et le test des imports paresseux lisent le second
    optionnelles = PROJET.get("optional-dependencies", {})
    assert deps.ALL in optionnelles
    declares = {
        extra: {_normaliser(_exigence(e)["nom"]) for e in exigences}
        for extra, exigences in optionnelles.items()
        if extra != deps.ALL
    }
    connus = {
        extra: {_normaliser(p.distribution) for p in paquets}
        for extra, paquets in deps.EXTRAS.items()
    }
    assert connus == declares
    for extra in declares:
        # nom normalise (PEP 685) : celui que pip et uv comparent
        assert re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", extra), extra


def _ecarts_de_bornes(exigence: str) -> list[str]:
    """Écarts à la règle des versions : borne basse, pas de borne haute."""
    trouve = _exigence(exigence)
    nom = _normaliser(trouve["nom"])
    operateurs = set(re.findall(r"===|==|~=|!=|<=|>=|<|>", trouve["versions"]))
    ecarts = []
    if ">=" not in operateurs:
        ecarts.append(f"{nom} : borne basse >= testee attendue")
    if operateurs & {"==", "===", "~="}:
        ecarts.append(f"{nom} : version figee, incompatible avec les autres extras")
    if operateurs & {"<", "<="} and nom not in BORNES_HAUTES:
        ecarts.append(f"{nom} : borne haute sans incompatibilite documentee")
    return ecarts


@pytest.mark.parametrize(
    ("exigence", "conforme"),
    [
        ("boto3>=1.34", True),
        ("pypsrp>=0.8,!=0.8.2", True),
        ("boto3", False),
        ("boto3==1.34.0", False),
        ("boto3~=1.34", False),
        ("boto3>=1.34,<2", False),
    ],
)
def test_regle_des_bornes(exigence: str, conforme: bool) -> None:
    assert (_ecarts_de_bornes(exigence) == []) is conforme


def test_dependances_d_execution_a_borne_basse() -> None:
    # borne basse testee par le job CI lowest-direct ; aucune borne haute sans
    # incompatibilite connue (docs/dev/dependances.md)
    ecarts = [
        ecart
        for extra, exigences in PROJET.get("optional-dependencies", {}).items()
        if extra != deps.ALL
        for exigence in exigences
        for ecart in _ecarts_de_bornes(exigence)
    ]
    assert ecarts == []
