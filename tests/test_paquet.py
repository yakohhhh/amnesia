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
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml

import amnesia

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
