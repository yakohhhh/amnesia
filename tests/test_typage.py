"""Typage statique : mypy strict, marqueur PEP 561 et classifier publies."""

import os
import re
import shutil
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path
from typing import Any

import pytest
import yaml

RACINE = Path(__file__).resolve().parent.parent
# uv run exporte UV (son propre binaire) ; sinon celui du PATH
UV = os.environ.get("UV") or shutil.which("uv") or ""


def _pyproject() -> dict[str, Any]:
    return tomllib.loads((RACINE / "pyproject.toml").read_text(encoding="utf-8"))


def test_configuration_mypy() -> None:
    config = _pyproject()
    mypy = config["tool"]["mypy"]
    assert mypy["strict"] is True
    assert mypy["warn_unreachable"] is True
    assert sorted(mypy["files"]) == ["src", "tests"]
    plancher = re.search(r">=\s*(\d+\.\d+)", config["project"]["requires-python"])
    assert plancher
    assert mypy["python_version"] == plancher[1]
    # pas d'ignore_missing_imports global : un override par module de SDK
    assert "ignore_missing_imports" not in mypy
    for override in mypy.get("overrides", []):
        modules = override["module"]
        modules = [modules] if isinstance(modules, str) else modules
        assert "*" not in modules, override


def test_ci_lance_mypy() -> None:
    ci = (RACINE / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    jobs = yaml.safe_load(ci)["jobs"]
    commandes = {
        nom: [etape.get("run", "") for etape in job.get("steps", [])]
        for nom, job in jobs.items()
    }
    assert "uv run mypy" in commandes["typecheck"]
    # Windows : la session nox typecheck, en plus de lint et tests
    assert any("typecheck" in c.split() for c in commandes["nox-windows"])


def _mypy(tmp_path: Path, source: str) -> tuple[int, set[str]]:
    pytest.importorskip("mypy")
    module = tmp_path / "cas.py"
    module.write_text(source, encoding="utf-8")
    # configuration du depot (pyproject.toml, cwd) ; cache desactive. Un fichier
    # passe en argument remplace les cibles de [tool.mypy] files.
    sortie = subprocess.run(  # noqa: S603 - interpreteur courant, sans shell
        [sys.executable, "-m", "mypy", "--cache-dir", os.devnull, str(module)],
        capture_output=True,
        # sortie de mypy en UTF-8 (chemins et messages) ; replace : un chemin dans
        # la page ANSI de Windows ne doit pas faire planter le test
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        encoding="utf-8",
        errors="replace",
        cwd=RACINE,
        check=False,
    )
    return sortie.returncode, set(re.findall(r"\[([a-z-]+)\]$", sortie.stdout, re.M))


@pytest.mark.parametrize(
    ("source", "code"),
    [
        ("def f(x):\n    return x\n", "no-untyped-def"),
        ("def f(x: int):\n    return x\n", "no-untyped-def"),
        ("def f() -> dict:\n    return {}\n", "type-arg"),
        (
            "from typing import Any\n\n\ndef f(x: Any) -> int:\n    return x\n",
            "no-any-return",
        ),
        (
            "def f(x: int) -> int:\n"
            "    if isinstance(x, int):\n"
            "        return x\n"
            "    return 0\n",
            "unreachable",
        ),
    ],
    ids=["non-annotee", "sans-retour", "generique-nu", "any-renvoye", "inatteignable"],
)
def test_code_mal_type_refuse(tmp_path: Path, source: str, code: str) -> None:
    retour, codes = _mypy(tmp_path, source)
    assert retour == 1
    assert code in codes


def test_code_annote_accepte(tmp_path: Path) -> None:
    source = "def f(x: int) -> dict[str, int]:\n    return {'x': x}\n"
    assert _mypy(tmp_path, source) == (0, set())


def _copie_source(source: Path) -> Path:
    # construction sur une copie : ni build/ ni egg-info dans le depot
    source.mkdir(exist_ok=True)
    for nom in ("pyproject.toml", "uv.lock", "README.md", "LICENSE"):
        shutil.copy2(RACINE / nom, source / nom)
    shutil.copytree(
        RACINE / "src",
        source / "src",
        ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"),
    )
    return source


def _uv_build(source: Path, dist: Path) -> subprocess.CompletedProcess[str]:
    # sdist puis wheel construit depuis le sdist, comme pour une publication.
    # cwd : uv lit [tool.uv] (build-constraint, exclude-newer) dans le
    # repertoire courant, pas dans la source passee en argument
    return subprocess.run(  # noqa: S603 - binaire uv, arguments constants
        [UV, "build", "--quiet", "--out-dir", str(dist), str(source)],
        capture_output=True,
        # uv ecrit ses messages en UTF-8 ; replace : diagnostic seulement
        encoding="utf-8",
        errors="replace",
        cwd=source,
        check=False,
    )


@pytest.fixture(scope="module")
def wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if not UV:
        pytest.skip("uv absent")
    source = _copie_source(tmp_path_factory.mktemp("source"))
    dist = tmp_path_factory.mktemp("dist")
    sortie = _uv_build(source, dist)
    assert sortie.returncode == 0, sortie.stderr
    (fichier,) = dist.glob("*.whl")
    return fichier


def test_build_applique_tool_uv_hors_du_depot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if not UV:
        pytest.skip("uv absent")
    # contrainte de build insatisfiable : le build doit echouer, meme si pytest
    # tourne hors du depot (sinon setuptools non epingle, hors delai de carence)
    source = _copie_source(tmp_path / "source")
    pyproject = source / "pyproject.toml"
    (epingle,) = _pyproject()["tool"]["uv"]["build-constraint-dependencies"]
    # la ligne de la contrainte seulement : le groupe dev epingle le meme setuptools
    ligne = 'build-constraint-dependencies = ["{}"]'
    texte = pyproject.read_text(encoding="utf-8")
    assert texte.count(ligne.format(epingle)) == 1
    pyproject.write_text(
        texte.replace(ligne.format(epingle), ligne.format("setuptools==0.9.8")),
        encoding="utf-8",
    )
    ailleurs = tmp_path / "ailleurs"
    ailleurs.mkdir()
    monkeypatch.chdir(ailleurs)
    sortie = _uv_build(source, tmp_path / "dist")
    assert sortie.returncode != 0
    assert "setuptools==0.9.8" in sortie.stderr


def test_wheel_contient_py_typed(wheel: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        # vide : un « partial » (PEP 561) ne concerne que les paquets de stubs
        assert archive.read("amnesia/py.typed") == b""


def test_wheel_declare_typing_typed(wheel: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        (nom,) = [n for n in archive.namelist() if n.endswith(".dist-info/METADATA")]
        metadata = archive.read(nom).decode("utf-8")
    assert "Classifier: Typing :: Typed" in metadata.splitlines()
