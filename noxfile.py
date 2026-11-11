"""Sessions nox : lint, typage, tests et build, installes depuis uv.lock.

Lister les sessions : ``uv run nox -l``.
Meme chose que la CI : ``uv run nox -s lint typecheck tests build lowest-direct``.
"""

import shutil
import sys
from pathlib import Path

import nox

nox.options.default_venv_backend = "uv"
nox.options.sessions = ["lint", "typecheck", "tests"]
nox.options.error_on_missing_interpreters = True

# du plancher de requires-python a la derniere version stable
PYTHONS = ["3.11", "3.12", "3.13", "3.14", "3.15"]

# comme le job test de la CI : tout open() ou subprocess texte sans encoding
# explicite fait echouer le test qui l'execute (docs/dev/encodage.md)
ENV_TESTS = {
    "PYTHONWARNDEFAULTENCODING": "1",
    "PYTEST_ADDOPTS": "-W error::EncodingWarning",
}


def _sync(session: nox.Session, *args: str) -> None:
    """Installe le projet et le groupe dev (ou *args) a l'identique de uv.lock."""
    session.run_install(
        "uv",
        "sync",
        "--locked",
        f"--python={session.virtualenv.location}",
        *args,
        env={"UV_PROJECT_ENVIRONMENT": session.virtualenv.location},
        external=True,
    )


@nox.session(python=PYTHONS[0])
def lint(session: nox.Session) -> None:
    _sync(session)
    session.run("ruff", "check", ".")
    session.run("ruff", "format", "--check", ".")


@nox.session(python=PYTHONS[0])
def typecheck(session: nox.Session) -> None:
    _sync(session)
    # sans argument : cibles et mode strict lus dans [tool.mypy] de pyproject.toml
    session.run("mypy", *session.posargs)


@nox.session(python=PYTHONS)
def tests(session: nox.Session) -> None:
    _sync(session)
    # sans argument, comme la CI : suite complete et seuil de couverture
    session.run(
        "pytest",
        *(session.posargs or ["--cov", "--cov-report=term-missing"]),
        env=ENV_TESTS,
    )


@nox.session(name="lowest-direct", python=PYTHONS[0])
def lowest_direct(session: nox.Session) -> None:
    """Tests avec les bornes basses des dependances d'execution (extras, #44).

    Outils de dev depuis uv.lock, puis le projet et tous ses extras resolus en
    lowest-direct : chaque dependance directe a sa borne basse declaree, les
    transitives au plus recent (delai de carence de [tool.uv] compris).
    """
    _sync(session)
    # --upgrade : sans lui, une version deja installee (dependance d'un outil de
    # dev) serait gardee au lieu de la borne basse
    session.run_install(
        "uv",
        "pip",
        "install",
        f"--python={session.virtualenv.location}",
        "--resolution=lowest-direct",
        "--upgrade",
        "--editable=.[all]",
        external=True,
    )
    # bornes basses compatibles entre elles et avec les outils de dev
    session.run(
        "uv", "pip", "check", f"--python={session.virtualenv.location}", external=True
    )
    session.run("pytest", *(session.posargs or ["-q"]), env=ENV_TESTS)


@nox.session(python=PYTHONS[0])
def build(session: nox.Session) -> None:
    """Construit sdist et wheel, les controle, puis installe le wheel a vide."""
    # outils du groupe build seulement : le projet n'est pas installe ici
    _sync(session, "--only-group=build")
    tmp = Path(session.create_tmp()).resolve()
    dist = tmp / "dist"
    shutil.rmtree(dist, ignore_errors=True)
    # backend fige par build-constraint-dependencies ; le wheel est construit
    # depuis le sdist, donc un fichier oublie dans le sdist casse le build
    session.run("uv", "build", "--no-sources", f"--out-dir={dist}", external=True)
    # uv build ajoute un .gitignore dans le repertoire de sortie
    (sdist,), (wheel,) = dist.glob("*.tar.gz"), dist.glob("*.whl")
    sdist, wheel = str(sdist), str(wheel)
    session.run("validate-pyproject", "pyproject.toml")
    session.run("twine", "check", "--strict", sdist, wheel)
    session.run("check-wheel-contents", wheel)

    # Venv vierge : ni le depot ni uv.lock, seulement le wheel (--no-index : rien
    # n'est tire d'un index). Les commandes tournent hors du depot.
    venv = tmp / "venv-vierge"
    shutil.rmtree(venv, ignore_errors=True)
    session.run("uv", "venv", f"--python={session.python}", str(venv), external=True)
    scripts = venv / ("Scripts" if sys.platform == "win32" else "bin")
    exe = ".exe" if sys.platform == "win32" else ""
    python, amnesia = str(scripts / f"python{exe}"), str(scripts / f"amnesia{exe}")
    session.run(
        "uv", "pip", "install", f"--python={python}", "--no-index", wheel, external=True
    )
    # socle sans dependance tierce (#44) : le wheel seul, aucun autre paquet.
    # --quiet : silent=True capture aussi stderr, ou uv nomme l'environnement
    installes = session.run(
        "uv",
        "pip",
        "freeze",
        "--quiet",
        f"--python={python}",
        external=True,
        silent=True,
    )
    noms = [
        ligne.split(" @ ")[0].split("==")[0]
        for ligne in installes.splitlines()
        if ligne.strip()
    ]
    if noms != ["amnesia-dfr"]:
        session.error(f"venv vierge : amnesia-dfr seul attendu, installes : {noms}")
    sources = str(Path("src").resolve())
    with session.chdir(tmp):
        attendue = session.run(
            python,
            "-I",
            "-c",
            "import importlib.metadata as m; print(m.version('amnesia-dfr'))",
            external=True,
            silent=True,
        ).strip()
        installee = session.run(amnesia, "--version", external=True, silent=True)
        session.run(amnesia, "list-checks", external=True)
        # meme version depuis les sources, sans installation (-S : sans site)
        depuis_sources = session.run(
            "python",
            "-S",
            "-m",
            "amnesia",
            "--version",
            env={"PYTHONPATH": sources},
            silent=True,
        )
    for sortie in (installee, depuis_sources):
        if sortie.strip() != f"amnesia {attendue}":
            session.error(f"version {sortie.strip()!r} != metadonnees {attendue!r}")
