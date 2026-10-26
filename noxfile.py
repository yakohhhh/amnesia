"""Sessions nox : lint, typage et tests, installes depuis uv.lock.

Lister les sessions : ``uv run nox -l``.
Meme chose que la CI : ``uv run nox -s lint typecheck tests``.
"""

import nox

nox.options.default_venv_backend = "uv"
nox.options.sessions = ["lint", "typecheck", "tests"]
nox.options.error_on_missing_interpreters = True

# du plancher de requires-python a la derniere version stable
PYTHONS = ["3.11", "3.12", "3.13", "3.14", "3.15"]


def _sync(session: nox.Session) -> None:
    """Installe le projet et le groupe dev a l'identique de uv.lock."""
    session.run_install(
        "uv",
        "sync",
        "--locked",
        f"--python={session.virtualenv.location}",
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
    session.run("pytest", *(session.posargs or ["--cov", "--cov-report=term-missing"]))
