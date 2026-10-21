"""Coherence de l'outillage entre les fichiers de configuration."""

import re
import tomllib
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent


def _version_verrouillee(paquet: str) -> str:
    lock = tomllib.loads((RACINE / "uv.lock").read_text(encoding="utf-8"))
    for p in lock["package"]:
        if p["name"] == paquet:
            return p["version"]
    raise AssertionError(f"{paquet} absent de uv.lock")


def test_ruff_meme_version_dans_pre_commit_et_uv_lock():
    config = (RACINE / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    bloc = re.search(
        r"repo: https://github\.com/astral-sh/ruff-pre-commit\n"
        r"\s+rev: [0-9a-f]{40}  # frozen: v(?P<version>\S+)",
        config,
    )
    assert bloc, "rev de ruff-pre-commit introuvable ou non fige sur un SHA"
    assert bloc["version"] == _version_verrouillee("ruff")


def test_hooks_pre_commit_figes_sur_un_sha():
    config = (RACINE / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    revs = re.findall(r"^\s+rev: (.+)$", config, flags=re.MULTILINE)
    assert revs
    for rev in revs:
        assert re.fullmatch(r"[0-9a-f]{40}  # frozen: v\S+", rev), rev
