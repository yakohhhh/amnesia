"""Mises a jour (Dependabot) et audit des vulnerabilites des dependances.

Procedure : docs/dev/dependances.md.
"""

import fnmatch
import re
import tomllib
from datetime import date
from pathlib import Path
from typing import Any

import pytest
import yaml

RACINE = Path(__file__).resolve().parent.parent
PYPROJECT = tomllib.loads((RACINE / "pyproject.toml").read_text(encoding="utf-8"))
CI = RACINE / ".github" / "workflows" / "ci.yml"

# identifiants acceptes par --ignore-vuln : GHSA, PYSEC, CVE, OSV...
EXCEPTION = re.compile(
    r"--ignore-vuln=(?P<id>[A-Z]+-[\w-]+)\s+#\s*(?P<raison>\S.*?)\s*;"
    r"\s*revue le (?P<date>\d{4}-\d{2}-\d{2})"
)


def _yaml(chemin: Path) -> Any:
    return yaml.safe_load(chemin.read_text(encoding="utf-8"))


def _dependabot() -> dict[str, dict[str, Any]]:
    config = _yaml(RACINE / ".github" / "dependabot.yml")
    assert config["version"] == 2
    return {maj["package-ecosystem"]: maj for maj in config["updates"]}


def _nom(exigence: str) -> str:
    trouve = re.match(r"[A-Za-z0-9][\w.-]*", exigence)
    assert trouve, exigence
    return trouve[0].lower()


def _etape(job: str, nom: str) -> dict[str, Any]:
    for etape in _yaml(CI)["jobs"][job]["steps"]:
        if etape.get("name") == nom:
            trouvee: dict[str, Any] = etape
            return trouvee
    raise AssertionError(f"etape {nom!r} absente du job {job}")


def test_ecosystemes_actions_et_uv_hebdomadaires() -> None:
    mises_a_jour = _dependabot()
    assert set(mises_a_jour) == {"github-actions", "uv"}
    for maj in mises_a_jour.values():
        assert maj["directory"] == "/"
        assert maj["schedule"]["interval"] == "weekly"


def test_cooldown_aligne_sur_le_delai_de_carence() -> None:
    # une version plus jeune que exclude-newer serait refusee par uv lock
    carence = re.fullmatch(r"(\d+) days", PYPROJECT["tool"]["uv"]["exclude-newer"])
    assert carence, PYPROJECT["tool"]["uv"]["exclude-newer"]
    for ecosysteme, maj in _dependabot().items():
        assert maj["cooldown"] == {"default-days": int(carence[1])}, ecosysteme


def test_labels_dependabot_declares() -> None:
    declares = {
        label["name"] for label in _yaml(RACINE / ".github" / "labels.yml")["labels"]
    }
    for ecosysteme, maj in _dependabot().items():
        assert set(maj["labels"]) == {"type:chore", "area:ci"}, ecosysteme
        assert set(maj["labels"]) <= declares, ecosysteme
        assert maj["commit-message"]["prefix"], ecosysteme


def test_actions_mises_a_jour_ensemble() -> None:
    groupes = _dependabot()["github-actions"]["groups"]
    assert groupes == {"actions": {"patterns": ["*"]}}


def test_outils_groupes_sauf_setuptools() -> None:
    motifs = _dependabot()["uv"]["groups"]["dev-tools"]["patterns"]
    outils = {
        _nom(exigence)
        for groupe in PYPROJECT["dependency-groups"].values()
        for exigence in groupe
    }
    assert outils
    for outil in outils - {"setuptools"}:
        assert any(fnmatch.fnmatch(outil, m) for m in motifs), f"{outil} hors groupe"
    # fige aussi dans build-constraint-dependencies : PR a part, completee a la main
    assert not any(fnmatch.fnmatch("setuptools", m) for m in motifs)
    # les dependances d'execution (SDK) restent une PR chacune
    assert "*" not in motifs


def test_outil_d_audit_epingle_dans_un_groupe_dedie() -> None:
    audit = PYPROJECT["dependency-groups"]["audit"]
    assert len(audit) == 1
    assert re.fullmatch(r"pip-audit==\d+(\.\d+)+", audit[0])
    for nom, groupe in PYPROJECT["dependency-groups"].items():
        if nom != "audit":
            assert not any(_nom(e) == "pip-audit" for e in groupe), nom


def test_pip_audit_sur_tout_le_lock() -> None:
    export = " ".join(_etape("pip-audit", "export de uv.lock (PEP 751)")["run"].split())
    # --locked : echec si uv.lock est perime ; tous les groupes, sans le projet
    for option in ("--locked", "--all-groups", "--no-emit-project"):
        assert option in export
    # pylock.toml : marqueurs ignores, paquets Windows compris (voir ci.yml)
    assert "--format pylock.toml" in export
    assert '--output-file "$RUNNER_TEMP/audit/pylock.toml"' in export
    audit = _etape("pip-audit", "pip-audit")["run"]
    commande = " ".join(audit.replace("\\\n", " ").split())
    assert "uv run --only-group audit pip-audit --strict --locked " in commande
    assert commande.endswith('"${exceptions[@]}" "$RUNNER_TEMP/audit"')


def test_pip_audit_chaque_semaine_et_requis() -> None:
    doc = _yaml(CI)
    # PyYAML lit la cle « on » comme le booleen True
    declencheurs = doc[True]
    assert {"push", "pull_request", "schedule"} <= set(declencheurs)
    assert re.fullmatch(r"\d+ \d+ \* \* \d", declencheurs["schedule"][0]["cron"])
    assert "pip-audit" in doc["jobs"]["ci-ok"]["needs"]
    # aucun if : le job tourne sur tous les evenements, schedule compris
    assert "if" not in doc["jobs"]["pip-audit"]


def test_configuration_dependabot_verifiee_en_ci() -> None:
    zizmor = _etape(
        "workflow-lint", "zizmor (version figee dans uv.lock, audits en ligne)"
    )
    # .github/ et non .github/workflows/ : zizmor audite aussi dependabot.yml
    assert zizmor["run"].endswith(" .github/")
    schema = _etape(
        "workflow-lint",
        "configuration Dependabot conforme au schema (embarque, hors ligne)",
    )
    commande = " ".join(schema["run"].split())
    assert commande == (
        "uv run --only-group ci check-jsonschema "
        "--builtin-schema vendor.dependabot .github/dependabot.yml"
    )


def _exceptions(script: str) -> list[str]:
    """Lignes du tableau bash « exceptions=( ... ) », commentaires seuls exclus."""
    bloc = re.search(r"^\s*exceptions=\(\n(.*?)^\s*\)\s*$", script, re.M | re.S)
    assert bloc, "tableau exceptions absent"
    lignes = [ligne.strip() for ligne in bloc[1].splitlines()]
    return [ligne for ligne in lignes if ligne and not ligne.startswith("#")]


def _exception_valide(ligne: str) -> bool:
    """« --ignore-vuln=ID  # raison ; revue le AAAA-MM-JJ », date reelle."""
    trouve = EXCEPTION.fullmatch(ligne)
    if trouve is None:
        return False
    try:
        date.fromisoformat(trouve["date"])
    except ValueError:
        return False
    return True


def test_exceptions_pip_audit_commentees() -> None:
    script = _etape("pip-audit", "pip-audit")["run"]
    for ligne in _exceptions(script):
        assert _exception_valide(ligne), (
            f"identifiant, raison et date attendus : {ligne}"
        )
    # aucune option --ignore-vuln hors du tableau (commentaires mis a part)
    hors_tableau = re.sub(r"exceptions=\(\n.*?^\s*\)", "", script, flags=re.M | re.S)
    for ligne in hors_tableau.splitlines():
        code = ligne.split("#", 1)[0]
        assert "--ignore-vuln" not in code, ligne


@pytest.mark.parametrize(
    "ligne",
    [
        "--ignore-vuln=GHSA-xmj3-9gf7-h52w  # code jamais appele ; revue le 2026-12-01",
        "--ignore-vuln=PYSEC-2026-1995 # pas de correctif ; revue le 2027-01-15",
        "--ignore-vuln=CVE-2026-112906  # correctif trop recent ; revue le 2026-11-05",
    ],
)
def test_exception_valide_acceptee(ligne: str) -> None:
    assert _exception_valide(ligne)


@pytest.mark.parametrize(
    "ligne",
    [
        "--ignore-vuln=GHSA-xmj3-9gf7-h52w",
        "--ignore-vuln=GHSA-xmj3-9gf7-h52w  # code jamais appele",
        "--ignore-vuln=GHSA-xmj3-9gf7-h52w  # revue le 2026-12-01",
        "--ignore-vuln=GHSA-xmj3-9gf7-h52w  # code jamais appele ; revue le AAAA-MM-JJ",
        "--ignore-vuln GHSA-xmj3-9gf7-h52w  # code jamais appele ; revue le 2026-12-01",
        "--ignore-vuln=  # code jamais appele ; revue le 2026-12-01",
        "--ignore-vuln=GHSA-xmj3-9gf7-h52w  # code jamais appele ; revue le 2026-13-45",
    ],
    ids=[
        "nue",
        "sans-date",
        "sans-raison",
        "date-gabarit",
        "sans-egal",
        "sans-id",
        "date-impossible",
    ],
)
def test_exception_incomplete_refusee(ligne: str) -> None:
    assert not _exception_valide(ligne)


def test_tableau_d_exceptions_lu() -> None:
    script = (
        "exceptions=(\n"
        "  # commentaire seul, ignore\n"
        "  --ignore-vuln=GHSA-aaaa-bbbb-cccc  # raison ; revue le 2026-12-01\n"
        "  --ignore-vuln=PYSEC-2026-1\n"
        ")\n"
        'pip-audit "${exceptions[@]}"\n'
    )
    assert _exceptions(script) == [
        "--ignore-vuln=GHSA-aaaa-bbbb-cccc  # raison ; revue le 2026-12-01",
        "--ignore-vuln=PYSEC-2026-1",
    ]


def _version_figee(depot: str) -> str:
    texte = (RACINE / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    trouve = re.search(
        rf"- repo: {re.escape(depot)}\n\s+rev: [0-9a-f]{{40}}  # frozen: v(\S+)", texte
    )
    assert trouve, depot
    return trouve[1]


def test_binaires_de_la_ci_alignes_sur_pre_commit() -> None:
    # Dependabot ne voit ni ces variables ni ces rev : montee manuelle, des deux
    # cotes a la fois (docs/dev/dependances.md)
    env = {
        cle: valeur
        for etape in [
            *_yaml(CI)["jobs"]["workflow-lint"]["steps"],
            *_yaml(CI)["jobs"]["gitleaks"]["steps"],
        ]
        for cle, valeur in etape.get("env", {}).items()
    }
    assert env["ACTIONLINT_VERSION"] == _version_figee(
        "https://github.com/rhysd/actionlint"
    )
    assert env["GITLEAKS_VERSION"] == _version_figee(
        "https://github.com/gitleaks/gitleaks"
    )
    for cle in ("ACTIONLINT_SHA256", "GITLEAKS_SHA256"):
        assert re.fullmatch(r"[0-9a-f]{64}", env[cle]), cle
