"""Coherence de l'outillage entre les fichiers de configuration."""

import re
import tomllib
from pathlib import Path

import pytest
import yaml

RACINE = Path(__file__).resolve().parent.parent
PRE_COMMIT = RACINE / ".pre-commit-config.yaml"


def _pre_commit() -> dict:
    return yaml.safe_load(PRE_COMMIT.read_text(encoding="utf-8"))


def _hook(hook_id: str) -> dict:
    for depot in _pre_commit()["repos"]:
        for hook in depot["hooks"]:
            if hook["id"] == hook_id:
                return hook
    raise AssertionError(f"hook {hook_id} absent")


def test_hooks_python_installes_depuis_uv_lock():
    # ruff et pre-commit-hooks ne passent pas par les environnements pip de
    # pre-commit (sans empreintes) : hooks locaux lances par uv run --locked.
    depots = {d["repo"] for d in _pre_commit()["repos"]}
    assert not depots & {
        "https://github.com/astral-sh/ruff-pre-commit",
        "https://github.com/pre-commit/pre-commit-hooks",
    }
    for depot in _pre_commit()["repos"]:
        if depot["repo"] != "local":
            continue
        for hook in depot["hooks"]:
            if hook["language"] == "system":
                # sans --no-sync ni --frozen : uv synchronise .venv sur le lock
                # avant d'executer, sinon --locked n'a aucun effet
                assert hook["entry"].startswith("uv run --locked "), hook
                assert "--no-sync" not in hook["entry"], hook
                assert "--frozen" not in hook["entry"], hook


def test_depots_distants_figes_sur_un_sha():
    distants = [d for d in _pre_commit()["repos"] if d["repo"] not in {"local", "meta"}]
    assert distants
    for depot in distants:
        assert re.fullmatch(r"[0-9a-f]{40}", str(depot["rev"])), depot["repo"]
        for hook in depot["hooks"]:
            # hooks Go : version de la chaine Go figee, pas « latest »
            assert re.fullmatch(r"\d+\.\d+\.\d+", hook.get("language_version", ""))
    texte = PRE_COMMIT.read_text(encoding="utf-8")
    for rev in re.findall(r"^\s+rev: (.+)$", texte, flags=re.MULTILINE):
        assert re.fullmatch(r"[0-9a-f]{40}  # frozen: v\S+", rev), rev


def _bloque(hook_id: str, chemin: str) -> bool:
    hook = _hook(hook_id)
    if not re.search(hook["files"], chemin):
        return False
    return not ("exclude" in hook and re.search(hook["exclude"], chemin))


@pytest.mark.parametrize(
    "chemin",
    [
        "amnesia-report.json",
        "Amnesia-Report.HTML",
        "out/AMNESIA-BUNDLE-acme.zip",
        "amnesia-out/dc01.json",
        "exports/acme.amnesia.JSON",
        "reports/acme-2026-10.json",
        "Rapport-ACME.PDF",
        "tests/fixtures/windows/raw/dc01-security.xml",
    ],
)
def test_sorties_client_refusees(chemin):
    assert _bloque("interdire-sorties-amnesia", chemin)


@pytest.mark.parametrize(
    "chemin",
    [
        "docs/guide.pdf",
        "docs/Guide.PDF",
        "src/amnesia/reports/__init__.py",
        "tests/fixtures/windows/auditpol-fr.csv",
        "README.md",
    ],
)
def test_fichiers_du_projet_acceptes(chemin):
    assert not _bloque("interdire-sorties-amnesia", chemin)
    assert not _bloque("interdire-fichiers-secrets", chemin)


@pytest.mark.parametrize(
    "chemin",
    [".env", ".env.local", "cfg/.ENV.prod", "graph-acme.pfx", "a.P12", "x.key"],
)
def test_fichiers_de_secrets_refuses(chemin):
    assert _bloque("interdire-fichiers-secrets", chemin)


@pytest.mark.parametrize("chemin", [".env.example", "cfg/.env.example", ".envrc"])
def test_modeles_de_configuration_acceptes(chemin):
    assert not _bloque("interdire-fichiers-secrets", chemin)


def _regle_gitleaks(regle_id: str) -> dict:
    config = tomllib.loads((RACINE / ".gitleaks.toml").read_text(encoding="utf-8"))
    for regle in config["rules"]:
        if regle["id"] == regle_id:
            return regle
    raise AssertionError(f"regle gitleaks {regle_id} absente")


def _secret_detecte(regle_id: str, ligne: str) -> bool:
    # Approximation en Python de la regle Go (RE2) : la regex, le groupe du
    # secret et l'allowlist. Le hook et le job CI font foi.
    regle = _regle_gitleaks(regle_id)
    trouve = re.search(regle["regex"], ligne)
    if not trouve:
        return False
    secret = trouve.group(regle.get("secretGroup", 0))
    motifs = [m for a in regle.get("allowlists", []) for m in a["regexes"]]
    return not any(re.search(m, secret) for m in motifs)


def _url(schema: str, compte: str, mdp: str, hote: str) -> str:
    # assemblee a l'execution : ces faux identifiants ne doivent pas apparaitre
    # tels quels dans le depot, sinon gitleaks les signalerait (a juste titre)
    return f"{schema}://{compte}:{mdp}@{hote}"


@pytest.mark.parametrize(
    "parties",
    [
        ("winrm", "audit", "Xk9pL2mQ7vTz", "dc01.corp.local"),
        ("WINRM", "audit", "Motdepasse1", "dc01"),
        ("winrm", "audit", "P@ssw0rd!2026", "dc01.acme.local"),
        ("ssh", "audit", "Zx81-Qp93:Lm27", "bastion"),
    ],
)
def test_identifiants_dans_une_url_detectes(parties):
    assert _secret_detecte("identifiants-dans-une-url", _url(*parties))


@pytest.mark.parametrize(
    "ligne",
    [
        "git+ssh://git@github.com:org/repo.git",
        "http://localhost:8080/api@v1",
        "docker://registry:5000/image@sha256:abc",
        "winrm://audit:<motdepasse>@dc01",
        "winrm://audit:changeme@dc01",
        "winrm://{compte}:{mdp}@{hote}:5986/wsman",
        "winrm://${COMPTE}:${MDP}@dc01",
    ],
)
def test_url_sans_identifiants_acceptees(ligne):
    assert not _secret_detecte("identifiants-dans-une-url", ligne)


def test_gitleaks_en_mode_fichier_recoit_les_fichiers():
    # le manifeste amont declare pass_filenames: false ; sans surcharge, la
    # boucle du hook ne recoit aucun fichier et passe a vide
    (hook,) = [
        h
        for d in _pre_commit()["repos"]
        for h in d["hooks"]
        if h.get("alias") == "gitleaks-fichiers"
    ]
    assert hook["pass_filenames"] is True
    assert "gitleaks dir" in hook["entry"]
    assert "--config .gitleaks.toml" in hook["entry"]
