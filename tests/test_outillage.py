"""Coherence de l'outillage entre les fichiers de configuration."""

import os
import re
import subprocess
import sys
import tomllib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

RACINE = Path(__file__).resolve().parent.parent
PRE_COMMIT = RACINE / ".pre-commit-config.yaml"


def _pre_commit() -> dict[str, Any]:
    config: dict[str, Any] = yaml.safe_load(PRE_COMMIT.read_text(encoding="utf-8"))
    return config


def _hook(hook_id: str) -> dict[str, Any]:
    for depot in _pre_commit()["repos"]:
        for hook in depot["hooks"]:
            if hook["id"] == hook_id:
                trouve: dict[str, Any] = hook
                return trouve
    raise AssertionError(f"hook {hook_id} absent")


def test_hooks_python_installes_depuis_uv_lock() -> None:
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


def test_depots_distants_figes_sur_un_sha() -> None:
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
def test_sorties_client_refusees(chemin: str) -> None:
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
def test_fichiers_du_projet_acceptes(chemin: str) -> None:
    assert not _bloque("interdire-sorties-amnesia", chemin)
    assert not _bloque("interdire-fichiers-secrets", chemin)


@pytest.mark.parametrize(
    "chemin",
    [".env", ".env.local", "cfg/.ENV.prod", "graph-acme.pfx", "a.P12", "x.key"],
)
def test_fichiers_de_secrets_refuses(chemin: str) -> None:
    assert _bloque("interdire-fichiers-secrets", chemin)


@pytest.mark.parametrize("chemin", [".env.example", "cfg/.env.example", ".envrc"])
def test_modeles_de_configuration_acceptes(chemin: str) -> None:
    assert not _bloque("interdire-fichiers-secrets", chemin)


def _regle_gitleaks(regle_id: str) -> dict[str, Any]:
    config = tomllib.loads((RACINE / ".gitleaks.toml").read_text(encoding="utf-8"))
    for regle in config["rules"]:
        if regle["id"] == regle_id:
            trouvee: dict[str, Any] = regle
            return trouvee
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
    # identifiants nommes : les faux secrets ne finissent pas dans .pytest_cache
    ids=[
        "winrm",
        "schema-majuscules",
        "arobase-dans-le-mdp",
        "deux-points-dans-le-mdp",
    ],
)
def test_identifiants_dans_une_url_detectes(parties: tuple[str, str, str, str]) -> None:
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
def test_url_sans_identifiants_acceptees(ligne: str) -> None:
    assert not _secret_detecte("identifiants-dans-une-url", ligne)


def test_gitleaks_en_mode_fichier_recoit_les_fichiers() -> None:
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
    # sortie exploitable (fichier, ligne, regle) mais secret toujours masque
    assert "--verbose" in hook["entry"]
    assert "--redact" in hook["entry"]


WORKFLOWS = sorted(
    p
    for motif in ("*.yml", "*.yaml")
    for p in (RACINE / ".github" / "workflows").glob(motif)
)
SHA_EPINGLE = re.compile(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}")


def _charger(wf: Path) -> tuple[str, dict[str, Any]]:
    texte = wf.read_text(encoding="utf-8")
    return texte, yaml.safe_load(texte)


def _etapes(doc: dict[str, Any]) -> Iterator[tuple[str, Any, Any]]:
    for nom, job in doc["jobs"].items():
        for etape in job.get("steps", []):
            yield nom, job, etape


def test_actions_epinglees_sur_un_sha_avec_version() -> None:
    assert WORKFLOWS
    for wf in WORKFLOWS:
        texte, doc = _charger(wf)
        refs = [job["uses"] for job in doc["jobs"].values() if "uses" in job]
        refs += [etape["uses"] for _, _, etape in _etapes(doc) if "uses" in etape]
        for ref in refs:
            assert SHA_EPINGLE.fullmatch(ref), f"{wf.name} : {ref} non epinglee"
        # la version lisible est un commentaire, invisible pour le parseur YAML
        for ligne in texte.splitlines():
            if re.match(r"\s*(-\s+)?uses:", ligne):
                assert re.search(r"@[0-9a-f]{40} # v\d+\.\d+\.\d+$", ligne), ligne


def test_workflows_durcis() -> None:
    assert WORKFLOWS
    for wf in WORKFLOWS:
        texte, doc = _charger(wf)
        assert "pull_request_target" not in texte, wf.name
        assert doc.get("permissions") == {}, f"{wf.name} : permissions: {{}} attendu"
        for nom, job in doc["jobs"].items():
            assert "permissions" in job, f"{wf.name}:{nom} sans permissions"
            if "uses" not in job:  # un workflow reutilisable n'a pas de timeout
                timeout = job.get("timeout-minutes")
                assert isinstance(timeout, int), f"{wf.name}:{nom} sans timeout"
        for nom, job, etape in _etapes(doc):
            uses, avec = etape.get("uses", ""), etape.get("with", {})
            if uses.startswith("actions/checkout@"):
                assert avec.get("persist-credentials") is False, f"{wf.name}:{nom}"
            if uses.startswith("astral-sh/setup-uv@"):
                cle = re.fullmatch(r"\$\{\{ env\.(\w+) \}\}", avec.get("checksum", ""))
                assert cle, f"{wf.name}:{nom} : setup-uv sans checksum fige"
                assert re.fullmatch(r"[0-9a-f]{64}", doc["env"][cle[1]]), cle[1]
                windows = "windows" in job["runs-on"]
                assert ("WINDOWS" in cle[1]) == windows, f"{wf.name}:{nom}"


def test_ci_ok_attend_tous_les_jobs() -> None:
    _, doc = _charger(RACINE / ".github" / "workflows" / "ci.yml")
    assert set(doc["jobs"]["ci-ok"]["needs"]) == set(doc["jobs"]) - {"ci-ok"}


def test_ci_rejoue_les_garde_fous_anti_fuite() -> None:
    _, doc = _charger(RACINE / ".github" / "workflows" / "ci.yml")
    job = doc["jobs"]["gitleaks"]
    commandes = "\n".join(e.get("run", "") for e in job["steps"])
    assert job["steps"][0]["with"]["fetch-depth"] == 0
    assert job["defaults"]["run"]["shell"] == "bash"  # pipefail
    assert "--diff-merges=remerge" in commandes
    # 4 appels : historique, arbre, blobs, messages ; aucun ne respecte
    # gitleaks:allow, et les 3 scans de fichiers ouvrent les archives
    scans = re.findall(r'gitleaks" (git|dir|stdin) ', commandes)
    assert sorted(scans) == ["dir", "dir", "git", "stdin"]
    assert commandes.count("--ignore-gitleaks-allow") == 4
    assert commandes.count("--max-archive-depth=2") == 3
    assert 'gitleaks" stdin ' in commandes
    assert "iconv -f UTF-16" in commandes
    assert 'gitleaks" dir ' in commandes
    assert "git cat-file blob" in commandes
    assert "scripts/verifier_chemins.py" in commandes
    assert "tests/test_gitleaks.py" in commandes


# depots de test independants de la config git du developpeur (signature,
# hooksPath, autocrlf...)
GIT_HERMETIQUE = {
    **os.environ,
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@t",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@t",
}


def _git(depot: Path, *args: str) -> None:
    subprocess.run(  # noqa: S603 - git et arguments constants, sans shell
        ["git", "-C", str(depot), *args],  # noqa: S607 - git du PATH
        check=True,
        capture_output=True,
        env=GIT_HERMETIQUE,
    )


def _verifier(depot: Path) -> subprocess.CompletedProcess[str]:
    script = RACINE / "scripts" / "verifier_chemins.py"
    return subprocess.run(  # noqa: S603 - interpreteur courant et script du depot
        [sys.executable, str(script), "--depot", str(depot)],
        capture_output=True,
        text=True,
        check=False,
        env=GIT_HERMETIQUE,
    )


def _depot(tmp_path: Path, fichiers: list[str]) -> Path:
    depot = tmp_path / "depot"
    depot.mkdir()
    _git(depot, "init", "-q", "-b", "main")
    for nom in fichiers:
        chemin = depot / nom
        chemin.parent.mkdir(parents=True, exist_ok=True)
        chemin.write_text("x\n", encoding="utf-8")
    _git(depot, "add", "-f", "--", *fichiers)
    _git(depot, "commit", "-q", "--no-verify", "-m", "t")
    return depot


def test_verifier_chemins_noms_accentues(tmp_path: Path) -> None:
    acceptes = ["src/ok.py", ".env.example", "docs/guide.pdf"]
    refuses = ["Rapport-Société.pdf", "clients/clé/.env"]
    sortie = _verifier(_depot(tmp_path, [*acceptes, *refuses]))
    assert sortie.returncode == 1
    for refuse in refuses:
        assert refuse in sortie.stdout
    for accepte in acceptes:
        assert accepte not in sortie.stdout


@pytest.mark.skipif(sys.platform == "win32", reason='« " » interdit par NTFS')
def test_verifier_chemins_nom_avec_guillemet(tmp_path: Path) -> None:
    # git echappe aussi « " » hors du mode -z ; le controle CI tourne sous Linux
    sortie = _verifier(_depot(tmp_path, ['reports/a"b.txt']))
    assert sortie.returncode == 1
    assert 'reports/a"b.txt' in sortie.stdout


def test_verifier_chemins_fichier_ajoute_dans_un_merge(tmp_path: Path) -> None:
    depot = _depot(tmp_path, ["a.txt"])
    _git(depot, "switch", "-q", "-c", "branche")
    (depot / "b.txt").write_text("b\n", encoding="utf-8")
    _git(depot, "add", "b.txt")
    _git(depot, "commit", "-q", "--no-verify", "-m", "b")
    _git(depot, "switch", "-q", "main")
    _git(depot, "merge", "-q", "--no-commit", "--no-ff", "branche")
    (depot / ".env").write_text("x\n", encoding="utf-8")
    _git(depot, "add", "-f", ".env")
    _git(depot, "commit", "-q", "--no-verify", "-m", "merge")
    _git(depot, "rm", "-q", "--cached", ".env")
    _git(depot, "commit", "-q", "--no-verify", "-m", "retrait")
    sortie = _verifier(depot)
    assert sortie.returncode == 1
    assert "interdire-fichiers-secrets : .env" in sortie.stdout


def test_verifier_chemins_depot_propre(tmp_path: Path) -> None:
    sortie = _verifier(_depot(tmp_path, ["src/ok.py", "README.md"]))
    assert sortie.returncode == 0, sortie.stdout
    assert "0 interdits" in sortie.stdout
