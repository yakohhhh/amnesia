# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Licence du coeur et politique de contribution (#30, ADR 0001).

LICENSE, README et pyproject.toml designent la meme licence (MIT), chaque
fichier de code porte son en-tete SPDX, REUSE.toml ne couvre que les fichiers
sans en-tete, et le controle DCO (scripts/verifier_dco.py, job CI dco) refuse un
commit sans Signed-off-by de son auteur. La conformite REUSE complete est
verifiee par reuse lint (job CI reuse), les metadonnees du wheel par
tests/test_paquet.py.
"""

import itertools
import os
import re
import runpy
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml

RACINE = Path(__file__).resolve().parent.parent
DEPOT = "https://github.com/yakohhhh/amnesia/blob/main"
ADR = "docs/adr/0001-modele-de-licence.md"
SCRIPT_DCO = RACINE / "scripts" / "verifier_dco.py"
PYPROJECT = tomllib.loads((RACINE / "pyproject.toml").read_text(encoding="utf-8"))
REUSE = tomllib.loads((RACINE / "REUSE.toml").read_text(encoding="utf-8"))
# fichiers de code : en-tete SPDX obligatoire, jamais couverts par REUSE.toml
CODE = {".py", ".pyi", ".ps1", ".psm1", ".psd1", ".sh"}
# donnees brutes des tests : couvertes par REUSE.toml, quel que soit leur type
FIXTURES = "tests/fixtures/"
# fichiers de licence, que reuse lint ne demande pas d'annoter
LICENCES = {"LICENSE", "REUSE.toml"}

# REUSE-IgnoreStart : motifs d'en-tete, pas l'en-tete de ce fichier
COPYRIGHT = re.compile(r"# SPDX-FileCopyrightText: \d{4}(?:-\d{4})? \S.*")
IDENTIFIANT = "# SPDX-License-Identifier: MIT"
ETIQUETTES = ("SPDX-FileCopyrightText:", "SPDX-License-Identifier:")
MENTION_LICENSE = "Copyright (c) 2026 Ayman Mazroui"
EXEMPLE = f"# SPDX-FileCopyrightText: 2026 A\n{IDENTIFIANT}\n\n"
# REUSE-IgnoreEnd


def _texte(chemin: Path) -> str:
    return chemin.read_text(encoding="utf-8")


def _section(texte: str, titre: str) -> str:
    for morceau in re.split(r"^## ", texte, flags=re.MULTILINE)[1:]:
        entete, _, corps = morceau.partition("\n")
        if entete.strip() == titre:
            return corps
    raise AssertionError(f"section {titre!r} absente")


def _ci() -> dict[str, Any]:
    ci: dict[str, Any] = yaml.safe_load(
        _texte(RACINE / ".github" / "workflows" / "ci.yml")
    )
    return ci


# Meme licence partout


def test_licence_mit_inchangee() -> None:
    licence = _texte(RACINE / "LICENSE")
    assert licence.startswith("MIT License\n")
    # titulaire inchange (ADR 0001, « Titulaire des droits »)
    assert MENTION_LICENSE in licence
    # texte de LICENSES/ (exige par REUSE) : copie conforme
    assert _texte(RACINE / "LICENSES" / "MIT.txt") == licence
    assert [n for n in _fichiers() if n.startswith("LICENSES/")] == ["LICENSES/MIT.txt"]


def test_pyproject_au_format_pep_639() -> None:
    projet = PYPROJECT["project"]
    assert projet["license"] == "MIT"
    assert projet["license-files"] == ["LICENSE"]
    assert not [c for c in projet["classifiers"] if c.startswith("License ::")]


def test_reuse_toml_declare_la_meme_licence() -> None:
    assert REUSE["version"] == 1
    assert REUSE["annotations"]
    for annotation in REUSE["annotations"]:
        assert annotation["SPDX-License-Identifier"] == "MIT"
        assert annotation["SPDX-FileCopyrightText"] == "2026 Ayman Mazroui"
        # une mention citee dans un document s'ajoute au titulaire declare ici
        assert annotation["precedence"] == "aggregate"


def test_readme_licence_alignee() -> None:
    licence = _section(_texte(RACINE / "README.md"), "Licence")
    assert "licence MIT" in licence
    # liens absolus : le README est la long_description publiee sur PyPI
    assert f"]({DEPOT}/LICENSE)" in licence
    assert f"]({DEPOT}/CONTRIBUTING.md#licence-des-contributions)" in licence
    assert "DCO" in licence
    assert "REUSE" in licence


def test_readme_vendable_aligne_sur_l_adr() -> None:
    vendable = _section(_texte(RACINE / "README.md"), "Vendable")
    assert "**open core**" in vendable
    assert f"]({DEPOT}/{ADR})" in vendable
    assert "licence MIT" in vendable
    assert "licence propriétaire" in vendable
    assert "hors de ce dépôt" in vendable
    # l'ancienne promesse contredisait la licence MIT
    assert "licence aux\nMSP" not in vendable
    assert "licence aux MSP" not in " ".join(vendable.split())


# En-tetes SPDX et REUSE.toml


def _fichiers() -> list[str]:
    # meme perimetre que reuse lint : fichiers suivis et non suivis non ignores
    sortie = subprocess.run(  # noqa: S603 - git et options constantes, sans shell
        [  # noqa: S607 - git du PATH, comme la CI
            "git",
            "-C",
            str(RACINE),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
        check=True,
        capture_output=True,
    ).stdout
    noms = {os.fsdecode(n) for n in sortie.split(b"\0") if n}
    return sorted(n for n in noms if (RACINE / n).is_file())


def _code(nom: str) -> bool:
    return Path(nom).suffix in CODE and not nom.startswith(FIXTURES)


def _motif_reuse(glob: str) -> re.Pattern[str]:
    # specification REUSE 3.3 : « * » sans « / », « ** » avec, « \\* » litteral
    morceaux = re.split(r"(\\\*|\*\*|\*)", glob)
    traduction = {"\\*": re.escape("*"), "**": ".*", "*": "[^/]*"}
    return re.compile("".join(traduction.get(m, re.escape(m)) for m in morceaux))


def _couvert_par_reuse_toml(nom: str) -> bool:
    for annotation in REUSE["annotations"]:
        globs = annotation["path"]
        for glob in [globs] if isinstance(globs, str) else globs:
            if _motif_reuse(glob).fullmatch(nom):
                return True
    return False


def _en_tete_valide(texte: str) -> bool:
    lignes = texte.removeprefix("﻿").splitlines()
    if lignes and lignes[0].startswith("#!"):
        lignes = lignes[1:]
    # premier bloc de commentaires du fichier, avant la docstring ou le code
    bloc = list(itertools.takewhile(lambda ligne: ligne.startswith("#"), lignes))
    copyright = any(COPYRIGHT.fullmatch(ligne) for ligne in bloc)
    return copyright and bloc.count(IDENTIFIANT) == 1


@pytest.mark.parametrize(
    ("glob", "chemin", "attendu"),
    [
        ("**.md", "README.md", True),
        ("**.md", "docs/adr/0001-modele-de-licence.md", True),
        ("*.md", "docs/RELEASING.md", False),
        ("src/amnesia/templates/**", "src/amnesia/templates/html/base.html", True),
        ("**.toml", "src/amnesia/catalog/questions/windows.toml", True),
        ("**.lock", "src/amnesia/catalog/ids.lock", True),
        ("tests/golden/**", "tests/golden.md", False),
        ("a\\*b", "a*b", True),
        ("a\\*b", "axb", False),
    ],
)
def test_motifs_reuse(glob: str, chemin: str, attendu: bool) -> None:
    assert bool(_motif_reuse(glob).fullmatch(chemin)) is attendu


def test_en_tete_spdx_sur_chaque_fichier_de_code() -> None:
    code = [nom for nom in _fichiers() if _code(nom)]
    assert "noxfile.py" in code
    assert "scripts/verifier_dco.py" in code
    sans_en_tete = [
        nom for nom in code if not _en_tete_valide(_texte_brut(RACINE / nom))
    ]
    # en-tete attendu en tete de fichier : voir CONTRIBUTING.md, « En-tetes SPDX »
    assert not sans_en_tete


def _texte_brut(chemin: Path) -> str:
    return chemin.read_bytes().decode("utf-8-sig", errors="replace")


def test_en_tete_avec_shebang_ou_bom_accepte() -> None:
    en_tete = EXEMPLE
    assert _en_tete_valide(en_tete + '"""Doc."""\n')
    assert _en_tete_valide("#!/usr/bin/env python3\n" + en_tete)
    assert _en_tete_valide("﻿" + en_tete.replace("2026", "2026-2027"))
    # titulaire absent, identifiant en double ou apres le code : refuses
    assert not _en_tete_valide(f"{IDENTIFIANT}\n")
    assert not _en_tete_valide(en_tete.replace("2026 A", "2026"))
    assert not _en_tete_valide(en_tete.replace("\n\n", f"\n{IDENTIFIANT}\n"))
    assert not _en_tete_valide('"""Doc."""\n' + en_tete)


def test_reuse_toml_ne_couvre_aucun_fichier_de_code() -> None:
    # sinon reuse lint ne signalerait plus un en-tete oublie
    couverts = [
        nom for nom in _fichiers() if _code(nom) and _couvert_par_reuse_toml(nom)
    ]
    assert not couverts


def test_chaque_fichier_a_une_licence() -> None:
    # equivalent hors ligne de reuse lint (job CI reuse), pour un retour local
    sans_licence = []
    for nom in _fichiers():
        if nom in LICENCES or nom.startswith("LICENSES/"):
            continue
        if _couvert_par_reuse_toml(nom):
            continue
        texte = _texte_brut(RACINE / nom)
        if not all(etiquette in texte for etiquette in ETIQUETTES):
            sans_licence.append(nom)
    # en-tete SPDX (code) ou motif de REUSE.toml (donnees, documentation)
    assert not sans_licence


# Controles en CI


def test_job_reuse_requis() -> None:
    ci = _ci()
    commandes = [e.get("run") for e in ci["jobs"]["reuse"]["steps"]]
    assert "uv run --only-group ci reuse lint" in commandes
    assert "reuse" in ci["jobs"]["ci-ok"]["needs"]
    # version figee dans uv.lock, detection d'encodage sans libmagic
    (reuse,) = [e for e in PYPROJECT["dependency-groups"]["ci"] if "reuse" in e]
    assert re.fullmatch(r"reuse\[charset-normalizer\]==\d+(\.\d+)+", reuse)
    commandes_doc = _texte(RACINE / "CONTRIBUTING.md")
    assert "uv run --only-group ci reuse lint" in commandes_doc


def test_job_dco_requis_sur_les_pr() -> None:
    ci = _ci()
    job = ci["jobs"]["dco"]
    assert "dco" in ci["jobs"]["ci-ok"]["needs"]
    # le job tourne toujours (ci-ok exige success) ; seule l'etape est conditionnelle
    assert "if" not in job
    checkout, controle = job["steps"]
    assert checkout["with"]["fetch-depth"] == 0
    # exemptions limitees au proprietaire (titulaire) et a Dependabot
    assert " ".join(controle["if"].split()) == (
        "github.event_name == 'pull_request' "
        "&& github.event.pull_request.author_association != 'OWNER' "
        "&& github.event.pull_request.user.login != 'dependabot[bot]'"
    )
    # valeurs du contexte github passees par l'environnement, jamais dans run
    assert controle["env"] == {
        "BASE": "origin/${{ github.base_ref }}",
        "TETE": "${{ github.event.pull_request.head.sha }}",
    }
    assert controle["run"] == 'python3 scripts/verifier_dco.py -- "$BASE" "$TETE"'


def test_contributing_decrit_le_dco() -> None:
    texte = _texte(RACINE / "CONTRIBUTING.md")
    licence = texte.partition("## Licence des contributions")[2]
    for element in (
        f"]({ADR})",
        "](https://developercertificate.org/)",
        "git commit -s",
        "Signed-off-by",
        "job CI `dco`",
        "](scripts/verifier_dco.py)",
        "Dependabot",
        "job CI `reuse`",
        "](REUSE.toml)",
        "](LICENSES/MIT.txt)",
    ):
        assert element in licence, element
    # DCO retenu, pas de CLA (ADR 0001, « CLA ou DCO »)
    assert "aucun CLA" in " ".join(licence.split())
    assert "CLA Assistant" not in texte


def test_label_edition_commerciale_declare() -> None:
    labels = yaml.safe_load(_texte(RACINE / ".github" / "labels.yml"))["labels"]
    noms = {label["name"] for label in labels}
    assert "edition:commerciale" in noms
    assert "`edition:commerciale`" in _texte(RACINE / "CONTRIBUTING.md")
    assert "`edition:commerciale`" in _texte(RACINE / ADR)


# scripts/verifier_dco.py

# depots de test independants de la config git du developpeur (signature,
# hooksPath, autocrlf...)
GIT_HERMETIQUE = {
    **os.environ,
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}
AUTEUR = ("Alice Martin", "alice@example.org")


def _git(
    depot: Path, *args: str, auteur: tuple[str, str] = AUTEUR, check: bool = True
) -> int:
    nom, courriel = auteur
    return subprocess.run(  # noqa: S603 - git et arguments constants, sans shell
        ["git", "-C", str(depot), *args],  # noqa: S607 - git du PATH
        check=check,
        capture_output=True,
        env={
            **GIT_HERMETIQUE,
            "GIT_AUTHOR_NAME": nom,
            "GIT_AUTHOR_EMAIL": courriel,
            "GIT_COMMITTER_NAME": nom,
            "GIT_COMMITTER_EMAIL": courriel,
        },
    ).returncode


def _commit(
    depot: Path, *messages: str, auteur: tuple[str, str] = AUTEUR, signe: bool = False
) -> None:
    fichier = depot / "fichier.txt"
    ancien = fichier.read_text(encoding="utf-8") if fichier.exists() else ""
    fichier.write_text(ancien + "x\n", encoding="utf-8")
    _git(depot, "add", "fichier.txt", auteur=auteur)
    options = ["-s"] if signe else []
    paragraphes = [o for m in messages for o in ("-m", m)]
    _git(depot, "commit", "-q", "--no-verify", *options, *paragraphes, auteur=auteur)


@pytest.fixture
def depot(tmp_path: Path) -> Path:
    # main : historique non signe, deja publie ; pr : la branche a verifier
    depot = tmp_path / "depot"
    depot.mkdir()
    _git(depot, "init", "-q", "-b", "main")
    _commit(depot, "Commit de main, sans Signed-off-by")
    _git(depot, "switch", "-q", "-c", "pr")
    return depot


def _dco(depot: Path, base: str = "main", tete: str = "pr") -> tuple[int, str]:
    sortie = subprocess.run(  # noqa: S603 - interpreteur courant et script du depot
        [sys.executable, str(SCRIPT_DCO), "--depot", str(depot), "--", base, tete],
        capture_output=True,
        encoding="utf-8",
        check=False,
        env={**GIT_HERMETIQUE, "PYTHONIOENCODING": "utf-8"},
    )
    return sortie.returncode, sortie.stdout + sortie.stderr


def test_dco_commit_signe_par_git_commit_s(depot: Path) -> None:
    _commit(depot, "Premier", signe=True)
    _commit(depot, "Second", "Corps.", signe=True)
    code, sortie = _dco(depot)
    assert code == 0, sortie
    assert "2 commits verifies, 0 sans DCO" in sortie


def test_dco_commit_sans_signature_refuse(depot: Path) -> None:
    _commit(depot, "Signe", signe=True)
    _commit(depot, "Oublie", "Pas de trailer.")
    code, sortie = _dco(depot)
    assert code == 1
    assert sortie.count("::error::") == 1
    assert "Signed-off-by: Alice Martin <alice@example.org>" in sortie
    assert "2 commits verifies, 1 sans DCO" in sortie


@pytest.mark.parametrize(
    "signature",
    [
        # adresse d'un autre que l'auteur
        "Signed-off-by: Alice Martin <bob@example.org>",
        # sans nom ou sans adresse
        "Signed-off-by: <alice@example.org>",
        "Signed-off-by: Alice Martin",
        # autre trailer
        "Acked-by: Alice Martin <alice@example.org>",
    ],
)
def test_dco_signature_invalide_refusee(depot: Path, signature: str) -> None:
    _commit(depot, "Titre", signature)
    code, sortie = _dco(depot)
    assert code == 1, sortie
    assert "1 commits verifies, 1 sans DCO" in sortie


def test_dco_signature_hors_trailers_refusee(depot: Path) -> None:
    # au milieu du corps, la ligne n'est pas un trailer pour git
    _commit(depot, "Titre", "Signed-off-by: Alice Martin <alice@example.org>", "Fin.")
    code, _ = _dco(depot)
    assert code == 1


def test_dco_casse_de_l_adresse_ignoree_et_chaine_de_signatures(depot: Path) -> None:
    # commit repris par un autre (cherry-pick -s) : la signature de l'auteur suffit
    _commit(
        depot,
        "Titre",
        "Signed-off-by: Alice Martin <Alice@Example.ORG>\n"
        "Signed-off-by: Bob Durand <bob@example.org>",
    )
    code, sortie = _dco(depot)
    assert code == 0, sortie


def test_dco_ignore_main_et_les_fusions_propres(depot: Path) -> None:
    _commit(depot, "Contribution", signe=True)
    _git(depot, "switch", "-q", "main")
    _commit(depot, "Autre commit de main, sans Signed-off-by")
    _git(depot, "switch", "-q", "pr")
    # fusion de main sans signature, comme le bouton « Update branch »
    _git(depot, "merge", "-q", "--no-ff", "--no-verify", "-m", "Fusion de main", "main")
    code, sortie = _dco(depot)
    assert code == 0, sortie
    assert "1 commits verifies, 0 sans DCO" in sortie


def _ecrire(depot: Path, nom: str, contenu: str) -> None:
    (depot / nom).write_text(contenu, encoding="utf-8")
    _git(depot, "add", nom)


@pytest.mark.parametrize("signe", [False, True])
def test_dco_fusion_qui_ajoute_du_contenu_verifiee(depot: Path, signe: bool) -> None:
    # un petit commit signe, puis une fusion qui apporte un fichier absent de ses
    # deux parents : sans Signed-off-by, ce contenu entrerait sans attestation
    _commit(depot, "Contribution", signe=True)
    _git(depot, "switch", "-q", "main")
    _ecrire(depot, "main.txt", "main\n")
    _git(depot, "commit", "-q", "--no-verify", "-m", "Commit de main")
    _git(depot, "switch", "-q", "pr")
    _git(depot, "merge", "-q", "--no-ff", "--no-commit", "main")
    _ecrire(depot, "porte_derobee.py", "print('x')\n")
    options = ["-s"] if signe else []
    _git(depot, "commit", "-q", "--no-verify", *options, "-m", "Fusion de main")
    code, sortie = _dco(depot)
    assert code == (0 if signe else 1), sortie
    assert f"2 commits verifies, {0 if signe else 1} sans DCO" in sortie


def test_dco_conflit_resolu_a_la_main_verifie(depot: Path) -> None:
    _ecrire(depot, "fichier.txt", "branche\n")
    _git(depot, "commit", "-q", "--no-verify", "-s", "-m", "Contribution")
    _git(depot, "switch", "-q", "main")
    _ecrire(depot, "fichier.txt", "main\n")
    _git(depot, "commit", "-q", "--no-verify", "-m", "Commit de main")
    _git(depot, "switch", "-q", "pr")
    # conflit (code 1), resolu a la main puis valide sans Signed-off-by
    assert _git(depot, "merge", "-q", "main", check=False) == 1
    _ecrire(depot, "fichier.txt", "resolution\n")
    _git(depot, "commit", "-q", "--no-verify", "--no-edit")
    code, sortie = _dco(depot)
    assert code == 1, sortie
    assert "2 commits verifies, 1 sans DCO" in sortie


def test_dco_fusion_de_plus_de_deux_parents_verifiee(depot: Path) -> None:
    for branche in ("a", "b"):
        _git(depot, "switch", "-q", "-c", branche, "main")
        _ecrire(depot, f"{branche}.txt", f"{branche}\n")
        _git(depot, "commit", "-q", "--no-verify", "-s", "-m", f"Branche {branche}")
    _git(depot, "switch", "-q", "pr")
    _git(depot, "merge", "-q", "--no-ff", "--no-verify", "-m", "Pieuvre", "a", "b")
    code, sortie = _dco(depot)
    assert code == 1, sortie
    assert "3 commits verifies, 1 sans DCO" in sortie


@pytest.mark.parametrize("separateur", ["\u2028", "\x1c", "\x85", "\x0b"])
def test_dco_nom_d_auteur_avec_fin_de_ligne_unicode(
    depot: Path, separateur: str
) -> None:
    # str.splitlines() couperait le nom : sa fin deviendrait le courriel de
    # l'auteur, et le Signed-off-by d'Eve validerait un commit de la victime
    auteur = (f"Eve{separateur}eve@example.net", "victime@example.com")
    _commit(depot, "Titre", "Signed-off-by: Eve <eve@example.net>", auteur=auteur)
    code, sortie = _dco(depot)
    assert code == 1, sortie
    assert "1 commits verifies, 1 sans DCO" in sortie
    assert "<victime@example.com>" in sortie


def test_dco_plage_vide_refusee(depot: Path) -> None:
    code, sortie = _dco(depot, tete="main")
    assert code == 1
    assert "::error::aucun commit a verifier dans main..main" in sortie


def test_dco_revision_inconnue_ou_option_refusee(depot: Path, tmp_path: Path) -> None:
    _commit(depot, "Signe", signe=True)
    code, sortie = _dco(depot, base="inexistante")
    assert code == 1
    assert "::error::git a echoue" in sortie
    # --end-of-options : une TETE en forme d'option reste une revision
    cible = tmp_path / "injecte.txt"
    code, sortie = _dco(depot, tete=f"--output={cible}")
    assert code == 1
    assert not cible.exists()


def test_dco_commande_de_workflow_neutralisee() -> None:
    module = runpy.run_path(str(SCRIPT_DCO))
    neutralise = module["_commande_workflow"]("a%\r\n::warning::b")
    assert neutralise == "a%25%0D%0A::warning::b"
