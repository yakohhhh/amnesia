# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""README et feuille de route alignés sur l'état réel (#32).

Le README est aussi la description publiée sur PyPI. Ces tests vérifient qu'il
ne promet que ce qui existe : ses commandes ``amnesia`` sont rejouées dans
l'ordre, comme dans un clone neuf, avec les codes de sortie qu'il annonce ; ses
liens sont absolus et désignent des fichiers présents ; ``docs/ROADMAP.md``
renvoie vers chaque milestone sans recopier les issues. La justesse du texte
reste jugée en revue.

Ce qu'un test ne peut pas rejouer hors ligne (``git clone``, ``uv sync``,
``pip install -e .``, syntaxe PowerShell) est vérifié à la main dans la PR.
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

import pytest
import yaml

from amnesia import exitcodes
from amnesia.checks import default_checks
from amnesia.cli import main

RACINE = Path(__file__).resolve().parent.parent
README = RACINE / "README.md"
ROADMAP = RACINE / "docs" / "ROADMAP.md"
MILESTONES = RACINE / ".github" / "milestones.yml"
DEPOT = "https://github.com/yakohhhh/amnesia"
BLOB = f"{DEPOT}/blob/main/"

# cible d'un lien en ligne [texte](cible), image d'un badge comprise
CIBLE = re.compile(r"\]\(\s*<?([^)\s>]+)")
LIEN_MILESTONE = re.compile(rf"\[([^\]]+)\]\({re.escape(DEPOT)}/milestone/(\d+)\)")
# critere de #32 : grep -nwiE "tu|ton|ta|tes|te|toi" README.md ; \b suit Unicode,
# « enquête » ne compte donc pas pour « te »
TUTOIEMENT = re.compile(r"\b(?:tu|ton|ta|tes|te|toi)\b", re.IGNORECASE)
# ligne d'un bloc de code qui lance amnesia avec au moins un argument
LANCE_AMNESIA = re.compile(r"\bamnesia[ \t]+\S")
# façons de lancer amnesia admises dans le README : tout ce qui suit est passé
# à la CLI
LANCEURS: tuple[tuple[str, ...], ...] = (
    ("uv", "run", "amnesia"),
    (".venv/bin/amnesia",),
    (".\\.venv\\Scripts\\amnesia",),
    ("PYTHONPATH=src", "python3", "-m", "amnesia"),
    ("py", "-m", "amnesia"),
    ("amnesia",),
)
NOMBRES = {1: "un", 2: "deux", 3: "trois", 4: "quatre", 5: "cinq", 6: "six"}


def _texte(fichier: Path) -> str:
    return fichier.read_text(encoding="utf-8")


def _sections(texte: str) -> dict[str, str]:
    # titres de niveau 2 hors blocs de code, corps aplati (les retours a la
    # ligne du Markdown coupent les expressions cherchees)
    sections: dict[str, list[str]] = {}
    courante: list[str] | None = None
    dans_code = False
    for ligne in texte.splitlines():
        if ligne.lstrip().startswith("```"):
            dans_code = not dans_code
        if not dans_code and ligne.startswith("## "):
            courante = sections.setdefault(ligne[3:].strip(), [])
        elif courante is not None:
            courante.append(ligne)
    return {
        titre: " ".join(" ".join(corps).split()) for titre, corps in sections.items()
    }


def _section(fichier: Path, titre: str) -> str:
    sections = _sections(_texte(fichier))
    assert titre in sections, f"{fichier.name} : section {titre!r} absente"
    return sections[titre]


def _blocs(texte: str) -> list[tuple[str, list[str]]]:
    """Blocs de code du document : (langage, lignes non vides)."""
    blocs: list[tuple[str, list[str]]] = []
    ouvert: tuple[str, list[str]] | None = None
    for ligne in texte.splitlines():
        if ligne.lstrip().startswith("```"):
            if ouvert is None:
                ouvert = (ligne.strip().removeprefix("```"), [])
            else:
                blocs.append(ouvert)
                ouvert = None
        elif ouvert is not None and ligne.strip():
            ouvert[1].append(ligne.strip())
    assert ouvert is None, "bloc de code non fermé"
    return blocs


def _arguments(ligne: str) -> list[str] | None:
    """Arguments passés à amnesia par ``ligne``, None si elle ne le lance pas."""
    # commentaire de fin de ligne retire ; aucun argument du README n'a de diese
    mots = ligne.partition("#")[0].split()
    for lanceur in LANCEURS:
        if tuple(mots[: len(lanceur)]) == lanceur:
            return mots[len(lanceur) :]
    return None


def _commandes() -> list[list[str]]:
    """Lignes de commande amnesia du README, dans l'ordre, sans doublon."""
    commandes: list[list[str]] = []
    for _, lignes in _blocs(_texte(README)):
        for ligne in lignes:
            if not LANCE_AMNESIA.search(ligne):
                continue
            arguments = _arguments(ligne)
            assert arguments is not None, f"lanceur inconnu de ce test : {ligne}"
            if arguments not in commandes:
                commandes.append(arguments)
    return commandes


def _milestones() -> list[dict[str, str]]:
    contenu = yaml.safe_load(_texte(MILESTONES))
    milestones: list[dict[str, str]] = contenu["milestones"]
    return milestones


# Commandes du README


def test_commandes_reconnues() -> None:
    # le test voit bien toutes les formes de lancement, variantes comprises
    commandes = _commandes()
    for attendue in (
        ["list-checks"],
        ["audit"],
        ["render", "amnesia-out/amnesia-report.json", "--format", "md"],
        ["render", "tests/fixtures/report-min.json"],
        ["--help"],
    ):
        assert attendue in commandes, attendue
    assert _arguments("cd amnesia") is None
    assert _arguments(".\\.venv\\Scripts\\amnesia --help") == ["--help"]
    assert _arguments("uv run amnesia audit  # commentaire") == ["audit"]


def test_commandes_rejouees_dans_l_ordre(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # clone neuf simule : repertoire vide (fixture autouse du conftest), ou seules
    # les fixtures du depot nommees par une commande sont recopiees
    audit_local = exitcodes.INCOMPLETE if sys.platform == "win32" else exitcodes.OK
    for arguments in _commandes():
        for argument in arguments:
            if argument.startswith("tests/fixtures/"):
                copie = tmp_path / argument
                copie.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(RACINE / argument, copie)
        if "--help" in arguments:
            with pytest.raises(SystemExit) as exc:
                main(arguments)
            code = exc.value.code
        else:
            code = main(arguments)
        attendu = audit_local if arguments[0] == "audit" else exitcodes.OK
        assert code == attendu, arguments
        capsys.readouterr()
    # l'audit a ecrit le rapport que la commande render suivante relit
    assert (tmp_path / "amnesia-out" / "amnesia-report.json").is_file()


def test_aucune_commande_sur_une_cible_distante() -> None:
    # la collecte distante (#63) et l'import de bundle (#52) n'existent pas : le
    # README ne lance que des audits locaux
    assert "dc01" not in _texte(README)
    for arguments in _commandes():
        for indice, argument in enumerate(arguments):
            if argument == "--target":
                assert arguments[indice + 1] == "local", arguments
            assert not argument.startswith(("--target=", "winrm:", "bundle:")), (
                arguments
            )


def test_sans_installation_depuis_les_sources() -> None:
    lignes = [ligne for _, bloc in _blocs(_texte(README)) for ligne in bloc]
    assert "PYTHONPATH=src python3 -m amnesia --help" in lignes
    assert '$env:PYTHONPATH = "src"' in lignes
    # -S : sans site-packages, donc sans l'installation editable de la suite de
    # tests ; seul PYTHONPATH=src, relatif a la racine, rend amnesia importable
    sortie = subprocess.run(
        # interpreteur courant et arguments constants, sans shell
        [sys.executable, "-S", "-m", "amnesia", "--help"],
        capture_output=True,
        cwd=RACINE,
        env={**os.environ, "PYTHONPATH": "src", "PYTHONIOENCODING": "utf-8"},
        encoding="utf-8",
        check=False,
        timeout=60,
    )
    assert sortie.returncode == 0, sortie.stderr
    assert sortie.stdout.startswith("usage: amnesia")


# Etat annonce


def test_etat_decrit_les_checks_enregistres(capsys: pytest.CaptureFixture[str]) -> None:
    # a mettre a jour avec le README des qu'un check est evalue ou ajoute
    etat = _section(README, "État")
    assert main(["list-checks"]) == exitcodes.OK
    lignes = capsys.readouterr().out.splitlines()
    assert len(lignes) == len(default_checks())
    assert all(" à implémenter " in ligne for ligne in lignes)
    assert all(ligne.split()[1] == "windows" for ligne in lignes)
    assert f"les {NOMBRES[len(lignes)]} checks Windows enregistrés" in etat
    assert "« à implémenter »" in etat
    assert "aucun angle mort" in etat
    # codes de sortie verifies par test_commandes_rejouees_dans_l_ordre
    assert (
        f"sous Windows, les {NOMBRES[len(lignes)]} checks sont « non exécutés »" in etat
    )
    assert f"code {exitcodes.INCOMPLETE} (audit incomplet)" in etat
    assert (
        f"sous Linux et macOS, ils sont « sans objet » et le code est {exitcodes.OK}"
        in etat
    )


def test_etat_renvoie_vers_les_milestones() -> None:
    etat = _section(README, "État")
    assert f"]({DEPOT}/milestones)" in etat
    assert f"]({BLOB}docs/ROADMAP.md)" in etat
    assert LIEN_MILESTONE.search(etat)


# Sections et ton


def test_section_vendable_retiree() -> None:
    # l'argumentaire commercial releve de l'offre (#90), pas de la description
    # du paquet ; le modele open core reste dans la section « Licence »
    assert "Vendable" not in _sections(_texte(README))


def test_scope_et_legal_renvoie_vers_les_tickets_de_garantie() -> None:
    scope = _section(README, "Scope & légal")
    assert "engagements de conception" in scope
    # perimetre autorise, allowlist de lecture seule, minimisation
    for ticket in (37, 39, 41):
        assert f"]({DEPOT}/issues/{ticket})" in scope, ticket


def test_aucun_tutoiement() -> None:
    assert TUTOIEMENT.search("Ce que ton SI aura oublié")
    assert not TUTOIEMENT.search("les questions d'enquête sans réponse")
    trouves = [
        f"README.md:{numero}: {ligne}"
        for numero, ligne in enumerate(_texte(README).splitlines(), start=1)
        if TUTOIEMENT.search(ligne)
    ]
    assert not trouves


# Liens


def test_liens_absolus_vers_des_fichiers_existants() -> None:
    # sur PyPI, un lien relatif ou une ancre pointe vers pypi.org
    cibles = CIBLE.findall(_texte(README))
    assert cibles
    assert not [cible for cible in cibles if not cible.startswith("https://")]
    fichiers = [c.removeprefix(BLOB) for c in cibles if c.startswith(BLOB)]
    assert fichiers
    for fichier in fichiers:
        chemin = unquote(fichier.partition("#")[0])
        assert (RACINE / chemin).is_file(), chemin


# Feuille de route


def test_roadmap_sans_liste_d_issues() -> None:
    texte = _texte(ROADMAP)
    assert "Créées automatiquement" not in texte
    assert "create-github-repo" not in texte
    # ni issue citee ni liste : les milestones GitHub sont la source unique
    assert not re.findall(r"#\d+", texte)
    assert not [
        ligne for ligne in texte.splitlines() if ligne.lstrip().startswith(("- ", "* "))
    ]
    assert f"]({DEPOT}/milestones)" in texte


def _numeros_de_la_roadmap() -> dict[str, int]:
    numeros: dict[str, int] = {}
    for titre, corps in _sections(_texte(ROADMAP)).items():
        (lien,) = LIEN_MILESTONE.findall(corps)
        numeros[titre] = int(lien[1])
    return numeros


def test_roadmap_renvoie_vers_chaque_milestone() -> None:
    milestones = _milestones()
    numeros = _numeros_de_la_roadmap()
    # une section par milestone declaree, dans le meme ordre
    assert list(numeros) == [m["title"] for m in milestones]
    # un numero de milestone GitHub par section, jamais le meme
    assert len(set(numeros.values())) == len(numeros)
    sections = _sections(_texte(ROADMAP))
    for milestone in milestones:
        version = re.match(r"Version (\d+\.\d+\.\d+) — ", milestone["description"])
        corps = sections[milestone["title"]]
        if version:
            assert f"version {version[1]}" in corps, milestone["title"]
        else:
            assert "sans version du paquet" in corps, milestone["title"]


def test_readme_et_roadmap_designent_les_memes_milestones() -> None:
    numeros = _numeros_de_la_roadmap()
    liens = LIEN_MILESTONE.findall(_texte(README))
    assert liens
    for libelle, numero in liens:
        # titre complet (« M1 — MVP (Windows + AD) ») ou abrege (« M1 »)
        titres = [t for t in numeros if t == libelle or t.startswith(f"{libelle} ")]
        assert len(titres) == 1, libelle
        assert numeros[titres[0]] == int(numero), libelle


def test_liens_relatifs_de_la_roadmap_existent() -> None:
    cibles = CIBLE.findall(_texte(ROADMAP))
    relatifs = [c for c in cibles if not c.startswith("https://")]
    assert relatifs
    for cible in relatifs:
        assert (ROADMAP.parent / cible.partition("#")[0]).is_file(), cible
