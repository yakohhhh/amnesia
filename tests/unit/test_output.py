# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Ecriture securisee des livrables (#25) : droits, atomicite, liens, git.

Le repertoire courant est tmp_path (conftest) : le dossier par defaut
amnesia-out/ y est cree, jamais dans le depot.
"""

from __future__ import annotations

import errno
import logging
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from amnesia import cli, exitcodes, output
from amnesia.cli import main
from amnesia.output import (
    DEFAULT_DIR,
    DEFAULT_REPORT,
    GITIGNORE,
    UnsafeDestinationError,
    git_repository,
    prepare_default_dir,
    warn_if_not_ignored,
    write_private,
)
from amnesia.runner import run_audit

GIT = shutil.which("git")
avec_git = pytest.mark.skipif(GIT is None, reason="git absent du PATH")
posix = pytest.mark.skipif(sys.platform == "win32", reason="droits POSIX")

# registre factice du conftest : un Gap high, donc code 1
CODE_AUDIT_FACTICE = exitcodes.GAPS


def _mode(chemin: Path) -> int:
    return stat.S_IMODE(chemin.stat().st_mode)


def _temporaires(dossier: Path) -> list[str]:
    return [p.name for p in dossier.iterdir() if p.name.startswith(".amnesia-")]


def _lien(lien: Path, cible: Path) -> None:
    try:
        lien.symlink_to(cible)
    except (OSError, NotImplementedError):
        pytest.skip("liens symboliques indisponibles")


@pytest.fixture
def umask_022() -> Iterator[None]:
    ancien = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(ancien)


# --- droits POSIX -----------------------------------------------------------


@posix
@pytest.mark.usefixtures("registre_factice", "umask_022")
def test_umask_022_rapport_0600_dossier_0700(tmp_path: Path) -> None:
    assert main(["audit"]) == CODE_AUDIT_FACTICE
    dossier = tmp_path / DEFAULT_DIR
    assert _mode(dossier) == 0o700
    assert _mode(dossier / DEFAULT_REPORT) == 0o600
    assert _mode(dossier / ".gitignore") == 0o600


@posix
@pytest.mark.usefixtures("registre_factice", "umask_022")
def test_umask_022_out_explicite_0600(tmp_path: Path) -> None:
    rapport = tmp_path / "r.json"
    assert main(["audit", "--out", str(rapport)]) == CODE_AUDIT_FACTICE
    assert _mode(rapport) == 0o600
    # --out explicite : ni amnesia-out/ ni temporaire
    assert [p.name for p in tmp_path.iterdir()] == ["r.json"]


@posix
@pytest.mark.parametrize("masque", [0o000, 0o022, 0o077, 0o277])
def test_droits_quel_que_soit_l_umask(tmp_path: Path, masque: int) -> None:
    ancien = os.umask(masque)
    try:
        dossier = tmp_path / DEFAULT_DIR
        prepare_default_dir(dossier)
        write_private(dossier / "r.json", b"{}\n")
    finally:
        os.umask(ancien)
    assert _mode(dossier) == 0o700
    assert _mode(dossier / "r.json") == 0o600
    assert _mode(dossier / ".gitignore") == 0o600


@posix
def test_dossier_existant_ramene_en_0700(tmp_path: Path) -> None:
    dossier = tmp_path / DEFAULT_DIR
    dossier.mkdir()
    dossier.chmod(0o755)
    prepare_default_dir(dossier)
    assert _mode(dossier) == 0o700


@posix
def test_dossier_existant_droits_refuses_signales(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger="amnesia.output")
    dossier = tmp_path / DEFAULT_DIR
    dossier.mkdir()
    dossier.chmod(0o755)

    def refus(self: Path, mode: int) -> None:
        raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(Path, "chmod", refus)
    # pas bloquant : le dossier reste utilisable, l'auditeur est prevenu
    prepare_default_dir(dossier)
    assert "droits 0700 impossibles à appliquer" in caplog.text
    assert (dossier / ".gitignore").read_bytes() == GITIGNORE


@posix
def test_remplacement_force_rend_un_fichier_0600(tmp_path: Path) -> None:
    rapport = tmp_path / "r.json"
    rapport.write_bytes(b"ancien")
    rapport.chmod(0o644)
    write_private(rapport, b"nouveau", force=True)
    assert rapport.read_bytes() == b"nouveau"
    assert _mode(rapport) == 0o600


@posix
def test_fchmod_refuse_signale_sans_bloquer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # FAT, exFAT, partage SMB : aucun droit POSIX a appliquer
    caplog.set_level(logging.WARNING, logger="amnesia.output")

    def refus(fd: int, mode: int) -> None:
        raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "fchmod", refus)
    write_private(tmp_path / "r.json", b"{}\n")
    assert (tmp_path / "r.json").read_bytes() == b"{}\n"
    assert "droits 0600 impossibles à appliquer" in caplog.text
    assert _temporaires(tmp_path) == []


# --- emplacement par defaut -------------------------------------------------


@pytest.mark.usefixtures("registre_factice")
def test_sans_out_rapport_dans_amnesia_out(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["audit"]) == CODE_AUDIT_FACTICE
    dossier = tmp_path / DEFAULT_DIR
    assert [p.name for p in tmp_path.iterdir()] == [DEFAULT_DIR]
    assert sorted(p.name for p in dossier.iterdir()) == [".gitignore", DEFAULT_REPORT]
    assert (dossier / ".gitignore").read_bytes() == b"*\n"
    assert (dossier / DEFAULT_REPORT).read_bytes().startswith(b"{")
    assert capsys.readouterr().err == ""


@pytest.mark.usefixtures("registre_factice")
def test_sans_out_rapport_existant_code_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["audit"]) == CODE_AUDIT_FACTICE
    rapport = tmp_path / DEFAULT_DIR / DEFAULT_REPORT
    avant = rapport.read_bytes()
    capsys.readouterr()
    with pytest.raises(SystemExit) as exc:
        main(["audit"])
    assert exc.value.code == exitcodes.USAGE
    assert "existe déjà (--overwrite pour l'écraser)" in capsys.readouterr().err
    assert rapport.read_bytes() == avant
    assert main(["audit", "--overwrite"]) == CODE_AUDIT_FACTICE


def test_gitignore_existant_jamais_reecrit(tmp_path: Path) -> None:
    dossier = tmp_path / DEFAULT_DIR
    dossier.mkdir()
    (dossier / ".gitignore").write_bytes(b"*.json\n")
    prepare_default_dir(dossier)
    assert (dossier / ".gitignore").read_bytes() == b"*.json\n"


@pytest.mark.usefixtures("registre_factice")
def test_dossier_par_defaut_occupe_par_un_fichier_code_4(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / DEFAULT_DIR).write_bytes(b"")
    assert main(["audit"]) == exitcodes.FATAL
    assert "création impossible" in capsys.readouterr().err
    assert (tmp_path / DEFAULT_DIR).read_bytes() == b""


def test_dossier_par_defaut_occupe_par_un_lien_casse(tmp_path: Path) -> None:
    dossier = tmp_path / DEFAULT_DIR
    _lien(dossier, tmp_path / "absent")
    with pytest.raises(NotADirectoryError):
        prepare_default_dir(dossier)
    assert not (tmp_path / "absent").exists()


# --- non-ecrasement ---------------------------------------------------------


def test_fichier_existant_refuse_contenu_inchange(tmp_path: Path) -> None:
    rapport = tmp_path / "r.json"
    rapport.write_bytes(b"ancien")
    with pytest.raises(FileExistsError):
        write_private(rapport, b"nouveau")
    assert rapport.read_bytes() == b"ancien"
    assert _temporaires(tmp_path) == []


def test_force_remplace_le_fichier(tmp_path: Path) -> None:
    rapport = tmp_path / "r.json"
    rapport.write_bytes(b"ancien")
    write_private(rapport, b"nouveau", force=True)
    assert rapport.read_bytes() == b"nouveau"
    assert _temporaires(tmp_path) == []


def test_dossier_a_la_destination_jamais_remplace(tmp_path: Path) -> None:
    dossier = tmp_path / "r.json"
    dossier.mkdir()
    with pytest.raises(FileExistsError):
        write_private(dossier, b"{}")
    with pytest.raises(OSError) as exc:
        write_private(dossier, b"{}", force=True)
    assert not isinstance(exc.value, FileExistsError | UnsafeDestinationError)
    assert dossier.is_dir()
    assert _temporaires(tmp_path) == []


def _audit_puis(action: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fait executer ``action`` par la CLI juste apres l'audit, avant l'ecriture."""

    def audit(*args: Any, **kwargs: Any) -> Any:
        resultat = run_audit(*args, **kwargs)
        action()
        return resultat

    monkeypatch.setattr(cli, "run_audit", audit)


@pytest.mark.usefixtures("registre_factice")
def test_fichier_apparu_pendant_l_audit_code_2(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rapport = tmp_path / "r.json"
    _audit_puis(lambda: rapport.write_bytes(b"ancien"), monkeypatch)
    # le test avant l'audit passe ; la publication, atomique, refuse ensuite
    assert main(["audit", "--out", str(rapport)]) == exitcodes.USAGE
    assert rapport.read_bytes() == b"ancien"
    erreur = capsys.readouterr().err
    assert "existe déjà (--overwrite pour l'écraser)" in erreur
    assert "rapport non écrit" in erreur
    assert [p.name for p in tmp_path.iterdir()] == ["r.json"]


# --- liens symboliques ------------------------------------------------------


@pytest.mark.parametrize("force", [False, True])
def test_lien_vers_un_fichier_refuse_cible_intacte(tmp_path: Path, force: bool) -> None:
    cible = tmp_path / "victime.txt"
    cible.write_bytes(b"SECRET\n")
    lien = tmp_path / "r.json"
    _lien(lien, cible)
    with pytest.raises(UnsafeDestinationError, match="lien symbolique refusé"):
        write_private(lien, b"{}", force=force)
    assert cible.read_bytes() == b"SECRET\n"
    assert lien.is_symlink()
    assert _temporaires(tmp_path) == []


@pytest.mark.parametrize("force", [False, True])
def test_lien_casse_refuse_rien_cree(tmp_path: Path, force: bool) -> None:
    cible = tmp_path / "ailleurs.json"
    lien = tmp_path / "r.json"
    _lien(lien, cible)
    with pytest.raises(UnsafeDestinationError):
        write_private(lien, b"{}", force=force)
    assert not cible.exists()
    assert _temporaires(tmp_path) == []


def test_lien_vers_un_dossier_refuse(tmp_path: Path) -> None:
    ailleurs = tmp_path / "ailleurs"
    ailleurs.mkdir()
    lien = tmp_path / "r.json"
    try:
        lien.symlink_to(ailleurs, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("liens symboliques indisponibles")
    with pytest.raises(UnsafeDestinationError):
        write_private(lien, b"{}", force=True)
    assert list(ailleurs.iterdir()) == []


@pytest.mark.usefixtures("registre_factice")
def test_lien_apparu_pendant_l_audit_code_2(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cible = tmp_path / "victime.txt"
    cible.write_bytes(b"SECRET\n")
    lien = tmp_path / "r.json"
    # sonde : saute le test si les liens symboliques sont indisponibles
    _lien(lien, cible)
    lien.unlink()
    _audit_puis(lambda: lien.symlink_to(cible), monkeypatch)
    assert main(["audit", "--out", str(lien), "--overwrite"]) == exitcodes.USAGE
    assert "lien symbolique refusé" in capsys.readouterr().err
    assert cible.read_bytes() == b"SECRET\n"
    assert lien.is_symlink()


def test_lien_physique_remplace_avec_force_cible_intacte(tmp_path: Path) -> None:
    cible = tmp_path / "victime.txt"
    cible.write_bytes(b"SECRET\n")
    lien = tmp_path / "r.json"
    try:
        lien.hardlink_to(cible)
    except (OSError, NotImplementedError):
        pytest.skip("liens physiques indisponibles")
    with pytest.raises(FileExistsError):
        write_private(lien, b"{}")
    # force remplace l'entree, jamais le contenu partage avec l'autre nom
    write_private(lien, b"{}", force=True)
    assert cible.read_bytes() == b"SECRET\n"
    assert lien.read_bytes() == b"{}"


# --- atomicite --------------------------------------------------------------


def _ecriture_interrompue(exception: BaseException) -> Any:
    def ecrire(fd: int, data: bytes) -> None:
        # une partie du contenu est deja sur le disque quand l'erreur survient
        os.write(fd, data[:5])
        raise exception

    return ecrire


@pytest.mark.parametrize("force", [False, True])
def test_erreur_pendant_l_ecriture_rien_ne_reste(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, force: bool
) -> None:
    rapport = tmp_path / "r.json"
    monkeypatch.setattr(
        output,
        "_ecrire_tout",
        _ecriture_interrompue(OSError(errno.ENOSPC, "plus de place")),
    )
    with pytest.raises(OSError, match="plus de place"):
        write_private(rapport, b'{"partiel": true}\n', force=force)
    assert list(tmp_path.iterdir()) == []


def test_erreur_pendant_l_ecriture_ancien_fichier_intact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    rapport = tmp_path / "r.json"
    rapport.write_bytes(b"ancien")
    monkeypatch.setattr(
        output, "_ecrire_tout", _ecriture_interrompue(OSError(errno.EIO, "E/S"))
    )
    with pytest.raises(OSError, match="E/S"):
        write_private(rapport, b"nouveau", force=True)
    assert rapport.read_bytes() == b"ancien"
    assert _temporaires(tmp_path) == []


def test_fsync_en_echec_rien_ne_reste(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def echec(fd: int) -> None:
        raise OSError(errno.EIO, "E/S")

    monkeypatch.setattr(os, "fsync", echec)
    with pytest.raises(OSError, match="E/S"):
        write_private(tmp_path / "r.json", b"{}")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.usefixtures("registre_factice")
def test_cli_erreur_pendant_l_ecriture_code_4_rien_ne_reste(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        output,
        "_ecrire_tout",
        _ecriture_interrompue(OSError(errno.ENOSPC, "plus de place")),
    )
    assert main(["audit", "--out", str(tmp_path / "r.json")]) == exitcodes.FATAL
    assert "écriture impossible : plus de place" in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == []


@pytest.mark.usefixtures("registre_factice")
def test_cli_ctrl_c_pendant_l_ecriture_code_130_rien_ne_reste(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # apres l'audit : le .gitignore du dossier par defaut est deja ecrit
    _audit_puis(
        lambda: monkeypatch.setattr(
            output, "_ecrire_tout", _ecriture_interrompue(KeyboardInterrupt())
        ),
        monkeypatch,
    )
    assert main(["audit"]) == exitcodes.INTERRUPTED
    # le dossier par defaut est prepare avant l'audit ; rien d'autre n'y reste
    dossier = tmp_path / DEFAULT_DIR
    assert [p.name for p in dossier.iterdir()] == [".gitignore"]


def test_noms_temporaires_epuises_pas_file_exists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(secrets, "token_hex", lambda n: "0" * 2 * n)
    (tmp_path / ".amnesia-0000000000000000.tmp").write_bytes(b"")
    # FileExistsError dirait a tort que la destination existe
    with pytest.raises(OSError, match="aucun nom de fichier temporaire") as exc:
        write_private(tmp_path / "r.json", b"{}")
    assert not isinstance(exc.value, FileExistsError)
    assert not (tmp_path / "r.json").exists()


def test_dossier_de_destination_absent(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        write_private(tmp_path / "absent" / "r.json", b"{}")
    assert list(tmp_path.iterdir()) == []


# --- publication sans lien physique (POSIX) ---------------------------------


@posix
@pytest.mark.parametrize("code", [errno.EPERM, errno.ENOTSUP])
def test_sans_lien_physique_repli_exclusif(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, code: int
) -> None:
    def refus(self: Path, cible: Path) -> None:
        raise OSError(code, os.strerror(code))

    # FAT, exFAT, certains partages : os.link refuse
    monkeypatch.setattr(Path, "hardlink_to", refus)
    rapport = tmp_path / "r.json"
    write_private(rapport, b"{}\n")
    assert rapport.read_bytes() == b"{}\n"
    assert _mode(rapport) == 0o600
    assert _temporaires(tmp_path) == []
    with pytest.raises(FileExistsError):
        write_private(rapport, b"nouveau")
    assert rapport.read_bytes() == b"{}\n"
    assert _temporaires(tmp_path) == []


@posix
def test_sans_lien_physique_erreur_rien_ne_reste(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def refus(self: Path, cible: Path) -> None:
        raise OSError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(Path, "hardlink_to", refus)
    vrai = output._ecrire_tout
    appels: list[int] = []

    def deuxieme_en_echec(fd: int, data: bytes) -> None:
        appels.append(fd)
        if len(appels) == 1:
            vrai(fd, data)
        else:
            _ecriture_interrompue(OSError(errno.ENOSPC, "plus de place"))(fd, data)

    monkeypatch.setattr(output, "_ecrire_tout", deuxieme_en_echec)
    with pytest.raises(OSError, match="plus de place"):
        write_private(tmp_path / "r.json", b'{"partiel": true}\n')
    assert list(tmp_path.iterdir()) == []


@posix
def test_lien_physique_autre_erreur_propagee(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def refus(self: Path, cible: Path) -> None:
        raise OSError(errno.EIO, "E/S")

    monkeypatch.setattr(Path, "hardlink_to", refus)
    with pytest.raises(OSError, match="E/S"):
        write_private(tmp_path / "r.json", b"{}")
    assert list(tmp_path.iterdir()) == []


@posix
def test_temporaire_non_supprime_apres_publication_signale(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger="amnesia.output")
    vrai = Path.unlink

    def unlink(self: Path, missing_ok: bool = False) -> None:
        if self.name.startswith(".amnesia-"):
            raise PermissionError(errno.EACCES, "Permission denied")
        vrai(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", unlink)
    # le livrable est publie et complet : pas d'erreur, un avertissement
    write_private(tmp_path / "r.json", b"{}")
    assert (tmp_path / "r.json").read_bytes() == b"{}"
    assert "non supprimé" in caplog.text


# --- depot git --------------------------------------------------------------


def _git(depot: Path, *args: str) -> str:
    assert GIT is not None
    resultat = subprocess.run(  # noqa: S603 - git par chemin absolu, arguments du test
        [GIT, "-C", str(depot), *args],
        capture_output=True,
        check=True,
        timeout=60,
    )
    return resultat.stdout.decode("utf-8", "replace")


@pytest.fixture
def depot_git(
    tmp_path: Path,
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Depot git vide dans tmp_path (repertoire courant), sans la config du poste."""
    # configuration globale propre au test, hors du depot (elle y serait non
    # suivie) ; safe.directory : sous Windows, un compte administrateur peut
    # creer des dossiers dont le proprietaire est le groupe Administrateurs
    config = tmp_path_factory.mktemp("config-git") / "gitconfig"
    config.write_bytes(b"[safe]\n\tdirectory = *\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for nom in list(os.environ):
        if nom.upper() in {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"}:
            monkeypatch.delenv(nom)
    _git(tmp_path, "init", "-q")
    return tmp_path


@avec_git
@pytest.mark.usefixtures("registre_factice")
def test_depot_git_rapport_par_defaut_invisible(
    depot_git: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["audit"]) == CODE_AUDIT_FACTICE
    assert (depot_git / DEFAULT_DIR / DEFAULT_REPORT).is_file()
    assert _git(depot_git, "status", "--porcelain", "--untracked-files=all") == ""
    assert "dépôt git" not in capsys.readouterr().err


@avec_git
@pytest.mark.usefixtures("registre_factice")
def test_depot_git_destination_non_ignoree_avertie(
    depot_git: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["audit", "--out", "client.json"]) == CODE_AUDIT_FACTICE
    erreur = capsys.readouterr().err
    assert "client.json : dans le dépôt git" in erreur
    assert "sans y être ignoré" in erreur
    assert "WARNING" in erreur
    # temoin : git voit bien le rapport
    assert "client.json" in _git(depot_git, "status", "--porcelain")


@avec_git
@pytest.mark.usefixtures("registre_factice")
def test_depot_git_destination_ignoree_sans_avertissement(
    depot_git: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (depot_git / ".gitignore").write_bytes(b"/rapports/\n")
    (depot_git / "rapports").mkdir()
    rapport = depot_git / "rapports" / "client.json"
    assert main(["audit", "--out", str(rapport)]) == CODE_AUDIT_FACTICE
    assert "dépôt git" not in capsys.readouterr().err


@avec_git
def test_depot_git_invalide_avertit(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger="amnesia.output")
    # .git vide : git check-ignore echoue (128), rien n'est verifie
    (tmp_path / ".git").mkdir()
    assert warn_if_not_ignored(tmp_path / "r.json")
    assert "git indisponible ou en échec" in caplog.text


def test_hors_depot_git_ni_avertissement_ni_git(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    def interdit(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("git lancé hors d'un dépôt")

    monkeypatch.setattr(subprocess, "run", interdit)
    caplog.set_level(logging.WARNING, logger="amnesia.output")
    # tmp_path n'est dans aucun depot : la recherche s'arrete a la racine
    assert git_repository(tmp_path / "r.json") is None
    assert not warn_if_not_ignored(tmp_path / "r.json")
    assert caplog.text == ""


def test_parent_illisible_pas_de_depot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def refus(self: Path) -> bool:
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(Path, "exists", refus)
    assert git_repository(tmp_path / "r.json") is None


@pytest.mark.usefixtures("registre_factice")
def test_destination_illisible_code_4_avant_l_audit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def refus(self: Path) -> bool:
        raise PermissionError(errno.EACCES, "Permission denied")

    def interdit(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("audit lancé malgré une destination illisible")

    monkeypatch.setattr(Path, "is_symlink", refus)
    monkeypatch.setattr(cli, "run_audit", interdit)
    assert main(["audit", "--out", str(tmp_path / "r.json")]) == exitcodes.FATAL
    assert "écriture impossible : Permission denied" in capsys.readouterr().err


def test_racine_trouvee_par_un_fichier_git(tmp_path: Path) -> None:
    # worktree ou sous-module : .git est un fichier
    (tmp_path / ".git").write_bytes(b"gitdir: ailleurs\n")
    (tmp_path / "a" / "b").mkdir(parents=True)
    assert git_repository(tmp_path / "a" / "b" / "r.json") == tmp_path.resolve()


@pytest.mark.parametrize("trouve", [None, "git"], ids=["absent", "relatif"])
def test_git_indisponible_avertit_sauf_gitignore_d_amnesia(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    trouve: str | None,
) -> None:
    # « git » relatif : trouve dans le repertoire courant (Windows), jamais lance
    monkeypatch.setattr(shutil, "which", lambda nom: trouve)
    caplog.set_level(logging.WARNING, logger="amnesia.output")
    (tmp_path / ".git").mkdir()
    assert warn_if_not_ignored(tmp_path / "r.json")
    assert "git indisponible ou en échec" in caplog.text
    caplog.clear()
    dossier = tmp_path / DEFAULT_DIR
    prepare_default_dir(dossier)
    assert not warn_if_not_ignored(dossier / DEFAULT_REPORT)
    assert caplog.text == ""


def test_git_bloque_avertit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    def delai(*args: Any, **kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired("git", 10)

    monkeypatch.setattr(shutil, "which", lambda nom: str(tmp_path / "git"))
    monkeypatch.setattr(subprocess, "run", delai)
    caplog.set_level(logging.WARNING, logger="amnesia.output")
    (tmp_path / ".git").mkdir()
    assert warn_if_not_ignored(tmp_path / "r.json")
    assert "git indisponible ou en échec" in caplog.text


def test_git_lance_sans_fsmonitor_ni_depot_de_l_environnement(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    appels: list[tuple[list[str], dict[str, str]]] = []

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        appels.append((argv, kwargs["env"]))
        return subprocess.CompletedProcess(argv, 1)

    faux_git = str(tmp_path / "bin" / "git")
    monkeypatch.setattr(shutil, "which", lambda nom: faux_git)
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "autre"))
    (tmp_path / ".git").mkdir()
    (tmp_path / "sous").mkdir()
    assert warn_if_not_ignored(tmp_path / "sous" / "r.json")
    ((argv, env),) = appels
    assert argv[:3] == [faux_git, "-c", "core.fsmonitor=false"]
    assert argv[-3:] == ["-q", "--", "sous/r.json"]
    assert "GIT_DIR" not in env
    # environnement de subprocess_env() : telemetrie coupee (#26)
    assert env["POWERSHELL_TELEMETRY_OPTOUT"] == "1"


# --- ACL Windows ------------------------------------------------------------

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    _noyau = ctypes.WinDLL("kernel32", use_last_error=True)
    _GetNamedSecurityInfoW = _advapi.GetNamedSecurityInfoW
    _GetNamedSecurityInfoW.argtypes = (
        wintypes.LPCWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    )
    _GetNamedSecurityInfoW.restype = wintypes.DWORD
    _VersSddl = _advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW
    _VersSddl.argtypes = (
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG),
    )
    _VersSddl.restype = wintypes.BOOL
    _SidBinaire = _advapi.ConvertStringSidToSidW
    _SidBinaire.argtypes = (wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p))
    _SidBinaire.restype = wintypes.BOOL
    _SidTexte = _advapi.ConvertSidToStringSidW
    _SidTexte.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
    _SidTexte.restype = wintypes.BOOL
    _LocalFree = _noyau.LocalFree
    _LocalFree.argtypes = (ctypes.c_void_p,)
    _LocalFree.restype = ctypes.c_void_p

    _SE_FILE_OBJECT = 1
    _DACL_SECURITY_INFORMATION = 4
    _SDDL_REVISION_1 = 1

    def _chaine(pointeur: ctypes.c_void_p) -> str:
        adresse = pointeur.value
        assert adresse is not None
        try:
            return ctypes.wstring_at(adresse)
        finally:
            _LocalFree(pointeur)

    def _dacl_sddl(chemin: Path) -> str:
        """DACL de ``chemin`` en SDDL, lue par l'API et non par icacls (localise)."""
        descripteur = ctypes.c_void_p()
        code = _GetNamedSecurityInfoW(
            str(chemin),
            _SE_FILE_OBJECT,
            _DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            ctypes.byref(descripteur),
        )
        if code:
            raise ctypes.WinError(code)
        try:
            texte = ctypes.c_void_p()
            if not _VersSddl(
                descripteur,
                _SDDL_REVISION_1,
                _DACL_SECURITY_INFORMATION,
                ctypes.byref(texte),
                None,
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            return _chaine(texte)
        finally:
            _LocalFree(descripteur)

    def _sid_canonique(sid: str) -> str:
        """``S-1-…`` d'un SID ou d'un alias SDDL (``LA``, ``BA``…)."""
        binaire = ctypes.c_void_p()
        if not _SidBinaire(sid, ctypes.byref(binaire)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            texte = ctypes.c_void_p()
            if not _SidTexte(binaire, ctypes.byref(texte)):
                raise ctypes.WinError(ctypes.get_last_error())
            return _chaine(texte)
        finally:
            _LocalFree(binaire)

    def _sid_whoami() -> str:
        """SID du compte courant selon whoami : source indépendante d'amnesia."""
        whoami = shutil.which("whoami")
        assert whoami is not None
        sortie = subprocess.run(  # noqa: S603 - outil systeme par chemin absolu
            [whoami, "/user", "/fo", "csv", "/nh"],
            capture_output=True,
            check=True,
            timeout=60,
        ).stdout
        trouves: list[bytes] = re.findall(rb"S-1-[0-9-]+", sortie)
        (sid,) = trouves
        return sid.decode("ascii")

    def _verifier_acl_privee(chemin: Path, drapeaux: str) -> None:
        sddl = _dacl_sddl(chemin)
        trouve = re.fullmatch(r"D:([A-Z]*)((?:\([^)]*\))+)", sddl)
        assert trouve is not None, sddl
        # P : DACL protegee, aucun heritage du dossier parent
        assert "P" in trouve.group(1), sddl
        aces = re.findall(r"\(([^)]*)\)", trouve.group(2))
        assert len(aces) == 1, sddl
        type_ace, heritage, droits, _, _, sid = aces[0].split(";")
        assert (type_ace, heritage, droits) == ("A", drapeaux, "FA"), sddl
        assert _sid_canonique(sid) == _sid_whoami(), sddl


@pytest.mark.windows
@pytest.mark.usefixtures("registre_factice")
def test_windows_acl_compte_courant_seul_sans_heritage(tmp_path: Path) -> None:
    assert main(["audit"]) == CODE_AUDIT_FACTICE
    dossier = tmp_path / DEFAULT_DIR
    # if et non skip : mypy n'analyse ces fonctions que sous Windows
    if sys.platform == "win32":
        _verifier_acl_privee(dossier / DEFAULT_REPORT, "")
        _verifier_acl_privee(dossier / ".gitignore", "")
        # OICI : ce qui sera cree dans le dossier herite de cette seule ACE
        _verifier_acl_privee(dossier, "OICI")


@pytest.mark.windows
@pytest.mark.usefixtures("registre_factice")
def test_windows_acl_out_explicite_et_remplacement(tmp_path: Path) -> None:
    # tmp_path porte l'ACL heritee du profil : le rapport ne doit pas l'avoir
    rapport = tmp_path / "r.json"
    assert main(["audit", "--out", str(rapport)]) == CODE_AUDIT_FACTICE
    if sys.platform == "win32":
        _verifier_acl_privee(rapport, "")
    assert main(["audit", "--out", str(rapport), "--overwrite"]) == (CODE_AUDIT_FACTICE)
    if sys.platform == "win32":
        _verifier_acl_privee(rapport, "")
    assert _temporaires(tmp_path) == []
