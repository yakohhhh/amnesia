"""Textes accentues et sortie robuste a l'encodage (docs/dev/encodage.md)."""

import io
import os
import subprocess
import sys
from pathlib import Path

import pytest

from amnesia.checks import default_checks
from amnesia.cli import _proteger_sorties, main


def test_titres_accentues(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["list-checks"]) == 0
    sortie = capsys.readouterr().out
    assert "Politique d'audit avancée" in sortie
    assert "Synchronisation NTP (cohérence des horodatages)" in sortie


def test_aide_accentuee(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    assert "questions d'enquête" in capsys.readouterr().out


def test_titres_sans_mot_desaccentue() -> None:
    # mots dont la version sans accent a deja ete livree par erreur
    desaccentues = ("enquete", "avancee", "coherence", "retention")
    for check in default_checks():
        for mot in desaccentues:
            assert mot not in check.title.lower(), check.id


def _cli(
    tmp_path: Path, encodage: str, *args: str | bytes
) -> subprocess.CompletedProcess[bytes]:
    # sortie redirigee vers un pipe, comme « amnesia audit > rapport.txt » ;
    # -X warn_default_encoding -W error : un open() sans encoding casse aussi la CLI
    env = {**os.environ, "PYTHONIOENCODING": encodage}
    return subprocess.run(  # noqa: S603 - interpreteur courant, arguments constants
        [
            sys.executable,
            "-X",
            "warn_default_encoding",
            "-W",
            "error",
            "-m",
            "amnesia",
            *args,
        ],
        capture_output=True,
        check=False,
        cwd=tmp_path,
        env=env,
    )


@pytest.mark.parametrize("encodage", ["cp1252", "cp850"])
def test_sortie_redirigee_page_de_code(tmp_path: Path, encodage: str) -> None:
    # « → » vient de la CLI, « ’ » du nom du rapport ; absents de cp850, et
    # « → » absent de cp1252 : sans repli, UnicodeEncodeError. La cible est
    # validee en ASCII (#18) : le texte non ASCII passe par --out.
    # Cible .invalid (RFC 6761), jamais localhost : une fois les run()
    # implémentés, ce test auditerait sinon la machine qui l'execute.
    args = (
        "audit",
        "--target",
        "winrm://poste-essai.invalid",
        "--out",
        "rapport d’audit.json",
    )
    reference = _cli(tmp_path, "utf-8", *args)
    assert reference.returncode == 0, reference.stderr
    texte = reference.stdout.decode("utf-8")
    assert "→" in texte
    assert "’" in texte
    assert "enregistrés" in texte

    resultat = _cli(tmp_path, encodage, *args)
    assert resultat.returncode == 0
    assert resultat.stderr == b""
    assert resultat.stdout == texte.encode(encodage, errors="replace")
    assert "enregistrés" in resultat.stdout.decode(encodage)


@pytest.mark.parametrize("encodage", ["cp1252", "cp850"])
def test_aide_et_liste_redirigees_page_de_code(tmp_path: Path, encodage: str) -> None:
    for args in (["--help"], ["list-checks"]):
        resultat = _cli(tmp_path, encodage, *args)
        assert resultat.returncode == 0, args
        assert resultat.stderr == b"", args
        assert "é" in resultat.stdout.decode(encodage), args


@pytest.mark.skipif(sys.platform == "win32", reason="argv en octets : POSIX")
def test_argv_non_utf8_sortie_utf8(tmp_path: Path) -> None:
    # nom Latin-1 passe par un script : l'octet 0xff devient le surrogate
    # U+DCFF, que l'UTF-8 strict refuse
    # (la cible, validee en ASCII par #18, refuserait l'octet : il passe par --out)
    resultat = _cli(
        tmp_path,
        "utf-8:strict",
        "audit",
        "--target",
        "winrm://essai.invalid",
        "--out",
        b"a\xffb.json",
    )
    assert resultat.returncode == 0, resultat.stderr
    assert resultat.stderr == b""
    assert "→ a\\udcffb.json".encode() in resultat.stdout


@pytest.mark.parametrize(
    ("errors", "rapport", "attendu"),
    [
        # octet 0xff d'argv sous POSIX
        ("strict", "a\udcffb.json", b"a\\udcffb.json"),
        # surrogate isole d'un nom Windows en UTF-8 Mode, hors U+DC80..U+DCFF
        ("surrogateescape", "a\ud800b.json", b"a\\ud800b.json"),
    ],
)
def test_surrogate_en_sortie_utf8(
    monkeypatch: pytest.MonkeyPatch, errors: str, rapport: str, attendu: bytes
) -> None:
    sortie = _flux("utf-8", errors)
    monkeypatch.setattr(sys, "stdout", sortie)
    # le surrogate passe par --out : la cible est validee en ASCII (#18)
    cible = "winrm://essai.invalid"
    assert main(["audit", "--target", cible, "--out", rapport]) == 0
    sortie.flush()
    tampon = sortie.buffer
    assert isinstance(tampon, io.BytesIO)
    assert attendu in tampon.getvalue()


def _flux(encodage: str, errors: str) -> io.TextIOWrapper:
    return io.TextIOWrapper(io.BytesIO(), encoding=encodage, errors=errors)


@pytest.mark.parametrize(
    ("encodage", "errors", "attendu"),
    [
        ("cp1252", "strict", "replace"),
        ("cp850", "surrogateescape", "replace"),
        # stderr garde backslashreplace, deja sans crash et plus informatif
        ("cp1252", "backslashreplace", "backslashreplace"),
        # en UTF-8 seuls les surrogates echouent : rendus en \udcxx
        ("utf-8", "strict", "backslashreplace"),
        ("UTF8", "strict", "backslashreplace"),
        # UTF-8 Mode : surrogateescape plante sur un surrogate hors U+DC80..U+DCFF
        ("utf-8", "surrogateescape", "backslashreplace"),
        ("utf-8", "replace", "replace"),
    ],
)
def test_proteger_sorties(
    monkeypatch: pytest.MonkeyPatch, encodage: str, errors: str, attendu: str
) -> None:
    sortie, erreur = _flux(encodage, errors), _flux(encodage, errors)
    monkeypatch.setattr(sys, "stdout", sortie)
    monkeypatch.setattr(sys, "stderr", erreur)
    _proteger_sorties()
    assert (sortie.errors, erreur.errors) == (attendu, attendu)


def test_proteger_sorties_sans_flux(monkeypatch: pytest.MonkeyPatch) -> None:
    # pythonw : stdout et stderr valent None
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    _proteger_sorties()


@pytest.mark.parametrize("appel", ["open", "subprocess"])
def test_encoding_warning_est_une_erreur(tmp_path: Path, appel: str) -> None:
    # garde-fou de la suite : CI et nox posent PYTHONWARNDEFAULTENCODING=1 et
    # PYTEST_ADDOPTS="-W error::EncodingWarning"
    if not sys.flags.warn_default_encoding:
        raison = "PYTHONWARNDEFAULTENCODING=1 absent : voir docs/dev/encodage.md"
        if os.environ.get("CI"):
            pytest.fail(raison)
        pytest.skip(raison)
    with pytest.raises(EncodingWarning):
        if appel == "open":
            (tmp_path / "f.txt").write_text("x")  # encoding omis : volontaire
        else:
            subprocess.run(
                [sys.executable, "-c", "pass"],
                capture_output=True,
                text=True,  # encoding omis : volontaire
                check=False,
            )
