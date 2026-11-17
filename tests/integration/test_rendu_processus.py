"""amnesia render en vrai processus : sortie redirigée en page de code (#23)."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "report-min.json"


def _rendre(
    tmp_path: Path, encodage: str, *args: str
) -> tuple[subprocess.CompletedProcess[bytes], bytes]:
    # stdout redirige vers un fichier, comme « amnesia render ... > out.txt » ;
    # -X warn_default_encoding -W error : un open() sans encoding casse la CLI
    sortie = tmp_path / "out.txt"
    env = {**os.environ, "PYTHONIOENCODING": encodage}
    with sortie.open("wb") as fichier:
        processus = subprocess.run(  # noqa: S603 - interpreteur courant
            [
                sys.executable,
                "-X",
                "warn_default_encoding",
                "-W",
                "error",
                "-m",
                "amnesia",
                "render",
                str(FIXTURE),
                *args,
            ],
            stdout=fichier,
            stderr=subprocess.PIPE,
            check=False,
            cwd=tmp_path,
            env=env,
        )
    return processus, sortie.read_bytes()


@pytest.mark.parametrize("encodage", ["cp1252", "cp850"])
@pytest.mark.parametrize("fmt", ["text", "md"])
def test_render_page_de_code(tmp_path: Path, encodage: str, fmt: str) -> None:
    # sans repli, « → » (absent de cp1252 et de cp850) deviendrait « ? »
    processus, octets = _rendre(tmp_path, encodage, "--format", fmt)
    assert processus.returncode == 0, processus.stderr
    texte = octets.decode(encodage)
    assert "->" in texte
    assert "→" not in texte
    assert "?" + " Impossible" not in texte
    assert "-> Impossible : le journal Security fait 20 Mo et a été écrasé" in texte
    assert b"Traceback" not in processus.stderr


def test_render_utf8(tmp_path: Path) -> None:
    processus, octets = _rendre(tmp_path, "utf-8")
    assert processus.returncode == 0, processus.stderr
    assert "→ Impossible : le journal Security" in octets.decode("utf-8")
    assert b"\x1b" not in octets
