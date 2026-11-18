# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Analyse sûre des fichiers importés : amnesia.inputs (#35).

Les fichiers hostiles sont fabriques par les tests (aucune fixture binaire dans
le depot) : bombes XML et ZIP, archives aux chemins pieges, Registry.pol
tronques. Toutes les valeurs sont fictives.
"""

from __future__ import annotations

import builtins
import copy
import csv
import functools
import io
import json
import os
import pickle
import shutil
import stat
import struct
import tempfile
import time
import traceback
import zipfile
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from amnesia import inputs
from amnesia.inputs import (
    DEFAULT_LIMITS,
    Limits,
    PolEntry,
    Rejection,
    UnsafeInputError,
)

MIO = 1024 * 1024
GIO = 1024 * MIO
# delai du critere d'acceptation : un fichier hostile est refuse vite
DELAI = 2.0
MARQUEUR = "MARQUEUR-CONFIDENTIEL-3f9a"


def _refus(appel: Callable[[], object]) -> UnsafeInputError:
    with pytest.raises(UnsafeInputError) as capture:
        appel()
    return capture.value


def _ecrire(dossier: Path, nom: str, contenu: bytes) -> Path:
    chemin = dossier / nom
    chemin.write_bytes(contenu)
    return chemin


# --- plafonds et exception ----------------------------------------------------


def test_plafonds_par_defaut() -> None:
    assert DEFAULT_LIMITS.max_bytes == 200 * MIO
    assert Limits() == DEFAULT_LIMITS


@pytest.mark.parametrize("valeur", [0, -1, True, 1.5, "10"])
def test_plafond_non_positif_refuse(valeur: Any) -> None:
    with pytest.raises(ValueError, match="max_bytes"):
        Limits(max_bytes=valeur)


def test_exception_copiable_et_sans_contenu() -> None:
    erreur = UnsafeInputError(Rejection.TOO_DEEP, "trop profond")
    assert isinstance(erreur, ValueError)
    assert str(erreur) == "trop profond"
    for copie in (copy.copy(erreur), pickle.loads(pickle.dumps(erreur))):  # noqa: S301 - objet du test, jamais un fichier
        assert (copie.code, copie.message) == (Rejection.TOO_DEEP, "trop profond")


# --- lecture plafonnee --------------------------------------------------------


def test_lecture_d_un_fichier_ordinaire(tmp_path: Path) -> None:
    fichier = _ecrire(tmp_path, "donnees.bin", b"\x00\x01abc")
    assert inputs.read_bytes(fichier) == b"\x00\x01abc"
    assert inputs.read_bytes(str(fichier), limits=Limits(max_bytes=5)) == b"\x00\x01abc"


def test_fichier_trop_gros_refuse_sans_etre_lu(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # fichier creux : plus gros que le plafond par defaut, sans occuper le disque
    fichier = tmp_path / "enorme.json"
    with fichier.open("wb") as flux:
        flux.truncate(DEFAULT_LIMITS.max_bytes + 1)

    def lecture_interdite(*_: object) -> bytes:
        raise AssertionError("le fichier ne doit pas être lu")

    monkeypatch.setattr(inputs, "_lire_flux", lecture_interdite)
    debut = time.monotonic()
    lecteurs: list[Callable[[Path], object]] = [
        inputs.read_bytes,
        inputs.load_json,
        inputs.load_xml,
    ]
    for lire in lecteurs:
        erreur = _refus(functools.partial(lire, fichier))
        assert erreur.code is Rejection.TOO_LARGE
    assert time.monotonic() - debut < DELAI


def test_flux_sans_fin_arrete_au_plafond() -> None:
    # FIFO, peripherique ou fichier qui grossit : stat() annonce 0, la lecture
    # s'arrete quand meme au premier octet de trop
    servis = 0

    def lire(taille: int) -> bytes:
        nonlocal servis
        servis += taille
        return b"\x00" * taille

    plafond = 3 * 64 * 1024 + 17
    erreur = _refus(lambda: inputs._lire_flux(lire, plafond))
    assert erreur.code is Rejection.TOO_LARGE
    assert servis == plafond + 1


def test_lecture_exacte_au_plafond(tmp_path: Path) -> None:
    fichier = _ecrire(tmp_path, "juste.bin", b"x" * 1000)
    assert len(inputs.read_bytes(fichier, limits=Limits(max_bytes=1000))) == 1000
    erreur = _refus(lambda: inputs.read_bytes(fichier, limits=Limits(max_bytes=999)))
    assert erreur.code is Rejection.TOO_LARGE


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO : POSIX seulement")
def test_fifo_refusee_sans_bloquer(tmp_path: Path) -> None:
    fifo = tmp_path / "tube"
    os.mkfifo(fifo)
    debut = time.monotonic()
    assert _refus(lambda: inputs.read_bytes(fifo)).code is Rejection.NOT_REGULAR_FILE
    assert _refus(lambda: inputs.load_json(fifo)).code is Rejection.NOT_REGULAR_FILE
    with pytest.raises(UnsafeInputError), inputs.extract_zip(fifo):
        pass
    assert time.monotonic() - debut < DELAI


@pytest.mark.skipif(not Path("/dev/zero").exists(), reason="/dev/zero : POSIX")
def test_peripherique_refuse() -> None:
    erreur = _refus(lambda: inputs.read_bytes("/dev/zero"))
    assert erreur.code is Rejection.NOT_REGULAR_FILE


def test_dossier_et_fichier_absent_refuses(tmp_path: Path) -> None:
    # sous Windows, ouvrir un dossier echoue avant fstat : illisible
    assert _refus(lambda: inputs.read_bytes(tmp_path)).code in {
        Rejection.NOT_REGULAR_FILE,
        Rejection.UNREADABLE,
    }
    absent = tmp_path / f"{MARQUEUR}.json"
    erreur = _refus(lambda: inputs.load_json(absent))
    assert erreur.code is Rejection.UNREADABLE
    # le chemin (nom de client, de mission) n'est pas repris non plus
    assert MARQUEUR not in str(erreur)


def test_octets_exiges() -> None:
    with pytest.raises(TypeError):
        inputs.loads_json("{}")  # type: ignore[arg-type]


# --- XML ----------------------------------------------------------------------

SYSMON = (
    '<?xml version="1.0" encoding="{encodage}"?>\n'
    '<Sysmon schemaversion="4.90">\n'
    "  <!-- configuration fictive -->\n"
    "  <EventFiltering>\n"
    '    <ProcessCreate onmatch="exclude">\n'
    '      <Image condition="is">C:\\Outils\\éditeur &amp; co.exe</Image>\n'
    "    </ProcessCreate>\n"
    "  </EventFiltering>\n"
    "</Sysmon>\n"
)

BILLION_LAUGHS = (
    '<?xml version="1.0"?>\n<!DOCTYPE lolz [\n <!ENTITY lol "lol">\n'
    + "".join(
        f' <!ENTITY lol{n} "{"&lol" + (str(n - 1) if n > 1 else "") + ";"}'
        f'{("&lol" + (str(n - 1) if n > 1 else "") + ";") * 9}">\n'
        for n in range(1, 10)
    )
    + "]>\n<lolz>&lol9;</lolz>\n"
).encode()
XXE = (
    b'<?xml version="1.0"?>\n'
    b'<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>\n'
    b"<r>&x;</r>\n"
)
DTD_EXTERNE = (
    b'<?xml version="1.0"?>\n<!DOCTYPE r SYSTEM "http://192.0.2.1/piege.dtd">\n<r/>\n'
)
ENTITE_PARAMETRE = (
    b'<!DOCTYPE r [<!ENTITY % p SYSTEM "http://192.0.2.1/p.dtd"> %p;]>\n<r/>\n'
)
EXPANSION_QUADRATIQUE = (
    b'<!DOCTYPE r [<!ENTITY a "' + b"a" * 50_000 + b'">]>\n<r>' + b"&a;" * 50_000
) + b"</r>\n"


@pytest.fixture
def ouvertures(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Chemins ouverts pendant le test, par open() ou os.open()."""
    vus: list[str] = []
    vrai_open, vrai_os_open = builtins.open, os.open

    def espion_open(fichier: Any, *args: Any, **kwargs: Any) -> Any:
        vus.append(str(fichier))
        return vrai_open(fichier, *args, **kwargs)

    def espion_os_open(chemin: Any, *args: Any, **kwargs: Any) -> int:
        vus.append(str(chemin))
        return vrai_os_open(chemin, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", espion_open)
    monkeypatch.setattr(os, "open", espion_os_open)
    return vus


def test_xml_valide() -> None:
    racine = inputs.loads_xml(SYSMON.format(encodage="utf-8").encode())
    assert racine.tag == "Sysmon"
    assert racine.attrib == {"schemaversion": "4.90"}
    image = racine.find("./EventFiltering/ProcessCreate/Image")
    assert image is not None
    assert image.text == "C:\\Outils\\éditeur & co.exe"
    assert image.attrib == {"condition": "is"}


@pytest.mark.parametrize(
    ("declare", "codec"),
    [
        ("utf-8", "utf-8"),
        ("UTF-8", "utf-8-sig"),
        ("utf-16", "utf-16"),
        ("utf-16", "utf-16-le"),
        ("utf-16", "utf-16-be"),
        ("iso-8859-1", "latin-1"),
        ("windows-1252", "cp1252"),
    ],
    ids=["utf8", "utf8-bom", "utf16", "utf16-le-bom", "utf16-be-bom", "latin1", "ansi"],
)
def test_xml_encodages_acceptes(declare: str, codec: str, tmp_path: Path) -> None:
    texte = SYSMON.format(encodage=declare)
    bom = {"utf-16-le": b"\xff\xfe", "utf-16-be": b"\xfe\xff"}.get(codec, b"")
    fichier = _ecrire(tmp_path, "sysmon.xml", bom + texte.encode(codec))
    image = inputs.load_xml(fichier).find(".//Image")
    assert image is not None
    assert image.text == "C:\\Outils\\éditeur & co.exe"


@pytest.mark.parametrize(
    "donnees",
    [
        "<r/>".encode("utf-16-le"),
        "<r/>".encode("utf-16-be"),
        "\ufeff<r/>".encode("utf-32-le"),
        "\ufeff<r/>".encode("utf-32-be"),
        b'<?xml version="1.0" encoding="utf-16"?><r/>',
        b'<?xml version="1.0" encoding="utf-7"?><r/>',
        b'<?xml version="1.0" encoding="cp037"?><r/>',
        b'<?xml version="1.0" encoding="utf-8"?><r>\xe9</r>',
        b"\xff\xfe<\x00r\x00/\x00>\x00\x00",
    ],
    ids=[
        "utf16-le-sans-bom",
        "utf16-be-sans-bom",
        "utf32-le",
        "utf32-be",
        "utf16-declare-sans-bom",
        "utf7",
        "ebcdic",
        "utf8-invalide",
        "utf16-tronque",
    ],
)
def test_xml_encodages_refuses(donnees: bytes) -> None:
    assert _refus(lambda: inputs.loads_xml(donnees)).code is Rejection.ENCODING


@pytest.mark.parametrize(
    "donnees",
    [BILLION_LAUGHS, XXE, DTD_EXTERNE, ENTITE_PARAMETRE, EXPANSION_QUADRATIQUE],
    ids=["billion-laughs", "xxe", "dtd-externe", "entite-parametre", "quadratique"],
)
def test_xml_hostile_refuse_vite_sans_fichier_ni_reseau(
    donnees: bytes, tmp_path: Path, ouvertures: list[str]
) -> None:
    # reseau : coupe par le conftest, une tentative leverait une autre exception
    fichier = _ecrire(tmp_path, "piege.xml", donnees)
    ouvertures.clear()
    debut = time.monotonic()
    erreurs = [
        _refus(lambda: inputs.loads_xml(donnees)),
        _refus(lambda: inputs.load_xml(fichier)),
        # meme refus en UTF-16 : l'encodage ne contourne pas le controle
        _refus(
            lambda: inputs.loads_xml(b"\xff\xfe" + donnees.decode().encode("utf-16-le"))
        ),
    ]
    assert time.monotonic() - debut < DELAI
    assert [e.code for e in erreurs] == [Rejection.FORBIDDEN] * 3
    assert "DOCTYPE" in str(erreurs[0])
    # seul le fichier demande a ete ouvert : ni /etc/passwd, ni DTD (les
    # sources Python que l'interpreteur relirait pour une trace ne comptent pas)
    assert [o for o in ouvertures if not o.endswith(".py")] == [str(fichier)]


def test_xml_entites_predefinies_et_espaces_de_noms() -> None:
    racine = inputs.loads_xml(
        b'<g:GPO xmlns:g="urn:exemple:gpo" g:id="1"><g:Name>&lt;a&gt; &#233;</g:Name>'
        b"<?cible instruction?></g:GPO>"
    )
    assert racine.tag == "{urn:exemple:gpo}GPO"
    assert racine.attrib == {"{urn:exemple:gpo}id": "1"}
    assert racine[0].tag == "{urn:exemple:gpo}Name"
    assert racine[0].text == "<a> é"
    assert len(racine) == 1


@pytest.mark.parametrize(
    "donnees",
    [
        b"",
        b"<r>",
        b"<r></s>",
        b"<r>&inconnue;</r>",
        b"<r/><r/>",
        b"texte",
        b"<r>\x00</r>",
    ],
)
def test_xml_mal_forme(donnees: bytes) -> None:
    erreur = _refus(lambda: inputs.loads_xml(donnees))
    assert erreur.code is Rejection.MALFORMED
    assert "ligne" in str(erreur)


def test_xml_profondeur_et_nombre_d_elements() -> None:
    debut = time.monotonic()
    profond = b"<a>" * 100_000 + b"</a>" * 100_000
    assert _refus(lambda: inputs.loads_xml(profond)).code is Rejection.TOO_DEEP
    assert time.monotonic() - debut < DELAI
    limites = Limits(max_depth=3, max_records=5)
    assert inputs.loads_xml(b"<a><b><c/></b><b/><b/></a>", limits=limites).tag == "a"
    trop_profond = b"<a><b><c><d/></c></b></a>"
    assert (
        _refus(lambda: inputs.loads_xml(trop_profond, limits=limites)).code
        is Rejection.TOO_DEEP
    )
    trop_large = b"<a><b/><b/><b/><b/><b/></a>"
    assert (
        _refus(lambda: inputs.loads_xml(trop_large, limits=limites)).code
        is Rejection.TOO_MANY
    )


# --- JSON ---------------------------------------------------------------------


@pytest.mark.parametrize("codec", ["utf-8", "utf-8-sig", "utf-16"])
def test_json_valide(codec: str, tmp_path: Path) -> None:
    texte = '{"hôte": "SRV-FILE", "journaux": [{"nom": "Security", "taille": 20}]}'
    fichier = _ecrire(tmp_path, "faits.json", texte.encode(codec))
    assert inputs.load_json(fichier) == {
        "hôte": "SRV-FILE",
        "journaux": [{"nom": "Security", "taille": 20}],
    }


@pytest.mark.parametrize(
    "donnees",
    [
        b"[" * 100_000 + b"]" * 100_000,
        b'{"a":' * 100_000 + b"1" + b"}" * 100_000,
        b"[" * 100_000,
        b'[{"a":' * 50_000,
    ],
    ids=["tableaux", "objets", "tableaux-ouverts", "mixte-ouvert"],
)
def test_json_imbrique_sur_100_000_niveaux(donnees: bytes, tmp_path: Path) -> None:
    fichier = _ecrire(tmp_path, "profond.json", donnees)
    debut = time.monotonic()
    # UnsafeInputError, jamais RecursionError : la profondeur se compte avant
    # l'analyse
    assert _refus(lambda: inputs.load_json(fichier)).code is Rejection.TOO_DEEP
    assert time.monotonic() - debut < DELAI


def test_json_profondeur_exacte() -> None:
    limites = Limits(max_depth=3)
    assert inputs.loads_json(b'[[{"a": 1}]]', limits=limites) == [[{"a": 1}]]
    erreur = _refus(lambda: inputs.loads_json(b'[[{"a": []}]]', limits=limites))
    assert erreur.code is Rejection.TOO_DEEP
    assert "3 niveaux" in str(erreur)


def test_json_crochets_dans_les_chaines_non_comptes() -> None:
    limites = Limits(max_depth=1, max_records=1)
    donnees = b'["[[[[{{{{", "\\"[[[", "\\\\", "]]]"]'
    assert inputs.loads_json(donnees, limits=limites) == [
        "[[[[{{{{",
        '"[[[',
        "\\",
        "]]]",
    ]


@pytest.mark.parametrize(
    "donnees",
    [
        b'"' + b'\\"' * 300_000,
        b'["' + b'\\"' * 300_000 + b"\\",
        b'"' * 300_001,
        b'"\\' * 300_000,
    ],
    ids=["jamais-fermee", "barre-finale", "guillemets", "alternance"],
)
def test_json_chaines_pathologiques_en_temps_lineaire(donnees: bytes) -> None:
    debut = time.monotonic()
    assert _refus(lambda: inputs.loads_json(donnees)).code is Rejection.MALFORMED
    assert time.monotonic() - debut < DELAI


@pytest.mark.parametrize(
    ("donnees", "code"),
    [
        (b'{"a": 1, "a": 2}', Rejection.DUPLICATE),
        (b'[{"b": {"c": 1, "c": 1}}]', Rejection.DUPLICATE),
        (b"[NaN]", Rejection.MALFORMED),
        (b"[-Infinity]", Rejection.MALFORMED),
        (b"[" + b"9" * 5000 + b"]", Rejection.MALFORMED),
        (b"{", Rejection.MALFORMED),
        (b"", Rejection.MALFORMED),
        (b"\xff\xfe\x00", Rejection.ENCODING),
        (b'{"a": "\xe9"}', Rejection.ENCODING),
        ("\ufeff[]".encode("utf-32-le"), Rejection.ENCODING),
    ],
)
def test_json_refuse(donnees: bytes, code: Rejection) -> None:
    assert _refus(lambda: inputs.loads_json(donnees)).code is code


def test_json_position_de_l_erreur_sans_contenu() -> None:
    erreur = _refus(lambda: inputs.loads_json(b'{"a": 1,\n  oups}'))
    assert str(erreur) == "JSON invalide (ligne 2, colonne 3)"


def test_json_trop_de_conteneurs() -> None:
    limites = Limits(max_records=3)
    assert inputs.loads_json(b"[[], {}]", limits=limites) == [[], {}]
    erreur = _refus(lambda: inputs.loads_json(b"[[], {}, []]", limits=limites))
    assert erreur.code is Rejection.TOO_MANY


def test_json_plus_gros_que_le_plafond(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    limites = Limits(max_bytes=1024)
    assert (
        _refus(
            lambda: inputs.loads_json(b"[" + b" " * 1024 + b"]", limits=limites)
        ).code
        is Rejection.TOO_LARGE
    )
    fichier = _ecrire(tmp_path, "gros.json", b"[" + b" " * MIO + b"]")
    monkeypatch.setattr(inputs, "_lire_flux", lambda *_: pytest.fail("fichier lu"))
    erreur = _refus(lambda: inputs.load_json(fichier, limits=limites))
    assert erreur.code is Rejection.TOO_LARGE
    assert "1024 octets" in str(erreur)


# --- TOML ---------------------------------------------------------------------


def test_toml_valide(tmp_path: Path) -> None:
    texte = '[mission]\nnom = "démonstration"\ncibles = ["local", "bundle:exemple"]\n'
    for codec in ("utf-8", "utf-8-sig", "utf-16"):
        fichier = _ecrire(tmp_path, "mission.toml", texte.encode(codec))
        assert inputs.load_toml(fichier) == {
            "mission": {"nom": "démonstration", "cibles": ["local", "bundle:exemple"]}
        }


def test_toml_imbrication() -> None:
    limites = Limits(max_depth=3)
    assert inputs.loads_toml(b"a = [[1]]\n", limits=limites) == {"a": [[1]]}
    erreur = _refus(lambda: inputs.loads_toml(b"a = [[[1]]]\n", limits=limites))
    assert erreur.code is Rejection.TOO_DEEP
    debut = time.monotonic()
    profond = b"a = " + b"[" * 100_000 + b"]" * 100_000 + b"\n"
    # erreur controlee, jamais RecursionError ; selon la version de Python,
    # tomllib refuse lui-meme l'imbrication (TOML invalide) ou epuise sa pile
    assert _refus(lambda: inputs.loads_toml(profond)).code in {
        Rejection.TOO_DEEP,
        Rejection.MALFORMED,
    }
    assert time.monotonic() - debut < DELAI


@pytest.mark.parametrize(
    ("donnees", "code"),
    [
        (b"a = 1\na = 2\n", Rejection.MALFORMED),
        (b"a = \n", Rejection.MALFORMED),
        (b"a = '\xe9'\n", Rejection.ENCODING),
        ("a = 1\n".encode("utf-16-le"), Rejection.MALFORMED),
    ],
)
def test_toml_refuse(donnees: bytes, code: Rejection) -> None:
    erreur = _refus(lambda: inputs.loads_toml(donnees))
    assert erreur.code is code


def test_toml_trop_de_conteneurs() -> None:
    erreur = _refus(
        lambda: inputs.loads_toml(b"a = [[], [], []]\n", limits=Limits(max_records=3))
    )
    assert erreur.code is Rejection.TOO_MANY


# --- CSV ----------------------------------------------------------------------

AUDIT_CSV = (
    "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,"
    "Exclusion Setting,Setting Value\r\n"
    ",System,Ouverture de session,{0cce9215-69ae-11d9-bed3-505054503030},"
    "Succès et échec,,3\r\n"
    ',System,"Création, processus",{0cce922b-69ae-11d9-bed3-505054503030},'
    "Succès,,1\r\n"
    "\r\n"
)


@pytest.mark.parametrize(
    ("codec", "encodage"),
    [
        ("utf-8", "utf-8"),
        ("utf-8-sig", "utf-8"),
        ("utf-16", "utf-8"),
        ("cp1252", "cp1252"),
    ],
)
def test_csv_valide(codec: str, encodage: str, tmp_path: Path) -> None:
    fichier = _ecrire(tmp_path, "audit.csv", AUDIT_CSV.encode(codec))
    lignes = inputs.load_csv(fichier, columns=7, encoding=encodage)
    assert len(lignes) == 3
    assert lignes[0][2] == "Subcategory"
    assert lignes[1][4] == "Succès et échec"
    assert lignes[2][2] == "Création, processus"


def test_csv_ansi_sans_codec_refuse() -> None:
    erreur = _refus(lambda: inputs.loads_csv(AUDIT_CSV.encode("cp1252")))
    assert erreur.code is Rejection.ENCODING


def test_csv_taille_de_champ_explicite_et_restauree() -> None:
    avant = csv.field_size_limit()
    limites = Limits(max_field_chars=10)
    assert (
        inputs.loads_csv(b"a,b\n0123456789,1\n", limits=limites)[1][0] == "0123456789"
    )
    erreur = _refus(lambda: inputs.loads_csv(b"a,b\n01234567890,1\n", limits=limites))
    assert erreur.code is Rejection.MALFORMED
    assert "10 caractères" in str(erreur)
    # reglage du processus : remis en place, meme apres un refus
    assert csv.field_size_limit() == avant


@pytest.mark.parametrize(
    ("donnees", "options", "code"),
    [
        (b"a,b\n1,2,3\n", {}, Rejection.MALFORMED),
        (b"a,b\n1\n", {}, Rejection.MALFORMED),
        (b"a,b\n1,2\n", {"columns": 3}, Rejection.MALFORMED),
        (b"a,b,c,d\n", {"limits": Limits(max_columns=3)}, Rejection.TOO_MANY),
        (b"a\n1\n2\n3\n", {"limits": Limits(max_records=3)}, Rejection.TOO_MANY),
        (b'a,b\n"1,2\n', {}, Rejection.MALFORMED),
        (b'a,b\n1,"2"x\n', {}, Rejection.MALFORMED),
    ],
    ids=[
        "colonne-en-trop",
        "colonne-manquante",
        "nombre-attendu",
        "trop-de-colonnes",
        "trop-de-lignes",
        "guillemet-ouvert",
        "guillemet-mal-place",
    ],
)
def test_csv_refuse(donnees: bytes, options: dict[str, Any], code: Rejection) -> None:
    assert _refus(lambda: inputs.loads_csv(donnees, **options)).code is code


def test_csv_separateur_et_ligne_de_l_erreur() -> None:
    assert inputs.loads_csv(b"a;b\n1;2\n", delimiter=";") == [["a", "b"], ["1", "2"]]
    erreur = _refus(lambda: inputs.loads_csv(b"a,b\n1,2\n1,2,3\n"))
    assert str(erreur) == "CSV invalide : 3 colonnes au lieu de 2 (ligne 3)"


# --- Registry.pol -------------------------------------------------------------

REG_SZ = 1
REG_DWORD = 4
ENTETE_POL = b"PReg\x01\x00\x00\x00"
CLE_AUDIT = "Software\\Policies\\Microsoft\\Windows\\EventLog\\Security"


def _u16(texte: str) -> bytes:
    return texte.encode("utf-16-le")


def _entree_pol(cle: str, valeur: str, type_: int, donnees: bytes) -> bytes:
    return b"".join(
        [
            _u16("["),
            _u16(cle + "\x00"),
            _u16(";"),
            _u16(valeur + "\x00"),
            _u16(";"),
            struct.pack("<I", type_),
            _u16(";"),
            struct.pack("<I", len(donnees)),
            _u16(";"),
            donnees,
            _u16("]"),
        ]
    )


POL = (
    ENTETE_POL
    + _entree_pol(CLE_AUDIT, "MaxSize", REG_DWORD, struct.pack("<I", 1_048_576))
    + _entree_pol(CLE_AUDIT, "Retention", REG_SZ, _u16("0\x00"))
    + _entree_pol(CLE_AUDIT, "**del.AutoBackupLogFiles", REG_SZ, b"")
)


def test_registry_pol_valide(tmp_path: Path) -> None:
    fichier = _ecrire(tmp_path, "Registry.pol", POL)
    entrees = inputs.load_registry_pol(fichier)
    assert entrees == (
        PolEntry(CLE_AUDIT, "MaxSize", REG_DWORD, struct.pack("<I", 1_048_576)),
        PolEntry(CLE_AUDIT, "Retention", REG_SZ, _u16("0\x00")),
        PolEntry(CLE_AUDIT, "**del.AutoBackupLogFiles", REG_SZ, b""),
    )
    assert inputs.loads_registry_pol(ENTETE_POL) == ()


def test_registry_pol_tronque_a_chaque_octet() -> None:
    # toute troncature est soit un fichier valide plus court (frontiere
    # d'entree), soit une UnsafeInputError : jamais une autre exception
    valides = 0
    for longueur in range(len(POL)):
        try:
            inputs.loads_registry_pol(POL[:longueur])
        except UnsafeInputError as exc:
            assert exc.code is Rejection.MALFORMED, longueur
        else:
            valides += 1
    # en-tete seul, puis fin de la premiere et de la deuxieme entree
    assert valides == 3


@pytest.mark.parametrize(
    ("donnees", "code"),
    [
        (b"", Rejection.MALFORMED),
        (b"PReg", Rejection.MALFORMED),
        (b"MZ\x90\x00\x01\x00\x00\x00", Rejection.MALFORMED),
        (b"preg\x01\x00\x00\x00", Rejection.MALFORMED),
        (b"PReg\x02\x00\x00\x00", Rejection.UNSUPPORTED),
        (b"PReg\x00\x00\x00\x01", Rejection.UNSUPPORTED),
        (ENTETE_POL + b"\x00", Rejection.MALFORMED),
        (ENTETE_POL + _u16("]"), Rejection.MALFORMED),
        # taille annoncee de 4 Gio pour 4 octets de donnees
        (
            ENTETE_POL
            + _entree_pol("K", "V", REG_DWORD, b"\x00" * 4).replace(
                struct.pack("<I", 4), b"\xff\xff\xff\xff"
            ),
            Rejection.MALFORMED,
        ),
        # nom sans terminateur, plus long que la borne
        (ENTETE_POL + _u16("[") + _u16("A" * 20_000), Rejection.TOO_LARGE),
        # demi-paire de substitution isolee
        (
            ENTETE_POL + _u16("[") + b"\x00\xd8" + _u16("\x00;"),
            Rejection.ENCODING,
        ),
        (POL + b"\x00\x00", Rejection.MALFORMED),
    ],
    ids=[
        "vide",
        "entete-tronque",
        "signature-invalide",
        "signature-en-minuscules",
        "version-2",
        "version-gros-boutiste",
        "octet-isole",
        "fermant-sans-ouvrant",
        "taille-mensongere",
        "nom-sans-fin",
        "utf16-invalide",
        "octets-en-trop",
    ],
)
def test_registry_pol_refuse(donnees: bytes, code: Rejection) -> None:
    assert _refus(lambda: inputs.loads_registry_pol(donnees)).code is code


def test_registry_pol_nombre_d_entrees() -> None:
    limites = Limits(max_records=2)
    erreur = _refus(lambda: inputs.loads_registry_pol(POL, limits=limites))
    assert erreur.code is Rejection.TOO_MANY


@given(st.binary(max_size=256))
def test_registry_pol_octets_quelconques_sans_exception_non_geree(corps: bytes) -> None:
    for donnees in (corps, ENTETE_POL + corps, POL + corps):
        try:
            entrees = inputs.loads_registry_pol(donnees)
        except UnsafeInputError:
            continue
        assert all(isinstance(entree, PolEntry) for entree in entrees)


# --- ZIP ----------------------------------------------------------------------

UTF8 = 0x800


@dataclass
class Entree:
    """Entrée d'une archive fabriquée octet par octet : tout peut y mentir."""

    nom: str
    contenu: bytes = b""
    mode: int = 0
    # attributs MS-DOS (0x10 : dossier), poses par les outils Windows
    dos: int = 0
    methode: int = zipfile.ZIP_DEFLATED
    drapeaux: int = UTF8
    # taille decompressee annoncee, si elle differe de celle du contenu
    annonce: int | None = None
    # donnees deja compressees, a la place de celles du contenu
    charge: bytes | None = None


def _degonfler(contenu: bytes) -> bytes:
    compresseur = zlib.compressobj(9, zlib.DEFLATED, -15)
    return compresseur.compress(contenu) + compresseur.flush()


def _zip(*entrees: Entree, annonce_entrees: int | None = None) -> bytes:
    corps = bytearray()
    central = bytearray()
    for entree in entrees:
        nom = entree.nom.encode("utf-8")
        if entree.charge is not None:
            charge = entree.charge
        elif entree.methode == zipfile.ZIP_DEFLATED:
            charge = _degonfler(entree.contenu)
        else:
            charge = entree.contenu
        taille = len(entree.contenu) if entree.annonce is None else entree.annonce
        communs = (
            entree.drapeaux,
            entree.methode,
            0,
            0x21,
            zlib.crc32(entree.contenu),
            len(charge),
            taille,
            len(nom),
            0,
        )
        decalage = len(corps)
        corps += struct.pack("<4sH4H3L2H", b"PK\x03\x04", 20, *communs) + nom + charge
        central += (
            struct.pack("<4s2H4H3L2H", b"PK\x01\x02", (3 << 8) | 20, 20, *communs)
            + struct.pack("<3H2L", 0, 0, 0, entree.mode << 16 | entree.dos, decalage)
            + nom
        )
    nombre = len(entrees) if annonce_entrees is None else annonce_entrees
    fin = struct.pack(
        "<4s4H2LH", b"PK\x05\x06", 0, 0, nombre, nombre, len(central), len(corps), 0
    )
    return bytes(corps + central + fin)


def _bombe(taille: int) -> bytes:
    """Flux deflate de ``taille`` zéros (multiple de 1 Mio), environ 1000 fois
    plus petit : un bloc compressé une fois, puis répété."""
    compresseur = zlib.compressobj(9, zlib.DEFLATED, -15)
    # Z_FULL_FLUSH : le bloc finit sur un octet entier et ne depend d'aucun
    # autre ; il se repete donc tel quel
    bloc = compresseur.compress(b"\x00" * MIO) + compresseur.flush(zlib.Z_FULL_FLUSH)
    return bloc * (taille // MIO) + compresseur.flush()


@pytest.fixture
def zone(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Dossier temporaire du test : les extractions s'y font, et rien n'en sort."""
    temporaire = tmp_path / "tmp"
    temporaire.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temporaire))
    return tmp_path


def _arbre(racine: Path) -> list[str]:
    return sorted(p.relative_to(racine).as_posix() for p in racine.rglob("*"))


def _extraire(archive: Path, limits: Limits = DEFAULT_LIMITS) -> dict[str, bytes]:
    with inputs.extract_zip(archive, limits=limits) as racine:
        return {
            chemin.relative_to(racine).as_posix(): chemin.read_bytes()
            for chemin in racine.rglob("*")
            if chemin.is_file()
        }


def test_zip_extrait_dans_un_dossier_prive_puis_supprime(zone: Path) -> None:
    archive = _ecrire(
        zone,
        "bundle.zip",
        _zip(
            Entree("manifeste.json", b'{"schema": "exemple"}'),
            Entree("gpo/", mode=stat.S_IFDIR | 0o755),
            Entree("gpo/{0A1B}/Registry.pol", POL, mode=stat.S_IFREG | 0o777),
            Entree("gpo/vide/", methode=zipfile.ZIP_STORED),
            Entree("brut.bin", b"\x00\xff" * 10, methode=zipfile.ZIP_STORED),
        ),
    )
    with inputs.extract_zip(archive) as racine:
        assert racine.parent == zone / "tmp"
        assert _arbre(racine) == [
            "brut.bin",
            "gpo",
            "gpo/vide",
            "gpo/{0A1B}",
            "gpo/{0A1B}/Registry.pol",
            "manifeste.json",
        ]
        assert (racine / "manifeste.json").read_bytes() == b'{"schema": "exemple"}'
        assert inputs.load_registry_pol(racine / "gpo/{0A1B}/Registry.pol")[
            0
        ].value == ("MaxSize")
        if os.name != "nt":
            assert stat.S_IMODE(racine.stat().st_mode) == 0o700
            assert stat.S_IMODE((racine / "gpo/{0A1B}").stat().st_mode) == 0o700
            # jamais le mode annonce par l'archive (0777)
            fichier = racine / "gpo/{0A1B}/Registry.pol"
            assert stat.S_IMODE(fichier.stat().st_mode) == 0o600
    assert not racine.exists()
    assert _arbre(zone) == ["bundle.zip", "tmp"]


def test_zip_dossier_supprime_si_l_appelant_echoue(zone: Path) -> None:
    archive = _ecrire(zone, "bundle.zip", _zip(Entree("a.txt", b"a")))
    with (
        pytest.raises(RuntimeError, match="appelant"),
        inputs.extract_zip(archive) as r,
    ):
        assert (r / "a.txt").exists()
        raise RuntimeError("appelant")
    assert _arbre(zone) == ["bundle.zip", "tmp"]


def test_zip_ecrit_par_zipfile_accepte(zone: Path) -> None:
    archive = zone / "standard.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as sortie:
        sortie.writestr("sysmon/config.xml", SYSMON.format(encodage="utf-8"))
        sortie.writestr("LISEZMOI.txt", "collecte fictive")
    assert sorted(_extraire(archive)) == ["LISEZMOI.txt", "sysmon/config.xml"]


def test_zip_dossier_sans_barre_finale(zone: Path) -> None:
    # dossier declare par son seul attribut (MS-DOS ou Unix), sans « / » final
    archive = _ecrire(
        zone,
        "windows.zip",
        _zip(
            Entree("journaux", dos=0x10, methode=zipfile.ZIP_STORED),
            Entree("journaux/app.txt", b"x"),
            Entree("vide", mode=stat.S_IFDIR | 0o755, methode=zipfile.ZIP_STORED),
        ),
    )
    with inputs.extract_zip(archive) as racine:
        assert _arbre(racine) == ["journaux", "journaux/app.txt", "vide"]
        assert (racine / "vide").is_dir()


LIEN = stat.S_IFLNK | 0o777

ARCHIVES_PIEGEES = [
    ("zip-slip", [Entree("../../evil.txt", b"x")], Rejection.UNSAFE_PATH),
    ("zip-slip-interne", [Entree("a/../../evil.txt", b"x")], Rejection.UNSAFE_PATH),
    ("zip-slip-windows", [Entree("..\\..\\evil.txt", b"x")], Rejection.UNSAFE_PATH),
    ("point-point-final", [Entree("a/..", b"x")], Rejection.UNSAFE_PATH),
    ("absolu", [Entree("/tmp/evil.txt", b"x")], Rejection.UNSAFE_PATH),  # noqa: S108 - nom d'entree piege, jamais ecrit
    ("absolu-windows", [Entree("C:\\evil.txt", b"x")], Rejection.UNSAFE_PATH),
    (
        "absolu-unc",
        [Entree("\\\\hote\\partage\\evil.txt", b"x")],
        Rejection.UNSAFE_PATH,
    ),
    ("lecteur-relatif", [Entree("C:evil.txt", b"x")], Rejection.UNSAFE_PATH),
    ("flux-ntfs", [Entree("a.txt:evil", b"x")], Rejection.UNSAFE_PATH),
    ("peripherique-windows", [Entree("dossier/NUL.txt", b"x")], Rejection.UNSAFE_PATH),
    ("point-final", [Entree("evil.txt.", b"x")], Rejection.UNSAFE_PATH),
    ("espace-finale", [Entree("evil.txt ", b"x")], Rejection.UNSAFE_PATH),
    ("composant-vide", [Entree("a//evil.txt", b"x")], Rejection.UNSAFE_PATH),
    ("composant-point", [Entree("./evil.txt", b"x")], Rejection.UNSAFE_PATH),
    ("octet-nul", [Entree("evil.txt\x00.json", b"x")], Rejection.UNSAFE_PATH),
    ("retour-a-la-ligne", [Entree("evil\n.txt", b"x")], Rejection.UNSAFE_PATH),
    ("nom-vide", [Entree("", b"x")], Rejection.UNSAFE_PATH),
    ("nom-trop-long", [Entree("a" * 300, b"x")], Rejection.UNSAFE_PATH),
    (
        "lien-symbolique",
        [Entree("lien", b"../../evil.txt", mode=LIEN, methode=zipfile.ZIP_STORED)],
        Rejection.LINK,
    ),
    (
        "lien-puis-fichier-dessous",
        [
            Entree("ok.txt", b"ok"),
            Entree("d", b"/", mode=LIEN, methode=zipfile.ZIP_STORED),
            Entree("d/evil.txt", b"x"),
        ],
        Rejection.LINK,
    ),
    ("peripherique", [Entree("zero", mode=stat.S_IFCHR | 0o666)], Rejection.LINK),
    ("fifo", [Entree("tube", mode=stat.S_IFIFO | 0o666)], Rejection.LINK),
    ("doublon", [Entree("a.txt", b"1"), Entree("a.txt", b"2")], Rejection.DUPLICATE),
    (
        "doublon-de-casse",
        [Entree("A.txt", b"1"), Entree("a.TXT", b"2")],
        Rejection.DUPLICATE,
    ),
    (
        "doublon-unicode",
        [Entree("caf\u00e9.txt", b"1"), Entree("cafe\u0301.txt", b"2")],
        Rejection.DUPLICATE,
    ),
    (
        "doublon-de-separateur",
        [Entree("a/b.txt", b"1"), Entree("a\\b.txt", b"2")],
        Rejection.DUPLICATE,
    ),
    (
        "fichier-et-dossier",
        [Entree("a", b"1"), Entree("a/b.txt", b"2")],
        Rejection.DUPLICATE,
    ),
    (
        "fichier-et-dossier-explicite",
        [Entree("a/"), Entree("a", b"1")],
        Rejection.DUPLICATE,
    ),
    ("chiffree", [Entree("a.txt", b"x", drapeaux=UTF8 | 0x1)], Rejection.UNSUPPORTED),
    (
        "bzip2",
        [Entree("a.txt", b"x", methode=zipfile.ZIP_BZIP2)],
        Rejection.UNSUPPORTED,
    ),
    ("lzma", [Entree("a.txt", b"x", methode=zipfile.ZIP_LZMA)], Rejection.UNSUPPORTED),
]


@pytest.mark.parametrize(
    ("entrees", "code"),
    [pytest.param(entrees, code, id=nom) for nom, entrees, code in ARCHIVES_PIEGEES],
)
def test_zip_piege_refuse_sans_rien_ecrire(
    entrees: list[Entree], code: Rejection, zone: Path
) -> None:
    # une entree saine en tete : meme elle n'est pas extraite, le refus porte
    # sur l'archive entiere, avant la premiere ecriture
    archive = _ecrire(zone, "piege.zip", _zip(Entree("sain.txt", b"ok"), *entrees))
    crees: list[str] = []
    vrai = Path.mkdir

    def mkdir(chemin: Path, *args: Any, **kwargs: Any) -> None:
        crees.append(str(chemin))
        vrai(chemin, *args, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(Path, "mkdir", mkdir)
        erreur = _refus(lambda: _extraire(archive))
    assert erreur.code is code
    assert crees == []
    # rien hors du dossier temporaire, et rien dedans non plus
    assert _arbre(zone) == ["piege.zip", "tmp"]
    assert not list(zone.parent.glob("evil.txt"))
    assert not list(zone.parent.parent.glob("evil.txt"))


def test_zip_bombe_refusee_des_le_plafond(
    zone: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    charge = _bombe(GIO)
    # une archive d'environ 1 Mio qui se decompresse en 1 Gio
    assert 0.5 * MIO < len(charge) < 2 * MIO
    ecrits: list[int] = []
    vrai = shutil.rmtree

    def rmtree(racine: Path, **options: Any) -> None:
        ecrits.append(sum(p.stat().st_size for p in racine.rglob("*") if p.is_file()))
        vrai(racine, **options)

    monkeypatch.setattr(shutil, "rmtree", rmtree)
    debut = time.monotonic()

    # 1. taille annoncee honnete, plafonds par defaut : refus avant d'ecrire
    honnete = _ecrire(
        zone, "bombe.zip", _zip(Entree("zeros", charge=charge, annonce=GIO))
    )
    assert _refus(lambda: _extraire(honnete)).code is Rejection.TOO_LARGE
    assert ecrits.pop() == 0

    # 2. tailles annoncees sous les plafonds d'octets : le ratio, compte sur
    # les octets reellement decompresses, arrete l'extraction en cours de route
    larges = Limits(max_bytes=2 * GIO, max_total_bytes=2 * GIO, max_ratio=10)
    erreur = _refus(lambda: _extraire(honnete, larges))
    assert erreur.code is Rejection.COMPRESSION_RATIO
    assert 0 < ecrits.pop() <= 10 * honnete.stat().st_size

    # 3. en-tete mensonger (1 Kio annonce) : jamais plus que l'annonce n'est
    # ecrit, et l'archive est refusee
    menteuse = _ecrire(
        zone, "menteuse.zip", _zip(Entree("zeros", charge=charge, annonce=1024))
    )
    assert _refus(lambda: _extraire(menteuse)).code is Rejection.MALFORMED
    assert ecrits.pop() <= 1024

    # 4. meme bombe repartie sur des entrees toutes sous le plafond par
    # fichier : le total est plafonne
    morceau = _bombe(128 * MIO)
    repartie = _ecrire(
        zone,
        "repartie.zip",
        _zip(*(Entree(f"z{n}", charge=morceau, annonce=128 * MIO) for n in range(9))),
    )
    assert _refus(lambda: _extraire(repartie)).code is Rejection.TOO_LARGE
    assert ecrits.pop() == 0

    assert time.monotonic() - debut < 10 * DELAI
    assert _arbre(zone / "tmp") == []


def test_zip_plafonds_tenus_sur_les_octets_ecrits(
    zone: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # zipfile s'arrete de lui-meme a la taille annoncee ; les plafonds ne
    # reposent pas sur lui : ici, la source rend plus que l'annonce
    archive = _ecrire(
        zone, "menteuse.zip", _zip(Entree("a.bin", b"a"), Entree("b.bin", b"b"))
    )
    ecrits: list[int] = []
    vrai = shutil.rmtree

    def rmtree(racine: Path, **options: Any) -> None:
        ecrits.append(sum(p.stat().st_size for p in racine.rglob("*") if p.is_file()))
        vrai(racine, **options)

    def open_(self: zipfile.ZipFile, info: zipfile.ZipInfo) -> io.BytesIO:
        return io.BytesIO(b"\x00" * 550_000)

    monkeypatch.setattr(shutil, "rmtree", rmtree)
    monkeypatch.setattr(zipfile.ZipFile, "open", open_)
    # par entree
    par_entree = Limits(max_bytes=500_000)
    assert _refus(lambda: _extraire(archive, par_entree)).code is Rejection.TOO_LARGE
    assert 0 < ecrits.pop() <= 500_000
    # au total : la premiere entree passe, la seconde depasse
    au_total = Limits(max_bytes=600_000, max_total_bytes=1_000_000)
    assert _refus(lambda: _extraire(archive, au_total)).code is Rejection.TOO_LARGE
    assert 550_000 < ecrits.pop() <= 1_000_000
    # ratio : 1,1 Mo pour une archive de quelques centaines d'octets
    assert _refus(lambda: _extraire(archive)).code is Rejection.COMPRESSION_RATIO
    assert 550_000 < ecrits.pop() <= MIO


def test_zip_petit_fichier_tres_compressible_accepte(zone: Path) -> None:
    # ratio superieur a 100, mais moins de 1 Mio : ce n'est pas une bombe
    archive = _ecrire(
        zone, "journal.zip", _zip(Entree("journal.txt", b"a" * (MIO // 2)))
    )
    assert archive.stat().st_size * 100 < MIO // 2
    assert _extraire(archive) == {"journal.txt": b"a" * (MIO // 2)}


def test_zip_nombre_d_entrees(zone: Path) -> None:
    limites = Limits(max_entries=3)
    trois = _ecrire(zone, "trois.zip", _zip(*(Entree(f"{n}.txt") for n in range(3))))
    assert len(_extraire(trois, limites)) == 3
    quatre = _ecrire(zone, "quatre.zip", _zip(*(Entree(f"{n}.txt") for n in range(4))))
    assert _refus(lambda: _extraire(quatre, limites)).code is Rejection.TOO_MANY
    # nombre annonce mensonger : les entrees lues sont comptees
    menteuse = _ecrire(
        zone,
        "menteuse.zip",
        _zip(*(Entree(f"{n}.txt") for n in range(4)), annonce_entrees=1),
    )
    assert _refus(lambda: _extraire(menteuse, limites)).code is Rejection.TOO_MANY
    # repertoire central demesure pour le nombre d'entrees admis
    catalogue = _ecrire(zone, "catalogue.zip", _zip(Entree("a" * 5000)))
    erreur = _refus(lambda: _extraire(catalogue, Limits(max_entries=1)))
    assert erreur.code is Rejection.TOO_MANY


def test_zip64_et_multi_volumes_refuses(zone: Path) -> None:
    classique = _zip(Entree("a.txt", b"a"))
    fin = classique[-22:]
    localisateur = b"PK\x06\x07" + b"\x00" * 16
    zip64 = _ecrire(zone, "zip64.zip", classique[:-22] + localisateur + fin)
    assert _refus(lambda: _extraire(zip64)).code is Rejection.UNSUPPORTED
    marqueur = _ecrire(
        zone, "marqueur.zip", _zip(Entree("a.txt"), annonce_entrees=0xFFFF)
    )
    assert _refus(lambda: _extraire(marqueur)).code is Rejection.UNSUPPORTED
    volumes = _ecrire(
        zone, "volumes.zip", classique[:-18] + b"\x01\x00" + classique[-16:]
    )
    assert _refus(lambda: _extraire(volumes)).code is Rejection.UNSUPPORTED


@pytest.mark.parametrize(
    "contenu",
    [
        b"",
        b"ceci n'est pas une archive",
        b"PK\x05\x06",
        _zip(Entree("a.txt", b"abc" * 100))[:-30],
        b"PK\x05\x06" + b"\xff" * 18,
    ],
    ids=["vide", "texte", "signature-seule", "tronquee", "fin-incoherente"],
)
def test_zip_invalide(contenu: bytes, zone: Path) -> None:
    archive = _ecrire(zone, "invalide.zip", contenu)
    assert _refus(lambda: _extraire(archive)).code in {
        Rejection.MALFORMED,
        Rejection.UNSUPPORTED,
    }
    assert _arbre(zone / "tmp") == []


def test_zip_donnees_corrompues(zone: Path) -> None:
    saine = _zip(Entree("a.txt", b"contenu " * 100, methode=zipfile.ZIP_STORED))
    # un octet du contenu change : le CRC ne correspond plus
    corrompue = _ecrire(zone, "crc.zip", saine.replace(b"contenu ", b"contenu!", 1))
    assert _refus(lambda: _extraire(corrompue)).code is Rejection.MALFORMED
    deflate = _ecrire(zone, "deflate.zip", _zip(Entree("a.txt", charge=b"\xff" * 64)))
    assert _refus(lambda: _extraire(deflate)).code is Rejection.MALFORMED
    assert _arbre(zone / "tmp") == []


def test_zip_plus_gros_que_le_plafond(zone: Path) -> None:
    archive = _ecrire(zone, "gros.zip", _zip(Entree("a.bin", os.urandom(4096))))
    erreur = _refus(lambda: _extraire(archive, Limits(max_bytes=1024)))
    assert erreur.code is Rejection.TOO_LARGE
    absent = _refus(lambda: _extraire(zone / "absent.zip"))
    assert absent.code is Rejection.UNREADABLE


# --- le message ne reproduit jamais le contenu --------------------------------


def _fichiers_marques(dossier: Path) -> Iterator[tuple[str, Callable[[], object]]]:
    m = MARQUEUR
    octets = m.encode()
    cas: list[tuple[str, bytes, Callable[[Path], object]]] = [
        (
            "xml-entite",
            f'<!DOCTYPE {m} [<!ENTITY {m} "{m}">]><r>&{m};</r>'.encode(),
            inputs.load_xml,
        ),
        ("xml-balise", f"<{m}><{m}>".encode(), inputs.load_xml),
        (
            "xml-encodage",
            f'<?xml version="1.0" encoding="{m}"?><r/>'.encode(),
            inputs.load_xml,
        ),
        ("json-syntaxe", f'{{"{m}": {m}}}'.encode(), inputs.load_json),
        ("json-doublon", f'{{"{m}": 1, "{m}": 2}}'.encode(), inputs.load_json),
        ("json-profond", octets + b"[" * 1000, inputs.load_json),
        ("json-octets", b'{"a": "' + octets + b'\xff"}', inputs.load_json),
        ("toml-doublon", f"[{m}]\na = 1\n[{m}]\n".encode(), inputs.load_toml),
        ("toml-caractere", f'{m} = "\x01{m}"\n'.encode(), inputs.load_toml),
        ("csv-colonnes", f"{m},b\n{m},{m},{m}\n".encode(), inputs.load_csv),
        ("csv-guillemets", f'a,b\n"{m}"{m},1\n'.encode(), inputs.load_csv),
        ("pol-signature", octets + POL, inputs.load_registry_pol),
        (
            "pol-tronque",
            ENTETE_POL + _entree_pol(m, m, REG_SZ, _u16(m))[:-6],
            inputs.load_registry_pol,
        ),
        ("zip-chemin", _zip(Entree(f"../{m}.txt", octets)), _extraire),
        ("zip-lien", _zip(Entree(m, octets, mode=LIEN)), _extraire),
        ("zip-doublon", _zip(Entree(m, octets), Entree(m, octets)), _extraire),
        ("zip-crc", _zip(Entree(m, octets, annonce=3)), _extraire),
        # 0x07 : bloc final de type reserve, invalide pour tout decompresseur
        ("zip-deflate", _zip(Entree(m, charge=b"\x07" + octets)), _extraire),
        ("zip-texte", octets * 10, _extraire),
    ]
    for nom, contenu, lire in cas:
        fichier = _ecrire(dossier, f"cas-{nom}.bin", contenu)
        yield nom, functools.partial(lire, fichier)


def test_message_d_erreur_sans_le_contenu_du_fichier(zone: Path) -> None:
    vus = 0
    for nom, lire in _fichiers_marques(zone):
        erreur = _refus(lire)
        trace = "".join(traceback.format_exception(erreur))
        for texte in (str(erreur), repr(erreur), repr(erreur.args), trace):
            assert MARQUEUR not in texte, nom
        # ni cause ni contexte : l'exception d'un analyseur porterait le contenu
        assert erreur.__cause__ is None, nom
        assert erreur.__context__ is None, nom
        vus += 1
    assert vus == 19


# --- filets de securite -------------------------------------------------------


def test_gestionnaires_d_entites_en_defense_en_profondeur() -> None:
    # jamais atteints : le DOCTYPE est refuse avant toute declaration d'entite
    for gestionnaire in (inputs._entite_refusee, inputs._reference_externe_refusee):
        assert _refus(gestionnaire).code is Rejection.FORBIDDEN


def test_json_recursion_de_l_analyseur_traduite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # plafond de profondeur releve par l'appelant au-dela de la pile de json :
    # selon la version de Python, l'analyseur epuise sa recursion (Python 3.11)
    # ou va au bout (3.14) ; dans les deux cas, jamais de RecursionError. C'est
    # pourquoi la profondeur se compte avant l'analyse.
    limites = Limits(max_depth=1_000_000)
    profond = b"[" * 100_000 + b"]" * 100_000
    try:
        valeur = inputs.loads_json(profond, limits=limites)
    except UnsafeInputError as exc:
        assert exc.code is Rejection.TOO_DEEP
    else:
        assert isinstance(valeur, list)

    def pile_epuisee(*_: object, **__: object) -> object:
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(json, "loads", pile_epuisee)
    erreur = _refus(lambda: inputs.loads_json(b"[]", limits=limites))
    assert erreur.code is Rejection.TOO_DEEP


def test_erreurs_du_systeme_traduites(
    zone: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = _ecrire(zone, "bundle.zip", _zip(Entree("a.txt", b"a")))
    fichier = _ecrire(zone, "faits.json", b"{}")
    vrai_open = os.open

    def creation_refusee(chemin: Any, drapeaux: int, *args: Any, **kwargs: Any) -> int:
        if drapeaux & os.O_CREAT:
            raise PermissionError(13, "Permission denied", str(chemin))
        return vrai_open(chemin, drapeaux, *args, **kwargs)

    def lecture_en_panne(*_: object) -> bytes:
        raise OSError(5, "Input/output error")

    def sans_dossier_temporaire(**_: object) -> str:
        raise FileNotFoundError(2, "No such file or directory", str(zone))

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", creation_refusee)
        erreur = _refus(lambda: _extraire(archive))
    assert erreur.code is Rejection.UNREADABLE
    assert str(erreur) == "extraction impossible : Permission denied"
    assert _arbre(zone / "tmp") == []

    with monkeypatch.context() as patch:
        patch.setattr(inputs, "_lire_flux", lecture_en_panne)
        erreur = _refus(lambda: inputs.load_json(fichier))
    assert str(erreur) == "lecture impossible : Input/output error"

    with monkeypatch.context() as patch:
        patch.setattr(os, "fstat", lecture_en_panne)
        erreur = _refus(lambda: inputs.load_json(fichier))
    assert erreur.code is Rejection.UNREADABLE

    with monkeypatch.context() as patch:
        patch.setattr(tempfile, "mkdtemp", sans_dossier_temporaire)
        erreur = _refus(lambda: _extraire(archive))
    assert erreur.code is Rejection.UNREADABLE
    assert str(zone) not in str(erreur)
