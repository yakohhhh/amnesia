# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Neutralisation des données hostiles, par contexte de sortie (#45).

Fonctions de ``amnesia.render.safe`` ; leur application par chaque rendu est
vérifiée par le test de contrat (test_contrat_rendus.py).
"""

from __future__ import annotations

import csv
import html
import io
import re

import pytest
from hypothesis import given
from hypothesis import strategies as st
from markdown_it import MarkdownIt

from amnesia.render import (
    Limit,
    for_csv_cell,
    for_html,
    for_markdown,
    for_terminal,
)
from amnesia.render.safe import truncation_mark

UN_MO = 2**20
BIDI = "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
# jamais dans une sortie : C0 sauf tabulation et saut de ligne, DEL, C1, bidi,
# separateurs Unicode de ligne
INTERDITS = frozenset(
    [chr(c) for c in range(0x20) if chr(c) not in "\t\n"]
    + [chr(c) for c in range(0x7F, 0xA0)]
    + list(BIDI)
    + ["\u2028", "\u2029"]
)
PONCTUATION = re.compile(r"[!-/:-@\[-`{-~]")
ECHAPPEMENT = re.compile(r"\\[!-/:-@\[-`{-~]")
# GFM et autoliens linkify, domaines reserves (.example, RFC 2606) compris
GFM = MarkdownIt("gfm-like")
assert GFM.linkify is not None, "linkify-it-py absent"
GFM.linkify.tlds(["example", "invalid"], keep_old=True)

# fragments qui ouvrent une sequence ou cassent un format, melanges a du texte
# quelconque : st.text() seul ne les produit presque jamais ensemble
_FRAGMENTS = st.sampled_from(
    [
        "\x1b",
        "\x1b[",
        "\x1b]",
        "\x1bP",
        "\x07",
        "\x1b\\",
        "\x9b",
        "\x9c",
        "\x9d",
        "31m",
        "0;titre",
        "\r",
        "\n",
        "\t",
        "\u2028",
        "\u202e",
        "\u2066",
        "\u200b",
        "`",
        "``",
        "|",
        "\\",
        "<",
        "&",
        '"',
        "'",
        "=",
        "\uff1d",
        "@",
        "-",
        " ",
        "https://evil.example/x",
        "www.evil.example",
        "[x](y)",
    ]
)
TEXTES = st.lists(st.one_of(st.text(), _FRAGMENTS), max_size=12).map("".join)


# --- terminal -------------------------------------------------------------------


def test_osc_supprime_avec_son_contenu() -> None:
    assert for_terminal("\x1b]0;pwned\x07SRV01") == "SRV01"


@pytest.mark.parametrize(
    ("entree", "attendu"),
    [
        # chaines de controle : contenu supprime jusqu'a BEL, ST ou la fin
        ("\x1b]8;;https://evil.example/x\x1b\\clic\x1b]8;;\x1b\\", "clic"),
        ("\x9d0;pwned\x9cSRV01", "SRV01"),
        ("SRV01\x1b]0;pwned", "SRV01"),
        ("\x1bP+q544e\x1b\\SRV01", "SRV01"),
        ("\x1b_apc\x07SRV01", "SRV01"),
        ("\x1b^pm\x07\x1bXsos\x07SRV01", "SRV01"),
        # CSI, en 7 et 8 bits
        ("\x1b[2K\x1b[1ASRV01", "SRV01"),
        ("\x1b[38;2;255;0;0mSRV01\x1b[0m", "SRV01"),
        ("\x1b[?1049hSRV01", "SRV01"),
        ("\x9b31mSRV01", "SRV01"),
        # autres sequences ESC, ESC isole
        ("\x1bcSRV01", "SRV01"),
        ("\x1b(BSRV01", "SRV01"),
        ("\x1b7SRV01\x1b8", "SRV01"),
        ("SRV01\x1b", "SRV01"),
        # C0, DEL et C1 isoles, controles bidirectionnels
        ("S\x00R\x07V\x08\x7f0\x851", "SRV01"),
        ("SRV01\u202e\u2066exe.gpj\u2069", "SRV01exe.gpj"),
        ("\u200eSRV\u200f01\u061c", "SRV01"),
    ],
)
def test_for_terminal_supprime_sequences_et_controles(
    entree: str, attendu: str
) -> None:
    assert for_terminal(entree) == attendu


def test_aucune_fausse_ligne() -> None:
    assert for_terminal("SRV01\r\n✔ OK") == "SRV01 ✔ OK"
    assert for_terminal("SRV01\r✔ OK") == "SRV01✔ OK"
    assert for_terminal("SRV01\n✔ OK") == "SRV01 ✔ OK"
    assert for_terminal("a\u2028b\u2029c") == "a b c"
    # tabulation gardee ; sauts de ligne gardes dans un champ multiligne
    assert for_terminal("a\tb") == "a\tb"
    assert for_terminal("SRV01\r\n✔ OK", multiline=True) == "SRV01\n✔ OK"
    assert for_terminal("a\u2028b", multiline=True) == "a\nb"


def test_invisibles_rendus_visibles() -> None:
    assert for_terminal("SRV\u200b01") == "SRV\\u200b01"
    assert for_terminal("\ue000\udcff") == "\\ue000\\udcff"
    # espaces Unicode, accents et texte ordinaire inchanges
    assert for_terminal("été\u00a0: «\u202fx\u202f»") == "été\u00a0: «\u202fx\u202f»"
    assert for_terminal("09:30 SRV-FILE l'hôte <a>") == "09:30 SRV-FILE l'hôte <a>"


@given(TEXTES)
def test_for_terminal_jamais_de_controle(texte: str) -> None:
    rendu = for_terminal(texte)
    assert not INTERDITS & set(rendu)
    assert "\n" not in rendu
    assert all(c == "\t" or c.isprintable() or c.isspace() for c in rendu)
    multiligne = for_terminal(texte, multiline=True)
    assert not INTERDITS & set(multiligne)
    assert multiligne.count("\n") <= texte.count("\n") + texte.count("\u2028") + (
        texte.count("\u2029")
    )


# --- troncature -----------------------------------------------------------------


def test_chaine_de_1_mo_tronquee_au_plafond() -> None:
    marque = "… [tronqué, 1048576 caractères]"
    assert truncation_mark(UN_MO) == marque
    assert for_terminal("A" * UN_MO, limit=Limit.NAME) == "A" * 256 + marque
    assert for_terminal("A" * UN_MO) == "A" * 1024 + marque
    assert for_terminal("A" * UN_MO, limit=Limit.EXCERPT) == "A" * 4096 + marque
    assert for_html("A" * UN_MO, limit=Limit.NAME) == "A" * 256 + marque
    assert for_csv_cell("=" * UN_MO, limit=Limit.NAME) == "'" + "=" * 256 + marque
    assert for_markdown("A" * UN_MO, limit=Limit.NAME) == (
        "A" * 256 + "… \\[tronqué\\, 1048576 caractères\\]"
    )
    assert for_markdown("A" * UN_MO, limit=Limit.NAME, code=True) == (
        "`" + "A" * 256 + "`… \\[tronqué\\, 1048576 caractères\\]"
    )


def test_plafonds_par_type_de_champ() -> None:
    assert (Limit.NAME, Limit.TEXT, Limit.EXCERPT) == (256, 1024, 4096)
    # au plafond, rien n'est coupe
    assert for_terminal("A" * 256, limit=Limit.NAME) == "A" * 256
    assert for_terminal("A" * 257, limit=Limit.NAME).endswith(
        "[tronqué, 257 caractères]"
    )
    with pytest.raises(ValueError, match="plafond invalide"):
        for_terminal("x", limit=0)


def test_coupe_avant_nettoyage() -> None:
    # une sequence coupee par le plafond est supprimee comme les autres
    rendu = for_terminal("\x1b]0;" + "p" * 300, limit=Limit.NAME)
    assert rendu == "… [tronqué, 304 caractères]"
    rendu = for_terminal("SRV01" + "\x1b[2K" * UN_MO, limit=Limit.NAME)
    assert rendu == f"SRV01… [tronqué, {5 + 4 * UN_MO} caractères]"


# --- Markdown -------------------------------------------------------------------


def test_for_markdown_echappe_toute_la_ponctuation_ascii() -> None:
    ponctuation = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
    assert for_markdown(ponctuation) == "".join("\\" + c for c in ponctuation)
    assert for_markdown("<script>alert(1)</script>") == (
        "\\<script\\>alert\\(1\\)\\<\\/script\\>"
    )
    assert for_markdown("a|b") == "a\\|b"
    # lettres, chiffres, accents et espaces inchanges ; espaces de bord retirees
    assert for_markdown("  Le journal Security été  ") == "Le journal Security été"


def test_for_markdown_sur_une_ligne_et_sans_controle() -> None:
    assert for_markdown("SRV01\r\n✔ OK") == "SRV01 ✔ OK"
    assert for_markdown("\x1b]0;pwned\x07SRV01") == "SRV01"
    assert for_markdown("SRV\u200b01") == "SRV\\\\u200b01"


@pytest.mark.parametrize(
    ("entree", "attendu"),
    [
        ("winrm://srv-file.exemple.invalid", "`winrm://srv-file.exemple.invalid`"),
        ("a`b", "``a`b``"),
        ("``a`b``", "``` ``a`b`` ```"),
        ("`", "`` ` ``"),
        ("a\\b", "`a\\b`"),
        ("  x  ", "`x`"),
        ("", ""),
        ("\x1b[2K", ""),
    ],
)
def test_span_de_code(entree: str, attendu: str) -> None:
    assert for_markdown(entree, code=True) == attendu


def test_span_de_code_en_tableau() -> None:
    assert for_markdown("a|b", code=True) == "`a|b`"
    assert for_markdown("a|b", code=True, table=True) == "`a\\|b`"
    # une phrase echappe deja la barre, en tableau comme ailleurs
    assert for_markdown("a|b", table=True) == "a\\|b"


@pytest.mark.parametrize(
    ("entree", "attendu"),
    [
        ("a\\|b", "a\\\\\\|b"),
        (
            "a\\|<img src=x onerror=alert(1)>",
            "a\\\\\\|\\<img src\\=x onerror\\=alert\\(1\\)\\>",
        ),
        ("a\\\\|https://evil.example/x", None),
    ],
)
def test_barre_oblique_inverse_devant_une_barre_en_tableau(
    entree: str, attendu: str | None
) -> None:
    # « `a\\|b` » : barre echappee pour un parseur, barre oblique inverse
    # echappee puis fin de cellule pour un autre, et la suite sort du span
    cellule = for_markdown(entree, code=True, table=True)
    assert "`" not in cellule
    if attendu is not None:
        assert cellule == attendu
    # chaque barre verticale suit un nombre impair de barres obliques inverses
    assert re.search(r"(?<!\\)(?:\\\\)*\|", cellule) is None
    # hors tableau, le span de code reste sans ambiguite
    assert for_markdown(entree, code=True) == f"`{entree}`"


@given(TEXTES)
def test_for_markdown_litteral(texte: str) -> None:
    attendu = " ".join(for_terminal(texte).split())
    phrase = for_markdown(texte)
    assert not INTERDITS & set(phrase)
    assert "\n" not in phrase
    # toute ponctuation ASCII est precedee d'une barre oblique inverse
    assert PONCTUATION.search(ECHAPPEMENT.sub("", phrase)) is None
    for rendu in (phrase, for_markdown(texte, code=True)):
        jetons = [
            j for b in GFM.parse(f"- {rendu}\n") for j in [b, *(b.children or [])]
        ]
        assert not {"link_open", "image", "html_inline", "html_block"} & {
            j.type for j in jetons
        }
        affiche = html.unescape(re.sub(r"<[^>]*>", "", GFM.render(f"- {rendu}\n")))
        assert " ".join(affiche.split()) == attendu


# --- HTML -----------------------------------------------------------------------


def test_for_html_echappe_balises_et_guillemets() -> None:
    assert for_html("<img src=x onerror=alert(1)>") == (
        "&lt;img src=x onerror=alert(1)&gt;"
    )
    assert for_html("\"' onmouseover=alert(1) x='") == (
        "&quot;&#x27; onmouseover=alert(1) x=&#x27;"
    )
    assert for_html("a & b") == "a &amp; b"
    assert for_html("\x1b]0;pwned\x07SRV01\u202e\r\nOK") == "SRV01 OK"


@given(TEXTES)
def test_for_html_sans_balise(texte: str) -> None:
    rendu = for_html(texte)
    assert not {"<", ">", '"', "'"} & set(rendu)
    assert not INTERDITS & set(rendu)
    assert html.unescape(rendu) == for_terminal(texte)


# --- CSV ------------------------------------------------------------------------


def test_for_csv_cell_dde() -> None:
    assert for_csv_cell("=cmd|' /C calc'!A0") == "'=cmd|' /C calc'!A0"


@pytest.mark.parametrize(
    "cellule",
    [
        '=HYPERLINK("https://evil.example/x","clic")',
        "+1+cmd|' /C calc'!A0",
        "-2+3",
        "@SUM(1+1)*cmd|' /C calc'!A0",
        "\t=1+1",
        "\r=1+1",
        "\n=1+1",
        "\uff1d1+1",
        "\uff0b1",
        "\uff0d1",
        "\uff201",
        "\ufe661+1",
    ],
)
def test_for_csv_cell_prefixe_les_formules(cellule: str) -> None:
    assert for_csv_cell(cellule) == "'" + cellule


@pytest.mark.parametrize("cellule", ["SRV01", "", " =1", "1-2", "a@b", "'=1"])
def test_for_csv_cell_sans_formule(cellule: str) -> None:
    assert for_csv_cell(cellule) == cellule


def test_for_csv_cell_nettoyee() -> None:
    # sequences et controles supprimes avant le test du premier caractere
    assert for_csv_cell("\x1b[2K=1+1") == "'=1+1"
    assert for_csv_cell("\x00@x") == "'@x"
    # cellule sur plusieurs lignes : sauts de ligne et tabulations gardes
    assert for_csv_cell("a\r\nb\tc\u202e") == "a\r\nb\tc"


@given(st.lists(TEXTES, min_size=1, max_size=4))
def test_for_csv_cell_quote_all(ligne: list[str]) -> None:
    cellules = [for_csv_cell(c) for c in ligne]
    for cellule in cellules:
        assert cellule[:1] not in {"=", "+", "-", "@", "\t", "\r", "\n", "\uff1d"}
        assert not (INTERDITS - {"\r"}) & set(cellule)
    flux = io.StringIO(newline="")
    csv.writer(flux, quoting=csv.QUOTE_ALL).writerow(cellules)
    relue = next(csv.reader(io.StringIO(flux.getvalue(), newline="")))
    assert relue == cellules
