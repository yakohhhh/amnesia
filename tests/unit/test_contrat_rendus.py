# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Contrat des rendus face aux données hostiles (#45).

Le corpus tests/fixtures/hostile/charges.json est injecté dans les noms d'hôtes,
de GPO et de canaux et dans les tags d'un rapport (fixture report-min.json),
puis chaque rendu de ``RENDERERS`` doit, pour chaque charge et chaque
regroupement :

- n'émettre aucun ESC, contrôle C0 (hors saut de ligne et tabulation), DEL,
  contrôle C1, contrôle bidirectionnel ni séparateur Unicode de ligne ;
- produire autant de lignes qu'avec un nom d'hôte ordinaire ;
- rester borné, une valeur démesurée étant tronquée et marquée ;
- afficher le texte attendu de la charge, et jamais ses fragments cachés ;
- passer les vérifications propres à son format (``MOTEURS``).

HTML (#77) et CSV (#76) ajoutent leur entrée à ``MOTEURS`` à leur arrivée.
"""

from __future__ import annotations

import copy
import functools
import html
import json
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from markdown_it import MarkdownIt
from markdown_it.token import Token

from amnesia.cli import main
from amnesia.render import (
    GROUP_BY,
    RENDERERS,
    RenderOptions,
    render_report,
)

RACINE = Path(__file__).resolve().parents[2]
FIXTURE = RACINE / "tests" / "fixtures" / "report-min.json"
CORPUS = RACINE / "tests" / "fixtures" / "hostile" / "charges.json"

TEMOIN = "SRV01"
BIDI = "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
INTERDITS = frozenset(
    [chr(c) for c in range(0x20) if chr(c) not in "\t\n"]
    + [chr(c) for c in range(0x7F, 0xA0)]
    + list(BIDI)
    + ["\u2028", "\u2029"]
)
# ecart de taille toleree avec le rendu temoin : une quinzaine de champs
# hostiles, chacun plafonne a 1 024 caracteres avant echappement
ECART_MAX = 64 * 1024

# parseurs de reference : CommonMark strict, et GFM avec tableaux, texte barre
# et autoliens (linkify : https://, www., adresses, domaines nus). Comme GFM,
# linkify accepte ici tout domaine, reserves compris (.example, RFC 2606).
COMMONMARK = MarkdownIt("commonmark")
GFM = MarkdownIt("gfm-like")
assert GFM.linkify is not None, "linkify-it-py absent"
GFM.linkify.tlds(["example", "invalid"], keep_old=True)
ACTIFS = frozenset({"link_open", "image", "html_inline", "html_block"})
_CODE = re.compile(r"<code[^>]*>.*?</code>", re.S)
# mention ou reference (GitHub) en debut de mot
_REFERENCE = re.compile(r"(?<!\w)[@#]\w")
# tableau GFM : lignes consecutives qui commencent par une barre ; separateur de
# cellule : barre non precedee d'une barre oblique inverse
_TABLEAU = re.compile(r"(?m)(?:^\|.*\n)+")
_BARRE = re.compile(r"(?<!\\)\|")
# meme separateur pour un parseur qui compte les barres obliques inverses : deux
# barres obliques forment une barre oblique echappee, et la barre verticale qui
# les suit coupe la cellule
_BARRE_STRICTE = re.compile(r"(?<!\\)(?:\\\\)*\|")


@dataclass(frozen=True)
class Charge:
    """Charge hostile du corpus."""

    nom: str
    valeur: str
    affiche: str | None
    jamais: tuple[str, ...] = ()

    @property
    def longueur(self) -> int:
        return len(self.valeur)


def _charges() -> list[Charge]:
    donnees = json.loads(CORPUS.read_text(encoding="utf-8"))
    charges = []
    for c in donnees["charges"]:
        if "valeur" in c:
            valeur = c["valeur"]
        else:
            fois, reste = divmod(c["longueur"], len(c["motif"]))
            assert reste == 0, c["nom"]
            valeur = c["motif"] * fois
        charges.append(
            Charge(
                nom=c["nom"],
                valeur=valeur,
                affiche=c.get("affiche", valeur),
                jamais=tuple(c.get("jamais", ())),
            )
        )
    return charges


CHARGES = _charges()


@functools.cache
def _base() -> dict[str, Any]:
    donnees: dict[str, Any] = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return donnees


def injecter(valeur: str) -> dict[str, Any]:
    """Rapport dont les valeurs venues de la cible portent ``valeur``."""
    donnees = copy.deepcopy(_base())
    gaps, resultats = donnees["gaps"], donnees["results"]
    # noms d'hotes : cibles de l'audit, des resultats et des Gaps
    donnees["targets"][0]["id"] = valeur
    for element in (*resultats, *gaps):
        element["target"] = valeur
    # noms de canal et de GPO dans les questions, raisons et messages
    gaps[0]["question"] = f"Qui a vidé le canal {valeur} ?"
    gaps[0]["reason"] = f"Le canal {valeur} a été vidé il y a 4 jours."
    gaps[1]["question"] = f"Quelles commandes la GPO {valeur} masque-t-elle ?"
    gaps[1]["reason"] = f"La GPO {valeur} désactive la journalisation."
    # check inconnu (titre de domaine) et identifiants d'un rapport modifie
    gaps[1]["check_id"] = f"{valeur}.gpo"
    sysmon = next(r for r in resultats if r["check_id"] == "win.sysmon")
    sysmon["check_id"] = f"win.{valeur}"
    sysmon["message"] = f"accès refusé à la GPO {valeur}"
    donnees["run"]["id"] = valeur
    donnees["run"]["started_at"] = valeur
    donnees["tool"]["version"] = valeur
    # tags et ressource : preuves que les rendus actuels n'affichent pas
    gaps[0]["resource"] = valeur
    gaps[0]["evidence"]["details"]["tags"] = {"Name": valeur}
    return donnees


# --- moteurs de rendu soumis au contrat -----------------------------------------


def _jetons(parseur: MarkdownIt, source: str) -> Iterator[Token]:
    for bloc in parseur.parse(source):
        yield bloc
        yield from bloc.children or ()


def _texte_affiche(html_rendu: str) -> str:
    return html.unescape(re.sub(r"<[^>]*>", "", html_rendu))


def _affiche_markdown(sortie: str) -> str:
    return _texte_affiche(GFM.render(sortie))


def _verifier_terminal(sortie: str) -> None:
    # rien d'invisible : chaque caractere s'affiche
    assert all(c == "\n" or c.isprintable() for c in sortie)


def _verifier_markdown(sortie: str) -> None:
    for parseur in (COMMONMARK, GFM):
        types = {j.type for j in _jetons(parseur, sortie)}
        assert not ACTIFS & types, ACTIFS & types
    # chaque ligne d'un tableau a autant de separateurs de cellule (barre non
    # echappee, regle de GFM) que son en-tete ; markdown-it completerait ou
    # tronquerait la ligne en silence
    tableaux = _TABLEAU.findall(sortie)
    assert tableaux
    for tableau in tableaux:
        lignes = tableau.splitlines()
        for separateur in (_BARRE, _BARRE_STRICTE):
            barres = {len(separateur.findall(ligne)) for ligne in lignes}
            assert len(barres) == 1, tableau
    assert all(c == "\n" or c.isprintable() for c in sortie)
    # cmark-gfm (GitHub) cherche liens, mentions et references dans le texte une
    # fois desechappe, ce que markdown-it ne fait pas : linkify repasse donc sur
    # le texte affiche hors des spans de code, ou rien ne doit venir du rapport
    hors_code = _texte_affiche(_CODE.sub("", GFM.render(sortie)))
    assert GFM.linkify is not None
    assert not GFM.linkify.test(hors_code), GFM.linkify.match(hors_code)
    assert _REFERENCE.search(hors_code) is None, hors_code


@dataclass(frozen=True)
class Moteur:
    """Rendu soumis au contrat, et vérifications propres à son format."""

    format: str
    affiche: Callable[[str], str] = field(repr=False)
    """Texte vu par le lecteur à partir de la sortie brute."""
    verifier: Callable[[str], None] = field(repr=False)


MOTEURS = (
    Moteur("text", affiche=str, verifier=_verifier_terminal),
    Moteur("md", affiche=_affiche_markdown, verifier=_verifier_markdown),
    # HTML (#77) et CSV (#76) : ajouter ici leur moteur et ses verifications
)


def test_tout_rendu_est_soumis_au_contrat() -> None:
    assert {m.format for m in MOTEURS} == set(RENDERERS)


@functools.cache
def _temoin(fmt: str, group_by: str) -> str:
    return render_report(injecter(TEMOIN), fmt, RenderOptions(group_by=group_by))


@pytest.mark.parametrize("moteur", MOTEURS, ids=lambda m: m.format)
@pytest.mark.parametrize("charge", CHARGES, ids=lambda c: c.nom)
@pytest.mark.parametrize("group_by", GROUP_BY)
def test_contrat(moteur: Moteur, charge: Charge, group_by: str) -> None:
    options = RenderOptions(group_by=group_by)
    sortie = render_report(injecter(charge.valeur), moteur.format, options)
    temoin = _temoin(moteur.format, group_by)
    assert not INTERDITS & set(sortie)
    # aucune fausse ligne
    assert sortie.count("\n") == temoin.count("\n")
    assert len(sortie.splitlines()) == len(temoin.splitlines())
    # taille bornee, valeur demesuree tronquee et marquee
    assert len(sortie) < len(temoin) + ECART_MAX
    affiche = moteur.affiche(sortie)
    if charge.longueur > 1024:
        assert f"… [tronqué, {charge.longueur} caractères]" in affiche
    if charge.affiche is not None:
        assert charge.affiche in affiche
    if charge.longueur <= 256:
        # la suite du champ, texte d'amnesia compris, n'est jamais avalee
        assert f"le canal {charge.affiche} a été vidé il y a 4 jours." in affiche
        assert f"accès refusé à la GPO {charge.affiche}" in affiche
    for fragment in charge.jamais:
        assert fragment not in affiche
    moteur.verifier(sortie)


@pytest.mark.parametrize("charge", CHARGES, ids=lambda c: c.nom)
def test_couleurs_seulement_d_amnesia(charge: Charge) -> None:
    options = RenderOptions(color=True)
    sortie = render_report(injecter(charge.valeur), "text", options)
    assert "\x1b[" in sortie
    # une fois retirees les couleurs (SGR) d'amnesia, plus aucun ESC
    assert "\x1b" not in re.sub(r"\x1b\[[0-9;]*m", "", sortie)
    assert not (INTERDITS - {"\x1b"}) & set(sortie)


# --- criteres d'acceptation de #45 --------------------------------------------


def test_titre_osc_par_la_cli(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    chemin = tmp_path / "rapport.json"
    donnees = injecter("\x1b]0;pwned\x07SRV01")
    chemin.write_text(json.dumps(donnees), encoding="utf-8")
    assert main(["render", str(chemin), "--format", "text"]) == 0
    sortie = capsys.readouterr().out
    assert "  Cible : SRV01\n" in sortie
    assert "pwned" not in sortie
    assert "\x1b" not in sortie
    assert not any(0x80 <= ord(c) <= 0x9F for c in sortie)
    assert not set(BIDI) & set(sortie)


@pytest.mark.parametrize("fmt", sorted(RENDERERS))
@pytest.mark.parametrize(
    "hote", ["SRV01\r✔ OK", "SRV01\n✔ OK", "SRV01\r\n✔ OK", "\r\n✔ OK\r\n"]
)
def test_aucune_ligne_supplementaire(fmt: str, hote: str) -> None:
    temoin = render_report(injecter(TEMOIN), fmt)
    sortie = render_report(injecter(hote), fmt)
    assert len(sortie.splitlines()) == len(temoin.splitlines())
    assert not any(ligne.startswith("✔") for ligne in sortie.splitlines())


def _champs_markdown(valeur: str) -> str:
    return render_report(injecter(valeur), "md")


@pytest.mark.parametrize(
    "valeur", ["<script>alert(1)</script>", "[lien](https://example.com)", "a|b"]
)
def test_markdown_litteral_pour_commonmark(valeur: str) -> None:
    sortie = _champs_markdown(valeur)
    for parseur in (COMMONMARK, GFM):
        assert not ACTIFS & {j.type for j in _jetons(parseur, sortie)}
    # question, raison et cible (liste) : le texte affiche est la valeur exacte
    affiche = _texte_affiche(COMMONMARK.render(sortie))
    assert f"Qui a vidé le canal {valeur} ?" in affiche
    assert f"le canal {valeur} a été vidé" in affiche
    assert f"Cible : {valeur}\n" in affiche
    # message d'erreur, dans une cellule du tableau GFM
    assert f"accès refusé à la GPO {valeur}" in _affiche_markdown(sortie)


def test_tableau_markdown_avec_barre() -> None:
    sortie = _champs_markdown("a|b")
    rendu = GFM.render(sortie)
    # ligne win.sysmon : 5 cellules, check, cible et message intacts
    (ligne,) = [tr for tr in re.findall(r"<tr>.*?</tr>", rendu, re.S) if "GPO" in tr]
    cellules = [_texte_affiche(c) for c in re.findall(r"<td>(.*?)</td>", ligne, re.S)]
    assert cellules == [
        "win.a|b",
        "a|b",
        "erreur",
        "accès refusé",
        "accès refusé à la GPO a|b",
    ]


@pytest.mark.parametrize("hote", ["https://evil.example/x", "www.evil.example"])
def test_markdown_sans_autolien_gfm(hote: str) -> None:
    # temoin : le parseur transforme bien la valeur brute en lien
    assert "link_open" in {j.type for j in _jetons(GFM, f"Cible : {hote}\n")}
    sortie = _champs_markdown(hote)
    assert "link_open" not in {j.type for j in _jetons(GFM, sortie)}
    assert "<a " not in GFM.render(sortie)
    assert f"Cible : {hote}\n" in _affiche_markdown(sortie)


def test_chaine_de_1_mo_dans_un_rendu() -> None:
    sortie = render_report(injecter("A" * 2**20), "text")
    assert f"  Cible : {'A' * 256}… [tronqué, 1048576 caractères]\n" in sortie
    assert len(sortie) < 32 * 1024
    # meme plafond en Markdown : la marque suit le span, ponctuation echappee
    markdown = render_report(injecter("A" * 2**20), "md")
    marque = "… \\[tronqué\\, 1048576 caractères\\]"
    assert f"  - Cible : `{'A' * 256}`{marque}\n" in markdown
    assert f" | `{'A' * 256}`{marque} | erreur | " in markdown
    assert len(markdown) < 32 * 1024


# lettres pleine chasse ou accentuees que le repli ASCII de l'encodage de sortie
# ramene a un schema ou a « www » : jamais un lien, meme apres le repli
LIENS_REPLIES = [
    "\uff48\uff54\uff54\uff50\uff53://evil.example/x",
    "http\u015b://evil.example/x",
    "\uff4d\uff41\uff49\uff4c\uff54\uff4f:a@evil.example",
    "\uff57\uff57\uff57.evil.example",
    "\u1e81\u1e81\u1e81.evil.example",
    # points de suspension, replies en « ... »
    "www\u2026evil.example",
]


@pytest.mark.parametrize("encodage", ["cp1252", "cp850", "ascii"])
@pytest.mark.parametrize("valeur", LIENS_REPLIES)
@pytest.mark.parametrize("group_by", GROUP_BY)
def test_markdown_lettres_repliees_sans_lien(
    encodage: str, valeur: str, group_by: str
) -> None:
    options = RenderOptions(encoding=encodage, group_by=group_by)
    sortie = render_report(injecter(valeur), "md", options)
    sortie.encode(encodage)
    for parseur in (COMMONMARK, GFM):
        assert not ACTIFS & {j.type for j in _jetons(parseur, sortie)}
