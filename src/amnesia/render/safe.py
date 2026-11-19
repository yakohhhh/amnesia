# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Neutralisation des données hostiles dans les rendus (#45).

Les chaînes affichées par amnesia viennent des cibles : noms de GPO, d'hôtes et
de canaux, configuration Sysmon, noms d'applications Entra, tags AWS. Une cible
compromise contrôle ces valeurs (docs/threat-model.md, H4, M01 et M02), et le
rapport JSON est un fichier modifiable. Toute valeur qui en vient passe donc par
la fonction de son contexte de sortie, jamais par une interpolation directe :

- ``for_terminal()`` : terminal (``--format text``) ;
- ``for_markdown()`` : Markdown GFM (``--format md``) ;
- ``for_html()`` : HTML (rapport #77) ;
- ``for_csv_cell()`` : cellule d'un export CSV ouvert dans un tableur (#76).

Toutes commencent par le même nettoyage. Les séquences d'échappement ECMA-48
(CSI, OSC, DCS...) sont supprimées avec leur contenu, ainsi que les contrôles
C0 (sauf la tabulation et le saut de ligne), DEL, les contrôles C1 et les
contrôles bidirectionnels (Trojan Source, CVE-2021-42574). Le retour chariot
est supprimé et, dans un champ monoligne, un saut de ligne devient une espace,
comme toute suite de blancs : aucune fausse ligne ne peut apparaître, ni par
saut de ligne, ni par remplissage. Une chaîne de contrôle sans fin ne perd que
son introducteur, pas le reste du champ. Les autres caractères invisibles
(U+200B, zones privées, surrogates isolés...) restent, mais sous leur forme
échappée (``\\u200b``) : l'analyste voit qu'une valeur en contient.

Troncature : une valeur plus longue que le plafond de son type de champ
(``Limit``) est coupée, puis suivie de la marque « … [tronqué, N caractères] »,
où N est sa longueur d'origine. La valeur complète reste dans le rapport JSON.
La coupe précède le nettoyage : celui d'une valeur de 1 Mo ne porte que sur ses
premiers caractères.

Chaque rendu de ``RENDERERS`` passe le test de contrat
(tests/unit/test_contrat_rendus.py) sur le corpus de charges hostiles
(tests/fixtures/hostile/) ; un nouveau rendu (HTML, CSV) y ajoute les
vérifications propres à son format.
"""

from __future__ import annotations

import html
import re
import unicodedata
from enum import IntEnum


class Limit(IntEnum):
    """Plafond d'affichage d'une valeur, en caractères, selon son type de champ."""

    NAME = 256
    """Nom ou identifiant : hôte, cible, GPO, canal, tag, check, exécution."""
    TEXT = 1024
    """Phrase : question, raison, message d'erreur."""
    EXCERPT = 4096
    """Extrait de preuve."""


# Sequences ECMA-48, retirees avec leur contenu, dans cet ordre :
# - chaines de controle OSC, DCS, SOS, PM et APC (ESC ] P X ^ _, ou C1), jusqu'a
#   leur fin : BEL ou ST (ESC \ ou C1). Sans fin, seul l'introducteur est retire
#   (alternatives suivantes et _SUPPRIMES) : le reste du champ, texte d'amnesia
#   compris, n'est pas a la merci d'un seul caractere. Le contenu ne traverse ni
#   ESC ni introducteur C1 : la recherche reste lineaire ;
# - CSI (ESC [ ou C1) : parametres, intermediaires et octet final ;
# - autres sequences ESC : intermediaires et octet final (ESC c, ESC ( B...).
_SEQUENCES = re.compile(
    r"(?:\x1b[\]PX^_]|[\x90\x98\x9d\x9e\x9f])"
    r"[^\x07\x1b\x90\x98\x9c-\x9f]*(?:\x07|\x1b\\|\x9c)"
    r"|(?:\x1b\[|\x9b)[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]?"
    r"|\x1b[\x20-\x2f]*[\x30-\x7e]?"
)
# controles bidirectionnels : memes caracteres que ceux que dumps_report()
# echappe dans le rapport JSON (amnesia.report)
_BIDI = "\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069"
# C0 sauf tabulation et saut de ligne, DEL, C1, bidi ; la variante CSV garde le
# retour chariot (cellule sur plusieurs lignes, entre guillemets)
_SUPPRIMES = re.compile(f"[\x00-\x08\x0b-\x1f\x7f-\x9f{_BIDI}]")
_SUPPRIMES_CSV = re.compile(f"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f{_BIDI}]")
_SAUTS = re.compile("[\n\u2028\u2029]")

# blancs d'un champ monoligne : espace, tabulation, espaces Unicode (categorie
# Zs) et caracteres imprimables sans dessin (braille vide, remplissages hangul).
# Une suite de blancs, ou une tabulation, devient une seule espace : sans cela,
# « SRV01 » suivi de 200 espaces et d'un faux constat simulerait une autre ligne
# ou une autre colonne. Une espace insecable isolee reste telle quelle.
_BLANC = " \t\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000\u2800\u3164\u115f\u1160\uffa0"
_BLANCS = re.compile(f"[{_BLANC}]{{2,}}|\t")

# ponctuation ASCII, toute echappable par une barre oblique inverse (CommonMark)
_PONCTUATION = re.compile(r"[!-/:-@\[-`{-~]")
_ACCENTS_GRAVES = re.compile("`+")

# premier caractere d'une formule de tableur, formes pleine chasse et petites
# formes comprises : NFKC ramene U+FF1D et U+FE66 a « = » (OWASP, CSV Injection)
_FORMULES = frozenset("=+-@")
_SAUTS_EN_TETE = frozenset("\t\r\n")


def _visible(caractere: str) -> str:
    # \u200b, \ue000, \udcff : la valeur reste lisible par l'analyste
    return caractere.encode("unicode_escape").decode("ascii")


def _nettoyer(texte: str, *, monoligne: bool, retour_chariot: bool = False) -> str:
    """``texte`` sans séquence ni contrôle, sur une ligne avec ``monoligne``."""
    texte = _SEQUENCES.sub("", texte)
    texte = (_SUPPRIMES_CSV if retour_chariot else _SUPPRIMES).sub("", texte)
    if monoligne:
        texte = _BLANCS.sub(" ", _SAUTS.sub(" ", texte))
    else:
        texte = _SAUTS.sub("\n", texte)
    if texte.isprintable():
        return texte
    # restent tabulations, sauts de ligne, espaces Unicode (gardes) et autres
    # caracteres invisibles (rendus visibles)
    return "".join(
        c
        if c.isprintable() or c in "\t\n\r" or unicodedata.category(c) == "Zs"
        else _visible(c)
        for c in texte
    )


def _tronquer(texte: str, limite: int) -> tuple[str, int | None]:
    """Début de ``texte`` et, s'il a été coupé, sa longueur d'origine."""
    if limite < 1:
        raise ValueError(f"plafond invalide : {limite!r}")
    if len(texte) <= limite:
        return texte, None
    return texte[:limite], len(texte)


def truncation_mark(length: int) -> str:
    """Marque ajoutée après une valeur tronquée : « … [tronqué, N caractères] »."""
    return f"… [tronqué, {length} caractères]"


def for_terminal(text: str, *, limit: int = Limit.TEXT, multiline: bool = False) -> str:
    """``text`` affichable dans un terminal, sans effet sur celui-ci.

    Aucune séquence d'échappement (titre de fenêtre, hyperlien OSC 8, couleur,
    effacement de ligne), aucun contrôle C0, DEL, C1 ni bidirectionnel :
    ``"\\x1b]0;pwned\\x07SRV01"`` s'affiche ``SRV01``. Le retour chariot est
    supprimé. Sauf avec ``multiline``, le champ tient sur une ligne : un saut de
    ligne (``\\n``, U+2028, U+2029) devient une espace, et une suite de blancs
    (espaces, tabulations, espaces Unicode) une seule espace, pour qu'un
    remplissage ne simule ni autre ligne ni autre colonne. Une chaîne de
    contrôle sans fin (OSC, DCS, APC... sans BEL ni ST) ne perd que son
    introducteur : le reste du champ est gardé. Au-delà de ``limit``
    caractères, ``text`` est tronqué et marqué (``truncation_mark()``).
    """
    tete, longueur = _tronquer(text, limit)
    rendu = _nettoyer(tete, monoligne=not multiline)
    return rendu if longueur is None else rendu + truncation_mark(longueur)


def _span_de_code(valeur: str) -> str:
    if not valeur:
        return ""
    # delimiteur plus long que toute suite d'accents graves de la valeur : le
    # span ne peut pas se refermer avant la fin
    plus_longue = max(map(len, _ACCENTS_GRAVES.findall(valeur)), default=0)
    delimiteur = "`" * (plus_longue + 1)
    if (
        valeur.startswith("`")
        or valeur.endswith("`")
        or (valeur.startswith(" ") and valeur.endswith(" ") and valeur.strip(" "))
    ):
        # le parseur retire une espace de chaque cote : un accent grave colle au
        # delimiteur l'allongerait, et les espaces de la valeur sont gardees
        valeur = f" {valeur} "
    return f"{delimiteur}{valeur}{delimiteur}"


def for_markdown(text: str, *, limit: int = Limit.TEXT) -> str:
    """``text`` en span de code, à insérer dans une ligne Markdown (GFM).

    Le texte est nettoyé comme pour le terminal, tient sur une ligne et perd ses
    espaces de début et de fin. Il devient un span de code, dont le contenu
    n'est jamais interprété : ni HTML, ni lien, ni image, ni emphase, ni
    entité. Le délimiteur est plus long que la plus longue suite d'accents
    graves du texte, et le span ne contient aucune barre oblique inverse
    d'échappement.

    Pourquoi du code, et non un échappement par barre oblique inverse : cmark-gfm
    (GitHub) cherche ses liens automatiques dans le texte une fois déséchappé.
    ``https\\:\\/\\/evil\\.example``, ``www\\.evil\\.example``,
    ``a\\@evil\\.example``, ``\\@compte`` et ``\\#1`` y redeviennent un lien, une
    adresse, une mention ou une référence. Seul un span de code y échappe ; la
    phrase d'une question ou d'un message s'affiche donc en chasse fixe.

    Barre verticale : GFM découpe une ligne de tableau en cellules avant toute
    analyse, spans de code compris, et les parseurs ne lisent pas tous de la
    même façon une barre oblique inverse suivie d'une barre dans un span. Le
    texte est donc découpé sur ``|`` : chaque segment a son span, et les
    segments sont joints par ``\\|``, hors de tout span : ``a|b`` donne deux
    spans. Ce rendu vaut dans un tableau comme ailleurs.

    Au-delà de ``limit`` caractères, ``text`` est tronqué et marqué ; la marque
    suit le span, ponctuation échappée.
    """
    tete, longueur = _tronquer(text, limit)
    valeur = _nettoyer(tete, monoligne=True).strip()
    rendu = "\\|".join(_span_de_code(segment) for segment in valeur.split("|"))
    if longueur is None:
        return rendu
    return rendu + _PONCTUATION.sub(r"\\\g<0>", truncation_mark(longueur))


def for_html(text: str, *, limit: int = Limit.TEXT) -> str:
    """``text`` à insérer dans du HTML : contenu d'élément ou attribut cité.

    Nettoyé comme pour le terminal (sur une ligne), puis ``html.escape()`` avec
    ``quote=True`` : ``<``, ``>``, ``&`` et les guillemets ``"`` et ``'``
    deviennent des entités. Au-delà de ``limit`` caractères, ``text`` est
    tronqué et marqué.

    En attribut, la valeur doit être entre guillemets (``title="..."``) : sans
    guillemets, une espace suffit à ouvrir un autre attribut. L'échappement ne
    dit rien du sens de la valeur : jamais dans ``href``, ``src``, ``style`` ni
    un attribut ``on*`` (``javascript:alert(1)`` ne contient aucun caractère à
    échapper), ni dans ``<script>`` ou ``<style>``.

    Exigences du rapport HTML (#77) : échappement automatique de Jinja2 activé
    et jamais ``|safe`` sur une donnée de la cible ; balise meta CSP
    ``default-src 'none'; style-src 'unsafe-inline'; img-src data:;
    font-src data:; base-uri 'none'; form-action 'none'`` (``font-src``
    explicite, sinon les polices embarquées sont bloquées ; ``base-uri`` et
    ``form-action`` ne retombent pas sur ``default-src``) ; aucun JavaScript ;
    CSS, polices et logo embarqués en ``data:``, car une ressource externe
    signale à un tiers l'ouverture du rapport.
    """
    tete, longueur = _tronquer(text, limit)
    rendu = html.escape(_nettoyer(tete, monoligne=True), quote=True)
    return rendu if longueur is None else rendu + truncation_mark(longueur)


def for_csv_cell(text: str, *, limit: int = Limit.TEXT) -> str:
    """``text`` en cellule CSV qu'un tableur n'évalue jamais comme une formule.

    Nettoyé comme pour le terminal, tabulations et sauts de ligne gardés : une
    cellule peut tenir sur plusieurs lignes. Une cellule qui commence par
    ``=``, ``+``, ``-``, ``@`` (ou leur forme pleine chasse, U+FF1D par
    exemple), une tabulation, un retour chariot ou un saut de ligne est
    préfixée par ``'`` : ``"=cmd|' /C calc'!A0"`` devient
    ``"'=cmd|' /C calc'!A0"``. Au-delà de ``limit`` caractères, ``text`` est
    tronqué et marqué.

    La cellule s'écrit avec le module ``csv`` et ``quoting=csv.QUOTE_ALL`` :
    séparateurs, guillemets et sauts de ligne restent dans leur cellule.
    """
    tete, longueur = _tronquer(text, limit)
    cellule = _nettoyer(tete, monoligne=False, retour_chariot=True)
    if longueur is not None:
        cellule += truncation_mark(longueur)
    premier = cellule[:1]
    if premier in _SAUTS_EN_TETE or unicodedata.normalize("NFKC", premier) in (
        _FORMULES
    ):
        cellule = "'" + cellule
    return cellule
