# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Rendu terminal : une entrée par angle mort, au format du README.

::

    [élevée] Qui s'est connecté en RDP sur SRV-FILE il y a trois semaines ?
      → Impossible : le journal Security fait 20 Mo et a été écrasé il y a 4 jours.
      Cible : winrm://srv-file.exemple.invalid
      Fenêtre observée 4 j / exigée 90 j

Couleurs ANSI seulement si ``RenderOptions.color`` est vrai (``color_enabled()``
décide pour la CLI) ; elles n'encadrent que les textes d'amnesia. Toute valeur
du rapport passe par ``for_terminal()`` (``amnesia.render.safe``) : aucune
séquence de contrôle venue d'une cible n'atteint le terminal, aucune ne forge
de fausse ligne, et une valeur démesurée est tronquée (256 caractères pour un
nom, 1 024 pour une phrase).
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from typing import Any

from .base import (
    NIVEAUX,
    TITLE,
    GapView,
    RenderOptions,
    ReportView,
    UnverifiedView,
    empty_line,
    fallback,
    filter_gaps,
    group_gaps,
    group_title,
    lowercase_first,
    plural,
    quantification,
    read_report,
    status_line,
    summary_lines,
    unverified_detail,
)
from .safe import Limit, for_terminal

_ESC = "\x1b"
# SGR par severite : gras rouge, rouge, jaune, cyan, attenue
_COULEURS = {
    "critical": "1;31",
    "high": "31",
    "medium": "33",
    "low": "36",
    "info": "2",
}
_GRAS = "1"
_ALERTE = "1;33"


def color_enabled(
    stream: object,
    environ: Mapping[str, str],
    *,
    no_color: bool = False,
    platform: str = sys.platform,
) -> bool:
    """Vrai si le rendu texte peut colorer ``stream``.

    Jamais avec ``--no-color``, avec ``NO_COLOR`` présente et non vide
    (https://no-color.org/), avec ``TERM=dumb``, ni quand ``stream`` n'est pas
    un terminal (redirection, pipe, fichier). Sous Windows, seulement dans
    Windows Terminal (``WT_SESSION``) : l'ancienne console afficherait les
    séquences telles quelles.
    """
    if no_color or environ.get("NO_COLOR") or environ.get("TERM") == "dumb":
        return False
    isatty = getattr(stream, "isatty", None)
    try:
        terminal = bool(isatty()) if callable(isatty) else False
    except (OSError, ValueError):
        # flux ferme ou detache
        terminal = False
    if not terminal:
        return False
    return platform != "win32" or bool(environ.get("WT_SESSION"))


def _nom(valeur: str) -> str:
    """Nom ou identifiant venu du rapport (cible, check, exécution)."""
    return for_terminal(valeur, limit=Limit.NAME)


class _Style:
    def __init__(self, couleur: bool) -> None:
        self._couleur = couleur

    def __call__(self, texte: str, sgr: str) -> str:
        if not self._couleur:
            return texte
        return f"{_ESC}[{sgr}m{texte}{_ESC}[0m"


def _titre(lignes: list[str], style: _Style, titre: str, sgr: str) -> None:
    # soulignement calcule sur le texte, sans les sequences de couleur
    lignes += ["", style(titre, sgr), "-" * len(titre)]


def _gap(gap: GapView, style: _Style) -> list[str]:
    severite = gap.severity.value
    etiquette = style(f"[{NIVEAUX[severite]}]", _COULEURS[severite])
    lignes = [
        "",
        f"{etiquette} {for_terminal(gap.question)}",
        f"  → Impossible : {lowercase_first(for_terminal(gap.reason))}",
        f"  Cible : {_nom(gap.target)}",
    ]
    quantite = quantification(gap)
    if quantite is not None:
        lignes.append(f"  {quantite}")
    return lignes


def _non_verifie(nv: UnverifiedView) -> str:
    statut, motif, message = unverified_detail(nv)
    ligne = f"- {_nom(nv.check_id)} sur {_nom(nv.target)} : {statut}, {motif}"
    return ligne if message is None else f"{ligne} ({for_terminal(message)})"


def _section_non_verifie(rapport: ReportView, style: _Style) -> list[str]:
    lignes: list[str] = []
    nombre = rapport.unverified_count
    titre = f"Non vérifié : {plural(nombre, 'check')}"
    _titre(lignes, style, titre, _ALERTE if nombre else _GRAS)
    if nombre == 0:
        lignes.append("Tous les checks ont été évalués.")
        return lignes
    lignes += [
        "Ces checks n'ont pas pu être évalués : ils ne sont jamais comptés conformes.",
        "",
    ]
    lignes += [_non_verifie(nv) for nv in rapport.unverified]
    if len(rapport.unverified) < nombre:
        manquants = nombre - len(rapport.unverified)
        lignes.append(f"- {plural(manquants, 'check')} sans détail dans le rapport")
    return lignes


class TextRenderer:
    """Rendu texte pour le terminal (``--format text``)."""

    def render(self, report: Mapping[str, Any], options: RenderOptions) -> str:
        """Texte du rendu, encodable dans ``options.encoding``."""
        rapport = read_report(report)
        style = _Style(options.color)
        lignes = [
            style(TITLE, _GRAS),
            f"Rapport : {_nom(rapport.run_id)} (amnesia "
            f"{_nom(rapport.tool_version)}, format {rapport.schema_version})",
            f"Audit du : {_nom(rapport.started_at)}",
            f"Cibles : {', '.join(_nom(c) for c in rapport.targets)}",
        ]
        avertissement = status_line(rapport)
        if avertissement is not None:
            lignes.append(style(avertissement, _ALERTE))

        visibles, masques = filter_gaps(rapport.gaps, options.min_severity)
        groupes = group_gaps(visibles, options.group_by)
        if not groupes:
            lignes += ["", empty_line(rapport, options.min_severity, masques)]
        for valeur, gaps in groupes:
            titre = group_title(options.group_by, valeur, len(gaps), _nom)
            sgr = (
                f"{_GRAS};{_COULEURS[valeur]}"
                if options.group_by == "severity"
                else _GRAS
            )
            _titre(lignes, style, titre, sgr)
            for gap in gaps:
                lignes += _gap(gap, style)

        lignes += _section_non_verifie(rapport, style)
        _titre(lignes, style, "Résumé", _GRAS)
        lignes += summary_lines(rapport, masques, options.min_severity)
        return fallback("\n".join(lignes) + "\n", options.encoding)
