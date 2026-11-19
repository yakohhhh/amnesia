# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Rendu Markdown (GFM) : un titre par groupe et un tableau récapitulatif.

Toute valeur du rapport passe par ``for_markdown()`` (``amnesia.render.safe``) :
une phrase (question, raison, message) a toute sa ponctuation ASCII échappée,
un nom ou un identifiant (cible, check, exécution) devient un span de code. Le
rendu ne contient donc ni lien, même automatique, ni image, ni HTML brut, ni
entité, et aucune cellule de tableau cassée. Pas de couleur. Le repli ASCII de
l'encodage de sortie (cp1252...) porte sur le document final : il ne produit que
des lettres, des chiffres ou des échappements visibles (``\\u4e2d``), qui ne
reforment aucun lien.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .base import (
    NIVEAUX,
    TITLE,
    GapView,
    RenderOptions,
    ReportView,
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
    summary_rows,
    synthesis,
    unverified_detail,
)
from .safe import Limit, for_markdown


def _nom(valeur: str, *, table: bool = False) -> str:
    """Nom ou identifiant venu du rapport, en span de code."""
    return for_markdown(valeur, limit=Limit.NAME, code=True, table=table)


def _gap(gap: GapView) -> list[str]:
    lignes = [
        f"- **{for_markdown(gap.question)}**",
        f"  - → Impossible : {lowercase_first(for_markdown(gap.reason))}",
        f"  - Sévérité : {NIVEAUX[gap.severity.value]} ({gap.severity.value})",
        f"  - Cible : {_nom(gap.target)}",
    ]
    quantite = quantification(gap)
    if quantite is not None:
        lignes.append(f"  - {quantite}")
    return lignes


def _section_non_verifie(rapport: ReportView) -> list[str]:
    nombre = rapport.unverified_count
    lignes = ["", f"## Non vérifié : {plural(nombre, 'check')}", ""]
    if nombre == 0:
        lignes.append("Tous les checks ont été évalués.")
        return lignes
    lignes += [
        "Ces checks n'ont pas pu être évalués : ils ne sont jamais comptés conformes.",
        "",
        "| Check | Cible | Statut | Motif | Message |",
        "| --- | --- | --- | --- | --- |",
    ]
    for nv in rapport.unverified:
        statut, motif, message = unverified_detail(nv)
        cellules = (
            _nom(nv.check_id, table=True),
            _nom(nv.target, table=True),
            statut,
            motif,
            "" if message is None else for_markdown(message, table=True),
        )
        lignes.append("| " + " | ".join(cellules) + " |")
    if len(rapport.unverified) < nombre:
        manquants = nombre - len(rapport.unverified)
        lignes += [
            "",
            f"{plural(manquants, 'check')} sans détail dans le rapport.",
        ]
    return lignes


class MarkdownRenderer:
    """Rendu Markdown GFM (``--format md``)."""

    def render(self, report: Mapping[str, Any], options: RenderOptions) -> str:
        """Texte du rendu, encodable dans ``options.encoding``."""
        rapport = read_report(report)
        cibles = ", ".join(_nom(c) for c in rapport.targets)
        lignes = [
            f"# {TITLE}",
            "",
            f"- Rapport : {_nom(rapport.run_id)} (amnesia "
            f"{_nom(rapport.tool_version)}, format {rapport.schema_version})",
            f"- Audit du : {_nom(rapport.started_at)}",
            f"- Cibles : {cibles}",
        ]
        avertissement = status_line(rapport)
        if avertissement is not None:
            lignes += ["", f"**{avertissement}**"]

        visibles, masques = filter_gaps(rapport.gaps, options.min_severity)
        groupes = group_gaps(visibles, options.group_by)
        if not groupes:
            lignes += ["", empty_line(rapport, options.min_severity, masques)]
        for valeur, gaps in groupes:
            titre = group_title(options.group_by, valeur, len(gaps), _nom)
            lignes += ["", f"## {titre}", ""]
            for gap in gaps:
                lignes += _gap(gap)

        lignes += _section_non_verifie(rapport)
        lignes += [
            "",
            "## Résumé",
            "",
            synthesis(rapport),
            "",
            "| Compteur | Nombre |",
            "| --- | ---: |",
        ]
        lignes += [
            f"| {libelle} | {nombre} |"
            for libelle, nombre in summary_rows(rapport, masques, options.min_severity)
        ]
        return fallback("\n".join(lignes) + "\n", options.encoding)
