"""Rendu Markdown (GFM) : un titre par groupe et un tableau récapitulatif.

Toute valeur du rapport passe par ``escape_markdown()`` : ni lien, ni image,
ni HTML brut, ni entité, et aucune cellule de tableau cassée. Pas de couleur.
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
    escape_markdown,
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


def _gap(gap: GapView) -> list[str]:
    lignes = [
        f"- **{escape_markdown(gap.question)}**",
        f"  - → Impossible : {lowercase_first(escape_markdown(gap.reason))}",
        f"  - Sévérité : {NIVEAUX[gap.severity.value]} ({gap.severity.value})",
        f"  - Cible : {escape_markdown(gap.target)}",
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
            escape_markdown(nv.check_id),
            escape_markdown(nv.target),
            statut,
            motif,
            "" if message is None else escape_markdown(message),
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
        cibles = ", ".join(escape_markdown(c) for c in rapport.targets)
        lignes = [
            f"# {TITLE}",
            "",
            f"- Rapport : {escape_markdown(rapport.run_id)} (amnesia "
            f"{escape_markdown(rapport.tool_version)}, format "
            f"{rapport.schema_version})",
            f"- Audit du : {escape_markdown(rapport.started_at)}",
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
            titre = group_title(options.group_by, valeur, len(gaps), escape_markdown)
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
