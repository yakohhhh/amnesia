"""Rendu Markdown (GFM) : un titre par groupe et un tableau récapitulatif.

Toute valeur du rapport passe par ``escape_markdown()`` : ni lien, ni image,
ni HTML brut, ni entité, et aucune cellule de tableau cassée. Pas de couleur.
Le repli ASCII d'une valeur précède son échappement : une lettre ramenée à
l'ASCII par l'encodage de sortie (cp1252...) ne reforme pas un lien.
"""

from __future__ import annotations

from collections.abc import Mapping
from functools import partial
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


def _gap(gap: GapView, encodage: str) -> list[str]:
    raison = lowercase_first(escape_markdown(gap.reason, encodage))
    lignes = [
        f"- **{escape_markdown(gap.question, encodage)}**",
        f"  - → Impossible : {raison}",
        f"  - Sévérité : {NIVEAUX[gap.severity.value]} ({gap.severity.value})",
        f"  - Cible : {escape_markdown(gap.target, encodage)}",
    ]
    quantite = quantification(gap)
    if quantite is not None:
        lignes.append(f"  - {quantite}")
    return lignes


def _section_non_verifie(rapport: ReportView, encodage: str) -> list[str]:
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
            escape_markdown(nv.check_id, encodage),
            escape_markdown(nv.target, encodage),
            statut,
            motif,
            "" if message is None else escape_markdown(message, encodage),
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
        # repli ASCII de chaque valeur avant son echappement (voir le module)
        echappe = partial(escape_markdown, encoding=options.encoding)
        cibles = ", ".join(echappe(c) for c in rapport.targets)
        lignes = [
            f"# {TITLE}",
            "",
            f"- Rapport : {echappe(rapport.run_id)} (amnesia "
            f"{echappe(rapport.tool_version)}, format "
            f"{rapport.schema_version})",
            f"- Audit du : {echappe(rapport.started_at)}",
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
            titre = group_title(options.group_by, valeur, len(gaps), echappe)
            lignes += ["", f"## {titre}", ""]
            for gap in gaps:
                lignes += _gap(gap, options.encoding)

        lignes += _section_non_verifie(rapport, options.encoding)
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
