"""Rendus lisibles d'un rapport JSON : les questions d'enquête sans réponse.

Le rendu est séparé de l'audit : la collecte a lieu sur site, le livrable est
souvent produit plus tard, et un rapport archivé se re-rend sans refaire
l'audit (``amnesia render <rapport.json> --format text|md``). Les rendus ne
lisent que le rapport JSON (#22), jamais les objets internes.

- ``RENDERERS`` : registre des rendus par format (``text``, ``md``) ;
- ``render_report()`` : rendu d'un rapport dans un format ;
- ``load_report()`` : lecture d'un fichier de rapport.

Un rapport dont la version MAJEURE de ``schema_version`` n'est pas prise en
charge est refusé (``ReportError``).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .base import (
    GROUP_BY,
    SEVERITIES,
    SUPPORTED_MAJOR,
    Renderer,
    RenderOptions,
    ReportError,
    escape_markdown,
    fallback,
    load_report,
    neutralize,
    read_report,
)
from .markdown import MarkdownRenderer
from .text import TextRenderer, color_enabled

RENDERERS: Mapping[str, Renderer] = {
    "text": TextRenderer(),
    "md": MarkdownRenderer(),
}
"""Rendus disponibles, par valeur de ``--format``."""


def render_report(
    report: Mapping[str, Any], fmt: str, options: RenderOptions | None = None
) -> str:
    """Rendu de ``report`` au format ``fmt`` (``text`` ou ``md``).

    Lève ``ValueError`` pour un format inconnu et ``ReportError`` pour un
    rapport refusé.
    """
    try:
        rendu = RENDERERS[fmt]
    except KeyError:
        raise ValueError(f"format de rendu inconnu : {fmt!r}") from None
    return rendu.render(report, RenderOptions() if options is None else options)


__all__ = [
    "GROUP_BY",
    "RENDERERS",
    "SEVERITIES",
    "SUPPORTED_MAJOR",
    "MarkdownRenderer",
    "RenderOptions",
    "Renderer",
    "ReportError",
    "TextRenderer",
    "color_enabled",
    "escape_markdown",
    "fallback",
    "load_report",
    "neutralize",
    "read_report",
    "render_report",
]
