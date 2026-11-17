"""Codes de sortie de la CLI : les seules valeurs que ``main()`` renvoie.

Lancé depuis un RMM, une tâche planifiée ou une CI, un audit qui trouve des
angles morts ou qui n'a rien pu vérifier ne doit jamais paraître vert. Le code
traduit donc le contenu du rapport, pas seulement le déroulement du programme.

====  =========================================================================
Code  Signification
====  =========================================================================
0     audit complet, aucun angle mort de sévérité >= ``--fail-on``
1     au moins un angle mort de sévérité >= ``--fail-on`` (prioritaire sur 3)
2     erreur d'usage ou de configuration (option, cible invalide)
3     audit incomplet : un check en erreur, non exécuté ou en délai dépassé,
      sans angle mort au-dessus du seuil ; « pas pu vérifier » n'est pas
      « conforme ». ``not_applicable`` ne rend pas l'audit incomplet
4     erreur fatale : aucune cible exploitable, rapport impossible à écrire ou
      à lire
130   interruption (Ctrl-C) ; un rapport partiel est écrit avec
      ``run.interrupted = true``
====  =========================================================================

``--fail-on never`` neutralise le code 1, jamais le code 3. La table est
stable (docs/RELEASING.md) : le sens d'un code ne change jamais et un code
retiré n'est jamais réattribué.
"""

from __future__ import annotations

import textwrap
from collections.abc import Mapping
from typing import Any

from .checks.base import Severity

OK = 0
"""Audit complet, aucun angle mort de sévérité >= ``--fail-on``."""

GAPS = 1
"""Au moins un angle mort de sévérité >= ``--fail-on`` (prioritaire sur 3)."""

USAGE = 2
"""Erreur d'usage ou de configuration (argparse, cible invalide)."""

INCOMPLETE = 3
"""Audit incomplet (check en erreur, non exécuté, délai dépassé), sans Gap >= seuil."""

FATAL = 4
"""Erreur fatale : aucune cible exploitable, rapport impossible à écrire ou à lire."""

INTERRUPTED = 130
"""Interruption Ctrl-C ; rapport partiel écrit avec ``run.interrupted = true``."""

NEVER = "never"
"""Valeur de ``--fail-on`` qui neutralise le code 1 (jamais le code 3)."""

FAIL_ON = (*(s.value for s in sorted(Severity, reverse=True)), NEVER)
"""Valeurs admises de ``--fail-on``, de ``critical`` à ``info``, puis ``never``."""

DEFAULT_FAIL_ON = Severity.LOW.value
"""Seuil par défaut de ``--fail-on``."""

TABLE: tuple[tuple[int, str], ...] = (
    (OK, "audit complet, aucun angle mort de sévérité >= --fail-on"),
    (GAPS, "au moins un angle mort de sévérité >= --fail-on (prioritaire sur 3)"),
    (USAGE, "erreur d'usage ou de configuration (option, cible invalide)"),
    (
        INCOMPLETE,
        "audit incomplet (check en erreur, non exécuté ou en délai dépassé) sans "
        "angle mort au-dessus du seuil : « pas pu vérifier » n'est pas « conforme »",
    ),
    (
        FATAL,
        "erreur fatale : aucune cible exploitable, rapport impossible à écrire "
        "ou à lire",
    ),
    (INTERRUPTED, "interruption (Ctrl-C) ; rapport partiel, run.interrupted = true"),
)
"""Table des codes, dans l'ordre, pour l'aide et la documentation."""


def table_text(width: int = 79) -> str:
    """Table des codes de sortie en texte, pour l'épilogue de ``--help``."""
    lignes = ["codes de sortie :"]
    for code, sens in TABLE:
        lignes.append(
            textwrap.fill(
                sens,
                width=width,
                initial_indent=f"  {code:<4} ",
                subsequent_indent=" " * 7,
            )
        )
    return "\n".join(lignes)


def threshold(fail_on: str) -> Severity | None:
    """Sévérité de seuil de ``fail_on``, ``None`` pour ``never`` ; ValueError sinon."""
    if fail_on == NEVER:
        return None
    return Severity.parse(fail_on)


def exit_code(report: Mapping[str, Any], fail_on: str) -> int:
    """Code 0, 1 ou 3 d'un rapport JSON v1 (#22) pour le seuil ``fail_on``.

    1 dès qu'un Gap a une sévérité >= ``fail_on`` (jamais avec ``never``) ;
    sinon 3 si ``run.complete`` est faux (check en erreur, non exécuté, audit
    interrompu) ; sinon 0. Le rapport est supposé valide (``build_report()`` ou
    ``amnesia.render.read_report()``) : une sévérité inconnue lève ValueError.
    """
    seuil = threshold(fail_on)
    if seuil is not None and any(
        Severity.parse(gap["severity"]) >= seuil for gap in report["gaps"]
    ):
        return GAPS
    if not report["run"]["complete"]:
        return INCOMPLETE
    return OK


__all__ = [
    "DEFAULT_FAIL_ON",
    "FAIL_ON",
    "FATAL",
    "GAPS",
    "INCOMPLETE",
    "INTERRUPTED",
    "NEVER",
    "OK",
    "TABLE",
    "USAGE",
    "exit_code",
    "table_text",
    "threshold",
]
