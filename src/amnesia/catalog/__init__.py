# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Catalogue central des questions d'enquête et de leurs exigences de télémétrie.

La promesse d'amnesia est la liste des questions auxquelles l'enquête ne pourra
pas répondre. Ces questions ne sont pas du texte libre semé dans les checks :
ce sont des données versionnées, embarquées dans le paquet (TOML, à côté de ce
fichier), que les checks désignent par identifiant.

- ``load_catalog()`` : catalogue embarqué, validé au chargement, mis en cache ;
- ``render_question(id, host=..., lookback_days=...)`` : texte d'une question,
  seule origine du champ ``question`` d'un ``Gap`` ;
- ``read_catalog(répertoire)`` : lecture validée d'un autre répertoire ;
- ``verify_registry(catalogue, metas)`` : lien réciproque avec le registre des
  checks (``checks`` d'une question, ``question_ids`` d'un check).

Format des fichiers, cycle de vie d'un identifiant et sources citées :
docs/catalogue.md.

>>> from amnesia.catalog import render_question
>>> render_question("Q-WIN-RDP-LOGON", host="SRV-FILE", lookback_days=21)
"Qui s'est connecté en RDP sur SRV-FILE il y a trois semaines ?"
"""

from .loader import (
    load_catalog,
    read_catalog,
    registry_errors,
    render_question,
    verify_registry,
)
from .model import (
    PLACEHOLDERS,
    Catalog,
    CatalogError,
    Prerequisite,
    PrerequisiteKind,
    Question,
    QuestionStatus,
    Role,
    Source,
    SourceKind,
    Theme,
    UnknownIdError,
    humanize_days,
)

__all__ = [
    "PLACEHOLDERS",
    "Catalog",
    "CatalogError",
    "Prerequisite",
    "PrerequisiteKind",
    "Question",
    "QuestionStatus",
    "Role",
    "Source",
    "SourceKind",
    "Theme",
    "UnknownIdError",
    "humanize_days",
    "load_catalog",
    "read_catalog",
    "registry_errors",
    "render_question",
    "verify_registry",
]
