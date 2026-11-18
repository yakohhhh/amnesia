# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Regenere docs/READ-ONLY.md depuis l'allowlist des operations (amnesia.readonly).

    uv run python scripts/generer_read_only.py

A relancer apres tout changement de src/amnesia/readonly.py : un test de
tests/unit/test_readonly.py echoue tant que le fichier n'est pas a jour.
"""

import sys
from pathlib import Path

from amnesia.readonly import render_markdown

DESTINATION = Path(__file__).resolve().parent.parent / "docs" / "READ-ONLY.md"


def main() -> int:
    # newline="\n" : LF aussi sous Windows, comme le reste de la documentation
    with DESTINATION.open("w", encoding="utf-8", newline="\n") as fichier:
        fichier.write(render_markdown())
    return 0


if __name__ == "__main__":
    sys.exit(main())
