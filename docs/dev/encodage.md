# Encodage des textes

amnesia s'adresse à des clients francophones et son rapport doit être livrable
tel quel : les textes s'écrivent avec leurs accents, et aucune sortie ne doit
planter à cause d'un encodage.

## Fichiers du dépôt

- Sources et fichiers texte en **UTF-8 sans BOM**, fins de ligne LF
  (`.editorconfig`, `.gitattributes`).
- Exception : les scripts et données PowerShell (`.ps1`, `.psm1`, `.psd1`,
  `.psrc`, `.pssc`) sont en **UTF-8 avec BOM** et CRLF. Sans BOM, Windows
  PowerShell 5.1 les lit dans la page de code ANSI et corrompt les accents.

## Textes destinés à l'utilisateur

- Accents attendus dans tout texte visible : messages et aide de la CLI, titres
  des checks, questions et raisons des `Gap`, rapports, docstrings de `src/`.
- Caractères typographiques admis : `→`, guillemets `« »`, apostrophe `’`, tiret
  demi-cadratin `–` (ruff accepte les deux derniers via `allowed-confusables`).
- Un repli ASCII plus lisible (`->`, guillemets droits) pour un terminal limité
  relève des renderers (#23), pas des textes eux-mêmes.

## Lecture et écriture

- Tout `open()`, `Path.read_text()` et `Path.write_text()` en mode texte passe
  `encoding="utf-8"` (ou un autre encodage explicite, justifié en commentaire).
- JSON écrit avec `ensure_ascii=False` : le rapport reste lisible, accents
  compris.
- `subprocess` en mode texte : toujours un `encoding=` explicite (pas de
  `text=True` seul), choisi d'après ce que l'outil appelé écrit réellement.
- Préférer des sources indépendantes de la langue du système (identifiants,
  GUID, sorties structurées) plutôt que l'analyse de textes localisés (#51).
- Hors périmètre ici : décodage UTF-16LE des sorties PowerShell (#48).

## Sortie de la CLI

Sous Windows avant Python 3.15 (UTF-8 Mode par défaut depuis, PEP 686), une
sortie redirigée (`amnesia audit > rapport.txt`, tâche planifiée, pipeline) est
encodée dans la page ANSI (cp1252 sur un poste français) : `→` y lève
`UnicodeEncodeError`. `’` échoue de même en cp850, page OEM de la console, avec
`PYTHONLEGACYWINDOWSSTDIO` ou un `PYTHONIOENCODING` imposé.

Au démarrage, `amnesia.cli.main()` passe donc stdout et stderr en
`errors="replace"` quand leur encodage n'est pas UTF-8 : un caractère
impossible à encoder devient `?`, sans crash. Un flux déjà tolérant (stderr en
`backslashreplace`) est laissé tel quel.

## Garde-fous

- `tests/unit/test_encodage.py` lance la CLI en sous-processus, sortie
  redirigée, sous `PYTHONIOENCODING=cp1252` puis `cp850` : code 0, aucun
  traceback.
- La suite tourne avec `PYTHONWARNDEFAULTENCODING=1` (EncodingWarning,
  PEP 597) et `-W error::EncodingWarning` : un `open()` ou un
  `subprocess.run(text=True)` sans encodage exécuté par un test le fait
  échouer. La règle ruff équivalente (`PLW1514`) est encore en preview.
  - en CI : variables posées sur le job `test` ; le job `nox-windows` les reçoit
    du `noxfile.py` ;
  - en local : `uv run nox -s tests`, ou directement :

    ```bash
    PYTHONWARNDEFAULTENCODING=1 PYTEST_ADDOPTS="-W error::EncodingWarning" uv run pytest
    ```

    Sans ces variables, le test du garde-fou est ignoré (SKIPPED) en local et
    échoue en CI.
