"""Journalisation d'amnesia : niveaux, sorties et expurgation des secrets.

Les diagnostics vont toujours sur stderr (et dans --log-file) ; stdout reste
reserve au rapport. Les SDK prevus (botocore, urllib3, msal, pypsrp...) ecrivent en
DEBUG les requetes signees et leurs en-tetes : ils restent plafonnes a WARNING,
meme en --debug, et tout ce qui sort passe par le filtre d'expurgation.

Loggers : ``amnesia``, ``amnesia.check.<id>`` et ``amnesia.collector.<transport>``.
"""

from __future__ import annotations

import json
import logging
import os
import re
import stat
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

LOGGER = "amnesia"
MASQUE = "***"
FORMATS = ("text", "json")

# Plafonnes a WARNING meme en --debug : botocore y journalise les requetes signees
# (Authorization, X-Amz-Security-Token), urllib3, spnego et pypsrp les echanges.
TIERS = (
    "botocore",
    "boto3",
    "urllib3",
    "requests_ntlm",
    "spnego",
    "pypsrp",
    "msal",
    "azure",
    "httpx",
)

_secrets: set[str] = set()
_verrou = threading.Lock()
# handlers poses par setup_logging, retires a l'appel suivant
_handlers: list[logging.Handler] = []

# (motif, remplacement), appliques dans l'ordre apres les secrets enregistres
_MOTIFS: tuple[tuple[re.Pattern[str], str], ...] = (
    # blocs PEM, y compris tronques (sans ligne END)
    (
        re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----(?:.*?-----END \1-----|.*)", re.S),
        MASQUE,
    ),
    # en-tetes d'authentification : la valeur court jusqu'a la fin de la ligne
    (
        re.compile(
            r"(?i)\b((?:proxy-)?authorization|x-amz-security-token)"
            r"(['\"]?\s*[:=]\s*)[^\r\n]*"
        ),
        rf"\1\2{MASQUE}",
    ),
    (re.compile(r"(?i)\b(bearer)\s+[\w.~+/=-]+"), rf"\1 {MASQUE}"),
    # JWT nus (en-tete base64url de « {" »)
    (re.compile(r"\beyJ[\w-]+\.[\w-]+(?:\.[\w-]*)?"), MASQUE),
    # cles d'acces AWS : longue duree (AKIA) et temporaires (ASIA)
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), MASQUE),
    # cle=valeur : password=, token=, secret=, sig= (SAS Azure), AccountKey=...
    (
        re.compile(
            r"(?i)([\w-]*(?:password|passwd|pwd|secret|token|sig|signature|key)"
            r"['\"]?\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s&,;]+)"
        ),
        rf"\1{MASQUE}",
    ),
    # identifiants dans une URL : winrm://utilisateur:motdepasse@hote
    (re.compile(r"(://[^\s/:@]+:)\S+(?=@)"), rf"\1{MASQUE}"),
)


def register_secret(valeur: str | None) -> None:
    """Enregistre une valeur a masquer dans tous les journaux (alimente par #38)."""
    if not valeur:
        return
    with _verrou:
        _secrets.add(valeur)
        # forme encodee dans une URL ou un corps de formulaire
        _secrets.add(quote(valeur, safe=""))


def redact(texte: str) -> str:
    """Masque les secrets enregistres et les motifs connus de jetons et de cles."""
    with _verrou:
        secrets = sorted(_secrets, key=len, reverse=True)
    for valeur in secrets:
        texte = texte.replace(valeur, MASQUE)
    for motif, remplacement in _MOTIFS:
        texte = motif.sub(remplacement, texte)
    return texte


def _champ(record: logging.LogRecord, nom: str) -> Any:
    valeur = getattr(record, nom, None)
    if valeur is None or isinstance(valeur, bool | int | float):
        return valeur
    return redact(str(valeur))


class _PlafondTiers(logging.Filter):
    """Sous WARNING, ne laisse passer que les loggers d'amnesia.

    Couvre aussi un logger tiers remis en DEBUG apres coup (par exemple par
    boto3.set_stream_logger).
    """

    def filter(self, record: logging.LogRecord) -> bool:
        return (
            record.levelno >= logging.WARNING
            or record.name == LOGGER
            or record.name.startswith(LOGGER + ".")
        )


class _Expurgation(logging.Filter):
    """Masque les secrets du message, des champs extra et des tracebacks.

    L'enregistrement est modifie en place : les handlers suivants recoivent aussi
    la version expurgee.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # arguments invalides : le gabarit seul, sans planter
            message = str(record.msg)
        record.msg = redact(message)
        record.args = None
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        if record.stack_info:
            record.stack_info = redact(record.stack_info)
        for nom in ("check_id", "target"):
            if getattr(record, nom, None) is not None:
                setattr(record, nom, _champ(record, nom))
        return True


def _sans_traceback(record: logging.LogRecord) -> logging.LogRecord:
    if not (record.exc_info or record.exc_text or record.stack_info):
        return record
    copie = logging.makeLogRecord(record.__dict__)
    copie.exc_info = copie.exc_text = copie.stack_info = None
    return copie


class _FormatTexte(logging.Formatter):
    """Une entree par ligne, horodatee en UTC ; traceback seulement en --debug."""

    converter = time.gmtime

    def __init__(self, tracebacks: bool) -> None:
        super().__init__(
            "%(asctime)s %(levelname)s %(name)s: %(message)s", "%Y-%m-%dT%H:%M:%SZ"
        )
        self._tracebacks = tracebacks

    def format(self, record: logging.LogRecord) -> str:
        if not self._tracebacks:
            record = _sans_traceback(record)
        return redact(super().format(record))


class _FormatJson(logging.Formatter):
    """Une ligne JSON par entree : ts (UTC), level, logger, check_id, target,
    duration_ms et msg ; exc et stack seulement en --debug.

    L'expurgation porte sur chaque champ avant l'encodage, jamais sur la ligne
    JSON (un motif pourrait y manger un guillemet).
    """

    def __init__(self, tracebacks: bool) -> None:
        super().__init__()
        self._tracebacks = tracebacks

    def format(self, record: logging.LogRecord) -> str:
        check_id = _champ(record, "check_id")
        prefixe = LOGGER + ".check."
        if check_id is None and record.name.startswith(prefixe):
            check_id = record.name.removeprefix(prefixe)
        entree = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "logger": record.name,
            "check_id": check_id,
            "target": _champ(record, "target"),
            "duration_ms": _champ(record, "duration_ms"),
            "msg": redact(record.getMessage()),
        }
        if self._tracebacks:
            if record.exc_info and not record.exc_text:
                record.exc_text = self.formatException(record.exc_info)
            if record.exc_text:
                entree["exc"] = redact(record.exc_text)
            if record.stack_info:
                entree["stack"] = redact(record.stack_info)
        return json.dumps(entree, ensure_ascii=False)


class _Stderr(logging.StreamHandler):
    """Ecrit sur le sys.stderr courant, resolu a chaque entree (comme lastResort)."""

    @property
    def stream(self) -> Any:
        return sys.stderr

    @stream.setter
    def stream(self, _valeur: Any) -> None:
        pass


def _ouvrir_journal(chemin: str) -> Any:
    """Ouvre le journal en ajout, cree en 0600 ; refuse un lien symbolique."""
    drapeaux = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(chemin, drapeaux, 0o600)
    try:
        # fichier preexistant : droits resserres (pas sous Windows ni sur /dev/*)
        if hasattr(os, "fchmod") and stat.S_ISREG(os.fstat(fd).st_mode):
            os.fchmod(fd, 0o600)
        return os.fdopen(fd, "a", encoding="utf-8")
    except BaseException:
        os.close(fd)
        raise


class _JournalFichier(logging.FileHandler):
    """FileHandler dont le fichier est cree en 0600."""

    def _open(self) -> Any:
        return _ouvrir_journal(self.baseFilename)


def setup_logging(
    verbosity: int = 0,
    debug: bool = False,
    log_file: Path | None = None,
    log_format: str = "text",
) -> logging.Logger:
    """Configure les journaux ; un nouvel appel remplace la configuration precedente.

    verbosity : -1 (-q, erreurs seulement), 0 (avertissements), 1 (-v, INFO),
    2 et plus (-vv, DEBUG pour amnesia seulement). debug force DEBUG et ajoute les
    tracebacks, jamais les variables locales. Le logger racine et les loggers
    tiers ne descendent jamais sous WARNING. Leve OSError si log_file ne peut
    pas etre ouvert, sans toucher a la configuration en place.
    """
    if log_format not in FORMATS:
        raise ValueError(f"format de journal inconnu : {log_format!r}")
    if verbosity < 0:
        niveau = logging.ERROR
    elif debug or verbosity >= 2:
        niveau = logging.DEBUG
    elif verbosity == 1:
        niveau = logging.INFO
    else:
        niveau = logging.WARNING
    plancher = logging.ERROR if verbosity < 0 else logging.WARNING

    formateur: logging.Formatter = (
        _FormatJson(debug) if log_format == "json" else _FormatTexte(debug)
    )
    handlers: list[logging.Handler] = [_Stderr()]
    if log_file is not None:
        handlers.append(_JournalFichier(log_file, encoding="utf-8"))
    for handler in handlers:
        handler.addFilter(_PlafondTiers())
        handler.addFilter(_Expurgation())
        handler.setFormatter(formateur)

    racine = logging.getLogger()
    with _verrou:
        for ancien in _handlers:
            racine.removeHandler(ancien)
            ancien.close()
        _handlers[:] = handlers
        for handler in handlers:
            racine.addHandler(handler)
    racine.setLevel(plancher)
    for nom in TIERS:
        logging.getLogger(nom).setLevel(plancher)
    logger = logging.getLogger(LOGGER)
    logger.setLevel(niveau)
    return logger


def check_logger(check_id: str) -> logging.Logger:
    """Logger d'un check : ``amnesia.check.<id>`` (check_id deduit en JSON)."""
    return logging.getLogger(f"{LOGGER}.check.{check_id}")


def collector_logger(transport: str) -> logging.Logger:
    """Logger d'un collecteur : ``amnesia.collector.<transport>``."""
    return logging.getLogger(f"{LOGGER}.collector.{transport}")
