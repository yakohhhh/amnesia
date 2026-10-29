"""Journalisation d'amnesia : niveaux, sorties et expurgation des secrets.

Les diagnostics vont toujours sur stderr (et dans --log-file) ; stdout reste
réservé au rapport. Les SDK prévus (botocore, urllib3, msal, pypsrp...) écrivent en
DEBUG les requêtes signées et leurs en-têtes : ils restent plafonnés à WARNING,
même en --debug, et tout ce qui sort passe par le filtre d'expurgation.

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
from typing import Any, TextIO
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

# contrôles C0 et C1, DEL, separateurs Unicode de ligne et surrogates isoles (nom
# de fichier non UTF-8) : rendus en \xNN ou \uNNNN dans le format texte ; le
# traceback garde ses \n (et la tabulation reste telle quelle)
_AUTRES = r"\x7f-\x9f\u2028\u2029\ud800-\udfff"
_CONTROLES = re.compile(rf"[\x00-\x08\x0a-\x1f{_AUTRES}]")
_CONTROLES_TRACEBACK = re.compile(rf"[\x00-\x08\x0b-\x1f{_AUTRES}]")
# json.dumps echappe deja les contrôles C0 ; restent C1, DEL, U+2028/U+2029 et
# les surrogates
_CONTROLES_JSON = re.compile(f"[{_AUTRES}]")

# (motif, remplacement), appliques dans l'ordre apres les secrets enregistrés.
# Cout lineaire exige (ReDoS) : un motif ne doit pas reparcourir une longue suite
# de caracteres depuis chacune de ses positions (blob base64, hex dump...), d'ou
# les ancrages (?<![\w-]) et les quantificateurs possessifs ou bornes.
_MOTIFS: tuple[tuple[re.Pattern[str], str], ...] = (
    # blocs PEM, y compris tronques (sans ligne END)
    (
        re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----(?:.*?-----END \1-----|.*)", re.S),
        MASQUE,
    ),
    # en-tetes d'authentification : la valeur court jusqu'a la fin de la ligne ;
    # la virgule couvre les listes de tuples (('Authorization', 'Basic ...'))
    (
        re.compile(
            r"(?i)\b((?:proxy-)?authorization|x-amz-security-token)"
            r"(['\"]?\s*[:=,]\s*)[^\r\n]*"
        ),
        rf"\1\2{MASQUE}",
    ),
    (re.compile(r"(?i)\b(bearer)\s+[\w.~+/=-]+"), rf"\1 {MASQUE}"),
    # autres schemas HTTP : Basic (user:pass en base64), NTLM, Negotiate (Kerberos)
    (
        re.compile(r"(?i)\b(basic|negotiate|ntlm|digest)\s+[A-Za-z0-9+/=._~-]{8,}"),
        rf"\1 {MASQUE}",
    ),
    # JWT nus (en-tete base64url de « {" ») : une seule tentative par suite de
    # caracteres, et seulement si elle est suivie d'un point
    (
        re.compile(
            r"(?<![\w-])(?=[\w-]*+\.[\w-])([\w-]*?)"
            r"\beyJ[\w-]*+\.[\w-]++(?:\.[\w-]*+)?"
        ),
        rf"\1{MASQUE}",
    ),
    # cles d'acces AWS : longue duree (AKIA) et temporaires (ASIA)
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), MASQUE),
    # cle=valeur : password=, token=, secret=, sig= (SAS Azure), AccountKey=...
    (
        re.compile(
            r"(?i)((?<![\w-])[\w-]*"
            r"(?:password|passwd|pwd|secret|token|sig|signature|key)"
            r"['\"]?\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s&,;]+)"
        ),
        rf"\1{MASQUE}",
    ),
    # identifiants dans une URL : winrm://utilisateur:motdepasse@hote (mot de passe
    # borne, sinon chaque « :// » d'une longue suite la reparcourt jusqu'au bout)
    (re.compile(r"(://[^\s/:@]+:)\S{1,512}(?=@)"), rf"\1{MASQUE}"),
)


def register_secret(valeur: str | None) -> None:
    """Enregistre une valeur à masquer dans tous les journaux (alimenté par #38)."""
    if not valeur:
        return
    with _verrou:
        _secrets.add(valeur)
        # forme encodee dans une URL ou un corps de formulaire
        _secrets.add(quote(valeur, safe=""))


def redact(texte: str) -> str:
    """Masque les secrets enregistrés et les motifs connus de jetons et de clés."""
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

    Couvre un logger tiers remis en DEBUG après coup par setLevel. Ne couvre PAS
    un handler posé directement sur un logger tiers : boto3.set_stream_logger
    ajoute le sien, sans plafond ni expurgation, et les requêtes signées partent
    en clair. D'où l'interdiction de set_stream_logger (ruff TID251, pyproject).
    """

    def filter(self, record: logging.LogRecord) -> bool:
        return (
            record.levelno >= logging.WARNING
            or record.name == LOGGER
            or record.name.startswith(LOGGER + ".")
        )


class _Expurgation(logging.Filter):
    """Masque les secrets du message, des champs extra et des tracebacks.

    L'enregistrement est modifié en place : les handlers suivants reçoivent aussi
    la version expurgée.
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


def _code(m: re.Match[str]) -> str:
    n = ord(m.group())
    return f"\\x{n:02x}" if n < 0x100 else f"\\u{n:04x}"


def _echapper(texte: str, motif: re.Pattern[str]) -> str:
    return motif.sub(_code, texte)


class _FormatTexte(logging.Formatter):
    """Une entrée par ligne, horodatée en UTC ; traceback seulement en --debug.

    Les caractères de contrôle venus d'un hôte audité (séquences ANSI/OSC, \\r,
    \\n) sont rendus visibles : ils ne peuvent ni agir sur le terminal ni forger
    une fausse entrée.
    """

    # staticmethod : appele sur l'instance, time.gmtime ne recoit pas self
    converter = staticmethod(time.gmtime)

    def __init__(self, tracebacks: bool) -> None:
        super().__init__(
            "%(asctime)s %(levelname)s %(name)s: %(message)s", "%Y-%m-%dT%H:%M:%SZ"
        )
        self._tracebacks = tracebacks

    def formatMessage(self, record: logging.LogRecord) -> str:
        return _echapper(super().formatMessage(record), _CONTROLES)

    def format(self, record: logging.LogRecord) -> str:
        if not self._tracebacks:
            record = _sans_traceback(record)
        # le message est deja sur une ligne ; le traceback garde ses \n
        return _echapper(redact(super().format(record)), _CONTROLES_TRACEBACK)


class _FormatJson(logging.Formatter):
    """Une ligne JSON par entrée : ts (UTC), level, logger, check_id, target,
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
        # echappes en \uNNNN : le JSON reste valide, surrogates isoles compris
        return _CONTROLES_JSON.sub(
            lambda m: f"\\u{ord(m.group()):04x}", json.dumps(entree, ensure_ascii=False)
        )


class _Stderr(logging.StreamHandler[TextIO]):
    """Écrit sur le sys.stderr courant, résolu à chaque entrée (comme lastResort)."""

    @property
    def stream(self) -> Any:
        return sys.stderr

    @stream.setter
    def stream(self, _valeur: Any) -> None:
        pass


def _ouvrir_journal(chemin: str) -> Any:
    """Ouvre le journal en ajout, créé en 0600 ; refuse un lien symbolique."""
    drapeaux = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(chemin, drapeaux, 0o600)
    try:
        # fichier preexistant : droits resserres (pas sous Windows ni sur /dev/*)
        if hasattr(os, "fchmod") and stat.S_ISREG(os.fstat(fd).st_mode):
            os.fchmod(fd, 0o600)
        # backslashreplace comme sys.stderr : un nom de fichier non UTF-8
        # (surrogateescape) ne doit pas faire perdre l'entree
        return os.fdopen(fd, "a", encoding="utf-8", errors="backslashreplace")
    except BaseException:
        os.close(fd)
        raise


class _JournalFichier(logging.FileHandler):
    """FileHandler dont le fichier est créé en 0600."""

    def _open(self) -> Any:
        return _ouvrir_journal(self.baseFilename)


def setup_logging(
    verbosity: int = 0,
    debug: bool = False,
    log_file: Path | None = None,
    log_format: str = "text",
) -> logging.Logger:
    """Configure les journaux ; un nouvel appel remplace la configuration précédente.

    verbosity : -1 (-q, erreurs seulement), 0 (avertissements), 1 (-v, INFO),
    2 et plus (-vv, DEBUG pour amnesia seulement). debug force DEBUG et ajoute les
    tracebacks, jamais les variables locales. Le logger racine et les loggers
    tiers ne descendent jamais sous WARNING. Lève OSError si log_file ne peut
    pas être ouvert, sans toucher à la configuration en place.
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
    """Logger d'un check : ``amnesia.check.<id>`` (check_id déduit en JSON)."""
    return logging.getLogger(f"{LOGGER}.check.{check_id}")


def collector_logger(transport: str) -> logging.Logger:
    """Logger d'un collecteur : ``amnesia.collector.<transport>``."""
    return logging.getLogger(f"{LOGGER}.collector.{transport}")
