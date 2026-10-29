"""Rapport JSON versionné : contrat machine d'un audit.

``build_report()`` transforme un ``AuditResult`` (#21) en document JSON v1 ;
``dumps_report()`` le sérialise de façon déterministe. Format, politique de
compatibilité et exemple complet : ``docs/format-rapport.md`` ; JSON Schema
draft 2020-12 embarqué dans le paquet : ``amnesia/schemas/report-v1.schema.json``
(``load_schema()``, ``amnesia schema``).

Structure :

- ``schema_version`` : SemVer du format (``1.0.0``) ;
- ``tool`` : nom, version d'amnesia, version du catalogue (``null`` avant #46) ;
- ``run`` : identifiant (UUID4), horodatages RFC 3339 en UTC (suffixe ``Z``),
  durée, ``complete``, ``interrupted``, profil (``null`` avant #47) et
  arguments de la ligne de commande, valeurs sensibles masquées ;
- ``targets`` : cibles auditées (identifiant, type, transport) ;
- ``results`` : un résultat par check et par cible, quel que soit son statut ;
- ``gaps`` : Gaps v1 (#16), du plus grave au moins grave ;
- ``summary`` : comptes par statut et par sévérité.

Déterminisme : listes triées, clés dans un ordre fixe, ``ensure_ascii=False``,
indentation de 2, saut de ligne final. Deux sérialisations du même audit sont
identiques octet pour octet.

Texte non encodable : un surrogate isolé (octet non UTF-8 d'argv, décodé en
``surrogateescape``, ou chemin de bundle) ferait échouer l'écriture du rapport en
UTF-8 strict. Il est remplacé par son échappement ``\\udcff`` (même forme que la
sortie de la CLI, docs/dev/encodage.md) : le texte rendu s'encode toujours en
UTF-8.

Données venues de la cible : messages, preuves et textes des Gaps sont écrits
tels quels, caractères de contrôle C1 (U+0080 à U+009F) et de direction
bidirectionnelle (U+202E...) compris ; seuls ceux en dessous de U+0020 sont
échappés par JSON (``\\u001b``). Les neutraliser à l'affichage revient aux rendus
(terminal, Markdown, HTML : #23, #45, #77), jamais au rapport, qui doit garder la
valeur observée.

Le rapport ne porte pas le nom du compte local qui a lancé l'audit
(``AuditResult.operator``) : il est remis au client.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from importlib.resources import files
from typing import Any

from .checks import REGISTRY
from .checks.base import CheckResult, Gap, assainir
from .runner import AuditResult, AuditSummary
from .target import Target

SCHEMA_VERSION = "1.0.0"
"""Version du format (SemVer) : MAJEURE si incompatible, MINEURE si champ ajouté."""

SCHEMA_RESOURCE = "schemas/report-v1.schema.json"
"""Chemin du JSON Schema dans le paquet ``amnesia``."""

TOOL_NAME = "amnesia"

SENSITIVE_OPTIONS = ("--password", "--token", "--secret", "--client-secret")
"""Options dont la valeur est masquée dans ``run.argv``, abréviations comprises."""

MASK = "***"


def load_schema() -> dict[str, Any]:
    """JSON Schema du rapport v1, lu dans le paquet installé."""
    schema: dict[str, Any] = json.loads(schema_text())
    return schema


def schema_text() -> str:
    """Texte du JSON Schema du rapport v1, tel qu'embarqué dans le paquet."""
    return files("amnesia").joinpath(SCHEMA_RESOURCE).read_text(encoding="utf-8")


def _sensible(option: str) -> bool:
    # argparse accepte une abreviation non ambigue (--tok pour --token) : tout
    # prefixe d'une option sensible est masque, quitte a masquer trop
    return (
        option.startswith("--")
        and len(option) > 2
        and any(sensible.startswith(option) for sensible in SENSITIVE_OPTIONS)
    )


def redact_argv(argv: Iterable[str]) -> list[str]:
    """Arguments de la ligne de commande, valeurs sensibles remplacées par ``***``.

    ``--token abc`` devient ``--token ***`` et ``--token=abc`` ``--token=***``,
    pour ``--password``, ``--token``, ``--secret``, ``--client-secret`` et
    leurs abréviations. L'argument qui suit une option sensible est masqué quelle
    que soit sa forme. Les autres arguments passent par ``assainir()`` :
    identifiants dans une URL, ``password=...``, caractères non imprimables et
    surrogates rendus visibles (``\\udcff``).
    """
    masques: list[str] = []
    masquer_suivant = False
    for argument in argv:
        if not isinstance(argument, str):
            raise TypeError(f"argv : chaîne attendue, reçu {type(argument).__name__}")
        if masquer_suivant:
            masques.append(MASK)
            masquer_suivant = False
            continue
        option, egal, _valeur = argument.partition("=")
        if _sensible(option):
            if egal:
                masques.append(f"{option}={MASK}")
            else:
                masques.append(option)
                masquer_suivant = True
            continue
        masques.append(assainir(argument))
    return masques


def _texte_utf8(texte: str) -> str:
    """``texte`` encodable en UTF-8 strict : surrogates isolés échappés."""
    try:
        texte.encode("utf-8")
    except UnicodeEncodeError:
        # backslashreplace : \udcff, deterministe et garde la valeur de l'octet
        return texte.encode("utf-8", "backslashreplace").decode("utf-8")
    return texte


def _sans_surrogates(valeur: Any) -> Any:
    """Copie de ``valeur`` (dict, list, str...) sans surrogate isolé."""
    if isinstance(valeur, str):
        return _texte_utf8(valeur)
    if isinstance(valeur, Mapping):
        return {_texte_utf8(cle): _sans_surrogates(v) for cle, v in valeur.items()}
    if isinstance(valeur, list | tuple):
        return [_sans_surrogates(v) for v in valeur]
    return valeur


def _rfc3339(horodatage: str) -> str:
    """Horodatage ISO 8601 avec fuseau, en RFC 3339 UTC à suffixe ``Z``."""
    instant = datetime.fromisoformat(horodatage)
    if instant.utcoffset() is None:
        raise ValueError(f"horodatage sans fuseau horaire : {horodatage!r}")
    return instant.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _domaine(check_id: str) -> str:
    # premier segment de l'id (win, ad...), impose par le registre (#17)
    return check_id.split(".", 1)[0]


def _cle_gap(gap: Gap) -> tuple[Any, ...]:
    # severite decroissante, domaine, check, cible ; Gap.sort_key() departage
    # les Gaps d'un meme resultat (question, ressource, empreinte)
    return (
        -gap.severity.rank,
        _domaine(gap.check_id),
        gap.check_id,
        gap.target,
        gap.sort_key(),
    )


def _versions_du_registre() -> dict[str, int]:
    return {meta.id: meta.version for meta in REGISTRY.metas()}


def _verifier_versions(versions: Mapping[str, int]) -> None:
    for check_id, version in versions.items():
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise ValueError(
                f"check_versions[{check_id!r}] : entier >= 1 attendu, reçu {version!r}"
            )


def _cible(target: Target) -> dict[str, Any]:
    return {
        "id": target.id,
        "kind": target.kind.value,
        "transport": target.transport.value,
    }


def _resultat(resultat: CheckResult, versions: Mapping[str, int]) -> dict[str, Any]:
    return {
        "check_id": resultat.check_id,
        "check_version": versions.get(resultat.check_id),
        "target": resultat.target,
        "status": resultat.status.value,
        "reason": None if resultat.reason is None else resultat.reason.value,
        "message": resultat.message,
        "error": None if resultat.error is None else resultat.error.to_dict(),
        "duration_s": resultat.duration_s,
    }


def _resume(resultats: Sequence[CheckResult]) -> dict[str, Any]:
    resume = AuditSummary.from_results(resultats)
    return {
        "total": resume.total,
        "by_status": dict(resume.by_status),
        "by_severity": dict(resume.by_severity),
        "gaps": resume.gaps,
        "excluded": resume.excluded,
        "not_evaluated": resume.not_evaluated,
    }


def build_report(
    audit: AuditResult,
    *,
    argv: Sequence[str] = (),
    check_versions: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    """Rapport v1 d'un audit, prêt pour ``dumps_report()``.

    ``argv`` : arguments de la ligne de commande sans le programme
    (``sys.argv[1:]``, dont le chemin révélerait le poste de l'auditeur),
    masqués par ``redact_argv()``. ``check_versions`` : version de chaque check
    par id ; par défaut celles du registre. Un check absent a une version
    ``null``.

    ``results`` est trié par ``check_id`` puis cible ; ``gaps`` par sévérité
    décroissante (de ``critical`` à ``info``), puis domaine, ``check_id``,
    cible, et enfin par ``Gap.sort_key()``. Aucun résultat n'est omis, quel que
    soit son statut.

    Lève ``ValueError`` si ``run_id`` n'est pas un UUID, si un horodatage n'a
    pas de fuseau ou si une version de check n'est pas un entier >= 1.
    """
    versions = _versions_du_registre() if check_versions is None else check_versions
    _verifier_versions(versions)
    resultats = sorted(audit.results, key=lambda r: (r.check_id, r.target))
    gaps = sorted((g for r in resultats for g in r.gaps), key=_cle_gap)
    rapport = {
        "schema_version": SCHEMA_VERSION,
        "tool": {
            "name": TOOL_NAME,
            "version": audit.amnesia_version,
            "catalog_version": None,
        },
        "run": {
            # forme canonique (minuscules) ; ValueError si ce n'est pas un UUID
            "id": str(uuid.UUID(audit.run_id)),
            "started_at": _rfc3339(audit.started_at),
            "finished_at": _rfc3339(audit.finished_at),
            "duration_s": audit.duration_s,
            "complete": audit.complete,
            "interrupted": audit.interrupted,
            "profile": None,
            "argv": redact_argv(argv),
        },
        "targets": [_cible(audit.target)],
        "results": [_resultat(r, versions) for r in resultats],
        "gaps": [g.to_dict() for g in gaps],
        "summary": _resume(resultats),
    }
    resultat: dict[str, Any] = _sans_surrogates(rapport)
    return resultat


def dumps_report(report: Mapping[str, Any]) -> str:
    """Texte JSON déterministe du rapport, encodable en UTF-8 strict.

    ``ensure_ascii=False`` (accents lisibles), indentation de 2, clés dans
    l'ordre de ``build_report()``, saut de ligne final. Les surrogates isolés
    sont échappés (``\\udcff``) ; un flottant non fini lève ``ValueError``.
    """
    texte = json.dumps(
        _sans_surrogates(report), ensure_ascii=False, indent=2, allow_nan=False
    )
    return texte + "\n"
