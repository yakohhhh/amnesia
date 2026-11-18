"""Couche de collecte : faits bruts d'une cible, séparés de leur évaluation.

Les collecteurs (``Collector``) joignent la cible et rendent un ``FactSet`` ; les
checks l'évaluent sans aucune I/O (``Check.evaluate``). ``resolve()`` traduit
les faits requis indisponibles en résultat, sans jamais produire de Gap.
Documentation : ``docs/dev/faits.md``.
"""

from .collectors import (
    SUBPROCESS_ENV,
    CachingCollector,
    Collector,
    FixtureCollector,
    LocalCollector,
    subprocess_env,
)
from .model import (
    FACT_DOMAINS,
    SCHEMA,
    Fact,
    FactSet,
    FactsFormatError,
    FactStatus,
    JSONValue,
    UnavailableReason,
    load_facts,
    validate_fact_name,
)
from .resolution import FactUnavailableError, resolve

__all__ = [
    "FACT_DOMAINS",
    "SCHEMA",
    "SUBPROCESS_ENV",
    "CachingCollector",
    "Collector",
    "Fact",
    "FactSet",
    "FactStatus",
    "FactUnavailableError",
    "FactsFormatError",
    "FixtureCollector",
    "JSONValue",
    "LocalCollector",
    "UnavailableReason",
    "load_facts",
    "resolve",
    "subprocess_env",
    "validate_fact_name",
]
