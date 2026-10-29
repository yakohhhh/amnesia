# Faits et collecte

Un check ne joint jamais la cible. Il déclare les **faits** qu'il lit
(`requires_facts`), un **collecteur** les rassemble une fois par cible et par
audit, et le check les **évalue** sans aucune I/O (`evaluate`). Cette séparation
permet :

- de tester chaque check sous Linux, sur la CI, avec des faits enregistrés ;
- de prendre en charge le local, WinRM et le hors-ligne sans dupliquer de check ;
- de ne lancer qu'une fois une collecte coûteuse (auditpol, registre) lue par
  plusieurs checks ;
- de distinguer « non configuré », une valeur observée qui peut produire un Gap,
  de « non lisible » (accès refusé, fait absent), qui n'en produit jamais.

Code : `src/amnesia/facts/` (modèle, collecteurs, `resolve()`) et
`src/amnesia/checks/context.py`.

## Enveloppe `amnesia.facts/1`

Un `FactSet` se sérialise en JSON dans une enveloppe versionnée, décrite par le
JSON Schema `src/amnesia/schemas/facts-1.schema.json` (draft 2020-12) :

```json
{
  "schema": "amnesia.facts/1",
  "facts": {
    "<clé>": {
      "status": "ok | unavailable",
      "value": "<valeur JSON, null si clé ou option absente>",
      "unavailable_reason": "access_denied | timeout | unreachable | unsupported | not_collected",
      "source": "<commande ou API>",
      "collected_at": "2026-10-21T09:30:00Z"
    }
  }
}
```

- Une autre valeur de `schema` (`amnesia.facts/99`...) est refusée avec un
  message explicite : `version de schéma de faits inconnue : 'amnesia.facts/99'
  (version prise en charge : amnesia.facts/1)`.
- Champs inconnus, clés JSON en double, `NaN` et `Infinity` sont refusés.
- `unavailable_reason` est absent ou `null` pour un fait `ok`, obligatoire pour
  un fait `unavailable`, dont la `value` est alors `null`.
- `collected_at` est en ISO 8601 avec fuseau, ramené en UTC ; un horodatage
  sans fuseau est refusé.
- Les valeurs sont figées à la lecture (tuples, mappings en lecture seule) : un
  même fait est lu par plusieurs checks, aucun ne peut le modifier pour les
  autres.

Le schéma détaillé des faits Windows (valeur de chaque clé) relève de #48.

### Clés

Forme `domaine.nom[.nom...][:qualificatif]` :

- domaine parmi `windows`, `ad`, `m365`, `aws`, `siem` ;
- segments en minuscules `[a-z0-9_]` ;
- qualificatif facultatif pour une instance : nom de journal, de service...
  (`[A-Za-z0-9_./-]`, espaces simples permis).

Exemples : `windows.auditpol.backup`, `windows.eventlog.config:Security`,
`windows.eventlog.config:Microsoft-Windows-Sysmon/Operational`.

### Observé ou indisponible

| Situation | Fait | Peut produire un Gap |
|---|---|---|
| option configurée | `ok`, valeur observée | oui |
| clé de registre ou option absente | `ok`, `value: null` | oui |
| accès refusé | `unavailable` / `access_denied` | non |
| délai dépassé | `unavailable` / `timeout` | non |
| cible injoignable | `unavailable` / `unreachable` | non |
| sans objet sur la cible (Windows sur Linux) | `unavailable` / `unsupported` | non |
| non collecté (bundle partiel, collecte à venir) | `unavailable` / `not_collected` | non |

## Traduction des indisponibilités : `resolve()`

Le moteur (#21) appelle `resolve(check_id, target, requires_facts, facts)` avant
`evaluate()`. Elle rend `None` si tous les faits requis sont observés, sinon un
`CheckResult` qui n'est **jamais** `gap` ni `pass` :

| Fait requis | Résultat |
|---|---|
| absent du `FactSet`, ou `not_collected` | `skipped` / `not_collected` |
| `access_denied`, `timeout`, `unreachable` | `error` avec le même motif |
| `unsupported` | `not_applicable` |

Plusieurs faits indisponibles : l'erreur l'emporte sur le saut, qui l'emporte
sur `not_applicable`. Un check n'est sans objet que si tous ses faits manquants
sont `unsupported` : le doute penche vers « non évalué », jamais vers
« vérifié ». Le message d'erreur nomme le fait, son motif et sa source, et passe
par le caviardage d'`ErrorInfo` ; la source citée par un résultat
`not_applicable` passe par le même caviardage (`assainir()`).

## Collecteurs

Protocole `Collector` : `collect(target, names, *, timeout) -> FactSet`. Un fait
demandé mais absent du résultat compte comme non collecté.

- `CachingCollector(inner)` : mémoïse par (cible, fait) pendant un audit ; un
  fait demandé par deux checks n'est collecté qu'une fois par cible, et un fait
  non rendu est mémorisé comme absent. Une instance par audit.
- `FixtureCollector(path)` : lit un fichier de faits (`tests/fixtures/facts/`),
  validé à la construction, et rend les faits demandés quelle que soit la cible.
- `LocalCollector()` : version minimale. Hors Windows, tous les faits
  `windows.*` sont `unavailable/unsupported`, si bien que les checks Windows
  sont `not_applicable` sur la CI ubuntu ; les autres faits, et les faits
  Windows sous Windows tant que leur collecte n'existe pas (#48), sont
  `unavailable/not_collected`. Il refuse une cible autre que `local`.

Hors périmètre : collecteur PowerShell (#48), WinRM (#63), import de bundle
(#52), collecteurs cloud (#95).

### Règles pour tout collecteur

- argv passé en liste, jamais `shell=True` : les règles ruff S602, S604 et S605
  sont actives sur `src/` (`tests/test_regles_ruff.py`), et un test parcourt
  l'AST de `src/` ;
- timeout explicite sur chaque appel, propagé depuis `collect(..., timeout=)`,
  qui refuse une valeur nulle, négative ou infinie ;
- `subprocess` avec un `encoding=` explicite (`docs/dev/encodage.md`) et
  `env=subprocess_env()` : un `pwsh` lancé sans `POWERSHELL_TELEMETRY_OPTOUT=1`
  envoie une télémétrie à Microsoft, et sans `POWERSHELL_UPDATECHECK=Off`
  vérifie ses mises à jour (#26) ;
- un collecteur ne joint que la cible désignée par l'utilisateur, jamais un
  tiers. Les collecteurs sont les seuls modules de `src/` autorisés à ouvrir une
  connexion : la règle ruff `TID251` interdit `socket.socket`,
  `socket.create_connection`, `asyncio.open_connection`, `http.client`,
  `urllib.request`, `urllib3`, `requests` et `httpx` partout ailleurs, avec une
  dérogation `per-file-ignores` pour `src/amnesia/facts/collectors.py` et le
  futur paquet `src/amnesia/facts/collectors/` (#63, #95). Cette liste est
  explicite et vérifiée par `tests/test_reseau.py`, qui parcourt aussi l'AST de
  `src/` ; un nouveau collecteur réseau s'y ajoute dans le ticket qui
  l'introduit, jamais par un `noqa` ;
- aucune analyse de texte localisé : uniquement des GUID, des valeurs
  numériques, le registre et l'EventData XML. Par exemple `auditpol /backup`
  (CSV avec le GUID de sous-catégorie et un `Setting Value` numérique, d'où le
  fait `windows.auditpol.backup`) plutôt que `auditpol /get`, dont
  l'« Inclusion Setting » est traduite ;
- un échec de collecte d'un fait donne un fait `unavailable` avec son motif, pas
  une exception.

## Écrire un check

```python
class MonCheck(Check):
    id = "win.mon_check"
    title = "..."
    requires_facts = ("windows.eventlog.config:Security",)

    def evaluate(self, facts: FactSet, ctx: Context) -> CheckResult: ...
```

- `requires_facts` : tuple de clés, sans doublon ; il sera repris dans les
  métadonnées du registre (#17).
- `evaluate(facts, ctx)` est une fonction pure : ni processus, ni réseau, ni
  fichier, ni horloge système. `ctx` (`Context`) regroupe la cible, la
  configuration en lecture seule, l'horloge (`ctx.clock()`, UTC) et le logger
  `amnesia.check.<id>` (`Context.for_check`).
- Les faits requis y sont tous observés (`facts.value(clé)`), mais une valeur
  peut être `None`.
- Tant qu'un check n'est pas écrit, il hérite d'`evaluate()`, qui lève
  `NotImplementedError` ; le moteur (#21) le rend en `skipped/not_implemented`.

## Exemple complet : tester un check avec `FixtureCollector`

Les deux fichiers ci-dessous sont la copie exacte de fichiers du dépôt, lancés
par la suite de tests sous Linux (un test vérifie la concordance).

Faits enregistrés, `tests/fixtures/facts/exemple.json` (données synthétiques,
voir `tests/fixtures/README.md`) :

<!-- exemple : tests/fixtures/facts/exemple.json -->
```json
{
  "schema": "amnesia.facts/1",
  "facts": {
    "windows.eventlog.config:Security": {
      "status": "ok",
      "value": {"max_size_bytes": 20971520, "retention": "overwrite"},
      "source": "Get-WinEvent -ListLog Security",
      "collected_at": "2026-10-21T09:30:00Z"
    },
    "windows.eventlog.config:System": {
      "status": "unavailable",
      "value": null,
      "unavailable_reason": "access_denied",
      "source": "Get-WinEvent -ListLog System",
      "collected_at": "2026-10-21T09:30:00Z"
    }
  }
}
```

Le check et ses tests, `tests/unit/test_exemple_faits.py` :

<!-- exemple : tests/unit/test_exemple_faits.py -->
```python
"""Exemple de docs/dev/faits.md : tester un check avec FixtureCollector."""

from collections.abc import Mapping
from pathlib import Path

from amnesia.checks import Check, Gap
from amnesia.checks.base import (
    CheckResult,
    Confidence,
    Evidence,
    Reason,
    Severity,
    Status,
)
from amnesia.checks.context import Context
from amnesia.facts import FactSet, FixtureCollector, resolve
from amnesia.target import Target

FIXTURE = Path(__file__).parent.parent / "fixtures" / "facts" / "exemple.json"
TAILLE_MIN = 1024**3  # 1 Gio


class RetentionSecurity(Check):
    """Exemple : le journal Security doit pouvoir atteindre 1 Gio."""

    id = "win.exemple_retention"
    title = "Taille du journal Security (exemple)"
    requires_facts = ("windows.eventlog.config:Security",)

    def evaluate(self, facts: FactSet, ctx: Context) -> CheckResult:
        # fonction pure : uniquement les faits et le contexte, aucune I/O
        nom = self.requires_facts[0]
        config = facts.value(nom)
        taille = config.get("max_size_bytes") if isinstance(config, Mapping) else None
        if isinstance(taille, int) and taille >= TAILLE_MIN:
            return CheckResult.passed(self.id, ctx.target.id)
        gap = Gap(
            check_id=self.id,
            target=ctx.target.id,
            resource=nom.split(":", 1)[1],  # journal : Security
            question="Qui s'est connecté sur cet hôte il y a trois semaines ?",
            reason=f"Journal limité à {taille} octets : écrasé en quelques jours.",
            severity=Severity.HIGH,
            evidence=Evidence(
                observed=taille,
                expected=TAILLE_MIN,
                unit="bytes",
                confidence=Confidence.MEASURED,
                source=facts[nom].source,
            ),
            remediation="Porter le journal à 1 Gio au moins par GPO.",
        )
        return CheckResult.with_gaps(self.id, ctx.target.id, [gap])


class RetentionSystem(RetentionSecurity):
    id = "win.exemple_retention_system"
    requires_facts = ("windows.eventlog.config:System",)


class RetentionSysmon(RetentionSecurity):
    id = "win.exemple_retention_sysmon"
    requires_facts = ("windows.eventlog.config:Microsoft-Windows-Sysmon/Operational",)


def auditer(check: Check) -> CheckResult:
    """Ce que fera le moteur (#21) : collecter, résoudre, puis évaluer."""
    cible = Target.parse("local")
    faits = FixtureCollector(FIXTURE).collect(cible, check.requires_facts, timeout=30)
    resultat = resolve(check.id, cible.id, check.requires_facts, faits)
    if resultat is not None:
        return resultat
    return check.evaluate(faits, Context.for_check(check.id, cible))


def test_journal_trop_petit_donne_un_gap() -> None:
    resultat = auditer(RetentionSecurity())
    assert resultat.status is Status.GAP
    assert "20971520 octets" in resultat.gaps[0].reason


def test_fait_inaccessible_donne_une_erreur_et_aucun_gap() -> None:
    resultat = auditer(RetentionSystem())
    assert resultat.status is Status.ERROR
    assert resultat.reason is Reason.ACCESS_DENIED
    assert resultat.gaps == ()


def test_fait_absent_donne_skipped_not_collected() -> None:
    resultat = auditer(RetentionSysmon())
    assert resultat.status is Status.SKIPPED
    assert resultat.reason is Reason.NOT_COLLECTED
```

La fonction `auditer()` reproduit ce que fera le moteur (#21) : collecter,
résoudre les indisponibilités, puis évaluer. Le même check donne un `gap` sur
un fait observé, une `error/access_denied` sans Gap sur un fait refusé, et un
`skipped/not_collected` sur un fait absent du fichier.
