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

- lecture seule : un collecteur n'exécute que des opérations de l'allowlist
  (`amnesia.readonly`, section « Lecture seule » ci-dessous). Un exécutable
  se lance par `run_command(argv, timeout=)`, seul appel à `subprocess` de
  `amnesia.facts` (vérifié sur l'AST) : programme hors allowlist, sans chemin
  complet ou avec d'autres arguments que ses formes figées, et
  `ReadOnlyViolation` est levée avant tout lancement ;
- argv passé en liste, jamais `shell=True`, programme désigné par son chemin
  complet : les règles ruff S602, S604, S605 et S607 sont actives sur `src/`
  (`tests/test_regles_ruff.py`), et un test parcourt l'AST de `src/` ;
- timeout explicite sur chaque appel, propagé depuis `collect(..., timeout=)`,
  qui refuse une valeur nulle, négative ou infinie ;
- `subprocess` avec un `encoding=` explicite (`docs/dev/encodage.md`) et
  `env=subprocess_env()` : un `pwsh` lancé sans `POWERSHELL_TELEMETRY_OPTOUT=1`
  envoie une télémétrie à Microsoft, et sans `POWERSHELL_UPDATECHECK=Off`
  vérifie ses mises à jour (#26). `tests/test_reseau.py` le vérifie sur l'AST
  de `src/` : chaque `subprocess.run`, `Popen`, `check_output`… et
  `asyncio.create_subprocess_*` (ou `loop.subprocess_exec`,
  `loop.subprocess_shell`) reçoit `env=subprocess_env(...)` explicite,
  et `os.system`, `os.popen`, `os.exec*` et `os.spawn*` sont refusés ;
- un collecteur ne joint que la cible désignée par l'utilisateur, jamais un
  tiers. Les collecteurs sont les seuls modules de `src/` autorisés à ouvrir une
  connexion : la règle ruff `TID251` interdit `socket.socket`,
  `socket.create_connection`, `asyncio.open_connection`,
  `asyncio.start_server`, `http.client`, `urllib.request`, `urllib3`,
  `requests`, `httpx` et les handlers de journalisation réseau
  (`logging.handlers.HTTPHandler`, `SysLogHandler`…) partout ailleurs, avec une
  dérogation `per-file-ignores` pour `src/amnesia/facts/collectors.py` et le
  futur paquet `src/amnesia/facts/collectors/` (#63, #95). Cette liste est
  explicite et vérifiée par `tests/test_reseau.py`, qui parcourt aussi l'AST de
  `src/` (imports, `importlib.import_module` d'un nom littéral, méthodes de
  connexion comme `loop.create_connection` quel que soit leur receveur) ; un
  nouveau collecteur réseau s'y ajoute dans le ticket qui l'introduit, jamais
  par un `noqa`. ruff lève `TID251` en entier, pas seulement ses API réseau :
  dans les collecteurs, les autres API interdites (`set_stream_logger`…) sont
  tenues par `tests/test_reseau.py`, qui relance ruff sans dérogation ni `noqa`
  et refuse `set_stream_logger` sur l'AST quel que soit son receveur ;
- aucune analyse de texte localisé : uniquement des GUID, des valeurs
  numériques, le registre et l'EventData XML. Par exemple la politique d'audit
  par GUID de sous-catégorie et valeur numérique (le `Setting Value` du CSV
  d'`auditpol /backup`, d'où le fait `windows.auditpol.backup`) plutôt que
  `auditpol /get`, dont l'« Inclusion Setting » est traduite ;
- aucune écriture sur la cible, même temporaire : `auditpol /backup
  /file:<fichier>` écrit un fichier sur la cible et n'entre pas dans
  l'allowlist ; en ligne, la même valeur se lit par l'API
  `AuditQuerySystemPolicy` ([ADR 0006](../adr/0006-garantie-lecture-seule.md)) ;
- un échec de collecte d'un fait donne un fait `unavailable` avec son motif, pas
  une exception ;
- un SDK tiers (WinRM, LDAP, Graph, boto3) s'importe dans `collect()`, après
  `require_extra("<extra>")`, jamais au niveau du module. Seule exception à la
  règle précédente : sans l'extra, `require_extra` lève `MissingExtra`, que le
  moteur traduit en « non évalué » avec la commande d'installation
  ([`docs/dev/dependances.md`](dependances.md)).

### Lecture seule : ajouter une opération à l'allowlist

`ALLOWED_OPERATIONS` (`src/amnesia/readonly.py`) est la source unique de ce
qu'un collecteur exécute sur une cible
([ADR 0006](../adr/0006-garantie-lecture-seule.md)) ;
[`docs/READ-ONLY.md`](../READ-ONLY.md) en est généré. Un collecteur qui a
besoin d'une nouvelle lecture l'y ajoute, dans la même PR :

- **exécutable** : une forme `Executable` par ligne de commande, arguments
  littéraux ou `Param` borné par une expression régulière qui ne laisse
  passer ni option (`/r:<hôte>`) ni chemin distant ; jamais une forme qui
  écrit, même un fichier temporaire (`auditpol /backup`, `reg export`,
  `wevtutil epl`) ;
- **script PowerShell** : un fichier de `src/amnesia/ps/`, jamais une chaîne
  dans le code Python, inscrit dans `SCRIPTS` avec son empreinte
  (`script_digest()`) et chargé par `load_script()`. Il n'emploie que les
  cmdlets (`PsCommand`, nom complet, aucun alias) et méthodes .NET
  (`PsMethod`) de l'allowlist, n'affecte que des variables simples et ne
  redirige rien vers un fichier. Un verbe interdit (`Set-`, `New-`...) n'est
  admis que par une exception nommée et justifiée (`exception=True`) ;
  `ForEach-Object` n'est pas admis, son paramètre `-MemberName` appelant
  une méthode hors de vue de l'analyse : utiliser l'instruction `foreach` ;
- **LDAP, AWS, HTTP** : le client passe par `ReadOnlyLdap`,
  `protect_aws_client()` ou `HttpGuard(api, base_url)` ; une opération qui
  laisse une trace ou consomme un quota chez le client porte un `opt_in`,
  décrit dans `OPT_INS`, et reste refusée par défaut ;
- `ALLOWLIST_VERSION` est incrémenté, puis `uv run python
  scripts/generer_read_only.py` régénère la documentation (un test échoue
  sinon).

`ReadOnlyViolation` signale un bug d'amnesia, pas un échec de collecte : un
collecteur la laisse remonter, hors de tout `except Exception`, au lieu d'en
faire un fait `unavailable`. Les scripts sont analysés par
`tests/integration/test_scripts_powershell.py`, qui demande `pwsh` : ignoré
sans lui sur un poste de développement, en échec sans lui sur la CI.

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
- `requires_extra` (facultatif) : extra optionnel sans lequel le check ne peut
  jamais être évalué, quel que soit le transport (SDK d'une API cloud :
  `"aws"`). Sans lui, le moteur rend `skipped/not_collected` avec la commande
  d'installation ; `amnesia list-checks` l'affiche. Convention :
  [`docs/dev/dependances.md`](dependances.md).

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

<!-- REUSE-IgnoreStart : en-tete SPDX du fichier cite, pas de ce document -->
<!-- exemple : tests/unit/test_exemple_faits.py -->
```python
# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

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
<!-- REUSE-IgnoreEnd -->

La fonction `auditer()` reproduit ce que fera le moteur (#21) : collecter,
résoudre les indisponibilités, puis évaluer. Le même check donne un `gap` sur
un fait observé, une `error/access_denied` sans Gap sur un fait refusé, et un
`skipped/not_collected` sur un fait absent du fichier.
