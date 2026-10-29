"""Exemple de docs/dev/faits.md : tester un check avec FixtureCollector."""

from collections.abc import Mapping
from pathlib import Path

from amnesia.checks import Check, Gap
from amnesia.checks.base import CheckResult, Reason, Status
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
        config = facts.value(self.requires_facts[0])
        taille = config.get("max_size_bytes") if isinstance(config, Mapping) else None
        if isinstance(taille, int) and taille >= TAILLE_MIN:
            return CheckResult.passed(self.id, ctx.target.id)
        gap = Gap(
            question="Qui s'est connecté sur cet hôte il y a trois semaines ?",
            reason=f"Journal limité à {taille} octets : écrasé en quelques jours.",
            severity="high",
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
