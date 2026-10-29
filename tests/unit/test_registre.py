"""Registre des checks : metadonnees validees, ids uniques, chargement (#17)."""

from __future__ import annotations

import ast
import dataclasses
import doctest
import importlib
import pkgutil
import re
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, cast

import pytest

import amnesia
from amnesia import checks
from amnesia.checks import (
    REGISTRY,
    Check,
    CheckMeta,
    CheckRegistrationError,
    Domain,
    DuplicateCheckError,
    Gap,
    InvalidCheckError,
    Registry,
    default_checks,
    register,
    registry,
)
from amnesia.checks.windows.event_log_retention import EventLogRetention
from amnesia.checks.windows.sysmon import SysmonPresent
from amnesia.target import Kind, Target

FORMAT_ID = re.compile(r"[a-z][a-z0-9]*(?:\.[a-z0-9_]+)+")
IDS_ACTUELS = {
    "win.audit_policy",
    "win.event_log_retention",
    "win.powershell_logging",
    "win.sysmon",
    "win.time_sync",
}
_ABSENT = object()
_PAQUET_ESSAI = "paquet_essai_registre"
_ENTETE = (
    "from amnesia.checks import Check, Domain, register\n"
    "from amnesia.target import Kind\n\n"
)


def _source_check(classe: str, check_id: str, *, decore: bool = True) -> str:
    """Source d'une classe de check valide, pour un module d'essai."""
    decorateur = "@register\n" if decore else ""
    return (
        f"{decorateur}class {classe}(Check):\n"
        f"    id = {check_id!r}\n"
        f"    title = 'Check {classe}'\n"
        "    description = 'Check declare par un module d essai.'\n"
        "    domain = Domain.WINDOWS\n"
        "    target_kinds = (Kind.WINDOWS_HOST,)\n"
        "    version = 1\n"
        "    default_severity = 'low'\n"
    )


@pytest.fixture
def paquet_essai(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Callable[[dict[str, str]], str]]:
    """Cree un paquet de checks hors du depot et rend son nom importable."""

    def creer(modules: dict[str, str]) -> str:
        dossier = tmp_path / "sources" / _PAQUET_ESSAI
        dossier.mkdir(parents=True)
        (dossier / "__init__.py").write_text("", encoding="utf-8")
        for module, source in modules.items():
            (dossier / f"{module}.py").write_text(_ENTETE + source, encoding="utf-8")
        monkeypatch.syspath_prepend(str(tmp_path / "sources"))
        return _PAQUET_ESSAI

    yield creer
    for nom in [n for n in sys.modules if n.split(".")[0] == _PAQUET_ESSAI]:
        del sys.modules[nom]


def _classe(
    nom: str = "Essai", *, module: str | None = None, **attributs: object
) -> type[Check]:
    """Classe de check valide, modifiee par attributs (_ABSENT : supprime)."""
    corps: dict[str, object] = {
        "id": "win.essai",
        "title": "Check d'essai",
        "description": "Check declare par les tests.",
        "domain": Domain.WINDOWS,
        "target_kinds": (Kind.WINDOWS_HOST,),
        "version": 1,
        "default_severity": "medium",
    }
    corps.update(attributs)
    corps = {cle: valeur for cle, valeur in corps.items() if valeur is not _ABSENT}
    if module is not None:
        corps["__module__"] = module
    return cast("type[Check]", type(nom, (Check,), corps))


# --- unicite ----------------------------------------------------------------


def test_doublon_nomme_les_deux_classes_et_modules() -> None:
    registre = Registry()
    registre.register(SysmonPresent)
    copie = _classe("SysmonTiers", module="amnesia_tiers.sysmon", id="win.sysmon")
    with pytest.raises(DuplicateCheckError) as exc:
        registre.register(copie)
    message = str(exc.value)
    assert "'win.sysmon'" in message
    assert "SysmonPresent" in message
    assert "amnesia.checks.windows.sysmon" in message
    assert "SysmonTiers" in message
    assert "amnesia_tiers.sysmon" in message
    # rien n'est remplace
    assert [m.class_name for m in registre.metas()] == ["SysmonPresent"]


def test_doublon_refuse_par_le_decorateur() -> None:
    avant = REGISTRY.metas()
    with pytest.raises(DuplicateCheckError, match="time_sync"):
        register(_classe("Horloge", id="win.time_sync"))
    assert REGISTRY.metas() == avant


def test_reenregistrer_la_meme_classe_est_sans_effet() -> None:
    registre = Registry()
    classe = _classe()
    assert registre.register(classe) is classe
    assert registre.register(classe) is classe
    assert len(registre.metas()) == 1


def test_meme_declaration_reimportee_remplace_l_ancienne() -> None:
    # meme module et meme nom qualifie : la declaration a ete reimportee
    registre = Registry()
    ancienne = registre.register(_classe("Essai", module="tiers.essai"))
    nouvelle = registre.register(_classe("Essai", module="tiers.essai"))
    assert ancienne is not nouvelle
    assert registre.classes() == [nouvelle]
    autre_module = _classe("Essai", module="tiers.autre")
    with pytest.raises(DuplicateCheckError, match=r"tiers\.essai.*tiers\.autre"):
        registre.register(autre_module)


def test_echec_repete_nomme_toujours_les_deux_classes(
    paquet_essai: Callable[[dict[str, str]], str],
) -> None:
    nom = paquet_essai({"a": _source_check("A", "win.a") + _source_check("B", "win.a")})
    registre = Registry([nom])
    # le module en echec est retire de sys.modules : le 2e appel le reimporte
    for _ in range(2):
        with pytest.raises(DuplicateCheckError) as exc:
            registre.metas()
        assert "classe A " in str(exc.value)
        assert "classe B " in str(exc.value)


def test_classe_heritee_sans_nouvel_id_est_un_doublon() -> None:
    registre = Registry()
    parent = registre.register(_classe("Parent"))
    enfant = cast("type[Check]", type("Enfant", (parent,), {}))
    with pytest.raises(DuplicateCheckError, match=r"Parent.*Enfant"):
        registre.register(enfant)


# --- validation des ids -----------------------------------------------------


@pytest.mark.parametrize(
    ("check_id", "domaine"),
    [
        ("Win.Audit", Domain.WINDOWS),
        ("sysmon", Domain.WINDOWS),
        ("aws.x", Domain.WINDOWS),
        ("win.Audit", Domain.WINDOWS),
        ("win.", Domain.WINDOWS),
        ("win..x", Domain.WINDOWS),
        ("win.x\n", Domain.WINDOWS),
        (" win.x", Domain.WINDOWS),
        ("win.x-y", Domain.WINDOWS),
        ("win.é", Domain.WINDOWS),
        ("1win.x", Domain.WINDOWS),
        ("windows.x", Domain.WINDOWS),
        ("win.x", Domain.AD),
        ("ad.x", Domain.WINDOWS),
        ("", Domain.WINDOWS),
    ],
)
def test_id_invalide_refuse(check_id: str, domaine: Domain) -> None:
    registre = Registry()
    with pytest.raises(InvalidCheckError, match="Essai") as exc:
        registre.register(_classe(id=check_id, domain=domaine))
    assert repr(check_id) in str(exc.value)
    assert registre.metas() == []


@pytest.mark.parametrize(
    ("check_id", "domaine"),
    [
        ("win.audit_policy", Domain.WINDOWS),
        ("win.sysmon.config", Domain.WINDOWS),
        ("win.4688", Domain.WINDOWS),
        ("ad.krbtgt_age", Domain.AD),
        ("m365.unified_audit_log", Domain.M365),
        ("aws.cloudtrail", Domain.AWS),
        ("siem.forwarding", Domain.SIEM),
    ],
)
def test_id_valide_accepte(check_id: str, domaine: Domain) -> None:
    registre = Registry()
    registre.register(_classe(id=check_id, domain=domaine))
    assert [m.id for m in registre.metas()] == [check_id]


def test_prefixes_des_domaines() -> None:
    assert {d.value for d in Domain} == {"windows", "ad", "m365", "aws", "siem"}
    assert {d: d.prefix for d in Domain} == {
        Domain.WINDOWS: "win",
        Domain.AD: "ad",
        Domain.M365: "m365",
        Domain.AWS: "aws",
        Domain.SIEM: "siem",
    }


# --- validation des autres metadonnees -------------------------------------


@pytest.mark.parametrize(
    ("attribut", "valeur"),
    [
        ("id", _ABSENT),
        ("title", _ABSENT),
        ("description", _ABSENT),
        ("domain", _ABSENT),
        ("target_kinds", _ABSENT),
        ("version", _ABSENT),
        ("default_severity", _ABSENT),
        ("id", 42),
        ("domain", "windows"),
        ("title", ""),
        ("title", "   "),
        ("title", "\x1b[31mrouge"),
        ("description", "ligne\nsuite"),
        ("version", 0),
        ("version", True),
        ("version", "1"),
        ("default_severity", "hihg"),
        ("default_severity", "HIGH"),
        ("target_kinds", ()),
        ("target_kinds", ("windows_host",)),
        ("target_kinds", [Kind.WINDOWS_HOST]),
        ("target_kinds", (Kind.WINDOWS_HOST, Kind.WINDOWS_HOST)),
        ("requires_facts", "windows.auditpol.backup"),
        ("requires_facts", ("",)),
        ("question_ids", ("q.rdp", "q.rdp")),
    ],
)
def test_metadonnee_invalide_refusee(attribut: str, valeur: object) -> None:
    classe = _classe()
    if valeur is _ABSENT:
        delattr(classe, attribut)
    else:
        setattr(classe, attribut, valeur)
    registre = Registry()
    with pytest.raises(InvalidCheckError, match=f"Essai : .*{attribut}"):
        registre.register(classe)
    assert registre.metas() == []


def test_classe_hors_check_refusee() -> None:
    with pytest.raises(InvalidCheckError, match="sous-classe de Check"):
        Registry().register(cast(Any, int))


def test_meta_figee_et_complete() -> None:
    registre = Registry()
    registre.register(
        _classe(
            requires_facts=("windows.auditpol.backup",),
            question_ids=("q.logon",),
            version=3,
            default_severity="critical",
        )
    )
    (meta,) = registre.metas()
    assert meta == CheckMeta(
        id="win.essai",
        title="Check d'essai",
        description="Check declare par les tests.",
        domain=Domain.WINDOWS,
        target_kinds=(Kind.WINDOWS_HOST,),
        version=3,
        default_severity="critical",
        requires_facts=("windows.auditpol.backup",),
        question_ids=("q.logon",),
        implemented=False,
        module=__name__,
        class_name="Essai",
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        meta.id = "win.autre"  # type: ignore[misc]


def test_implemented_derive_de_la_surcharge_de_run() -> None:
    class Implemente(Check):
        id = "win.implemente"
        title = "Check implémenté"
        description = "Surcharge run()."
        domain = Domain.WINDOWS
        target_kinds = (Kind.WINDOWS_HOST,)
        version = 1
        default_severity = "low"

        def run(self, target: Target) -> list[Gap]:
            return []

    registre = Registry()
    registre.register(Implemente)
    registre.register(_classe())
    assert {m.id: m.implemented for m in registre.metas()} == {
        "win.essai": False,
        "win.implemente": True,
    }


# --- instances neuves -------------------------------------------------------


def test_default_checks_instances_neuves() -> None:
    a, b = default_checks(), default_checks()
    assert a[0] is not b[0]
    assert len(a) == len(b) == len(IDS_ACTUELS)
    for x, y in zip(a, b, strict=True):
        assert x is not y
        assert type(x) is type(y)


def test_create_all_trie_par_id() -> None:
    registre = Registry()
    registre.register(_classe("Zulu", id="win.zulu"))
    registre.register(_classe("Alpha", id="win.alpha"))
    instances = registre.create_all()
    assert [c.id for c in instances] == ["win.alpha", "win.zulu"]
    assert [type(c).__name__ for c in instances] == ["Alpha", "Zulu"]
    assert registre.create_all()[0] is not instances[0]


# --- checks actuels et organisation ----------------------------------------


def test_checks_actuels() -> None:
    metas = REGISTRY.metas()
    assert {m.id for m in metas} == IDS_ACTUELS
    for meta in metas:
        assert FORMAT_ID.fullmatch(meta.id), meta.id
        assert meta.domain is Domain.WINDOWS
        assert meta.target_kinds == (Kind.WINDOWS_HOST,)
        assert meta.version == 1
        assert meta.default_severity in registry.SEVERITES
        assert meta.requires_facts == ()
        assert meta.description.strip()
        assert not meta.implemented, meta.id


def test_un_module_par_check_windows() -> None:
    for meta in REGISTRY.metas():
        nom = meta.id.split(".", 1)[1]
        assert meta.module == f"amnesia.checks.windows.{nom}", meta.id
    assert len({m.module for m in REGISTRY.metas()}) == len(IDS_ACTUELS)


def test_classes_triees_par_id() -> None:
    assert [c.id for c in REGISTRY.classes()] == sorted(IDS_ACTUELS)


def test_retention_des_journaux_coherente() -> None:
    assert EventLogRetention.id == "win.event_log_retention"
    assert EventLogRetention.__module__.endswith(".event_log_retention")
    assert "journaux d'événements" in EventLogRetention.title
    assert "rétention" in EventLogRetention.title.lower()


def test_ancien_id_absent_des_sources() -> None:
    sources = Path(amnesia.__file__).parent
    for fichier in sources.rglob("*.py"):
        texte = fichier.read_text(encoding="utf-8")
        for ancien in ("security_log_size", "SecurityLogRetention"):
            assert ancien not in texte, f"{fichier.name} : {ancien}"
    assert not (sources / "checks" / "windows.py").exists()


# --- chargement -------------------------------------------------------------


def test_paquets_par_defaut_couvrent_chaque_domaine() -> None:
    sous_paquets = {
        f"amnesia.checks.{m.name}"
        for m in pkgutil.iter_modules(checks.__path__)
        if m.ispkg
    }
    assert set(REGISTRY.packages) == sous_paquets
    assert {"amnesia.checks.windows", "amnesia.checks.ad"} <= sous_paquets


def test_paquet_ad_charge_meme_sans_check(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delitem(sys.modules, "amnesia.checks.ad", raising=False)
    registre = Registry(["amnesia.checks.ad"])
    du_domaine_ad = [m for m in REGISTRY.metas() if m.domain is Domain.AD]
    assert registre.metas() == du_domaine_ad
    assert "amnesia.checks.ad" in sys.modules


def test_registre_dedie_recueille_les_checks_de_ses_paquets() -> None:
    registre = Registry(["amnesia.checks.windows"])
    assert {m.id for m in registre.metas()} == IDS_ACTUELS
    assert registre.classes() == REGISTRY.classes()


def test_registre_dedie_ne_touche_pas_le_registre_par_defaut(
    paquet_essai: Callable[[dict[str, str]], str],
) -> None:
    avant = REGISTRY.metas()
    nom = paquet_essai({"a": _source_check("A", "win.a")})
    registre = Registry([nom])
    assert [(m.id, m.module) for m in registre.metas()] == [("win.a", f"{nom}.a")]
    assert REGISTRY.metas() == avant
    # module deja importe : un second registre le relit
    assert [m.id for m in Registry([nom]).metas()] == ["win.a"]


@pytest.mark.parametrize(
    "source",
    [
        _source_check("Oubli", "win.oubli", decore=False),
        "from amnesia.checks.windows.sysmon import SysmonPresent\n",
        "",
    ],
    ids=["register-oublie", "check-seulement-importe", "module-vide"],
)
def test_module_sans_check_declare_signale(
    paquet_essai: Callable[[dict[str, str]], str], source: str
) -> None:
    nom = paquet_essai({"a": _source_check("A", "win.a"), "oubli": source})
    registre = Registry([nom])
    with pytest.raises(CheckRegistrationError, match=r"oubli : aucun check.*@register"):
        registre.metas()


def test_chaque_module_windows_declare_un_check() -> None:
    windows = importlib.import_module("amnesia.checks.windows")
    modules = {
        f"amnesia.checks.windows.{m.name}"
        for m in pkgutil.iter_modules(windows.__path__)
    }
    assert modules == {m.module for m in REGISTRY.metas()}


def test_chargement_unique(monkeypatch: pytest.MonkeyPatch) -> None:
    importes: list[str] = []
    vrai_import = importlib.import_module

    def espion(nom: str, package: str | None = None) -> Any:
        importes.append(nom)
        return vrai_import(nom, package)

    monkeypatch.setattr(importlib, "import_module", espion)
    registre = Registry(["amnesia.checks.windows"])
    registre.load()
    assert {m.id for m in registre.metas()} == IDS_ACTUELS
    assert {type(c).id for c in registre.create_all()} == IDS_ACTUELS
    attendus = sorted(f"amnesia.checks.windows.{i.split('.')[1]}" for i in IDS_ACTUELS)
    assert importes == ["amnesia.checks.windows", *attendus]


def test_paquet_inconnu_signale() -> None:
    registre = Registry(["amnesia.checks.inexistant"])
    with pytest.raises(ModuleNotFoundError):
        registre.load()
    # pas de chargement partiel considere comme acquis
    with pytest.raises(ModuleNotFoundError):
        registre.metas()


class _ImportsDeModule(ast.NodeVisitor):
    """Imports executes a l'import du module (hors fonctions)."""

    def __init__(self) -> None:
        self.modules: list[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        pass

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        pass

    def visit_Import(self, node: ast.Import) -> None:
        self.modules.extend(alias.name for alias in node.names)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level == 0 and node.module is not None:
            self.modules.append(node.module)


def test_aucun_sdk_importe_au_niveau_des_modules_de_checks() -> None:
    # list-checks doit fonctionner sans les extras : SDK importes par les
    # collecteurs (#20, #44), jamais par un module de check
    dossier = Path(checks.__file__).parent
    fichiers = sorted(dossier.rglob("*.py"))
    assert len(fichiers) >= len(IDS_ACTUELS)
    for fichier in fichiers:
        visiteur = _ImportsDeModule()
        visiteur.visit(ast.parse(fichier.read_text(encoding="utf-8")))
        for module in visiteur.modules:
            racine = module.split(".")[0]
            assert racine in sys.stdlib_module_names or racine == "amnesia", (
                f"{fichier.relative_to(dossier)} importe {module}"
            )


def test_exemple_de_la_docstring() -> None:
    resultat = doctest.testmod(registry)
    assert resultat.attempted > 0
    assert resultat.failed == 0
