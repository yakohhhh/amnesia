# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Lien entre le catalogue, le registre des checks et le code des checks (#46).

Deux garde-fous :

- le lien déclaré des deux côtés (``checks`` d'une question, ``question_ids``
  d'un check) est réciproque ;
- une analyse statique (AST) des modules de ``src/amnesia/checks/`` : aucune
  question écrite en dur dans un ``Gap``, aucun identifiant de question absent
  du catalogue.
"""

import ast
import dataclasses
from pathlib import Path

import pytest

from amnesia.catalog import (
    Catalog,
    CatalogError,
    load_catalog,
    registry_errors,
    verify_registry,
)
from amnesia.checks import REGISTRY, Check, CheckMeta, Domain, Registry
from amnesia.checks.base import FORMAT_QUESTION_ID
from amnesia.target import Kind

RACINE = Path(__file__).resolve().parent.parent.parent
CHECKS = RACINE / "src" / "amnesia" / "checks"


# --- registre des checks ---------------------------------------------------------


def test_catalogue_et_registre_coherents() -> None:
    assert registry_errors(load_catalog(), REGISTRY.metas()) == []
    verify_registry(load_catalog(), REGISTRY.metas())


def test_chaque_check_du_registre_est_reference_par_une_question() -> None:
    catalogue = load_catalog()
    metas = REGISTRY.metas()
    assert len(metas) == 5
    for meta in metas:
        questions = catalogue.questions_of_check(meta.id)
        assert questions, f"{meta.id} : aucune question du catalogue ne le cite"
        # les deux declarations disent la meme chose
        assert sorted(meta.question_ids) == [q.id for q in questions]
        assert list(meta.question_ids) == sorted(meta.question_ids), meta.id


def test_checks_cites_par_le_catalogue_tous_enregistres() -> None:
    connus = {m.id for m in REGISTRY.metas()}
    cites = {check for q in load_catalog() for check in q.checks}
    assert cites == connus


def _catalogue_modifie(question_id: str, checks: tuple[str, ...]) -> Catalog:
    """Catalogue embarqué dont une question cite d'autres checks."""
    catalogue = load_catalog()
    questions = [
        dataclasses.replace(q, checks=checks) if q.id == question_id else q
        for q in catalogue
    ]
    return Catalog(catalogue.version, questions, catalogue.sources)


def test_check_inconnu_du_registre() -> None:
    catalogue = _catalogue_modifie("Q-WIN-TIMELINE", ("win.time_sync", "win.inconnu"))
    erreurs = registry_errors(catalogue, REGISTRY.metas())
    assert erreurs == [
        "questions/windows.toml : question Q-WIN-TIMELINE : checks : check inconnu "
        "du registre 'win.inconnu'"
    ]
    with pytest.raises(CatalogError) as exc:
        verify_registry(catalogue, REGISTRY.metas())
    assert exc.value.errors == tuple(erreurs)


def test_lien_non_reciproque_cote_catalogue() -> None:
    # la question cite un check qui ne la cite pas
    catalogue = _catalogue_modifie("Q-WIN-TIMELINE", ("win.time_sync", "win.sysmon"))
    (erreur,) = registry_errors(catalogue, REGISTRY.metas())
    assert erreur == (
        "questions/windows.toml : question Q-WIN-TIMELINE : checks : win.sysmon ne "
        "cite pas cette question dans question_ids (module "
        "amnesia.checks.windows.sysmon)"
    )


def _meta(question_ids: tuple[str, ...]) -> CheckMeta:
    class Factice(Check):
        id = "win.factice"
        title = "Check factice"
        description = "Sert à vérifier le lien avec le catalogue."
        domain = Domain.WINDOWS
        target_kinds = (Kind.WINDOWS_HOST,)
        version = 1
        default_severity = "low"

    Factice.question_ids = question_ids
    registre = Registry()
    registre.register(Factice)
    (meta,) = registre.metas()
    return meta


def test_lien_non_reciproque_cote_check() -> None:
    # le check cite une question qui ne le liste pas, puis une question inconnue
    metas = [*REGISTRY.metas(), _meta(("Q-WIN-TIMELINE", "Q-WIN-INCONNUE"))]
    erreurs = registry_errors(load_catalog(), metas)
    assert len(erreurs) == 2
    lieu = f"check win.factice (module {__name__})"
    assert erreurs[0] == (
        f"{lieu} : question_ids : Q-WIN-TIMELINE ne liste pas ce check dans son "
        "champ checks"
    )
    assert erreurs[1] == (
        f"{lieu} : question_ids : question inconnue du catalogue 'Q-WIN-INCONNUE'"
    )


def test_check_sans_question_accepte() -> None:
    # un check peut exister avant d'etre relie : aucune erreur de son cote
    assert registry_errors(load_catalog(), [*REGISTRY.metas(), _meta(())]) == []


# --- analyse statique des modules de checks --------------------------------------


def _modules_de_checks() -> list[Path]:
    return sorted(CHECKS.rglob("*.py"))


def _nom_appele(appel: ast.Call) -> str:
    fonction = appel.func
    if isinstance(fonction, ast.Name):
        return fonction.id
    if isinstance(fonction, ast.Attribute):
        return fonction.attr
    return ""


def _est_litteral(valeur: ast.expr) -> bool:
    """Vrai si l'expression fabrique un texte sur place au lieu de le recevoir.

    Chaîne, f-string, concaténation, ``%``, ``"...".format()``,
    ``"".join(...)`` : tout ce qui n'est ni un nom ni un appel de fonction.
    """
    if isinstance(valeur, ast.Constant | ast.JoinedStr | ast.BinOp):
        return True
    if isinstance(valeur, ast.IfExp):
        return _est_litteral(valeur.body) or _est_litteral(valeur.orelse)
    return (
        isinstance(valeur, ast.Call)
        and isinstance(valeur.func, ast.Attribute)
        and isinstance(valeur.func.value, ast.Constant | ast.JoinedStr)
    )


def _docstrings(arbre: ast.AST) -> set[int]:
    """Identité des nœuds de docstrings : du texte, pas des identifiants."""
    ids: set[int] = set()
    for noeud in ast.walk(arbre):
        if not isinstance(
            noeud, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef
        ):
            continue
        corps = noeud.body
        if (
            corps
            and isinstance(corps[0], ast.Expr)
            and isinstance(corps[0].value, ast.Constant)
        ):
            ids.add(id(corps[0].value))
    return ids


def _ecarts(source: str, connues: frozenset[str]) -> list[str]:
    """Ce qui, dans un module de check, contourne le catalogue.

    - ``Gap(question=<texte écrit sur place>)`` : la question vient de
      ``render_question()`` ;
    - ``question_id=...``, ``question_ids = (...)``, ``render_question("...")``
      ou toute chaîne de la forme ``Q-...`` : l'identifiant existe au catalogue.
    """
    arbre = ast.parse(source)
    docstrings = _docstrings(arbre)
    ecarts: list[str] = []
    for noeud in ast.walk(arbre):
        if isinstance(noeud, ast.Call) and _nom_appele(noeud) == "Gap":
            for argument in noeud.keywords:
                if argument.arg == "question" and _est_litteral(argument.value):
                    ecarts.append(
                        f"ligne {noeud.lineno} : Gap(question=...) écrit en dur "
                        "(utiliser render_question())"
                    )
        if (
            isinstance(noeud, ast.Constant)
            and isinstance(noeud.value, str)
            and id(noeud) not in docstrings
            and FORMAT_QUESTION_ID.fullmatch(noeud.value)
            and noeud.value not in connues
        ):
            ecarts.append(
                f"ligne {noeud.lineno} : question_id absent du catalogue : "
                f"{noeud.value!r}"
            )
    return ecarts


def _connues() -> frozenset[str]:
    return frozenset(q.id for q in load_catalog())


def test_aucun_check_ne_contourne_le_catalogue() -> None:
    modules = _modules_de_checks()
    # modele, registre, contexte et les cinq checks Windows au moins
    assert len(modules) >= 10
    connues = _connues()
    for chemin in modules:
        ecarts = _ecarts(chemin.read_text(encoding="utf-8"), connues)
        assert not ecarts, f"{chemin.relative_to(RACINE).as_posix()} : {ecarts}"


@pytest.mark.parametrize(
    "valeur",
    [
        '"Qui s\'est connecté ?"',
        'f"Qui s\'est connecté sur {hote} ?"',
        '"Qui s\'est connecté sur " + hote + " ?"',
        '"Qui s\'est connecté sur %s ?" % hote',
        '"Qui s\'est connecté sur {} ?".format(hote)',
        '" ".join(["Qui", "?"])',
        'texte if connu else "Qui ?"',
    ],
)
def test_question_ecrite_en_dur_detectee(valeur: str) -> None:
    source = (
        "from ..base import Gap\n"
        "def evaluate(self, facts, ctx):\n"
        "    return Gap(\n"
        "        check_id=self.id,\n"
        '        question_id="Q-WIN-RDP-LOGON",\n'
        f"        question={valeur},\n"
        "    )\n"
    )
    (ecart,) = _ecarts(source, _connues())
    assert ecart == (
        "ligne 3 : Gap(question=...) écrit en dur (utiliser render_question())"
    )
    # meme constat quand Gap est atteint par son module
    assert _ecarts(source.replace("return Gap(", "return base.Gap("), _connues())


@pytest.mark.parametrize(
    "ligne",
    [
        'question_ids = ("Q-WIN-RDP-LOGON", "Q-WIN-INCONNUE")',
        'QUESTION = "Q-WIN-INCONNUE"',
        'gap = Gap(question_id="Q-WIN-INCONNUE", question=texte)',
        'texte = render_question("Q-WIN-INCONNUE", host=hote, lookback_days=21)',
        'ids = {"rdp": "Q-WIN-INCONNUE"}',
    ],
)
def test_question_id_absent_du_catalogue_detecte(ligne: str) -> None:
    (ecart,) = _ecarts(f"class C:\n    {ligne}\n", _connues())
    assert ecart == "ligne 2 : question_id absent du catalogue : 'Q-WIN-INCONNUE'"


def test_usage_conforme_accepte() -> None:
    source = (
        '"""Module de check : cite Q-WIN-INCONNUE dans sa docstring."""\n'
        "from ...catalog import render_question\n"
        "from ..base import Gap\n"
        "class C:\n"
        '    """Q-WIN-INCONNUE"""\n'
        '    question_ids = ("Q-WIN-RDP-LOGON",)\n'
        "    def evaluate(self, facts, ctx):\n"
        "        question = render_question(\n"
        "            self.question_ids[0], host=ctx.target.id, lookback_days=21\n"
        "        )\n"
        "        return [\n"
        "            Gap(question_id=self.question_ids[0], question=question),\n"
        "            Gap(\n"
        '                question_id="Q-WIN-POWERSHELL",\n'
        "                question=render_question(\n"
        '                    "Q-WIN-POWERSHELL", host=ctx.target.id, lookback_days=7\n'
        "                ),\n"
        "            ),\n"
        "        ]\n"
    )
    assert _ecarts(source, _connues()) == []
