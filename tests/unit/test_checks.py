"""Registre des checks et modele Check / Gap."""

import re

import pytest

from amnesia.checks import Check, Gap, default_checks
from amnesia.checks.context import Context
from amnesia.facts import FactSet
from amnesia.target import Target

FORMAT_ID = re.compile(r"[a-z][a-z0-9]*(?:\.[a-z0-9_]+)+")


def test_registre_non_vide_et_compose_de_checks() -> None:
    checks = default_checks()
    assert checks
    for check in checks:
        assert isinstance(check, Check)


def test_ids_uniques_et_bien_formes() -> None:
    ids = [check.id for check in default_checks()]
    assert len(ids) == len(set(ids))
    for check_id in ids:
        assert FORMAT_ID.fullmatch(check_id), check_id


def test_titres_non_vides() -> None:
    for check in default_checks():
        assert check.title.strip(), check.id


def test_registre_renvoie_une_copie() -> None:
    # un appelant qui modifie la liste ne doit pas alterer le registre
    default_checks().clear()
    assert default_checks()


def test_evaluate_non_implemente() -> None:
    with pytest.raises(NotImplementedError):
        Check().evaluate(FactSet(), Context(Target.parse("localhost")))


def test_gap_sans_severite_refuse() -> None:
    # plus de severite par defaut (#16) : chaque check la choisit explicitement
    with pytest.raises(TypeError, match="severity"):
        Gap(question="Qui s'est connecte ?", reason="journal ecrase")  # type: ignore[call-arg]
