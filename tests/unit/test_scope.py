# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Périmètre autorisé (#37) : déclaration, contrôle de la cible, base d'autorisation.

La résolution des noms est toujours simulée : ``amnesia.scope`` n'ouvre aucune
connexion, et le réseau est coupé par tests/conftest.py.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Sequence
from datetime import UTC, date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from amnesia import log
from amnesia.config import example_toml
from amnesia.inputs import loads_toml
from amnesia.scope import (
    SOURCE_MISSION,
    SOURCE_OPTION,
    TYPES,
    Authorization,
    Basis,
    Refusal,
    Rules,
    Scope,
    ScopeError,
    ScopeRefusal,
    authorize,
    confirmation_name,
    load_scope,
    parse_reference,
    parse_scope,
)
from amnesia.target import Kind, Target, TargetError, Transport, normalize_host

RACINE = Path(__file__).resolve().parents[2]
DOC = RACINE / "docs" / "perimetre.md"
README = RACINE / "README.md"

PENDANT = datetime(2026, 1, 14, 10, 0, tzinfo=UTC)
GUID = "00000000-0000-4000-8000-000000000000"


def _table(**remplace: Any) -> dict[str, Any]:
    table: dict[str, Any] = {
        "mission_id": "MISSION-0001",
        "valid_from": date(2026, 1, 12),
        "valid_until": date(2026, 1, 16),
        "authorization": {
            "reference": "LM-2026-001",
            "date": date(2026, 1, 5),
            "signatory": "Prénom Nom",
            "signatory_role": "RSSI",
        },
        "include": {"dns": ["*.corp.example"]},
    }
    table.update(remplace)
    return table


def _scope(
    include: dict[str, list[str]] | None = None,
    exclude: dict[str, list[str]] | None = None,
) -> Scope:
    table = _table()
    if include is not None:
        table["include"] = include
    if exclude is not None:
        table["exclude"] = exclude
    return parse_scope(table)


def _cible(texte: str) -> Target:
    return Target.parse(texte)


def _resolution(*adresses: str) -> Callable[[str], Sequence[str]]:
    return lambda _nom: list(adresses)


def _jamais(_nom: str) -> Sequence[str]:
    raise AssertionError("résolution inattendue")


def _refus(
    scope: Scope, cible: str | Target, **options: Any
) -> pytest.ExceptionInfo[ScopeRefusal]:
    target = _cible(cible) if isinstance(cible, str) else cible
    with pytest.raises(ScopeRefusal) as exc:
        scope.verify(target, **{"now": PENDANT, **options})
    # le message s'affiche tel quel : imprimable, sans caractere de controle
    assert exc.value.message.isprintable()
    assert str(exc.value) == exc.value.message
    return exc


# --- normalize_host (amnesia.target) ---


@pytest.mark.parametrize(
    ("brut", "attendu"),
    [
        ("SRV01.Corp.Example.", "srv01.corp.example"),
        ("192.0.2.10", "192.0.2.10"),
        ("2001:DB8::10", "2001:db8::10"),
        ("[2001:db8::10]", "2001:db8::10"),
    ],
)
def test_normalize_host_meme_forme_que_la_cible(brut: str, attendu: str) -> None:
    assert normalize_host(brut) == attendu
    hote = f"[{attendu}]" if ":" in attendu else attendu
    assert Target.parse(f"winrm://{hote}").address == attendu


@pytest.mark.parametrize(
    "brut", ["", "srv 01", "*.corp.example", "srv01;x", "-srv", "192.0.2.256", "é.x"]
)
def test_normalize_host_refuse(brut: str) -> None:
    with pytest.raises(TargetError):
        normalize_host(brut)


# --- declaration ---


def test_parse_normalise_trie_et_dedoublonne() -> None:
    scope = parse_scope(
        _table(
            include={
                "hosts": ["SRV02.Corp.Example.", "srv01.corp.example", "192.0.2.10"],
                "dns": ["*.Corp.Example", "*.corp.example"],
                "ad_domains": ["CORP.example"],
                "cidrs": ["192.0.2.0/255.255.255.0", "2001:DB8::/32"],
                "entra_tenants": [GUID.upper()],
                "aws_accounts": ["000000000000"],
            },
            exclude={"hosts": ["srv09.corp.example"]},
            active_tests=True,
        ),
        source=SOURCE_MISSION,
    )
    assert scope.include == Rules(
        hosts=("192.0.2.10", "srv01.corp.example", "srv02.corp.example"),
        dns=("*.corp.example",),
        ad_domains=("corp.example",),
        cidrs=("192.0.2.0/24", "2001:db8::/32"),
        entra_tenants=(GUID,),
        aws_accounts=("000000000000",),
    )
    assert scope.exclude == Rules(hosts=("srv09.corp.example",))
    assert not scope.include.empty
    assert Rules().empty
    assert list(scope.include.to_dict()) == list(TYPES)
    assert (scope.mission_id, scope.source) == ("MISSION-0001", SOURCE_MISSION)
    assert scope.authorization_reference == "LM-2026-001"
    assert scope.authorization_date == date(2026, 1, 5)
    assert (scope.signatory, scope.signatory_role) == ("Prénom Nom", "RSSI")
    assert (scope.valid_from, scope.valid_until) == (
        date(2026, 1, 12),
        date(2026, 1, 16),
    )
    assert scope.active_tests is True


def test_valeurs_par_defaut_tests_actifs_fermes_et_dates_en_texte() -> None:
    scope = parse_scope(_table(valid_from="2026-01-12", valid_until="2026-01-16"))
    assert scope.active_tests is False
    assert scope.exclude.empty
    assert scope.source == SOURCE_OPTION
    assert scope.valid_from == date(2026, 1, 12)


@pytest.mark.parametrize(
    "cle", ["mission_id", "valid_from", "valid_until", "authorization", "include"]
)
def test_cle_obligatoire_absente(cle: str) -> None:
    table = _table()
    del table[cle]
    with pytest.raises(ScopeError, match=rf"scope\.{cle} : clé obligatoire absente"):
        parse_scope(table)


@pytest.mark.parametrize("cle", ["reference", "date", "signatory", "signatory_role"])
def test_autorisation_incomplete(cle: str) -> None:
    table = _table()
    del table["authorization"][cle]
    with pytest.raises(ScopeError, match=rf"scope\.authorization\.{cle} : clé oblig"):
        parse_scope(table)


def test_cle_inconnue_avec_suggestion() -> None:
    with pytest.raises(ScopeError, match=r"scope\.valid_form.*scope\.valid_from"):
        parse_scope(_table(valid_form="2026-01-12"))
    with pytest.raises(ScopeError, match=r"scope\.include\.host.*include\.hosts"):
        parse_scope(_table(include={"host": ["srv01.corp.example"]}))
    with pytest.raises(ScopeError, match=r"scope\.authorization\.signataire"):
        parse_scope(_table(authorization={"signataire": "x"}))
    # une cle hostile est citee echappee
    with pytest.raises(ScopeError) as exc:
        parse_scope(_table(**{"x\x1b[2J": 1}))
    assert "\x1b" not in str(exc.value)


@pytest.mark.parametrize(
    ("remplace", "motif"),
    [
        ({"include": {"dns": ["corp.example"]}}, r"include\.dns\[0\] : motif"),
        ({"include": {"dns": ["*.*.corp.example"]}}, r"include\.dns\[0\]"),
        ({"include": {"dns": ["*corp.example"]}}, r"include\.dns\[0\] : motif"),
        ({"include": {"dns": ["*"]}}, r"include\.dns\[0\] : motif"),
        ({"include": {"dns": ["*.192.0.2.1"]}}, r"include\.dns\[0\]"),
        ({"include": {"hosts": ["*.corp.example"]}}, r"include\.hosts\[0\].*dns"),
        ({"include": {"hosts": ["srv01 corp"]}}, r"include\.hosts\[0\]"),
        ({"include": {"hosts": ["a", "srv_01"]}}, r"include\.hosts\[1\]"),
        ({"include": {"ad_domains": ["192.0.2.1"]}}, r"ad_domains\[0\] : nom de dom"),
        ({"include": {"cidrs": ["10.0.1.7/16"]}}, r"cidrs\[0\] : plage CIDR"),
        ({"include": {"cidrs": ["192.0.2.0/33"]}}, r"cidrs\[0\] : plage CIDR"),
        ({"include": {"cidrs": ["srv01"]}}, r"cidrs\[0\] : plage CIDR"),
        ({"include": {"cidrs": ["0.0.0.0/0"]}}, r"cidrs\[0\] : une plage qui couvre"),
        ({"include": {"cidrs": ["::/0"]}}, r"cidrs\[0\] : une plage qui couvre"),
        ({"include": {"entra_tenants": ["corp.example"]}}, r"entra_tenants\[0\]"),
        ({"include": {"aws_accounts": ["12345"]}}, r"aws_accounts\[0\]"),
        ({"include": {"aws_accounts": [123456789012]}}, r"aws_accounts\[0\] : chaîne"),
        ({"include": {"hosts": "srv01.corp.example"}}, r"include\.hosts : tableau"),
        ({"include": {}}, r"scope\.include : au moins une inclusion"),
        ({"include": {"hosts": []}}, r"scope\.include : au moins une inclusion"),
        ({"include": ["srv01"]}, r"scope\.include : table attendue"),
        ({"exclude": {"cidrs": ["192.0.2.1/24"]}}, r"exclude\.cidrs\[0\]"),
        ({"valid_until": date(2026, 1, 11)}, r"valid_until .* précède"),
        ({"valid_from": "12/01/2026"}, r"valid_from : date ISO 8601"),
        ({"valid_from": "2026-02-30"}, r"valid_from : date ISO 8601"),
        ({"valid_from": datetime(2026, 1, 12, tzinfo=UTC)}, r"valid_from : date ISO"),
        ({"active_tests": "true"}, r"active_tests : booléen"),
        ({"active_tests": 1}, r"active_tests : booléen"),
        ({"mission_id": ""}, r"mission_id : chaîne vide"),
        ({"mission_id": 7}, r"mission_id : chaîne attendue"),
        ({"mission_id": "x" * 201}, r"mission_id : 200 caractères"),
        ({"mission_id": "a\x1b[31mb"}, r"mission_id : caractère de contrôle"),
        (
            {"mission_id": "a" + chr(0x202E) + "b"},
            r"mission_id : caractère de contrôle",
        ),
        ({"authorization": "LM-2026-001"}, r"scope\.authorization : table"),
    ],
)
def test_declaration_refusee(remplace: dict[str, Any], motif: str) -> None:
    with pytest.raises(ScopeError, match=motif):
        parse_scope(_table(**remplace))


def test_table_scope_refusee_si_ce_n_est_pas_une_table() -> None:
    with pytest.raises(ScopeError, match=r"scope : table attendue"):
        parse_scope(["srv01.corp.example"])


def test_autorisation_posterieure_au_debut_refusee() -> None:
    table = _table()
    table["authorization"]["date"] = date(2026, 1, 13)
    with pytest.raises(ScopeError, match="une autorisation écrite précède"):
        parse_scope(table)
    table["authorization"]["date"] = date(2026, 1, 12)
    assert parse_scope(table).authorization_date == date(2026, 1, 12)


def test_texte_qui_ressemble_a_un_secret_refuse_sans_etre_repris() -> None:
    for valeur in (
        "password=hunter2",
        "https://audit:" + "hunter2" + "@srv.corp.example/",
    ):
        with pytest.raises(ScopeError, match="ressemble à un secret") as exc:
            parse_scope(_table(mission_id=valeur))
        assert "hunter2" not in str(exc.value)
    try:
        log.register_secret("valeur-lue-ailleurs")
        with pytest.raises(ScopeError, match="ressemble à un secret"):
            parse_scope(_table(mission_id="valeur-lue-ailleurs"))
    finally:
        log._secrets.clear()
    # l'espace insecable d'un nom propre n'est pas un secret
    table = _table()
    table["authorization"]["signatory"] = "Prénom" + chr(0xA0) + "Nom"
    assert parse_scope(table).signatory == "Prénom" + chr(0xA0) + "Nom"


# --- condensat ---


def test_sha256_du_json_canonique() -> None:
    scope = _scope()
    canonique = json.dumps(
        scope.declaration(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    assert scope.sha256() == hashlib.sha256(canonique.encode("utf-8")).hexdigest()
    assert re.fullmatch("[0-9a-f]{64}", scope.sha256())
    assert scope.declaration()["authorization"]["signatory"] == "Prénom Nom"


def test_sha256_independant_de_l_ordre_de_la_casse_et_de_la_source() -> None:
    a = parse_scope(
        _table(include={"hosts": ["srv02.corp.example", "SRV01.corp.example"]}),
        source=SOURCE_MISSION,
    )
    b = parse_scope(
        _table(
            include={
                "hosts": ["srv01.corp.example", "srv02.corp.example."] * 2,
                "dns": [],
            },
            valid_from="2026-01-12",
        ),
        source=SOURCE_OPTION,
    )
    assert a.sha256() == b.sha256()


@pytest.mark.parametrize(
    "remplace",
    [
        {"mission_id": "MISSION-0002"},
        {"valid_until": date(2026, 1, 17)},
        {"active_tests": True},
        {"include": {"dns": ["*.corp.example"], "hosts": ["srv01.autre.example"]}},
        {"exclude": {"hosts": ["srv09.corp.example"]}},
    ],
)
def test_sha256_change_avec_la_declaration(remplace: dict[str, Any]) -> None:
    assert parse_scope(_table(**remplace)).sha256() != _scope().sha256()


def test_sha256_couvre_le_signataire() -> None:
    table = _table()
    table["authorization"]["signatory"] = "Autre Signataire"
    assert parse_scope(table).sha256() != _scope().sha256()


# --- fichier de perimetre ---

FICHIER = """\
[scope]
mission_id = "MISSION-0001"
valid_from = 2026-01-12
valid_until = 2026-01-16

[scope.authorization]
reference = "LM-2026-001"
date = 2026-01-05
signatory = "Prénom Nom"
signatory_role = "RSSI"

[scope.include]
dns = ["*.corp.example"]
"""


def _fichier(tmp_path: Path, texte: str) -> Path:
    chemin = tmp_path / "perimetre.toml"
    chemin.write_bytes(texte.encode("utf-8"))
    return chemin


def test_load_scope(tmp_path: Path) -> None:
    scope = load_scope(_fichier(tmp_path, FICHIER))
    assert scope == _scope()
    assert scope.source == SOURCE_OPTION
    assert scope.sha256() == _scope().sha256()


@pytest.mark.parametrize(
    ("texte", "motif"),
    [
        ("", r"section \[scope\] absente"),
        ('mission_id = "MISSION-0001"\n', r"section \[scope\] absente"),
        (FICHIER + '\n[mission]\nclient = "x"\n', r"'mission' hors de la section"),
        ('profile = "pme"\n' + FICHIER, r"'profile' hors de la section"),
        ("[scope\n", "TOML"),
        ("scope = 3\n", r"scope : table attendue"),
    ],
)
def test_load_scope_refuse(tmp_path: Path, texte: str, motif: str) -> None:
    with pytest.raises(ScopeError, match=motif):
        load_scope(_fichier(tmp_path, texte))


def test_load_scope_fichier_absent(tmp_path: Path) -> None:
    with pytest.raises(ScopeError) as exc:
        load_scope(tmp_path / "absent.toml")
    # le chemin est ajoute par l'appelant, neutralise
    assert "absent.toml" not in str(exc.value)


# --- critere : CIDR, motif DNS, exclusion prioritaire ---


def test_adresse_acceptee_dans_la_plage() -> None:
    scope = _scope(include={"cidrs": ["10.0.0.0/16"]})
    assert scope.verify(_cible("winrm://10.0.1.7"), now=PENDANT) == ()
    exc = _refus(scope, "winrm://10.1.0.7")
    assert exc.value.code is Refusal.OUT_OF_SCOPE


def test_nom_hors_du_motif_refuse() -> None:
    scope = _scope(include={"dns": ["*.corp.local"]})
    assert scope.verify(_cible("winrm://srv01.corp.local"), now=PENDANT) == ()
    exc = _refus(scope, "winrm://srv01.other.local")
    assert exc.value.code is Refusal.OUT_OF_SCOPE
    assert "winrm://srv01.other.local" in exc.value.message


@pytest.mark.parametrize(
    ("cible", "include", "exclude"),
    [
        ("winrm://10.0.1.7", {"cidrs": ["10.0.0.0/16"]}, {"hosts": ["10.0.1.7"]}),
        ("winrm://10.0.1.7", {"cidrs": ["10.0.0.0/16"]}, {"cidrs": ["10.0.1.0/24"]}),
        ("winrm://10.0.1.7", {"hosts": ["10.0.1.7"]}, {"cidrs": ["10.0.0.0/8"]}),
        (
            "winrm://srv01.corp.local",
            {"dns": ["*.corp.local"]},
            {"hosts": ["srv01.corp.local"]},
        ),
        (
            "winrm://srv01.corp.local",
            {"hosts": ["srv01.corp.local"]},
            {"dns": ["*.corp.local"]},
        ),
        (
            "winrm://srv01.corp.local",
            {"hosts": ["srv01.corp.local"]},
            {"ad_domains": ["corp.local"]},
        ),
        (
            "winrm://[2001:db8::10]",
            {"cidrs": ["2001:db8::/32"]},
            {"cidrs": ["2001:db8::/64"]},
        ),
    ],
)
def test_une_exclusion_l_emporte_sur_une_inclusion(
    cible: str, include: dict[str, list[str]], exclude: dict[str, list[str]]
) -> None:
    assert _scope(include=include).verify(_cible(cible), now=PENDANT) == ()
    exc = _refus(_scope(include=include, exclude=exclude), cible)
    assert exc.value.code is Refusal.EXCLUDED
    assert "exclue" in exc.value.message


@pytest.mark.parametrize(
    "exclude",
    [
        {"dns": ["*.filiale.corp.example"]},
        {"ad_domains": ["filiale.corp.example"]},
        {"dns": ["*.corp.example"]},
    ],
)
def test_une_exclusion_par_nom_couvre_toute_la_profondeur(
    exclude: dict[str, list[str]],
) -> None:
    # en inclusion un motif couvre un seul label ; en exclusion, tout ce qui
    # se trouve sous le domaine nomme : dans le doute, la cible est refusee
    include = {
        "dns": ["*.paris.filiale.corp.example"],
        "hosts": ["srv01.corp.example", "autre.example"],
    }
    scope = _scope(include=include, exclude=exclude)
    cible = "winrm://srv01.paris.filiale.corp.example"
    assert _scope(include=include).verify(_cible(cible), now=PENDANT) == ()
    assert _refus(scope, cible).value.code is Refusal.EXCLUDED
    # ce que l'exclusion ne nomme pas reste inclus
    assert scope.verify(_cible("winrm://autre.example"), now=PENDANT) == ()


def test_exclusion_d_un_motif_ne_couvre_pas_le_domaine_lui_meme() -> None:
    scope = _scope(
        include={"hosts": ["corp.example", "srv01.corp.example"]},
        exclude={"dns": ["*.corp.example"]},
    )
    assert scope.verify(_cible("winrm://corp.example"), now=PENDANT) == ()
    assert _refus(scope, "winrm://srv01.corp.example").value.code is Refusal.EXCLUDED


# --- noms ---


@pytest.mark.parametrize(
    ("cible", "incluse"),
    [
        ("winrm://srv01.corp.example", True),
        ("winrm://SRV01.Corp.Example.:5986", True),
        ("winrm://corp.example", False),
        ("winrm://srv01.filiale.corp.example", False),
        ("winrm://srv01.evilcorp.example", False),
        ("winrm://corp.example.evil.example", False),
        ("winrm://srv01.corp.example.evil.example", False),
        ("winrm://srv01", False),
    ],
)
def test_motif_dns_couvre_exactement_un_label(cible: str, incluse: bool) -> None:
    scope = _scope(include={"dns": ["*.corp.example"]})
    if incluse:
        assert scope.verify(_cible(cible), now=PENDANT, resolver=_jamais) == ()
    else:
        assert _refus(scope, cible, resolver=_jamais).value.code is (
            Refusal.OUT_OF_SCOPE
        )


@pytest.mark.parametrize(
    ("cible", "incluse"),
    [
        ("winrm://corp.example", True),
        ("winrm://dc01.corp.example", True),
        ("winrm://dc01.filiale.corp.example", False),
        ("winrm://dc01.autre.example", False),
    ],
)
def test_domaine_ad_couvre_le_domaine_et_ses_hotes_directs(
    cible: str, incluse: bool
) -> None:
    scope = _scope(include={"ad_domains": ["corp.example"]})
    if incluse:
        assert scope.verify(_cible(cible), now=PENDANT) == ()
    else:
        assert _refus(scope, cible).value.code is Refusal.OUT_OF_SCOPE


def test_hote_exact() -> None:
    scope = _scope(include={"hosts": ["srv01.corp.example", "192.0.2.10"]})
    assert scope.verify(_cible("winrm://srv01.corp.example:5986"), now=PENDANT) == ()
    assert scope.verify(_cible("winrm://192.0.2.10"), now=PENDANT) == ()
    assert _refus(scope, "winrm://192.0.2.11").value.code is Refusal.OUT_OF_SCOPE
    # une adresse exacte est une plage : un autre nom peut y mener, il est resolu
    autre = "winrm://srv02.corp.example"
    assert _refus(scope, autre).value.code is Refusal.UNRESOLVED
    assert (
        _refus(scope, autre, resolver=_resolution("192.0.2.11")).value.code
        is Refusal.OUT_OF_SCOPE
    )
    assert scope.verify(
        _cible(autre), now=PENDANT, resolver=_resolution("192.0.2.10")
    ) == ("192.0.2.10",)
    noms = _scope(include={"hosts": ["srv01.corp.example"]})
    assert _refus(noms, autre, resolver=_jamais).value.code is Refusal.OUT_OF_SCOPE


def test_adresse_jamais_comparee_aux_noms() -> None:
    # aucune resolution inverse : une adresse ne correspond qu'a une plage
    scope = _scope(include={"dns": ["*.corp.example"]})
    exc = _refus(scope, "winrm://192.0.2.10", resolver=_jamais)
    assert exc.value.code is Refusal.OUT_OF_SCOPE


def test_ipv6() -> None:
    scope = _scope(include={"cidrs": ["2001:db8::/32", "192.0.2.0/24"]})
    assert scope.verify(_cible("winrm://[2001:DB8::10]"), now=PENDANT) == ()
    exc = _refus(scope, "winrm://[2001:db9::10]")
    assert exc.value.code is Refusal.OUT_OF_SCOPE


# --- critere : nom resolu, toutes les adresses dans les plages ---


def test_nom_dont_une_adresse_sort_de_la_plage_refuse() -> None:
    scope = _scope(include={"cidrs": ["192.0.2.0/24"]})
    exc = _refus(
        scope,
        "winrm://srv01.corp.example",
        resolver=_resolution("192.0.2.10", "198.51.100.7"),
    )
    assert exc.value.code is Refusal.OUT_OF_SCOPE
    assert "198.51.100.7" in exc.value.message
    assert "toutes les adresses" in exc.value.message


def test_nom_dont_toutes_les_adresses_sont_dans_les_plages_accepte() -> None:
    scope = _scope(include={"cidrs": ["192.0.2.0/24", "2001:db8::/32"]})
    demandes: list[str] = []

    def resoudre(nom: str) -> Sequence[str]:
        demandes.append(nom)
        return ["192.0.2.10", "2001:db8::10", "192.0.2.10"]

    adresses = scope.verify(
        _cible("winrm://SRV01.corp.example"), now=PENDANT, resolver=resoudre
    )
    # adresses verifiees, pour que le collecteur s'y connecte sans re-resoudre
    assert adresses == ("192.0.2.10", "2001:db8::10")
    assert demandes == ["srv01.corp.example"]


@pytest.mark.parametrize(
    "resolues",
    [["::ffff:192.0.2.10"], ["192.0.2.10%eth0"], ["2001:db8::10%3"]],
)
def test_adresses_resolues_normalisees(resolues: list[str]) -> None:
    scope = _scope(include={"cidrs": ["192.0.2.0/24", "2001:db8::/32"]})
    adresses = scope.verify(
        _cible("winrm://srv01.corp.example"),
        now=PENDANT,
        resolver=_resolution(*resolues),
    )
    assert adresses in {("192.0.2.10",), ("2001:db8::10",)}


def test_sans_resolution_disponible_refus() -> None:
    scope = _scope(include={"cidrs": ["192.0.2.0/24"]})
    exc = _refus(scope, "winrm://srv01.corp.example")
    assert exc.value.code is Refusal.UNRESOLVED
    assert "adresse IP" in exc.value.message


def _echec(_nom: str) -> Sequence[str]:
    raise OSError("résolution impossible")


@pytest.mark.parametrize(
    "resolver",
    [_echec, _resolution(), _resolution("pas-une-adresse"), _resolution("")],
    ids=["erreur", "vide", "illisible", "chaine-vide"],
)
def test_nom_non_resolu_refus(resolver: Callable[[str], Sequence[str]]) -> None:
    scope = _scope(include={"cidrs": ["192.0.2.0/24"]})
    exc = _refus(scope, "winrm://srv01.corp.example", resolver=resolver)
    assert exc.value.code is Refusal.UNRESOLVED


def test_nom_inclus_par_son_nom_aucune_resolution() -> None:
    scope = _scope(
        include={"dns": ["*.corp.example"], "cidrs": ["192.0.2.0/24"]},
        exclude={"hosts": ["srv09.corp.example"]},
    )
    assert (
        scope.verify(
            _cible("winrm://srv01.corp.example"), now=PENDANT, resolver=_jamais
        )
        == ()
    )


def test_nom_hors_de_tout_sans_plage_aucune_resolution() -> None:
    scope = _scope(
        include={"dns": ["*.corp.example"]}, exclude={"cidrs": ["192.0.2.0/24"]}
    )
    exc = _refus(scope, "winrm://srv01.autre.example", resolver=_jamais)
    assert exc.value.code is Refusal.OUT_OF_SCOPE


def test_exclusion_par_adresse_d_un_nom_inclus() -> None:
    # le nom est inclus, mais une de ses adresses est exclue : refus
    scope = _scope(
        include={"dns": ["*.corp.example"]}, exclude={"cidrs": ["192.0.2.128/25"]}
    )
    cible = "winrm://srv01.corp.example"
    exc = _refus(scope, cible, resolver=_resolution("192.0.2.10", "192.0.2.200"))
    assert exc.value.code is Refusal.EXCLUDED
    assert "192.0.2.200" in exc.value.message
    # sans resolution, impossible de savoir : refus
    assert _refus(scope, cible).value.code is Refusal.UNRESOLVED
    assert _refus(scope, cible, resolver=_echec).value.code is Refusal.UNRESOLVED
    # aucune adresse exclue : accepte, meme hors de toute plage incluse
    adresses = scope.verify(
        _cible(cible), now=PENDANT, resolver=_resolution("198.51.100.7")
    )
    assert adresses == ("198.51.100.7",)


def test_exclusion_d_une_adresse_exacte_d_un_nom_resolu() -> None:
    scope = _scope(
        include={"cidrs": ["192.0.2.0/24"]}, exclude={"hosts": ["192.0.2.10"]}
    )
    exc = _refus(
        scope, "winrm://srv01.corp.example", resolver=_resolution("192.0.2.10")
    )
    assert exc.value.code is Refusal.EXCLUDED


# --- critere : periode de validite ---


@pytest.mark.parametrize(
    ("instant", "code"),
    [
        (datetime(2026, 1, 11, 23, 59, tzinfo=UTC), Refusal.NOT_YET_VALID),
        (datetime(2025, 6, 1, 12, 0, tzinfo=UTC), Refusal.NOT_YET_VALID),
        (datetime(2026, 1, 17, 0, 0, tzinfo=UTC), Refusal.EXPIRED),
        (datetime(2027, 1, 14, 12, 0, tzinfo=UTC), Refusal.EXPIRED),
        # aux bornes, la date du poste et la date UTC doivent etre dans la periode
        (
            datetime(2026, 1, 12, 0, 30, tzinfo=timezone(timedelta(hours=2))),
            Refusal.NOT_YET_VALID,
        ),
        (
            datetime(2026, 1, 16, 23, 30, tzinfo=timezone(timedelta(hours=-5))),
            Refusal.EXPIRED,
        ),
        (
            datetime(2026, 1, 11, 23, 30, tzinfo=timezone(timedelta(hours=-5))),
            Refusal.NOT_YET_VALID,
        ),
        (
            datetime(2026, 1, 17, 0, 30, tzinfo=timezone(timedelta(hours=2))),
            Refusal.EXPIRED,
        ),
    ],
)
def test_hors_periode_refuse(instant: datetime, code: Refusal) -> None:
    exc = _refus(_scope(), "winrm://srv01.corp.example", now=instant)
    assert exc.value.code is code
    assert "LM-2026-001" in exc.value.message
    assert "2026-01-12" in exc.value.message
    assert "2026-01-16" in exc.value.message


@pytest.mark.parametrize(
    "instant",
    [
        datetime(2026, 1, 12, 0, 0, tzinfo=UTC),
        datetime(2026, 1, 16, 23, 59, 59, tzinfo=UTC),
        datetime(2026, 1, 14, 3, 0, tzinfo=timezone(timedelta(hours=11))),
    ],
)
def test_bornes_de_la_periode_incluses(instant: datetime) -> None:
    assert _scope().verify(_cible("winrm://srv01.corp.example"), now=instant) == ()


def test_periode_verifiee_avant_la_cible() -> None:
    # hors periode, meme une cible incluse est refusee, sans resolution
    scope = _scope(include={"cidrs": ["192.0.2.0/24"]})
    exc = _refus(
        scope,
        "winrm://srv01.corp.example",
        now=datetime(2026, 2, 1, tzinfo=UTC),
        resolver=_jamais,
    )
    assert exc.value.code is Refusal.EXPIRED


def test_instant_sans_fuseau_refuse() -> None:
    with pytest.raises(ValueError, match="fuseau"):
        _scope().verify(
            _cible("winrm://srv01.corp.example"),
            now=datetime(2026, 1, 14, 10, 0),  # noqa: DTZ001 - cas refuse
        )


def test_instant_par_defaut_maintenant() -> None:
    # le perimetre de janvier 2026 est expire a la date d'aujourd'hui
    with pytest.raises(ScopeRefusal) as exc:
        _scope().verify(_cible("winrm://srv01.corp.example"))
    assert exc.value.code is Refusal.EXPIRED


# --- machine locale, autres types de cible ---


def test_machine_locale_designee_par_son_nom() -> None:
    scope = _scope(include={"dns": ["*.corp.example"]})
    local = _cible("local")
    assert (
        scope.verify(
            local,
            now=PENDANT,
            local_name=lambda: "SRV01.Corp.Example",
            resolver=_jamais,
        )
        == ()
    )
    exc = _refus(scope, local, local_name=lambda: "poste-auditeur")
    assert exc.value.code is Refusal.OUT_OF_SCOPE
    assert "machine locale" in exc.value.message
    assert "poste-auditeur" in exc.value.message


def test_machine_locale_exclue() -> None:
    scope = _scope(
        include={"dns": ["*.corp.example"]}, exclude={"hosts": ["srv01.corp.example"]}
    )
    exc = _refus(scope, _cible("local"), local_name=lambda: "srv01.corp.example")
    assert exc.value.code is Refusal.EXCLUDED


@pytest.mark.parametrize("nom", ["PC_COMPTA", "", "poste\x1b[2J", "a b"])
def test_nom_local_incomparable_refuse(nom: str) -> None:
    scope = _scope(include={"dns": ["*.corp.example"]})
    exc = _refus(scope, _cible("local"), local_name=lambda: nom)
    assert exc.value.code is Refusal.OUT_OF_SCOPE
    assert "\x1b" not in exc.value.message


def test_nom_local_par_defaut_celui_du_systeme(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("platform.node", lambda: "srv01.corp.example")
    assert _scope().verify(_cible("local"), now=PENDANT) == ()
    monkeypatch.setattr("platform.node", lambda: "poste-auditeur")
    assert _refus(_scope(), _cible("local")).value.code is Refusal.OUT_OF_SCOPE


def test_tenant_entra_et_compte_aws() -> None:
    scope = _scope(
        include={
            "entra_tenants": [GUID],
            "aws_accounts": ["000000000000", "111111111111"],
        },
        exclude={"aws_accounts": ["111111111111"]},
    )
    tenant = Target(Kind.M365_TENANT, Transport.API, address=GUID.upper())
    assert scope.verify(tenant, now=PENDANT) == ()
    autre = Target(Kind.M365_TENANT, Transport.API, address=GUID.replace("4", "5"))
    assert _refus(scope, autre).value.code is Refusal.OUT_OF_SCOPE
    compte = Target(Kind.AWS_ACCOUNT, Transport.API, address="000000000000")
    assert scope.verify(compte, now=PENDANT) == ()
    exclu = Target(Kind.AWS_ACCOUNT, Transport.API, address="111111111111")
    assert _refus(scope, exclu).value.code is Refusal.EXCLUDED
    sans_id = Target(Kind.AWS_ACCOUNT, Transport.API)
    assert _refus(scope, sans_id).value.code is Refusal.OUT_OF_SCOPE
    # un identifiant de compte n'est jamais compare aux hotes
    hotes = _scope(include={"hosts": ["000000000000.corp.example"]})
    assert _refus(hotes, compte).value.code is Refusal.OUT_OF_SCOPE


def test_cible_api_designee_par_un_hote() -> None:
    scope = _scope(include={"hosts": ["siem.corp.example"]})
    siem = Target(Kind.SIEM, Transport.API, address="SIEM.corp.example")
    assert scope.verify(siem, now=PENDANT) == ()
    autre = Target(Kind.SIEM, Transport.API, address="siem.autre.example")
    assert _refus(scope, autre).value.code is Refusal.OUT_OF_SCOPE
    invalide = Target(Kind.SIEM, Transport.API, address="siem corp")
    assert _refus(scope, invalide).value.code is Refusal.OUT_OF_SCOPE


def test_cible_incomparable_refusee(tmp_path: Path) -> None:
    bundle = Target(Kind.WINDOWS_HOST, Transport.BUNDLE, path=tmp_path)
    assert _refus(_scope(), bundle).value.code is Refusal.UNSUPPORTED
    sans_adresse = Target(Kind.SIEM, Transport.API)
    assert _refus(_scope(), sans_adresse).value.code is Refusal.UNSUPPORTED


# --- base d'autorisation ---


def _saisie(texte: str | None) -> Callable[[Target, str], str | None]:
    return lambda _cible, _attendu: texte


def _saisie_interdite(_target: Target, _attendu: str) -> str | None:
    raise AssertionError("confirmation inattendue")


def test_authorize_avec_perimetre() -> None:
    scope = _scope(include={"cidrs": ["192.0.2.0/24"]})
    autorisation = authorize(
        _cible("winrm://srv01.corp.example"),
        scope=scope,
        now=PENDANT,
        resolver=_resolution("192.0.2.10"),
        confirm=_saisie_interdite,
    )
    assert autorisation == Authorization(
        Basis.SCOPE, scope=scope, addresses=("192.0.2.10",)
    )
    with pytest.raises(ScopeRefusal) as exc:
        authorize(_cible("winrm://198.51.100.7"), scope=scope, now=PENDANT)
    assert exc.value.code is Refusal.OUT_OF_SCOPE


def test_authorize_perimetre_et_reference_incompatibles() -> None:
    with pytest.raises(ValueError, match="authorized_by"):
        authorize(_cible("local"), scope=_scope(), authorized_by="LM-2026-001")


def test_authorize_reference_declaree() -> None:
    autorisation = authorize(
        _cible("winrm://srv01.corp.example"),
        authorized_by="LM-2026-001",
        confirm=_saisie_interdite,
    )
    assert autorisation == Authorization(Basis.AUTHORIZED_BY, reference="LM-2026-001")


@pytest.mark.parametrize("cible", ["local", "winrm://srv01.corp.example"])
def test_authorize_sans_perimetre_ni_reference_ni_terminal_refus(cible: str) -> None:
    with pytest.raises(ScopeRefusal) as exc:
        authorize(_cible(cible))
    assert exc.value.code is Refusal.NO_AUTHORIZATION
    assert "--authorized-by" in exc.value.message
    assert "--scope" in exc.value.message


@pytest.mark.parametrize(
    ("cible", "attendu", "saisies"),
    [
        ("local", "local", ["local", "local\n", "  LOCAL \r\n"]),
        ("localhost", "local", ["local"]),
        (
            "winrm://SRV01.Corp.Example:5986",
            "srv01.corp.example",
            ["srv01.corp.example\n", "SRV01.corp.example"],
        ),
        ("winrm://192.0.2.10", "192.0.2.10", ["192.0.2.10\n"]),
        ("winrm://[2001:db8::10]", "2001:db8::10", ["2001:db8::10", "[2001:DB8::10]"]),
    ],
)
def test_authorize_confirmation_du_nom_exact(
    cible: str, attendu: str, saisies: list[str]
) -> None:
    target = _cible(cible)
    assert confirmation_name(target) == attendu
    recus: list[tuple[Target, str]] = []

    def confirmer(cible_demandee: Target, nom: str) -> str | None:
        recus.append((cible_demandee, nom))
        return saisies[0]

    assert authorize(target, confirm=confirmer) == Authorization(Basis.CONFIRMATION)
    assert recus == [(target, attendu)]
    for saisie in saisies:
        assert authorize(target, confirm=_saisie(saisie)).basis is Basis.CONFIRMATION


@pytest.mark.parametrize(
    "saisie",
    [None, "", "\n", "oui", "o", "srv01", "srv02.corp.example", "srv01.corp.example.x"],
)
def test_authorize_confirmation_refusee(saisie: str | None) -> None:
    with pytest.raises(ScopeRefusal) as exc:
        authorize(_cible("winrm://srv01.corp.example"), confirm=_saisie(saisie))
    assert exc.value.code is Refusal.NOT_CONFIRMED
    assert "srv01.corp.example" in exc.value.message


def test_authorize_bundle_aucun_systeme_joint(tmp_path: Path) -> None:
    bundle = _cible(f"bundle:{tmp_path}")
    assert authorize(bundle, confirm=_saisie_interdite) == Authorization(Basis.OFFLINE)
    assert authorize(bundle) == Authorization(Basis.OFFLINE)
    # un perimetre expire ne bloque pas la relecture d'une collecte deja faite,
    # et reste recopie dans le rapport
    scope = _scope()
    assert authorize(bundle, scope=scope) == Authorization(Basis.OFFLINE, scope=scope)
    assert authorize(bundle, authorized_by="LM-2026-001") == Authorization(
        Basis.OFFLINE, reference="LM-2026-001"
    )


def test_parse_reference() -> None:
    assert parse_reference("LM-2026-001 du 5 janvier") == "LM-2026-001 du 5 janvier"
    for refusee in ("", "   ", "x" * 201, "LM\x1b[2J", "LM\n2026", 7):
        with pytest.raises(ScopeError, match="--authorized-by"):
            parse_reference(refusee)
    with pytest.raises(ScopeError, match="ressemble à un secret") as exc:
        parse_reference("token: hunter2hunter2")
    assert "hunter2" not in str(exc.value)


def test_bloc_du_rapport() -> None:
    scope = parse_scope(_table(active_tests=True), source=SOURCE_MISSION)
    bloc = Authorization(Basis.SCOPE, scope=scope).to_dict()
    assert bloc["basis"] == "scope"
    assert bloc["source"] == "mission"
    assert bloc["mission_id"] == "MISSION-0001"
    assert bloc["sha256"] == scope.sha256()
    assert bloc["authorization"] == {"reference": "LM-2026-001", "date": "2026-01-05"}
    assert (bloc["valid_from"], bloc["valid_until"]) == ("2026-01-12", "2026-01-16")
    assert bloc["active_tests"] is True
    assert bloc["include"] == scope.include.to_dict()
    assert bloc["exclude"] == scope.exclude.to_dict()
    # memes cles avec ou sans perimetre : tous les champs sont toujours presents
    sans = Authorization(Basis.AUTHORIZED_BY, reference="LM-2026-001").to_dict()
    assert list(sans) == list(bloc)
    assert sans["authorization"] == {"reference": "LM-2026-001", "date": None}
    assert "Prénom Nom" not in json.dumps(bloc, ensure_ascii=False)


# --- documentation ---


def _blocs_toml(texte: str) -> list[str]:
    return re.findall(r"```toml\n(.*?)\n```", texte, re.DOTALL)


def test_exemple_de_la_doc_valide() -> None:
    (bloc,) = _blocs_toml(DOC.read_text(encoding="utf-8"))
    document = loads_toml(bloc.encode("utf-8"))
    assert list(document) == ["scope"]
    scope = parse_scope(document["scope"])
    assert all(getattr(scope.include, type_) for type_ in TYPES)
    assert not scope.exclude.empty
    # chaque cle et chaque type sont documentes
    texte = DOC.read_text(encoding="utf-8")
    for cle in ("mission_id", "valid_from", "valid_until", "active_tests"):
        assert f"`scope.{cle}`" in texte
    for cle in ("reference", "date", "signatory", "signatory_role"):
        assert f"`scope.authorization.{cle}`" in texte
    for type_ in TYPES:
        assert f"| `{type_}` |" in texte


def test_exemple_de_amnesia_init_valide_une_fois_decommente() -> None:
    lignes = example_toml().splitlines()
    debut = lignes.index("# [scope]")
    fin = lignes.index("[thresholds]")
    bloc = "\n".join(ligne.removeprefix("#").strip() for ligne in lignes[debut:fin])
    scope = parse_scope(loads_toml(bloc.encode("utf-8"))["scope"])
    assert scope.mission_id == "MISSION-0001"
    assert not scope.include.empty
    assert not scope.exclude.empty


def test_doc_rappelle_l_article_323_1_et_l_acces_delegue() -> None:
    for fichier in (DOC, README):
        texte = " ".join(fichier.read_text(encoding="utf-8").split())
        assert "article 323-1 du Code pénal" in texte, fichier.name
        assert "100 000 €" in texte, fichier.name
        assert "150 000 €" in texte, fichier.name
        assert "GDAP" in texte, fichier.name
        assert "cross-account" in texte, fichier.name
        assert "ne vaut pas mandat d'audit" in texte, fichier.name
    doc = " ".join(DOC.read_text(encoding="utf-8").split())
    assert "trois ans d'emprisonnement" in doc
    assert "cinq ans d'emprisonnement" in doc
