"""Structure du modele de menace (docs/threat-model.md).

Le document sert de source a SECURITY.md (#28) : ces tests verifient qu'il reste
exploitable (chaque menace classee, traitee et rattachee a un ticket), pas que
son contenu est juste. Ce jugement reste celui de la revue.
"""

import re
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parent.parent
MODELE = RACINE / "docs" / "threat-model.md"
STRIDE = set("STRIDE")
TICKETS = re.compile(r"#\d+(, #\d+)*")


def _section(titre: str) -> str:
    texte = MODELE.read_text(encoding="utf-8")
    for morceau in re.split(r"^## ", texte, flags=re.MULTILINE)[1:]:
        entete, _, corps = morceau.partition("\n")
        if entete.strip() == titre:
            return corps
    raise AssertionError(f"section {titre!r} absente")


def _lignes(titre: str, prefixe: str) -> dict[str, list[str]]:
    # lignes de tableau dont la premiere cellule est un identifiant (M01, RR1...)
    lignes = {}
    for ligne in _section(titre).splitlines():
        if not ligne.startswith("|"):
            continue
        cellules = [c.strip() for c in ligne.strip().strip("|").split("|")]
        if re.fullmatch(rf"{prefixe}\d+", cellules[0]):
            assert cellules[0] not in lignes, f"identifiant en double : {cellules[0]}"
            lignes[cellules[0]] = cellules
    assert lignes, f"aucune ligne {prefixe} dans {titre!r}"
    return lignes


def _menaces() -> dict[str, list[str]]:
    menaces = _lignes("Menaces et mesures", "M")
    for ident, cellules in menaces.items():
        # ID | STRIDE | Menace | Acteur | Actifs | Mesures | Tickets
        assert len(cellules) == 7, ident
    return menaces


def test_schema_de_flux_avec_frontieres_de_confiance() -> None:
    flux = _section("Flux")
    (schema,) = re.findall(r"```mermaid\n(.*?)```", flux, flags=re.DOTALL)
    zones = re.findall(r"^\s*subgraph (Z\d+)\[", schema, flags=re.MULTILINE)
    # sans au moins deux zones, aucune frontiere n'apparait
    assert len(zones) >= 2
    assert set(zones) == set(_lignes("Flux", "Z"))
    # chaque flux du tableau figure dans le schema, et inversement
    assert set(re.findall(r'"(F\d+) ', schema)) == set(_lignes("Flux", "F"))


@pytest.mark.parametrize(
    ("titre", "elements"),
    [
        (
            "Flux",
            ["WinRM/PSRP", "LDAP", "Microsoft Graph", "API AWS", "#48", "#52"],
        ),
        (
            "Actifs",
            [
                "Identifiants et jetons d'audit",
                "Collectes brutes",
                "Rapports",
                "Journal d'exécution",
                "Intégrité des cibles",
                "Confiance du client",
            ],
        ),
        (
            "Acteurs",
            [
                "Cible compromise",
                "Consultant ou opérateur MSP",
                "poste volé",
                "Destinataire du rapport",
                "Tiers sur le réseau",
                "Fournisseur de dépendance",
            ],
        ),
    ],
)
def test_elements_minimaux_du_ticket(titre: str, elements: list[str]) -> None:
    corps = _section(titre)
    for element in elements:
        assert element in corps, element


def test_rapport_vers_client_dans_les_flux() -> None:
    assert any("Rapport → client" in c for c in _lignes("Flux", "F").values())


def test_chaque_menace_classee_traitee_et_rattachee_a_un_ticket() -> None:
    acteurs = set(_lignes("Acteurs", "AC"))
    actifs = set(_lignes("Actifs", "A"))
    for ident, cellules in _menaces().items():
        _, lettre, menace, acteur, cibles, mesures, tickets = cellules
        assert lettre in STRIDE, ident
        assert menace, ident
        assert mesures, ident
        # numeros d'issue uniquement, pas de cle provisoire
        assert TICKETS.fullmatch(tickets), ident
        assert acteur in acteurs, ident
        assert set(cibles.split(", ")) <= actifs, ident


def test_six_categories_couvertes_et_tableau_de_couverture_a_jour() -> None:
    attendu: dict[str, set[str]] = {lettre: set() for lettre in STRIDE}
    for ident, cellules in _menaces().items():
        attendu[cellules[1]].add(ident)
    couverture = {}
    for ligne in _section("Couverture STRIDE").splitlines():
        cellules = [c.strip() for c in ligne.strip().strip("|").split("|")]
        if ligne.startswith("|") and cellules[0] in STRIDE:
            couverture[cellules[0]] = set(cellules[1].split(", "))
    assert couverture == attendu
    # une categorie sans menace devrait etre justifiee par ecrit : il n'y en a pas
    assert all(attendu.values())


def test_identifiants_cites_tous_definis() -> None:
    # un renvoi (RR10 depuis une mesure, A7 depuis un acteur...) vers un
    # identifiant absent des tableaux serait une promesse sans contenu
    definis = set()
    for titre, prefixe in [
        ("Flux", "Z"),
        ("Flux", "F"),
        ("Actifs", "A"),
        ("Acteurs", "AC"),
        ("Menaces et mesures", "M"),
        ("Risques résiduels", "RR"),
    ]:
        definis |= set(_lignes(titre, prefixe))
    texte = MODELE.read_text(encoding="utf-8")
    cites = set(re.findall(r"\b(?:Z|F|AC|A|M|RR)\d+\b", texte))
    assert cites - definis == set()


def test_risques_residuels_justifies() -> None:
    for ident, cellules in _lignes("Risques résiduels", "RR").items():
        _, risque, justification = cellules
        assert risque, ident
        assert len(justification) > 40, ident


def test_regle_de_revision_ecrite() -> None:
    revision = _section("Révision")
    for exigence in ["Nouveau transport ou connecteur", "Clôture de chaque milestone"]:
        assert exigence in revision
    assert "#29" in revision
