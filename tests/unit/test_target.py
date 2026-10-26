"""Modele Target : grammaire, normalisation et refus de --target."""

import re
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from amnesia.target import Kind, Target, TargetError, Transport

# nom de 253 caracteres, la limite RFC 1035 en notation pointee
NOM_253 = ".".join(["a" * 63] * 3 + ["b" * 61])

# grammaire des id normalises, reecrite ici independamment du module
_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_ID = re.compile(
    rf"local"
    rf"|winrm://(?:(?:{_LABEL}\.)*{_LABEL}|\[[0-9a-f:.]+\])(?::[0-9]{{1,5}})?"
    rf"|bundle:(?!-)[!-~]+"
)
_INTERDITS = set(";|&$`'\"<>")


def test_winrm_fqdn_normalise():
    cible = Target.parse("winrm://SRV-FILE.corp.local.:5986")
    assert cible.kind == Kind.WINDOWS_HOST == "windows_host"
    assert cible.transport == Transport.WINRM == "winrm"
    assert cible.address == "srv-file.corp.local"
    assert cible.port == 5986
    assert cible.path is None
    assert cible.id == "winrm://srv-file.corp.local:5986"


@pytest.mark.parametrize(
    ("brut", "transport", "address", "port", "id_"),
    [
        ("localhost", Transport.LOCAL, None, None, "local"),
        ("local", Transport.LOCAL, None, None, "local"),
        ("LocalHost", Transport.LOCAL, None, None, "local"),
        ("winrm://10.0.0.5", Transport.WINRM, "10.0.0.5", None, "winrm://10.0.0.5"),
        (
            "winrm://[fe80::1]:5986",
            Transport.WINRM,
            "fe80::1",
            5986,
            "winrm://[fe80::1]:5986",
        ),
        (
            "WINRM://[FE80:0:0::1]",
            Transport.WINRM,
            "fe80::1",
            None,
            "winrm://[fe80::1]",
        ),
        ("winrm://dc01:1", Transport.WINRM, "dc01", 1, "winrm://dc01:1"),
        ("winrm://dc01:65535", Transport.WINRM, "dc01", 65535, "winrm://dc01:65535"),
        (
            "winrm://xn--bcher-kva.example",
            Transport.WINRM,
            "xn--bcher-kva.example",
            None,
            "winrm://xn--bcher-kva.example",
        ),
        (f"winrm://{NOM_253}.", Transport.WINRM, NOM_253, None, f"winrm://{NOM_253}"),
    ],
)
def test_cibles_acceptees(brut, transport, address, port, id_):
    cible = Target.parse(brut)
    assert cible.kind == Kind.WINDOWS_HOST
    assert cible.transport == transport
    assert cible.address == address
    assert cible.port == port
    assert cible.id == str(cible) == id_
    assert Target.parse(cible.id) == cible


@pytest.mark.parametrize("nature", ["dossier", "fichier"])
def test_bundle_existant_accepte(tmp_path, monkeypatch, nature):
    monkeypatch.chdir(tmp_path)
    bundle = Path("collecte")
    if nature == "dossier":
        bundle.mkdir()
    else:
        bundle.write_bytes(b"")
    cible = Target.parse(
        "bundle:./collecte/" if nature == "dossier" else "bundle:collecte"
    )
    assert (cible.kind, cible.transport) == (Kind.WINDOWS_HOST, Transport.BUNDLE)
    assert cible.path == bundle
    assert cible.address is None
    assert cible.id == "bundle:collecte"


@pytest.mark.parametrize(
    ("brut", "motif"),
    [
        ("", "vide"),
        ("   ", "vide"),
        ("winrm://", "hote manquant"),
        ("winrm://:5986", "hote manquant"),
        ("dc01; Remove-Item C:\\ -Recurse", "espace"),
        ("winrm://$(whoami)", "metacaractere"),
        ("winrm://dc01`nGet-Process", "metacaractere"),
        ("winrm://dc01,dc02", "metacaractere"),
        ("winrm://dc01|calc", "metacaractere"),
        ("winrm://user:pass@dc01", "identifiants"),
        ("user@dc01", "identifiants"),
        ("winrm://-dc01", "tiret"),
        ("winrm://dc01-.corp", "tiret"),
        ("-dc01", "tiret"),
        (f"winrm://{NOM_253}b", "trop long"),
        ("winrm://" + "a" * 64, "63"),
        ("winrm://dc01..corp", "63"),
        ("winrm://dc_01", "63"),
        ("winrm://dc01\x1b[31m", "controle"),
        ("winrm://dc01\nfoo", "controle"),
        ("winrm://dc01\x9b", "controle"),
        ("winrm://d\u0441\u0030\u0031", "ASCII"),  # c cyrillique (U+0441)
        ("winrm://dc01\u202e", "ASCII"),  # surcharge bidi (Trojan Source)
        ("http://dc01", "schema inconnu"),
        ("C:\\bundle", "schema inconnu"),
        ("winrm:dc01", "winrm://<hote>"),
        ("winrm://dc01:0", "port"),
        ("winrm://dc01:65536", "port"),
        ("winrm://dc01:", "port"),
        ("winrm://dc01:+80", "port"),
        ("winrm://dc01/wsman", "chemin"),
        ("winrm://fe80::1", "crochets"),
        ("winrm://[fe80::1", "crochet"),
        ("winrm://[fe80::1]x", "inattendus"),
        ("winrm://[10.0.0.5]", "IPv6"),
        ("winrm://10.0.0.256", "IPv4"),
        ("winrm://2130706433", "IPv4"),
        ("bundle:", "manquant"),
        ("bundle:n-existe-pas", "introuvable"),
        ("bundle:-x", "tiret"),
        ("x" * 5000, "trop longue"),
    ],
)
def test_cibles_refusees(brut, motif):
    with pytest.raises(TargetError, match=re.escape(motif)):
        Target.parse(brut)


@pytest.mark.parametrize(
    ("brut", "suggestion"),
    [
        ("dc01", "winrm://dc01"),
        ("DC01.corp.local.", "winrm://dc01.corp.local"),
        ("10.0.0.5:5986", "winrm://10.0.0.5:5986"),
        ("fe80::1", "winrm://[fe80::1]"),
    ],
)
def test_nom_nu_suggere_winrm(brut, suggestion):
    with pytest.raises(TargetError, match=re.escape(f"utiliser {suggestion}")):
        Target.parse(brut)


@pytest.mark.parametrize("gabarit", ["winrm://audit:{}@dc01", "audit:{}@dc01"])
@pytest.mark.parametrize("suffixe", ["", "!"])
def test_identifiants_jamais_repris_dans_le_message(gabarit, suffixe):
    # assemble a l'execution : un faux identifiant ne doit pas figurer tel quel
    # dans le depot, sinon gitleaks le signalerait (a juste titre)
    mot_de_passe = "Kq7" + "vX2" + "pL9" + suffixe
    with pytest.raises(TargetError) as exc:
        Target.parse(gabarit.format(mot_de_passe))
    assert mot_de_passe.rstrip("!") not in str(exc.value)


def test_message_echappe_la_saisie():
    # un chemin inexistant est repris, mais echappe et tronque
    with pytest.raises(TargetError) as exc:
        Target.parse("bundle:" + "z" * 200)
    assert len(str(exc.value)) < 120


def test_target_figee():
    cible = Target.parse("winrm://dc01")
    with pytest.raises(AttributeError):
        cible.address = "dc02"  # type: ignore[misc]


# chaines quelconques, et chaines prefixees d'un schema pour atteindre les
# branches winrm et bundle que st.text() seul ne produit presque jamais
_PREFIXES = st.sampled_from(
    ["", "local", "winrm://", "WinRM://", "winrm://[", "bundle:", "http://", "-"]
)
_SAISIES = st.one_of(
    st.text(),
    st.builds(lambda p, s: p + s, _PREFIXES, st.text()),
    st.builds(
        lambda p, s: p + s,
        _PREFIXES,
        st.from_regex(r"[A-Za-z0-9.:\[\]-]{0,40}", fullmatch=True),
    ),
)


@given(_SAISIES)
def test_parse_renvoie_une_cible_valide_ou_leve_target_error(brut):
    try:
        cible = Target.parse(brut)
    except TargetError:
        return
    assert isinstance(cible, Target)
    assert _ID.fullmatch(cible.id), cible.id
    assert cible.id.isascii()
    assert cible.id.isprintable()
    assert not _INTERDITS & set(cible.id)
    if cible.address is not None:
        assert len(cible.address) <= 253
    if cible.port is not None:
        assert 1 <= cible.port <= 65535
    # l'id est un point fixe : le re-analyser redonne la meme cible
    assert Target.parse(cible.id) == cible
