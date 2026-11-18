# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Type Secret et sources des secrets d'authentification (amnesia.secrets, #38)."""

from __future__ import annotations

import copy
import dataclasses
import getpass
import io
import json
import logging
import os
import pickle
import sys
import types
import warnings
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from amnesia import log, secrets
from amnesia.checks.base import ErrorInfo, assainir
from amnesia.secrets import Secret, SecretError

# valeurs factices, coupees en deux : aucun motif de secret dans le depot
CONNU = "hunter2"
FACTICE = "valeur-" + "factice/+d'essai"
VARIABLE = "AMNESIA_WINRM_PASSWORD"

posix = pytest.mark.skipif(sys.platform == "win32", reason="droits POSIX")


@pytest.fixture(autouse=True)
def _secrets_oublies() -> Iterator[None]:
    """Aucun secret enregistré ne passe d'un test à l'autre."""
    yield
    log._secrets.clear()


class _Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


def _sans_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))


def _saisie_interdite(*_args: object, **_kwargs: object) -> str:
    raise AssertionError("getpass appelé sans terminal")


def _fichier(tmp_path: Path, contenu: bytes, mode: int = 0o600) -> Path:
    chemin = tmp_path / "mot-de-passe.txt"
    chemin.write_bytes(contenu)
    chemin.chmod(mode)
    return chemin


# --- type Secret ---


def test_secret_masque_dans_repr_str_et_fstring() -> None:
    secret = Secret(CONNU)
    textes = [
        repr(secret),
        str(secret),
        f"{secret}",
        f"{secret!r}",
        f"{secret!s:>20}",
        f"{secret:>20}",
        format(secret, "s"),
        "%s %r" % (secret, secret),  # noqa: UP031 (le formatage % est le sujet)
        "{}".format(secret),  # noqa: UP032 (str.format est le sujet)
        repr([secret]),
        repr({"mot_de_passe": secret}),
    ]
    for texte in textes:
        assert CONNU not in texte
        assert log.MASQUE in texte
    assert repr(secret) == str(secret) == f"{secret}" == log.MASQUE


def test_secret_rendu_par_reveal_seulement() -> None:
    secret = Secret(CONNU)
    assert secret.reveal() == CONNU
    # ni attribut public, ni __dict__ : rien a parcourir pour un serialiseur
    assert not hasattr(secret, "__dict__")
    assert [nom for nom in dir(secret) if not nom.startswith("_")] == ["reveal"]


def test_json_dumps_refuse_un_secret() -> None:
    secret = Secret(CONNU)
    for valeur in (secret, {"mot_de_passe": secret}, [secret]):
        with pytest.raises(TypeError) as exc:
            json.dumps(valeur)
        assert CONNU not in str(exc.value)
    # un repli default=str ne rend que le masque
    assert CONNU not in json.dumps({"mot_de_passe": secret}, default=str)


def test_pickle_copie_et_asdict_refuses() -> None:
    @dataclasses.dataclass
    class Identifiants:
        compte: str
        mot_de_passe: Secret

    secret = Secret(CONNU)
    identifiants = Identifiants("auditeur", secret)
    assert CONNU not in repr(identifiants)
    for operation in (
        lambda: pickle.dumps(secret),
        lambda: copy.copy(secret),
        lambda: copy.deepcopy(secret),
        lambda: dataclasses.asdict(identifiants),
    ):
        with pytest.raises(TypeError) as exc:
            operation()
        assert CONNU not in str(exc.value)


@pytest.mark.parametrize("valeur", ["", None, b"octets", 12])
def test_secret_refuse_une_valeur_vide_ou_non_textuelle(valeur: Any) -> None:
    with pytest.raises((TypeError, ValueError)) as exc:
        Secret(valeur)
    assert "octets" not in str(exc.value)


def test_secret_enregistre_aupres_de_l_expurgation() -> None:
    Secret(FACTICE)
    assert FACTICE not in log.redact(f"refus pour {FACTICE} sur dc01")
    assert FACTICE not in log.mask_secrets(f"refus pour {FACTICE}")
    # messages d'erreur du rapport (ErrorInfo) : meme masquage
    assert FACTICE not in assainir(f"identifiants refusés : {FACTICE}")
    info = ErrorInfo.from_exception(PermissionError(f"401 avec {FACTICE}"))
    assert FACTICE not in info.message
    assert log.MASQUE in info.message


def test_mask_secrets_laisse_le_reste_intact() -> None:
    texte = "password=abc token=def sur winrm://dc01"
    assert log.mask_secrets(texte) == texte
    Secret(FACTICE)
    assert log.mask_secrets(texte) == texte


# --- fichier ---


@posix
@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660, 0o666, 0o610, 0o601])
def test_fichier_trop_ouvert_refuse(tmp_path: Path, mode: int) -> None:
    chemin = _fichier(tmp_path, FACTICE.encode() + b"\n", mode)
    with pytest.raises(SecretError, match="trop larges") as exc:
        secrets.from_file(chemin)
    assert FACTICE not in str(exc.value)
    assert f"{mode:04o}" in str(exc.value)


@posix
@pytest.mark.parametrize("mode", [0o600, 0o400])
def test_fichier_prive_accepte(tmp_path: Path, mode: int) -> None:
    chemin = _fichier(tmp_path, FACTICE.encode() + b"\n", mode)
    assert secrets.from_file(chemin).reveal() == FACTICE


@posix
def test_fichier_droits_lus_a_travers_un_lien(tmp_path: Path) -> None:
    cible = _fichier(tmp_path, FACTICE.encode(), 0o644)
    lien = tmp_path / "lien"
    lien.symlink_to(cible)
    with pytest.raises(SecretError, match="trop larges"):
        secrets.from_file(lien)


@posix
def test_fichier_d_un_autre_compte_refuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chemin = _fichier(tmp_path, FACTICE.encode())
    monkeypatch.setattr(os, "geteuid", lambda: chemin.stat().st_uid + 1)
    with pytest.raises(SecretError, match="autre compte"):
        secrets.from_file(chemin)


@posix
def test_fifo_refusee_sans_bloquer(tmp_path: Path) -> None:
    fifo = tmp_path / "tube"
    # if et non skip seul : mypy n'analyse os.mkfifo que hors Windows
    if sys.platform != "win32":
        os.mkfifo(fifo, 0o600)
    with pytest.raises(SecretError, match="fichier ordinaire"):
        secrets.from_file(fifo)


@pytest.mark.skipif(sys.platform != "win32", reason="ACL Windows")
def test_fichier_sous_windows_avertit_de_l_acl(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    chemin = _fichier(tmp_path, FACTICE.encode())
    with caplog.at_level(logging.WARNING, logger="amnesia.secrets"):
        assert secrets.from_file(chemin).reveal() == FACTICE
    assert "ACL" in caplog.text
    assert FACTICE not in caplog.text


@pytest.mark.parametrize(
    ("contenu", "attendu"),
    [
        (b"abc d\n", "abc d"),
        (b"abc d\r\n", "abc d"),
        (b"abc d", "abc d"),
        (b"\xef\xbb\xbfabc d\r\n", "abc d"),
        (" espaces gardés \n".encode(), " espaces gardés "),
    ],
)
def test_fichier_fin_de_ligne_et_bom_retires(
    tmp_path: Path, contenu: bytes, attendu: str
) -> None:
    assert secrets.from_file(_fichier(tmp_path, contenu)).reveal() == attendu


@pytest.mark.parametrize(
    ("contenu", "motif"),
    [
        (b"", "vide"),
        (b"\n", "vide"),
        (b"ligne-une\nligne-deux\n", "une seule ligne"),
        (b"nul\x00dedans", "une seule ligne"),
        (b"\xff\xfe-pas-utf8", "UTF-8"),
        (b"x" * (secrets.MAX_FILE_SIZE + 1), "octets"),
    ],
)
def test_fichier_invalide_refuse_sans_citer_le_contenu(
    tmp_path: Path, contenu: bytes, motif: str
) -> None:
    with pytest.raises(SecretError, match=motif) as exc:
        secrets.from_file(_fichier(tmp_path, contenu))
    assert "ligne-une" not in str(exc.value)
    assert "pas-utf8" not in str(exc.value)
    # l'exception d'origine (UnicodeDecodeError) porte les octets lus
    assert exc.value.__cause__ is None
    assert exc.value.__context__ is None or exc.value.__suppress_context__


def test_fichier_absent_ou_dossier_refuse(tmp_path: Path) -> None:
    for chemin in (tmp_path / "absent.txt", tmp_path):
        with pytest.raises(SecretError, match="fichier de secret"):
            secrets.from_file(chemin)


# --- variable d'environnement ---


def test_variable_retiree_de_l_environnement_apres_lecture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(VARIABLE, FACTICE)
    secret = secrets.from_env(VARIABLE)
    assert secret is not None
    assert secret.reveal() == FACTICE
    assert VARIABLE not in os.environ
    assert os.environ.get(VARIABLE) is None
    # une seconde lecture ne trouve plus rien
    assert secrets.from_env(VARIABLE) is None


def test_variable_absente_ou_vide(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(VARIABLE, raising=False)
    assert secrets.from_env(VARIABLE) is None
    monkeypatch.setenv(VARIABLE, "")
    with pytest.raises(SecretError, match="vide"):
        secrets.from_env(VARIABLE)
    assert VARIABLE not in os.environ


def test_variable_d_un_environnement_fourni() -> None:
    environ = {VARIABLE: FACTICE, "AUTRE": "x"}
    secret = secrets.from_env(VARIABLE, environ)
    assert secret is not None
    assert environ == {"AUTRE": "x"}


@pytest.mark.parametrize("fin", ["\n", "\r\n"])
def test_variable_fin_de_ligne_finale_retiree(fin: str) -> None:
    # secret de CI ou fichier monte dans une variable : meme valeur que from_file
    secret = secrets.from_env(VARIABLE, {VARIABLE: FACTICE + fin})
    assert secret is not None
    assert secret.reveal() == FACTICE
    assert log.MASQUE in assainir(f"401 avec {FACTICE} (refus)")


@pytest.mark.parametrize(
    ("valeur", "motif"),
    [
        # octet non UTF-8 de l'environnement, vu par Python comme un surrogate
        ("x\udce9y", "UTF-8 attendu"),
        ("a\nb", "une seule ligne"),
        ("a\x00b", "une seule ligne"),
        ("\n", "vide"),
    ],
)
def test_variable_invalide_refusee_sans_citer_la_valeur(
    valeur: str, motif: str
) -> None:
    environ = {VARIABLE: valeur}
    with pytest.raises(SecretError, match=motif) as exc:
        secrets.from_env(VARIABLE, environ)
    assert valeur not in str(exc.value)
    assert "udce9" not in str(exc.value)
    # l'exception d'origine (UnicodeEncodeError) citerait le caractere
    assert exc.value.__context__ is None or exc.value.__suppress_context__
    assert environ == {}


def test_enregistrement_d_un_surrogate_sans_exception() -> None:
    log.register_secret("x\udce9y-factice")
    assert log.mask_secrets("a x\udce9y-factice b") == f"a {log.MASQUE} b"


@pytest.mark.parametrize(
    "valeur",
    [
        "Fa\\ctice-9x",
        'Fa"ctice-9x',
        "Fa'ctice-9x",
        "Fa'ct\"ice-9x",
        "Facticé-9x",
        "Fa\tctice-9x",
    ],
)
def test_formes_echappees_du_secret_masquees(valeur: str) -> None:
    # repr(), ascii() et JSON : les formes d'une chaine dans un message
    # d'exception (requests, urllib3, SDK) ou dans un corps de reponse
    Secret(valeur)
    exc = RuntimeError(f"logon failure {valeur}")
    formes = [
        f"échec avec {valeur}",
        f"échec avec {valeur!r}",
        f"échec avec {valeur!a}",
        repr(exc),
        ascii(exc),
        repr(KeyError(valeur)),
        repr({"p": valeur, "q": 'l\'autre "champ"'}),
        json.dumps(valeur),
        json.dumps({"p": valeur}),
        json.dumps({"p": valeur}, ensure_ascii=False),
    ]
    for forme in formes:
        for masque in (log.mask_secrets, log.redact, assainir):
            rendu = masque(forme)
            assert log.MASQUE in rendu, forme
            assert "Fa" not in rendu, forme
            assert "-9x" not in rendu, forme
    message = ErrorInfo.from_exception(KeyError(valeur)).message
    assert "Fa" not in message
    assert "-9x" not in message


# --- trousseau ---


def _backend(module: str, nom: str, **attributs: Any) -> Any:
    classe = type(nom, (), {"__module__": module, **attributs})
    return classe()


def _faux_keyring(
    monkeypatch: pytest.MonkeyPatch, backend: Any, entrees: dict[tuple[str, str], str]
) -> list[tuple[str, str]]:
    """Installe un faux module keyring ; rend la liste des lectures faites."""
    lectures: list[tuple[str, str]] = []

    def get_password(service: str, compte: str) -> str | None:
        lectures.append((service, compte))
        return entrees.get((service, compte))

    module: Any = types.ModuleType("keyring")
    module.get_keyring = lambda: backend
    module.get_password = get_password
    monkeypatch.setitem(sys.modules, "keyring", module)
    return lectures


def test_trousseau_du_systeme_lu_dans_l_espace_de_la_mission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = _backend("keyring.backends.macOS", "Keyring")
    entrees = {("amnesia/mission-essai", "winrm-password"): FACTICE}
    lectures = _faux_keyring(monkeypatch, backend, entrees)
    secret = secrets.from_keyring("mission-essai", "winrm-password")
    assert secret is not None
    assert secret.reveal() == FACTICE
    assert lectures == [("amnesia/mission-essai", "winrm-password")]
    assert secrets.from_keyring("autre-mission", "winrm-password") is None


@pytest.mark.parametrize(
    "backend",
    [
        _backend("keyrings.alt.file", "PlaintextKeyring"),
        _backend("keyrings.alt.file", "EncryptedKeyring"),
        _backend("un_paquet.inconnu", "Trousseau"),
        _backend(
            "keyring.backends.chainer",
            "ChainerBackend",
            backends=[
                _backend("keyring.backends.SecretService", "Keyring"),
                _backend("keyrings.alt.file", "PlaintextKeyring"),
            ],
        ),
    ],
)
def test_trousseau_en_clair_refuse(
    monkeypatch: pytest.MonkeyPatch, backend: Any
) -> None:
    entrees = {("amnesia/mission-essai", "winrm-password"): FACTICE}
    lectures = _faux_keyring(monkeypatch, backend, entrees)
    with pytest.raises(SecretError, match="en clair") as exc:
        secrets.from_keyring("mission-essai", "winrm-password")
    assert "refusé" in str(exc.value)
    assert "trousseaux du système" in str(exc.value)
    # refuse avant toute lecture
    assert lectures == []


def test_backend_plaintext_nomme_dans_le_refus(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _faux_keyring(monkeypatch, _backend("keyrings.alt.file", "PlaintextKeyring"), {})
    with pytest.raises(SecretError, match=r"keyrings\.alt\.file\.PlaintextKeyring"):
        secrets.from_keyring("mission-essai", "winrm-password")


@pytest.mark.parametrize(
    "backend",
    [
        _backend("keyring.backends.fail", "Keyring"),
        _backend("keyring.backends.null", "Keyring"),
        _backend("keyring.backends.chainer", "ChainerBackend", backends=[]),
    ],
)
def test_aucun_trousseau_source_ignoree(
    monkeypatch: pytest.MonkeyPatch, backend: Any
) -> None:
    lectures = _faux_keyring(monkeypatch, backend, {})
    assert secrets.from_keyring("mission-essai", "winrm-password") is None
    assert lectures == []


def test_module_keyring_absent_source_ignoree(monkeypatch: pytest.MonkeyPatch) -> None:
    # None dans sys.modules : l'import leve ImportError
    monkeypatch.setitem(sys.modules, "keyring", None)
    assert secrets.from_keyring("mission-essai", "winrm-password") is None


def test_erreur_du_trousseau_sans_son_message(monkeypatch: pytest.MonkeyPatch) -> None:
    def echec(service: str, compte: str) -> str:
        raise RuntimeError(f"trousseau verrouillé, valeur {FACTICE}")

    backend = _backend("keyring.backends.SecretService", "Keyring")
    module: Any = types.ModuleType("keyring")
    module.get_keyring = lambda: backend
    module.get_password = echec
    monkeypatch.setitem(sys.modules, "keyring", module)
    with pytest.raises(SecretError, match="RuntimeError") as exc:
        secrets.from_keyring("mission-essai", "winrm-password")
    assert FACTICE not in str(exc.value)
    assert exc.value.__cause__ is None


@pytest.mark.parametrize(
    ("mission", "nom"),
    [("a/b", "x"), ("", "x"), ("m", "x/y"), ("../m", "x"), ("m", "é"), ("m" * 65, "x")],
)
def test_entree_du_trousseau_noms_stricts(mission: str, nom: str) -> None:
    with pytest.raises(ValueError, match="trousseau"):
        secrets.keyring_entry(mission, nom)


# --- invite ---


def test_invite_sans_terminal_echoue_sans_attendre(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _sans_terminal(monkeypatch)
    monkeypatch.setattr(getpass, "getpass", _saisie_interdite)
    with pytest.raises(SecretError, match="aucun terminal"):
        secrets.from_prompt("Mot de passe : ")


@pytest.mark.parametrize("flux", [None, object()])
def test_invite_sans_entree_standard(
    monkeypatch: pytest.MonkeyPatch, flux: object
) -> None:
    monkeypatch.setattr(sys, "stdin", flux)
    monkeypatch.setattr(getpass, "getpass", _saisie_interdite)
    with pytest.raises(SecretError, match="aucun terminal"):
        secrets.from_prompt("Mot de passe : ")


def test_invite_avec_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    invites: list[str] = []

    def saisie(invite: str) -> str:
        invites.append(invite)
        return FACTICE

    monkeypatch.setattr(sys, "stdin", _Terminal())
    monkeypatch.setattr(getpass, "getpass", saisie)
    assert secrets.from_prompt("Mot de passe : ").reveal() == FACTICE
    assert invites == ["Mot de passe : "]


def test_invite_refuse_une_saisie_avec_echo(monkeypatch: pytest.MonkeyPatch) -> None:
    def saisie(invite: str) -> str:
        # ce que fait getpass quand il ne peut pas couper l'echo
        warnings.warn("écho non coupé", getpass.GetPassWarning, stacklevel=1)
        raise AssertionError("lecture avec écho")

    monkeypatch.setattr(sys, "stdin", _Terminal())
    monkeypatch.setattr(getpass, "getpass", saisie)
    with pytest.raises(SecretError, match="écho"):
        secrets.from_prompt("Mot de passe : ")


@pytest.mark.parametrize(
    ("retour", "motif"), [("", "vide"), (EOFError(), "interrompue")]
)
def test_invite_vide_ou_fin_de_fichier(
    monkeypatch: pytest.MonkeyPatch, retour: str | EOFError, motif: str
) -> None:
    def saisie(invite: str) -> str:
        if isinstance(retour, EOFError):
            raise retour
        return retour

    monkeypatch.setattr(sys, "stdin", _Terminal())
    monkeypatch.setattr(getpass, "getpass", saisie)
    with pytest.raises(SecretError, match=motif):
        secrets.from_prompt("Mot de passe : ")


# --- ordre des sources ---


def test_ordre_fichier_puis_variable_puis_trousseau_puis_invite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chemin = _fichier(tmp_path, b"du-fichier\n")
    backend = _backend("keyring.backends.Windows", "WinVaultKeyring")
    entrees = {("amnesia/mission-essai", "winrm-password"): "du-trousseau"}
    _faux_keyring(monkeypatch, backend, entrees)
    monkeypatch.setattr(sys, "stdin", _Terminal())
    monkeypatch.setattr(getpass, "getpass", lambda invite: "de-l-invite")

    def lire(**sources: Any) -> str:
        return secrets.resolve("winrm-password", **sources).reveal()

    monkeypatch.setenv(VARIABLE, "de-la-variable")
    complet = {"env": VARIABLE, "mission": "mission-essai", "prompt": "? "}
    assert lire(file=chemin, **complet) == "du-fichier"
    # le fichier l'emporte, mais la variable ne reste pas dans l'environnement
    assert VARIABLE not in os.environ
    monkeypatch.setenv(VARIABLE, "de-la-variable")
    assert lire(**complet) == "de-la-variable"
    assert VARIABLE not in os.environ
    assert lire(**complet) == "du-trousseau"
    assert lire(env=VARIABLE, mission="autre-mission", prompt="? ") == "de-l-invite"
    assert lire(env=VARIABLE, prompt="? ") == "de-l-invite"


def test_aucune_source_et_pas_de_terminal_echec_immediat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(VARIABLE, raising=False)
    monkeypatch.setitem(sys.modules, "keyring", None)
    _sans_terminal(monkeypatch)
    monkeypatch.setattr(getpass, "getpass", _saisie_interdite)
    with pytest.raises(SecretError) as exc:
        secrets.resolve(
            "winrm-password", env=VARIABLE, mission="mission-essai", prompt="? "
        )
    message = str(exc.value)
    assert "winrm-password" in message
    assert VARIABLE in message
    assert "amnesia/mission-essai/winrm-password" in message
    assert "aucun terminal" in message


def test_source_designee_refusee_sans_repli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # un fichier designe mais refuse n'est pas remplace par une autre source
    monkeypatch.setenv(VARIABLE, "de-la-variable")
    with pytest.raises(SecretError, match="fichier de secret"):
        secrets.resolve("winrm-password", file=tmp_path / "absent", env=VARIABLE)
    assert VARIABLE not in os.environ
    with pytest.raises(SecretError, match="aucune source"):
        secrets.resolve("winrm-password")
