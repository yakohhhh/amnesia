# SPDX-FileCopyrightText: 2026 Ayman Mazroui
# SPDX-License-Identifier: MIT

"""Fichier de mission amnesia.toml : lecture, validation, priorité (#36)."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import warnings
from datetime import date
from pathlib import Path

import pytest

from amnesia.config import (
    DEFAULT_FILE,
    KEYS,
    SOURCE_CWD,
    SOURCE_OPTION,
    THRESHOLDS,
    TLP,
    Config,
    ConfigError,
    Origin,
    Threshold,
    example_toml,
    load_config,
)

SEUIL = "thresholds.security_log_min_retention_days"


def _fichier(tmp_path: Path, texte: str, nom: str = DEFAULT_FILE) -> Path:
    chemin = tmp_path / nom
    # octets : memes fins de ligne sous Windows que sous Linux
    chemin.write_bytes(texte.encode("utf-8"))
    # droits fixes : un fichier non designe est refuse s'il est inscriptible
    # par le groupe, ce que donnerait un umask 002
    chemin.chmod(0o600)
    return chemin


def _refus(tmp_path: Path, texte: str) -> str:
    with pytest.raises(ConfigError) as exc:
        load_config(_fichier(tmp_path, texte))
    return str(exc.value)


# --- valeurs par defaut et exemple ---------------------------------------------


def test_sans_fichier_valeurs_par_defaut(tmp_path: Path) -> None:
    config = load_config(directory=tmp_path)
    assert config.source is None
    assert set(config.origins.values()) == {Origin.DEFAULT}
    assert config.values["report.lang"] == "fr"
    assert config.values["report.formats"] == ("json",)
    assert config.profile is None
    assert config.section("mission") == dict.fromkeys(
        ("client", "reference", "auditor", "start", "end", "tlp")
    )
    assert config.thresholds() == {t.name: t.default for t in THRESHOLDS}
    assert config == Config.defaults()


def test_fichier_du_repertoire_courant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fichier(tmp_path, 'profile = "pme"\n')
    monkeypatch.chdir(tmp_path)
    config = load_config()
    assert config.source == Path(DEFAULT_FILE)
    assert config.source_kind == SOURCE_CWD == "cwd"
    assert load_config(Path(DEFAULT_FILE)).source_kind == SOURCE_OPTION == "--config"
    assert load_config(directory=tmp_path / "vide").source_kind is None
    assert config.profile == "pme"
    assert config.origins["profile"] is Origin.FILE


def test_exemple_se_charge_sans_erreur_ni_avertissement(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    chemin = _fichier(tmp_path, example_toml())
    with warnings.catch_warnings(), caplog.at_level(logging.DEBUG):
        warnings.simplefilter("error")
        config = load_config(chemin)
    assert not caplog.records
    assert config.section("mission") == {
        "client": "Client Exemple",
        "reference": "MISSION-0001",
        "auditor": "Équipe d'audit",
        "start": "2026-01-12",
        "end": "2026-01-16",
        "tlp": "TLP:AMBER",
    }
    # l'exemple reprend les valeurs par defaut : meme configuration hors mission
    defauts = Config.defaults()
    assert config.section("report") == defauts.section("report")
    assert config.thresholds() == defauts.thresholds()


def test_exemple_commente_chaque_cle() -> None:
    lignes = example_toml().splitlines()
    cles = [
        (numero, ligne.partition("=")[0].strip().removeprefix("# "))
        for numero, ligne in enumerate(lignes)
        if (" = " in ligne and not ligne.startswith("# "))
        or ligne.startswith("# profile")
    ]
    noms = {cle.path.rpartition(".")[2] for cle in KEYS} | {t.name for t in THRESHOLDS}
    assert {nom for _, nom in cles} == noms
    for numero, nom in cles:
        assert lignes[numero - 1].startswith("# "), nom
    # ASCII hors commentaires et valeurs : lisible quel que soit l'editeur
    assert "\r" not in example_toml()


# --- priorite ------------------------------------------------------------------


def test_priorite_cli_puis_fichier_puis_defaut(tmp_path: Path) -> None:
    chemin = _fichier(tmp_path, "[thresholds]\nsecurity_log_min_retention_days = 400\n")
    fichier = load_config(chemin)
    assert fichier.values[SEUIL] == 400
    assert fichier.origins[SEUIL] is Origin.FILE
    assert fichier.origins[SEUIL].value == "fichier"
    cli = load_config(chemin, overrides=[f"{SEUIL}=500"])
    assert cli.values[SEUIL] == 500
    assert cli.origins[SEUIL] is Origin.CLI
    assert cli.origins[SEUIL].value == "cli"
    # le reste garde son origine
    assert cli.origins["thresholds.ntp_max_offset_seconds"] is Origin.DEFAULT
    assert Config.defaults().values[SEUIL] == 90


def test_lang_de_la_cli_l_emporte(tmp_path: Path) -> None:
    chemin = _fichier(tmp_path, '[report]\nlang = "fr"\n')
    assert load_config(chemin).values["report.lang"] == "fr"
    config = load_config(chemin, overrides=["report.lang=en"])
    assert config.values["report.lang"] == "en"
    assert config.origins["report.lang"] is Origin.CLI


def test_derniere_surcharge_gagne_et_types_de_la_cli(tmp_path: Path) -> None:
    config = load_config(
        directory=tmp_path,
        overrides=[
            f"{SEUIL}=120",
            f"{SEUIL}=180",
            "thresholds.ntp_max_offset_seconds=1",
            "report.formats=json, md",
            "mission.start=2026-03-02",
            "mission.client=Client = Exemple",
        ],
    )
    assert config.values[SEUIL] == 180
    assert config.values["thresholds.ntp_max_offset_seconds"] == 1.0
    assert config.values["report.formats"] == ("json", "md")
    assert config.values["mission.start"] == date(2026, 3, 2)
    # seul le premier « = » separe la cle de la valeur
    assert config.values["mission.client"] == "Client = Exemple"


# --- validation stricte --------------------------------------------------------


def test_cle_inconnue_chemin_et_suggestion(tmp_path: Path) -> None:
    message = _refus(tmp_path, "[thresholds]\nsecurty_log_min_retention_days = 400\n")
    assert "thresholds.securty_log_min_retention_days" in message
    assert "« thresholds.security_log_min_retention_days »" in message
    assert message.startswith(str(tmp_path / DEFAULT_FILE))


@pytest.mark.parametrize(
    ("texte", "attendu"),
    [
        ("[misson]\nclient = 'x'\n", "voulais-tu dire « mission »"),
        ("[mission]\nclint = 'x'\n", "voulais-tu dire « mission.client »"),
        ("zzz = 1\n", "clé inconnue « zzz »"),
        ("mission = 3\n", "mission : table attendue"),
        ("[mission.sous]\na = 1\n", "clé inconnue « mission.sous »"),
        ('"a\\tb" = 1\n', "clé inconnue « 'a\\tb' »"),
    ],
)
def test_cles_et_sections_inconnues(tmp_path: Path, texte: str, attendu: str) -> None:
    assert attendu in _refus(tmp_path, texte)


@pytest.mark.parametrize(
    "texte",
    [
        'password = "x"\n',
        '[mission]\npassword = "x"\n',
        '[mission]\nAPI_TOKEN = "x"\n',
        '[winrm]\nclient_secret = "x"\n',
        '[report]\nsigning_key = "x"\n',
        '[[cibles]]\npasswd = "x"\n',
        'apikey = ""\n',
    ],
)
def test_cle_de_secret_refusee_sans_reprendre_la_valeur(
    tmp_path: Path, texte: str
) -> None:
    message = _refus(tmp_path, texte)
    assert "aucun secret" in message
    assert "docs/SECRETS.md" in message
    assert "--password-file" in message
    assert '"x"' not in message
    assert "« x »" not in message


def test_secret_refuse_aussi_dans_une_surcharge(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="aucun secret") as exc:
        load_config(directory=tmp_path, overrides=["mission.password=hunter2"])
    assert "hunter2" not in str(exc.value)


def test_tlp_white_refuse_avec_message_explicite(tmp_path: Path) -> None:
    message = _refus(tmp_path, '[mission]\ntlp = "TLP:WHITE"\n')
    assert "mission.tlp" in message
    assert "TLP 1.0" in message
    assert "TLP:CLEAR" in message


@pytest.mark.parametrize("tlp", TLP)
def test_tlp_2_0_accepte(tmp_path: Path, tlp: str) -> None:
    config = load_config(_fichier(tmp_path, f'[mission]\ntlp = "{tlp}"\n'))
    assert config.values["mission.tlp"] == tlp


@pytest.mark.parametrize(
    ("texte", "attendu"),
    [
        ('[mission]\ntlp = "tlp:amber"\n', "mission.tlp : marquage"),
        ('[mission]\ntlp = "TLP:AMBRE"\n', "voulais-tu dire « TLP:AMBER »"),
        ("[mission]\ntlp = 3\n", "mission.tlp : marquage"),
        ("[mission]\nclient = 3\n", "mission.client : chaîne attendue"),
        ('[mission]\nclient = "  "\n', "mission.client : chaîne vide"),
        ('[mission]\nclient = "a\\u001b[31m"\n', "mission.client : caractère"),
        ('[mission]\nclient = "a\\u202eb"\n', "mission.client : caractère"),
        (f'[mission]\nclient = "{"a" * 201}"\n', "200 caractères au plus"),
        ('[mission]\nstart = "12/01/2026"\n', "mission.start : date ISO 8601"),
        ('[mission]\nstart = "2026-02-30"\n', "mission.start : date ISO 8601"),
        ("[mission]\nstart = 2026-01-12T10:00:00\n", "mission.start : date ISO 8601"),
        ("[mission]\nstart = 20260112\n", "mission.start : date ISO 8601"),
        (
            "[mission]\nstart = 2026-01-16\nend = 2026-01-12\n",
            "mission.end (2026-01-12) précède mission.start (2026-01-16)",
        ),
        ('profile = "Mon Profil"\n', "profile : nom de profil attendu"),
        ('[report]\nlang = "de"\n', "report.lang : langue 'de' refusée"),
        ('[report]\nformats = "json"\n', "report.formats : tableau non vide"),
        ("[report]\nformats = []\n", "report.formats : tableau non vide"),
        ('[report]\nformats = ["pdf"]\n', "report.formats : format 'pdf' refusée"),
        ('[report]\nformats = ["md", "md"]\n', "report.formats : format en double"),
        ("[report]\noutput_dir = 3\n", "report.output_dir : chaîne attendue"),
    ],
)
def test_valeurs_refusees(tmp_path: Path, texte: str, attendu: str) -> None:
    assert attendu in _refus(tmp_path, texte)


def test_dates_toml_et_chaine_iso(tmp_path: Path) -> None:
    config = load_config(
        _fichier(tmp_path, '[mission]\nstart = 2026-01-12\nend = "2026-01-12"\n')
    )
    assert config.values["mission.start"] == date(2026, 1, 12)
    assert config.values["mission.end"] == date(2026, 1, 12)


@pytest.mark.parametrize(
    "valeur", ["0", "3651", "-1", "90.5", "true", '"90"', "inf", "nan", "1e400"]
)
def test_seuil_entier_hors_bornes_ou_mal_type(tmp_path: Path, valeur: str) -> None:
    message = _refus(
        tmp_path, f"[thresholds]\nsecurity_log_min_retention_days = {valeur}\n"
    )
    # inf et nan sont refuses des la lecture (amnesia.inputs)
    assert SEUIL in message or "TOML" in message


@pytest.mark.parametrize("valeur", ["0", "3600.5", "-0.5", "true"])
def test_seuil_decimal_hors_bornes(tmp_path: Path, valeur: str) -> None:
    message = _refus(tmp_path, f"[thresholds]\nntp_max_offset_seconds = {valeur}\n")
    assert "thresholds.ntp_max_offset_seconds" in message
    assert "0.001 à 3600" in message


@pytest.mark.parametrize(
    "surcharge",
    [
        f"{SEUIL}=abc",
        f"{SEUIL}=1.5",
        f"{SEUIL}=0",
        f"{SEUIL}=",
        f"{SEUIL}={'9' * 5000}",
    ],
)
def test_seuil_refuse_dans_une_surcharge(tmp_path: Path, surcharge: str) -> None:
    with pytest.raises(ConfigError, match=SEUIL):
        load_config(directory=tmp_path, overrides=[surcharge])


@pytest.mark.parametrize("surcharge", ["sans-egal", "=valeur", ""])
def test_surcharge_mal_formee(tmp_path: Path, surcharge: str) -> None:
    with pytest.raises(ConfigError, match="CLÉ=VALEUR"):
        load_config(directory=tmp_path, overrides=[surcharge])


def test_surcharge_de_cle_inconnue(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"voulais-tu dire « report\.lang »"):
        load_config(directory=tmp_path, overrides=["report.lan=en"])


def test_seuils_d_une_autre_table(tmp_path: Path) -> None:
    seuil = Threshold("essai_max", 3, 1, 10, "essais", "nombre d'essais")
    chemin = _fichier(tmp_path, "[thresholds]\nessai_max = 7\n")
    config = load_config(chemin, thresholds=[seuil])
    assert config.thresholds() == {"essai_max": 7}
    with pytest.raises(ConfigError, match="clé inconnue"):
        load_config(chemin)


# --- lecture par la couche sure --------------------------------------------------


def test_fichier_absent_illisible_ou_mal_forme(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="absent"):
        load_config(tmp_path / "absent.toml")
    with pytest.raises(ConfigError, match="TOML invalide"):
        load_config(_fichier(tmp_path, "[mission\n"))
    # un dossier nomme amnesia.toml : refuse, pas ignore
    dossier = tmp_path / "ici"
    (dossier / DEFAULT_FILE).mkdir(parents=True)
    with pytest.raises(ConfigError):
        load_config(directory=dossier)


def test_fichier_demesure_refuse_sans_etre_analyse(tmp_path: Path) -> None:
    chemin = _fichier(tmp_path, "# " + "a" * (1024 * 1024 + 1) + "\n")
    with pytest.raises(ConfigError, match=DEFAULT_FILE):
        load_config(chemin)


def test_bom_et_fins_de_ligne_windows(tmp_path: Path) -> None:
    chemin = tmp_path / DEFAULT_FILE
    texte = '[mission]\r\nclient = "Client Exemple"\r\nstart = 2026-01-12\r\n'
    chemin.write_bytes(b"\xef\xbb\xbf" + texte.encode("utf-8"))
    config = load_config(chemin)
    assert config.values["mission.client"] == "Client Exemple"
    assert config.values["mission.start"] == date(2026, 1, 12)


# --- configuration effective ---------------------------------------------------


def test_config_hash_du_json_canonique(tmp_path: Path) -> None:
    config = load_config(_fichier(tmp_path, example_toml()))
    canonique = config.canonical_json()
    assert json.loads(canonique) == config.to_dict()
    assert canonique == json.dumps(
        config.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    assert config.config_hash() == hashlib.sha256(canonique.encode()).hexdigest()
    assert config.to_dict()["mission"]["start"] == "2026-01-12"
    assert config.to_dict()["profile"] is None
    assert config.to_dict()["report"]["formats"] == ["json"]


def test_config_hash_ignore_l_origine_pas_la_valeur(tmp_path: Path) -> None:
    fichier = load_config(
        _fichier(tmp_path, "[thresholds]\nsecurity_log_min_retention_days = 400\n")
    )
    cli = load_config(directory=tmp_path / "vide", overrides=[f"{SEUIL}=400"])
    assert fichier.origins != cli.origins
    assert fichier.config_hash() == cli.config_hash()
    assert fichier.config_hash() != Config.defaults().config_hash()


def test_configuration_en_lecture_seule() -> None:
    config = Config.defaults()
    with pytest.raises(TypeError):
        config.values["profile"] = "x"  # type: ignore[index]
    reglages = config.for_checks()
    assert reglages["thresholds"]["security_log_min_retention_days"] == 90
    with pytest.raises(TypeError):
        reglages["thresholds"]["security_log_min_retention_days"] = 1


def test_rows_dans_l_ordre_d_affichage() -> None:
    lignes = Config.defaults().rows()
    assert [chemin for chemin, _, _ in lignes][:7] == [cle.path for cle in KEYS][:7]
    assert ("report.formats", ["json"], Origin.DEFAULT) in lignes


# --- fichier non designe (repertoire courant) ----------------------------------


def _lien(cible: Path, lien: Path) -> None:
    try:
        lien.symlink_to(cible)
    except (OSError, NotImplementedError):
        pytest.skip("liens symboliques indisponibles")


def test_fichier_non_designe_lien_symbolique_refuse(tmp_path: Path) -> None:
    ailleurs = _fichier(tmp_path, 'profile = "pme"\n', "ailleurs.toml")
    dossier = tmp_path / "ici"
    dossier.mkdir()
    _lien(ailleurs, dossier / DEFAULT_FILE)
    with pytest.raises(ConfigError, match="lien symbolique refusé") as exc:
        load_config(directory=dossier)
    assert "--config" in str(exc.value)
    # designe, le meme lien est lu
    assert load_config(dossier / DEFAULT_FILE).profile == "pme"


def test_fichier_non_designe_lien_casse_refuse(tmp_path: Path) -> None:
    _lien(tmp_path / "absent.toml", tmp_path / DEFAULT_FILE)
    with pytest.raises(ConfigError, match="lien symbolique refusé"):
        load_config(directory=tmp_path)


@pytest.mark.skipif(sys.platform == "win32", reason="droits POSIX")
@pytest.mark.parametrize("droits", [0o620, 0o602, 0o666, 0o664])
def test_fichier_non_designe_inscriptible_par_d_autres_refuse(
    tmp_path: Path, droits: int
) -> None:
    chemin = _fichier(tmp_path, 'profile = "pme"\n')
    chemin.chmod(droits)
    with pytest.raises(ConfigError, match=f"droits {droits:04o}") as exc:
        load_config(directory=tmp_path)
    assert "chmod go-w" in str(exc.value)
    # designe par --config, il est lu ; lisible par d'autres, il reste admis
    assert load_config(chemin).profile == "pme"
    chemin.chmod(0o644)
    assert load_config(directory=tmp_path).profile == "pme"


@pytest.mark.skipif(sys.platform == "win32", reason="droits POSIX")
def test_fichier_non_designe_d_un_autre_compte_refuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chemin = _fichier(tmp_path, 'profile = "pme"\n')
    autre = os.geteuid() + 1
    monkeypatch.setattr(os, "geteuid", lambda: autre)
    with pytest.raises(ConfigError, match="appartient à un autre compte"):
        load_config(directory=tmp_path)
    assert load_config(chemin).profile == "pme"


# --- constats de revue ---------------------------------------------------------

GEANT = "0x" + "F" * 6000


@pytest.mark.parametrize(
    ("texte", "chemin"),
    [
        (f"[thresholds]\nsecurity_log_min_retention_days = {GEANT}\n", SEUIL),
        (f"[thresholds]\nntp_max_offset_seconds = {GEANT}\n", "ntp_max_offset"),
        (f"[mission]\ntlp = {GEANT}\n", "mission.tlp"),
        (f"[report]\nformats = [{GEANT}]\n", "report.formats"),
        (f"[report]\nlang = {GEANT}\n", "report.lang"),
    ],
)
def test_entier_geant_refuse_proprement(
    tmp_path: Path, texte: str, chemin: str
) -> None:
    message = _refus(tmp_path, texte)
    assert chemin in message
    assert "FFFF" not in message


@pytest.mark.parametrize(
    "valeur",
    [
        "password=hunter2",
        "Client Exemple pwd: hunter2",
        "https://bob:motdepasse@hote.exemple.invalid/x",
        "api_key=abcdef",
        "Bearer abcdef",
    ],
)
@pytest.mark.parametrize("cle", ["mission.client", "mission.auditor"])
def test_texte_libre_qui_ressemble_a_un_secret_refuse(
    tmp_path: Path, cle: str, valeur: str
) -> None:
    section, nom = cle.split(".")
    for erreur in (
        _refus(tmp_path, f'[{section}]\n{nom} = "{valeur}"\n'),
        _refus_cli(tmp_path, f"{cle}={valeur}"),
    ):
        assert cle in erreur
        assert "ressemble à un secret" in erreur
        assert "docs/SECRETS.md" in erreur
        assert "hunter2" not in erreur
        assert "motdepasse" not in erreur
        assert "abcdef" not in erreur


def _refus_cli(tmp_path: Path, surcharge: str) -> str:
    with pytest.raises(ConfigError) as exc:
        load_config(directory=tmp_path / "vide", overrides=[surcharge])
    return str(exc.value)


@pytest.mark.parametrize(
    "dossier",
    [
        "/ailleurs/livrables",
        "../ailleurs",
        "livrables/../../ailleurs",
        "livrables\\\\..\\\\..",
        "C:\\\\ailleurs",
        "C:ailleurs",
        "\\\\\\\\serveur\\\\partage\\\\x",
        "\\\\ailleurs",
        "..",
    ],
)
def test_output_dir_du_fichier_relatif_sans_remontee(
    tmp_path: Path, dossier: str
) -> None:
    message = _refus(tmp_path, f'[report]\noutput_dir = "{dossier}"\n')
    assert "report.output_dir : chemin relatif sans « .. » attendu" in message
    assert "--set report.output_dir=" in message


def test_output_dir_absolu_admis_depuis_la_ligne_de_commande(tmp_path: Path) -> None:
    absolu = str(tmp_path / "livrables")
    config = load_config(directory=tmp_path, overrides=[f"report.output_dir={absolu}"])
    assert config.values["report.output_dir"] == absolu
    assert config.origins["report.output_dir"] is Origin.CLI
    relatif = load_config(
        _fichier(tmp_path, '[report]\noutput_dir = "livrables/2026..01/a..b"\n')
    )
    assert relatif.values["report.output_dir"] == "livrables/2026..01/a..b"


@pytest.mark.parametrize(
    "client", ["Dupont\u00a0& Fils", "Société X\u00a0: siège", "Client\u202fExemple"]
)
def test_espace_insecable_admise(tmp_path: Path, client: str) -> None:
    config = load_config(_fichier(tmp_path, f'[mission]\nclient = "{client}"\n'))
    assert config.values["mission.client"] == client
    assert json.loads(config.canonical_json())["mission"]["client"] == client


@pytest.mark.parametrize(
    "caractere",
    ["\\u0000", "\\u009b", "\\u200b", "\\u2028", "\\u2029", "\\ue000", "\\n"],
)
def test_caracteres_de_controle_et_de_format_refuses(
    tmp_path: Path, caractere: str
) -> None:
    message = _refus(tmp_path, f'[mission]\nclient = "a{caractere}b"\n')
    assert "mission.client : caractère" in message


def test_cle_racine_apres_une_section(tmp_path: Path) -> None:
    message = _refus(
        tmp_path, '[mission]\nclient = "Client Exemple"\nprofile = "pme"\n'
    )
    assert "clé « profile » lue dans la section [mission]" in message
    assert "avant la première section" in message
    assert "voulais-tu dire" not in message


def test_cle_connue_au_nom_de_secret_admise(tmp_path: Path) -> None:
    seuil = Threshold(
        "krbtgt_password_max_age_days", 180, 1, 3650, "jours", "âge du mot de passe"
    )
    chemin = _fichier(tmp_path, "[thresholds]\nkrbtgt_password_max_age_days = 90\n")
    cle = "thresholds.krbtgt_password_max_age_days"
    assert load_config(chemin, thresholds=[seuil]).values[cle] == 90
    surcharge = load_config(
        directory=tmp_path / "vide", thresholds=[seuil], overrides=[f"{cle}=365"]
    )
    assert surcharge.values[cle] == 365
    # inconnue, la meme cle reste un secret refuse ; une voisine aussi
    with pytest.raises(ConfigError, match="aucun secret"):
        load_config(chemin)
    with pytest.raises(ConfigError, match="aucun secret"):
        load_config(
            directory=tmp_path / "vide",
            thresholds=[seuil],
            overrides=["thresholds.krbtgt_password=x"],
        )


@pytest.mark.parametrize(
    "surcharge",
    [
        f"{SEUIL}=5_0",
        f"{SEUIL}= 50 ",
        f"{SEUIL}=+50",
        f"{SEUIL}=\u0665\u0660",
        "thresholds.ntp_max_offset_seconds=1_0",
        "thresholds.ntp_max_offset_seconds= 1 ",
        "thresholds.ntp_max_offset_seconds=1e2",
        "thresholds.ntp_max_offset_seconds=nan",
        "thresholds.ntp_max_offset_seconds=inf",
    ],
)
def test_nombre_de_la_cli_en_chiffres_stricts(tmp_path: Path, surcharge: str) -> None:
    with pytest.raises(ConfigError, match="thresholds"):
        load_config(directory=tmp_path, overrides=[surcharge])


def test_bornes_incluses(tmp_path: Path) -> None:
    config = load_config(
        _fichier(
            tmp_path,
            "[thresholds]\nsecurity_log_min_retention_days = 3650\n"
            "ntp_max_offset_seconds = 3600\n",
        )
    )
    assert config.values[SEUIL] == 3650
    assert config.values["thresholds.ntp_max_offset_seconds"] == 3600.0
    bas = load_config(
        directory=tmp_path / "vide",
        overrides=[f"{SEUIL}=1", "thresholds.ntp_max_offset_seconds=0.001"],
    )
    assert bas.values[SEUIL] == 1
    assert bas.values["thresholds.ntp_max_offset_seconds"] == 0.001


def test_seuil_decimal_entier_ou_flottant_meme_condensat(tmp_path: Path) -> None:
    entier = load_config(
        _fichier(tmp_path, "[thresholds]\nntp_max_offset_seconds = 5\n")
    )
    flottant = load_config(
        _fichier(tmp_path, "[thresholds]\nntp_max_offset_seconds = 5.0\n", "b.toml")
    )
    valeur = entier.values["thresholds.ntp_max_offset_seconds"]
    assert isinstance(valeur, float)
    assert entier.canonical_json() == flottant.canonical_json()
    assert (
        entier.config_hash()
        == flottant.config_hash()
        == Config.defaults().config_hash()
    )
