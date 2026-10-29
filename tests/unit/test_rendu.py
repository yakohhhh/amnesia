"""Rendus « questions sans réponse » en terminal et en Markdown (#23)."""

from __future__ import annotations

import copy
import io
import json
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from amnesia.cli import CODE_RAPPORT_ILLISIBLE, main
from amnesia.render import (
    GROUP_BY,
    RENDERERS,
    SEVERITIES,
    SUPPORTED_MAJOR,
    MarkdownRenderer,
    RenderOptions,
    ReportError,
    TextRenderer,
    color_enabled,
    escape_markdown,
    fallback,
    load_report,
    neutralize,
    read_report,
    render_report,
)
from amnesia.render.base import (
    GapView,
    group_gaps,
    lowercase_first,
    quantification,
)
from amnesia.report import SCHEMA_VERSION

RACINE = Path(__file__).resolve().parents[2]
FIXTURE = RACINE / "tests" / "fixtures" / "report-min.json"
GOLDENS = {
    "text": RACINE / "tests" / "golden" / "report-min.txt",
    "md": RACINE / "tests" / "golden" / "report-min.md",
}
RAPPORT_22 = RACINE / "tests" / "golden" / "report.json"

QUESTION_RDP = "Qui s'est connecté en RDP sur SRV-FILE il y a trois semaines ?"
IMPOSSIBLE_RDP = (
    "→ Impossible : le journal Security fait 20 Mo et a été écrasé il y a 4 jours."
)
CIBLE = "winrm://srv-file.exemple.invalid"

# ESC, CSI (C1), BEL, NUL, DEL, retour chariot, saut de ligne, bidi, U+2028 et
# hyperlien OSC 8 : rien de tout cela ne doit atteindre le terminal brut
HOSTILE = (
    "\x1b[2J\x1b]8;;https://evil.example\x07clic\x1b]8;;\x07\x9b31m"
    "\u202eabc\r\nFAUX\u2028x\x00\x7f"
)
CONTROLES = ("\x1b", "\x9b", "\x07", "\x00", "\x7f", "\r", "\u202e", "\u2028")


def rapport() -> dict[str, Any]:
    """Copie de la fixture report-min.json."""
    donnees: dict[str, Any] = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return donnees


def gap(
    severity: str,
    question: str,
    *,
    check_id: str = "win.event_log_retention",
    target: str = CIBLE,
) -> dict[str, Any]:
    """Gap du rapport, dérivé du premier Gap de la fixture."""
    donnees: dict[str, Any] = copy.deepcopy(rapport()["gaps"][0])
    donnees.update(
        severity=severity, question=question, check_id=check_id, target=target
    )
    return donnees


def recompter(donnees: dict[str, Any]) -> dict[str, Any]:
    """Compteurs de ``summary`` recalculés depuis ``results`` et ``gaps``."""
    resultats, gaps = donnees["results"], donnees["gaps"]
    statuts = [r["status"] for r in resultats]
    exclus = sum(r["reason"] == "user_excluded" for r in resultats)
    donnees["summary"] = {
        "total": len(resultats),
        "by_status": {s: statuts.count(s) for s in donnees["summary"]["by_status"]},
        "by_severity": {s: sum(g["severity"] == s for g in gaps) for s in SEVERITIES},
        "gaps": len(gaps),
        "excluded": exclus,
        "not_evaluated": statuts.count("error") + statuts.count("skipped") - exclus,
    }
    return donnees


def avec_gaps(*gaps: dict[str, Any]) -> dict[str, Any]:
    """Fixture dont les Gaps sont remplacés ; sans Gap, plus de résultat gap."""
    donnees = rapport()
    donnees["gaps"] = list(gaps)
    if not gaps:
        for resultat in donnees["results"]:
            if resultat["status"] == "gap":
                resultat["status"] = "pass"
    return recompter(donnees)


def sans_non_verifie(donnees: dict[str, Any]) -> dict[str, Any]:
    """Rapport complet : résultats error et skipped retirés, compteurs à jour."""
    donnees["results"] = [
        r for r in donnees["results"] if r["status"] not in ("error", "skipped")
    ]
    donnees["run"]["complete"] = True
    return recompter(donnees)


def texte(donnees: dict[str, Any], **options: Any) -> str:
    return TextRenderer().render(donnees, RenderOptions(**options))


def markdown(donnees: dict[str, Any], **options: Any) -> str:
    return MarkdownRenderer().render(donnees, RenderOptions(**options))


TOUS_LES_RENDUS: list[Callable[..., str]] = [texte, markdown]


def ecrire(tmp_path: Path, donnees: Any) -> Path:
    chemin = tmp_path / "rapport.json"
    chemin.write_text(json.dumps(donnees, ensure_ascii=False), encoding="utf-8")
    return chemin


# --- golden files et format du README ------------------------------------------


@pytest.mark.parametrize("fmt", ["text", "md"])
def test_golden(fmt: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["render", str(FIXTURE), "--format", fmt]) == 0
    sortie = capsys.readouterr().out
    golden = GOLDENS[fmt]
    if os.environ.get("AMNESIA_UPDATE_GOLDEN") == "1":
        golden.parent.mkdir(exist_ok=True)
        golden.write_bytes(sortie.encode("utf-8"))
    assert golden.read_bytes() == sortie.encode("utf-8"), (
        "golden perime : relancer avec AMNESIA_UPDATE_GOLDEN=1 et relire le diff"
    )
    # le rendu par l'API est identique a celui de la CLI
    assert render_report(rapport(), fmt) == sortie


def test_golden_sans_espace_final() -> None:
    # hooks trailing-whitespace et end-of-file-fixer : le golden reste stable
    for golden in GOLDENS.values():
        contenu = golden.read_text(encoding="utf-8")
        assert contenu.endswith("\n")
        assert not contenu.endswith("\n\n")
        assert all(ligne == ligne.rstrip() for ligne in contenu.splitlines())


def test_format_du_readme() -> None:
    lignes = texte(rapport()).splitlines()
    (indice,) = [i for i, ligne in enumerate(lignes) if ligne.endswith(QUESTION_RDP)]
    assert lignes[indice] == f"[élevée] {QUESTION_RDP}"
    assert lignes[indice + 1].strip() == IMPOSSIBLE_RDP
    assert lignes[indice + 2].strip() == f"Cible : {CIBLE}"
    assert lignes[indice + 3].strip() == "Fenêtre observée 4 j / exigée 90 j"


def test_format_du_readme_markdown() -> None:
    sortie = markdown(rapport())
    assert f"- **{QUESTION_RDP}**\n  - {IMPOSSIBLE_RDP}\n" in sortie


def test_rapport_de_22() -> None:
    # le golden du rapport JSON (#22) se rend sans erreur, dans les deux formats
    donnees = json.loads(RAPPORT_22.read_text(encoding="utf-8"))
    for fmt in RENDERERS:
        assert QUESTION_RDP in render_report(donnees, fmt)


# --- tri, regroupements et filtre ----------------------------------------------


def _cinq_gaps() -> dict[str, Any]:
    # ordre d'entree volontairement melange
    return avec_gaps(
        gap("info", "Question info ?"),
        gap("low", "Question low ?"),
        gap("critical", "Question critical ?"),
        gap("medium", "Question medium ?"),
        gap("high", "Question high ?"),
    )


@pytest.mark.parametrize("rendre", TOUS_LES_RENDUS)
@pytest.mark.parametrize("group_by", GROUP_BY)
def test_gaps_de_critical_a_info(rendre: Callable[..., str], group_by: str) -> None:
    sortie = rendre(_cinq_gaps(), group_by=group_by)
    positions = [sortie.index(f"Question {s} ?") for s in SEVERITIES]
    assert positions == sorted(positions)


def test_titres_par_severite() -> None:
    sortie = texte(_cinq_gaps())
    titres = [ligne for ligne in sortie.splitlines() if ligne.startswith("Sévérité ")]
    assert titres == [
        "Sévérité critique (critical) : 1 angle mort",
        "Sévérité élevée (high) : 1 angle mort",
        "Sévérité moyenne (medium) : 1 angle mort",
        "Sévérité faible (low) : 1 angle mort",
        "Sévérité info (info) : 1 angle mort",
    ]


def test_group_by_domain() -> None:
    donnees = avec_gaps(
        gap("medium", "Question win 1 ?", check_id="win.sysmon"),
        gap("high", "Question ad ?", check_id="ad.kerberos"),
        gap("critical", "Question win 2 ?", check_id="win.audit_policy"),
        gap("low", "Question inconnue ?", check_id="xyz.autre"),
    )
    for rendre, prefixe in ((texte, ""), (markdown, "## ")):
        sortie = rendre(donnees, group_by="domain")
        titres = [
            ligne.removeprefix(prefixe)
            for ligne in sortie.splitlines()
            if ligne.startswith(f"{prefixe}Domaine ")
        ]
        assert titres == [
            "Domaine Active Directory (ad) : 1 angle mort",
            "Domaine Windows (win) : 2 angles morts",
            "Domaine xyz : 1 angle mort",
        ]
        # dans un groupe : de critical a info
        assert sortie.index("Question win 2 ?") < sortie.index("Question win 1 ?")


def test_group_by_target() -> None:
    donnees = avec_gaps(
        gap("low", "Question a ?", target="winrm://a.exemple.invalid"),
        gap("high", "Question b ?", target="winrm://b.exemple.invalid"),
        gap("critical", "Question a2 ?", target="winrm://a.exemple.invalid"),
    )
    sortie = texte(donnees, group_by="target")
    titres = [ligne for ligne in sortie.splitlines() if ligne.startswith("Cible ")]
    assert titres == [
        "Cible winrm://a.exemple.invalid : 2 angles morts",
        "Cible winrm://b.exemple.invalid : 1 angle mort",
    ]
    md = markdown(donnees, group_by="target")
    assert "## Cible winrm\\://a.exemple.invalid : 2 angles morts" in md
    assert "## Cible winrm\\://b.exemple.invalid : 1 angle mort" in md


def test_min_severity_high_par_la_cli(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    chemin = ecrire(tmp_path, _cinq_gaps())
    for fmt in RENDERERS:
        args = ["render", str(chemin), "--format", fmt, "--min-severity", "high"]
        assert main(args) == 0
        sortie = capsys.readouterr().out
        assert "Question critical ?" in sortie
        assert "Question high ?" in sortie
        for masquee in ("medium", "low", "info"):
            assert f"Question {masquee} ?" not in sortie
        assert "Masqués par --min-severity high" in sortie


def test_min_severity_masque_tout() -> None:
    donnees = avec_gaps(gap("medium", "Question medium ?"))
    sortie = texte(donnees, min_severity="critical")
    assert "Question medium ?" not in sortie
    assert "0 angle mort de sévérité critique ou plus (1 angle mort sous ce seuil" in (
        sortie
    )
    assert "aucun angle mort" not in sortie.casefold()


# --- non verifie : jamais « aucun angle mort » ---------------------------------


@pytest.mark.parametrize("rendre", TOUS_LES_RENDUS)
def test_section_non_verifie(rendre: Callable[..., str]) -> None:
    sortie = rendre(rapport())
    assert "Non vérifié : 2 checks" in sortie
    assert "accès refusé" in sortie
    assert "accès refusé à la configuration Sysmon" in sortie
    assert "check non implémenté" in sortie
    assert "aucun angle mort" not in sortie.casefold()


@pytest.mark.parametrize("rendre", TOUS_LES_RENDUS)
@pytest.mark.parametrize("statut", ["error", "skipped"])
def test_zero_gap_et_check_non_verifie(rendre: Callable[..., str], statut: str) -> None:
    donnees = sans_non_verifie(avec_gaps())
    motif = "timeout" if statut == "error" else "user_excluded"
    donnees["results"].append(
        {
            "check_id": "win.sysmon",
            "check_version": 1,
            "target": CIBLE,
            "status": statut,
            "reason": motif,
            "message": "",
            "error": None,
            "duration_s": None,
        }
    )
    sortie = rendre(recompter(donnees))
    assert "aucun angle mort" not in sortie.casefold()
    assert "Non vérifié : 1 check" in sortie
    assert ("délai dépassé" if statut == "error" else "exclu par l'utilisateur") in (
        sortie
    )
    assert "la cible n'est pas pour autant conforme" in sortie


@pytest.mark.parametrize("rendre", TOUS_LES_RENDUS)
def test_resume_incoherent_jamais_conforme(rendre: Callable[..., str]) -> None:
    # aucun resultat error/skipped, mais summary en compte un : non verifie
    donnees = sans_non_verifie(avec_gaps())
    donnees["summary"]["not_evaluated"] = 1
    sortie = rendre(donnees)
    assert "aucun angle mort" not in sortie.casefold()
    assert "1 check sans détail dans le rapport" in sortie


@pytest.mark.parametrize("rendre", TOUS_LES_RENDUS)
def test_audit_interrompu(rendre: Callable[..., str]) -> None:
    donnees = sans_non_verifie(avec_gaps())
    donnees["run"]["interrupted"] = True
    sortie = rendre(donnees)
    assert "Audit interrompu : résultats partiels." in sortie
    assert "aucun angle mort" not in sortie.casefold()


@pytest.mark.parametrize("rendre", TOUS_LES_RENDUS)
def test_aucun_angle_mort_si_tout_est_verifie(rendre: Callable[..., str]) -> None:
    # temoin : la phrase existe bien quand tout a ete evalue
    sortie = rendre(sans_non_verifie(avec_gaps()))
    assert "Aucun angle mort détecté : tous les checks ont été évalués." in sortie
    assert "Tous les checks ont été évalués." in sortie
    assert "Audit incomplet" not in sortie


def test_resume_chiffre() -> None:
    sortie = texte(rapport())
    assert (
        "Résultats : 6 ; conformes 1, avec angle mort 2, en erreur 1, "
        "non exécutés 1, sans objet 1"
    ) in sortie
    assert "Angles morts : 2 ; critique 0, élevée 1, moyenne 1, faible 0, info 0" in (
        sortie
    )
    md = markdown(rapport())
    assert "| Angles morts de sévérité élevée (high) | 1 |" in md


def test_motif_absent_et_message_redondant() -> None:
    donnees = rapport()
    sysmon = next(r for r in donnees["results"] if r["check_id"] == "win.sysmon")
    sysmon["reason"] = None
    sysmon["message"] = "  "
    sortie = texte(donnees)
    assert "- win.sysmon sur winrm://srv-file.exemple.invalid : erreur, motif non" in (
        sortie
    )


# --- couleurs -------------------------------------------------------------------


class _Terminal(io.StringIO):
    encoding = "utf-8"

    def isatty(self) -> bool:
        return True


def test_color_enabled() -> None:
    tty, pipe = _Terminal(), io.StringIO()
    assert color_enabled(tty, {}, platform="linux")
    assert color_enabled(tty, {"NO_COLOR": ""}, platform="linux")
    assert not color_enabled(tty, {"NO_COLOR": "1"}, platform="linux")
    assert not color_enabled(tty, {}, no_color=True, platform="linux")
    assert not color_enabled(tty, {"TERM": "dumb"}, platform="linux")
    assert not color_enabled(pipe, {}, platform="linux")
    assert not color_enabled(object(), {}, platform="linux")
    assert not color_enabled(tty, {}, platform="win32")
    assert color_enabled(tty, {"WT_SESSION": "1"}, platform="win32")


def test_color_enabled_flux_ferme() -> None:
    flux = io.StringIO()
    flux.close()
    assert not color_enabled(flux, {}, platform="linux")


def _rendu_cli(
    monkeypatch: pytest.MonkeyPatch, *args: str, environ: dict[str, str]
) -> str:
    for nom in ("NO_COLOR", "TERM", "WT_SESSION"):
        monkeypatch.delenv(nom, raising=False)
    for nom, valeur in environ.items():
        monkeypatch.setenv(nom, valeur)
    terminal = _Terminal()
    monkeypatch.setattr("sys.stdout", terminal)
    assert main(["render", str(FIXTURE), *args]) == 0
    return terminal.getvalue()


def test_couleurs_sur_un_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    # temoin : sur un terminal, sans NO_COLOR, le rendu texte est colore
    sortie = _rendu_cli(monkeypatch, environ={"WT_SESSION": "1"})
    assert "\x1b[" in sortie
    # seules des sequences SGR d'amnesia : rien d'autre une fois retirees
    assert "\x1b" not in re.sub(r"\x1b\[[0-9;]*m", "", sortie)
    assert re.sub(r"\x1b\[[0-9;]*m", "", sortie) == texte(rapport())


@pytest.mark.parametrize(
    ("args", "environ"),
    [
        ((), {"NO_COLOR": "1", "WT_SESSION": "1"}),
        (("--no-color",), {"WT_SESSION": "1"}),
        (("--format", "md"), {"WT_SESSION": "1"}),
    ],
)
def test_sans_couleur(
    monkeypatch: pytest.MonkeyPatch, args: tuple[str, ...], environ: dict[str, str]
) -> None:
    assert "\x1b" not in _rendu_cli(monkeypatch, *args, environ=environ)


def test_sans_couleur_hors_terminal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("WT_SESSION", "1")
    assert main(["render", str(FIXTURE)]) == 0
    assert "\x1b" not in capsys.readouterr().out


# --- securite : valeurs hostiles -------------------------------------------------


def _hostile() -> dict[str, Any]:
    donnees = avec_gaps(
        gap("high", HOSTILE, check_id="win." + HOSTILE, target=HOSTILE),
        gap("low", "Question ?", target=HOSTILE),
    )
    donnees["gaps"][0]["reason"] = HOSTILE
    donnees["run"]["id"] = HOSTILE
    donnees["run"]["started_at"] = HOSTILE
    donnees["tool"]["version"] = HOSTILE
    donnees["targets"][0]["id"] = HOSTILE
    for resultat in donnees["results"]:
        resultat["message"] = HOSTILE
        resultat["target"] = HOSTILE
    return donnees


@pytest.mark.parametrize("rendre", TOUS_LES_RENDUS)
@pytest.mark.parametrize("group_by", GROUP_BY)
def test_aucune_sequence_de_controle(rendre: Callable[..., str], group_by: str) -> None:
    sortie = rendre(_hostile(), group_by=group_by)
    for controle in CONTROLES:
        assert controle not in sortie
    assert all(c == "\n" or c.isprintable() for c in sortie)
    # aucune fausse entree forgee par un saut de ligne
    assert not any(ligne.startswith("FAUX") for ligne in sortie.splitlines())
    assert "\\x1b[2J" in sortie or "\\\\x1b\\[2J" in sortie


def test_couleurs_et_valeurs_hostiles() -> None:
    sortie = texte(_hostile(), color=True)
    assert "\x1b" not in re.sub(r"\x1b\[[0-9;]*m", "", sortie)


def test_neutralize() -> None:
    assert neutralize("a\x1b[31mb") == "a\\x1b[31mb"
    assert neutralize("\u202eabc\r\n") == "\\u202eabc\\r\\n"
    assert neutralize("\x9b\udcff\ue000") == "\\x9b\\udcff\\ue000"
    # espaces Unicode et accents conserves
    assert neutralize("été\u00a0: «\u202fx\u202f»") == "été\u00a0: «\u202fx\u202f»"


def test_escape_markdown() -> None:
    hostile = (
        "[clic](https://evil.example) ![pixel](https://evil.example/p.png) "
        "<img src=x onerror=alert(1)> &#x202e; www.evil.example WWW.evil.example "
        "a@b.example mailto:a@b.example `code` *gras* _it_ ~barre~ | cellule | "
        "#12 $x$ \\[ \x1b[31m"
    )
    echappe = escape_markdown(hostile)
    # aucun caractere special qui ne soit precede d'une barre oblique inverse
    assert re.search(r"(?<!\\)[\[\]()<>&|`*_~!@#$]", echappe) is None
    assert "\\[clic\\]\\(https\\://evil.example\\)" in echappe
    assert "\\!\\[pixel\\]" in echappe
    assert "\\<img" in echappe
    assert "\\&\\#x202e;" in echappe
    assert "www\\.evil" in echappe
    assert "WWW\\.evil" in echappe
    assert "a\\@b" in echappe
    assert "mailto\\:" in echappe
    assert "\\|" in echappe
    assert "\\\\x1b\\[31m" in echappe
    assert "\x1b" not in echappe
    # texte ordinaire inchange : heures, tirets, apostrophes
    assert escape_markdown(" 09:30 SRV-FILE l'hôte ") == "09:30 SRV-FILE l'hôte"


def test_markdown_hostile_sans_lien_ni_html() -> None:
    donnees = avec_gaps(gap("high", "[x](https://evil.example) <b>gras</b>"))
    sysmon = next(r for r in donnees["results"] if r["check_id"] == "win.sysmon")
    sysmon["message"] = "a | b"
    sortie = markdown(donnees)
    assert "](" not in sortie
    assert "<b>" not in sortie
    assert "| a \\| b |" in sortie


# --- repli ASCII et textes ------------------------------------------------------


def test_fallback() -> None:
    assert fallback("→ « été » ’ – … x", "utf-8") == "→ « été » ’ – … x"
    assert fallback("→ « été »", "cp1252") == "-> « été »"
    assert fallback("→ « été » ’ – — …", "ascii") == '-> " ete " \' - - ...'
    assert fallback("中\u00a0x", "ascii") == "\\u4e2d x"
    assert fallback("中", "cp1252") == "\\u4e2d"
    # formes pleine chasse : jamais ramenees a « < », « [ » ou « & »
    assert fallback("\uff1cb\uff1e\uff3b\uff06", "cp1252") == (
        "\\uff1cb\\uff1e\\uff3b\\uff06"
    )
    assert fallback("\uff21\u00b2", "ascii") == "A2"


def test_markdown_pleine_chasse_en_cp1252() -> None:
    donnees = avec_gaps(gap("high", "\uff1cimg src=x\uff1e \uff3bx\uff3d\uff08y\uff09"))
    sortie = markdown(donnees, encoding="cp1252")
    assert "<img" not in sortie
    assert "[x](y)" not in sortie
    assert "\\uff1cimg" in sortie


def test_escape_markdown_repli_avant_echappement() -> None:
    # pleine chasse et accents absents de l'encodage : replies, puis echappes
    assert escape_markdown("\uff48\uff54\uff54\uff50\uff53://x", "cp1252") == (
        "https\\://x"
    )
    assert escape_markdown("http\u015b://x", "ascii") == "https\\://x"
    assert escape_markdown("\u1e81\u1e81\u1e81.x", "cp850") == "www\\.x"
    assert escape_markdown("\uff1cb", "cp1252") == "\\\\uff1cb"
    # sans encodage, ou si tout est representable : aucun repli
    assert escape_markdown("http\u015b://x") == "http\u015b://x"
    assert escape_markdown("http\u015b://x", "utf-8") == "http\u015b://x"


# lettres pleine chasse ou accentuees que le repli ASCII ramene a un schema
# ou a « www » : apres repli, un lien automatique GFM si l'echappement precede
LIENS_REPLIES = [
    ("\uff48\uff54\uff54\uff50\uff53://evil.example/x", "https\\:"),
    ("http\u015b://evil.example/x", "https\\:"),
    ("\uff4d\uff41\uff49\uff4c\uff54\uff4f:a", "mailto\\:"),
    ("\uff57\uff57\uff57.evil.example", "www\\."),
    ("\u1e81\u1e81\u1e81.evil.example", "www\\."),
]


@pytest.mark.parametrize("encodage", ["cp1252", "cp850", "ascii"])
@pytest.mark.parametrize(("hostile", "echappe"), LIENS_REPLIES)
@pytest.mark.parametrize("group_by", GROUP_BY)
def test_markdown_lettres_repliees_sans_lien(
    encodage: str, hostile: str, echappe: str, group_by: str
) -> None:
    donnees = avec_gaps(gap("high", f"Voir {hostile}", target=hostile))
    sysmon = next(r for r in donnees["results"] if r["check_id"] == "win.sysmon")
    sysmon["message"] = hostile
    sysmon["target"] = hostile
    donnees["run"]["targets"] = [hostile]
    sortie = markdown(donnees, encoding=encodage, group_by=group_by)
    sortie.encode(encodage)
    minuscules = sortie.lower()
    for lien in ("https:", "mailto:", "www."):
        assert lien not in minuscules
    assert echappe in sortie


@pytest.mark.parametrize("encodage", ["cp1252", "cp850", "ascii"])
def test_rendu_encodable(encodage: str) -> None:
    for rendre in TOUS_LES_RENDUS:
        sortie = rendre(_hostile(), encoding=encodage)
        sortie.encode(encodage)
        assert "->" in sortie


@pytest.mark.parametrize(
    ("entree", "attendu"),
    [
        ("Le journal Security", "le journal Security"),
        ("L'événement 4688", "l'événement 4688"),
        ("Aucune trace", "aucune trace"),
        ("Sysmon n'est pas installé", "Sysmon n'est pas installé"),
        ("RDP désactivé", "RDP désactivé"),
        ("LE JOURNAL", "LE JOURNAL"),
        ("le journal", "le journal"),
        ("4 jours", "4 jours"),
        ("", ""),
    ],
)
def test_lowercase_first(entree: str, attendu: str) -> None:
    assert lowercase_first(entree) == attendu


def _vue(observee: float | None, exigee: float | None) -> GapView:
    vue = read_report(rapport()).gaps[0]
    return GapView(
        check_id=vue.check_id,
        target=vue.target,
        question=vue.question,
        reason=vue.reason,
        severity=vue.severity,
        observed_window_days=observee,
        required_window_days=exigee,
    )


@pytest.mark.parametrize(
    ("observee", "exigee", "attendu"),
    [
        (4, 180, "Fenêtre observée 4 j / exigée 180 j"),
        (4.0, 180.0, "Fenêtre observée 4 j / exigée 180 j"),
        (2.5, None, "Fenêtre observée 2,5 j"),
        (None, 90, "Fenêtre exigée 90 j"),
        (0.001, 7, "Fenêtre observée < 0,01 j / exigée 7 j"),
        (None, None, None),
    ],
)
def test_quantification(
    observee: float | None, exigee: float | None, attendu: str | None
) -> None:
    assert quantification(_vue(observee, exigee)) == attendu


# --- version du format et rapports invalides ----------------------------------


def test_version_majeure_non_prise_en_charge(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    donnees = rapport()
    donnees["schema_version"] = "2.0.0"
    chemin = ecrire(tmp_path, donnees)
    for fmt in RENDERERS:
        assert main(["render", str(chemin), "--format", fmt]) == 4
        sortie = capsys.readouterr()
        assert sortie.out == ""
        assert "format de rapport 2.0.0 non pris en charge" in sortie.err
        assert f"{SUPPORTED_MAJOR}.x.y" in sortie.err
    assert CODE_RAPPORT_ILLISIBLE == 4


@pytest.mark.parametrize("version", ["0.9.0", "2.0.0", "10.1.0", "1.0", "01.0.0", 1])
def test_schema_version_refusee(version: object) -> None:
    donnees = rapport()
    donnees["schema_version"] = version
    for rendu in RENDERERS.values():
        with pytest.raises(ReportError, match=r"schema_version|format de rapport"):
            rendu.render(donnees, RenderOptions())


def test_version_mineure_acceptee() -> None:
    # une MINEURE ne fait qu'ajouter des champs, ignores par les rendus
    donnees = rapport()
    donnees["schema_version"] = f"{SUPPORTED_MAJOR}.7.3"
    donnees["champ_futur"] = {"x": 1}
    donnees["gaps"][0]["champ_futur"] = []
    assert QUESTION_RDP in texte(donnees)
    assert SCHEMA_VERSION.startswith(f"{SUPPORTED_MAJOR}.")


def _retirer(cle: str) -> Callable[[dict[str, Any]], None]:
    def modifier(donnees: dict[str, Any]) -> None:
        del donnees[cle]

    return modifier


def _poser(
    chemin: tuple[str | int, ...], valeur: object
) -> Callable[[dict[str, Any]], None]:
    def modifier(donnees: dict[str, Any]) -> None:
        cible: Any = donnees
        for cle in chemin[:-1]:
            cible = cible[cle]
        cible[chemin[-1]] = valeur

    return modifier


@pytest.mark.parametrize(
    ("modifier", "message"),
    [
        (_retirer("schema_version"), "schema_version : champ manquant"),
        (_retirer("gaps"), "gaps : champ manquant"),
        (_poser(("gaps",), {}), "gaps : liste attendue"),
        (_poser(("gaps", 0), "x"), r"gaps\[0\] : objet attendu"),
        (_poser(("gaps", 0, "severity"), "urgent"), r"gaps\[0\]\.severity"),
        (_poser(("gaps", 0, "severity"), 3), r"gaps\[0\]\.severity : valeur"),
        (_poser(("gaps", 0, "question"), 3), r"gaps\[0\]\.question : chaîne"),
        (_poser(("gaps", 0, "evidence"), None), r"gaps\[0\]\.evidence : objet"),
        (
            _poser(("gaps", 0, "evidence", "observed_window_days"), -1),
            r"observed_window_days : nombre de jours",
        ),
        (
            _poser(("gaps", 0, "evidence", "required_window_days"), True),
            r"required_window_days : nombre de jours",
        ),
        (_poser(("results", 0), []), r"results\[0\] : objet attendu"),
        (_poser(("results", 0, "status"), "ok"), r"results\[0\]\.status"),
        (_poser(("results", 4, "reason"), "inconnu"), r"results\[4\]\.reason"),
        (_poser(("summary", "total"), -1), "summary.total : entier"),
        (_poser(("summary", "gaps"), True), "summary.gaps : entier"),
        (_retirer("summary"), "summary : champ manquant"),
        (
            _poser(("summary", "by_status"), {"pass": 1}),
            "summary.by_status.gap : champ manquant",
        ),
        (_poser(("tool",), []), "tool : objet attendu"),
        (_poser(("run", "complete"), "oui"), "run.complete : booléen"),
        (_poser(("targets", 0), "local"), r"targets\[0\] : objet attendu"),
        (_poser(("targets", 0, "id"), None), r"targets\[0\]\.id : chaîne"),
    ],
)
def test_rapport_invalide(
    modifier: Callable[[dict[str, Any]], None], message: str
) -> None:
    donnees = rapport()
    modifier(donnees)
    with pytest.raises(ReportError, match=message):
        read_report(donnees)


def test_valeur_fautive_jamais_recopiee() -> None:
    donnees = rapport()
    donnees["gaps"][0]["severity"] = "\x1b]0;titre\x07"
    with pytest.raises(ReportError) as exc:
        read_report(donnees)
    assert "\x1b" not in str(exc.value)
    assert "valeurs valides : critical, high" in str(exc.value)


def test_rapport_non_objet() -> None:
    with pytest.raises(ReportError, match="objet JSON"):
        read_report([])  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("contenu", "message"),
    [
        (b"{", r"JSON invalide \(ligne 1, colonne 2\)"),
        (b"[1, 2]", "objet JSON"),
        (b'{"x": NaN}', r"valeur non finie \(NaN\)"),
        (b'{"x": -Infinity}', "valeur non finie"),
        (b"\xff\xfe{}", "UTF-8"),
        (b"[" * 100_000, "JSON"),
        (b'{"x": ' + b"9" * 5000 + b"}", "nombre hors limites"),
    ],
    # ids courts : par defaut pytest derive l'id du contenu, et tmp_path en fait
    # un nom de dossier, trop long pour Windows avec 100 000 crochets
    ids=["tronque", "liste", "nan", "infini", "bom-utf16", "profondeur", "nombre"],
)
def test_load_report_illisible(tmp_path: Path, contenu: bytes, message: str) -> None:
    chemin = tmp_path / "rapport.json"
    chemin.write_bytes(contenu)
    with pytest.raises(ReportError, match=message):
        load_report(chemin)


def test_load_report_absent(tmp_path: Path) -> None:
    with pytest.raises(ReportError, match="lecture impossible"):
        load_report(tmp_path / "absent.json")


def test_load_report_bom(tmp_path: Path) -> None:
    chemin = tmp_path / "rapport.json"
    chemin.write_bytes(b"\xef\xbb\xbf" + FIXTURE.read_bytes())
    assert load_report(chemin) == rapport()


def test_cli_rapport_illisible(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["render", str(tmp_path / "absent.json")]) == CODE_RAPPORT_ILLISIBLE
    sortie = capsys.readouterr()
    assert sortie.out == ""
    assert "refusé : lecture impossible" in sortie.err


# --- API ------------------------------------------------------------------------


def test_registre_des_rendus() -> None:
    assert set(RENDERERS) == {"text", "md"}
    assert isinstance(RENDERERS["text"], TextRenderer)
    assert isinstance(RENDERERS["md"], MarkdownRenderer)
    with pytest.raises(ValueError, match="format de rendu inconnu"):
        render_report(rapport(), "html")


@pytest.mark.parametrize(
    ("options", "erreur"),
    [
        ({"group_by": "scenario"}, ValueError),
        ({"min_severity": "urgent"}, ValueError),
        ({"color": 1}, TypeError),
        ({"encoding": "inexistant-42"}, ValueError),
    ],
)
def test_options_invalides(options: dict[str, Any], erreur: type[Exception]) -> None:
    with pytest.raises(erreur):
        RenderOptions(**options)


def test_group_gaps_inconnu() -> None:
    with pytest.raises(ValueError, match="group_by inconnu"):
        group_gaps([], "scenario")


def test_aide_de_render(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["render", "--help"])
    assert exc.value.code == 0
    aide = capsys.readouterr().out
    for option in ("--format", "--group-by", "--min-severity", "--no-color"):
        assert option in aide
