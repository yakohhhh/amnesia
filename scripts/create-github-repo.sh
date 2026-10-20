#!/usr/bin/env bash
# Crée le repo GitHub et ouvre toutes les issues. Idempotent. Voir ../GO-LIVE.md
set -euo pipefail
cd "$(dirname "$0")/.."

REPO_NAME="${REPO_NAME:-amnesia}"
VISIBILITY="${VISIBILITY:-private}"
DESC="Audit de forensic readiness: ce que ton SI aura oublie le jour de l'incident"

command -v gh >/dev/null || { echo "gh manquant — voir GO-LIVE.md"; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "Pas connecte: lance 'gh auth login'"; exit 1; }

[ -d .git ] || git init -q
git add -A
git diff --cached --quiet 2>/dev/null || git commit -q -m "Initial scaffold" || true
git branch -M main 2>/dev/null || true

if gh repo view "$REPO_NAME" >/dev/null 2>&1; then
  echo "Repo $REPO_NAME existe deja — push."
  git remote get-url origin >/dev/null 2>&1 || gh repo set-default "$REPO_NAME" >/dev/null 2>&1 || true
  git push -u origin main 2>/dev/null || true
else
  gh repo create "$REPO_NAME" --"$VISIBILITY" --source=. --remote=origin --description "$DESC" --push
fi

SLUG="$(gh repo view "$REPO_NAME" --json nameWithOwner -q .nameWithOwner)"
echo "Repo: $SLUG"

label()     { gh label create "$1" --color "$2" --description "$3" --force >/dev/null 2>&1 || true; }
milestone() { gh api --silent -X POST "repos/$SLUG/milestones" -f title="$1" -f description="$2" >/dev/null 2>&1 || true; }
issue()     { gh issue create --title "$1" --label "$2" --milestone "$3" --body "$4" >/dev/null && echo "  issue: $1"; }

label "type:feature"     "1d76db" "Nouvelle fonctionnalite"
label "type:chore"       "fef2c0" "Outillage / maintenance"
label "type:docs"        "0075ca" "Documentation"
label "priority:high"    "d93f0b" "Prioritaire"
label "good first issue" "7057ff" "Bon point de depart"

milestone "M0 — Scaffold"            "Mise en place"
milestone "M1 — MVP (Windows + AD)"  "Checks endpoints + AD + rapport des angles morts"
milestone "M2 — Cloud"               "M365/Entra, CloudTrail, forwarding SIEM"
milestone "Backlog"                  "Plus tard"

issue "CI : ruff + pytest" "type:chore,good first issue" "M0 — Scaffold" "$(cat <<'I'
Pipeline GitHub Actions.

**Acceptance**
- [ ] `ruff check .` et `pytest` au push et en PR
- [ ] badge CI dans le README
I
)"

issue "Moteur de checks + agregation des Gaps" "type:feature" "M0 — Scaffold" "$(cat <<'I'
Executer les checks et collecter leurs angles morts.

**Acceptance**
- [ ] runner qui appelle `Check.run(target)` et agrege les `Gap`
- [ ] gestion des erreurs par check (un check qui plante n'arrete pas tout)
- [ ] tests du runner avec des checks factices
I
)"

issue "Rapport JSON + rendu questions sans reponse" "type:feature" "M0 — Scaffold" "$(cat <<'I'
Sorties machine et humaine.

**Acceptance**
- [ ] `amnesia-report.json` (gaps tries par severite)
- [ ] rendu texte/HTML qui formule chaque angle mort comme une question
I
)"

issue "Check politique d'audit avancee (Windows)" "type:feature,priority:high" "M1 — MVP (Windows + AD)" "$(cat <<'I'
Verifier l'advanced audit policy.

**Acceptance**
- [ ] lit la config d'audit (auditpol / GPO)
- [ ] `Gap` si logon / process creation / object access ne sont pas audites
I
)"

issue "Check Sysmon" "type:feature" "M1 — MVP (Windows + AD)" "$(cat <<'I'
Sysmon present et configure.

**Acceptance**
- [ ] detecte la presence du service + version
- [ ] signale l'absence de config ou une config vide
I
)"

issue "Check logging PowerShell" "type:feature" "M1 — MVP (Windows + AD)" "$(cat <<'I'
Script block + module logging.

**Acceptance**
- [ ] verifie les cles/GPO correspondantes
- [ ] `Gap` si desactive
I
)"

issue "Check taille/retention des journaux" "type:feature,priority:high" "M1 — MVP (Windows + AD)" "$(cat <<'I'
Surtout le journal Security (risque d'ecrasement rapide).

**Acceptance**
- [ ] lit la taille max et estime la fenetre de retention reelle
- [ ] `Gap` chiffre: "~N jours avant ecrasement"
I
)"

issue "Check NTP / time sync" "type:feature,good first issue" "M1 — MVP (Windows + AD)" "$(cat <<'I'
Coherence des horodatages.

**Acceptance**
- [ ] verifie la source de temps et le decalage
- [ ] `Gap` si non synchronise
I
)"

issue "Collecte distante via WinRM" "type:feature" "M1 — MVP (Windows + AD)" "$(cat <<'I'
Executer les checks sur un hote distant.

**Acceptance**
- [ ] connexion WinRM (auth + TLS)
- [ ] les checks Windows tournent a distance comme en local
I
)"

issue "Check retention Microsoft 365 / Entra ID" "type:feature" "M2 — Cloud" "$(cat <<'I'
Audit log et sign-in logs.

**Acceptance**
- [ ] via Microsoft Graph, verifie la retention effective
- [ ] `Gap` si la fenetre est trop courte pour une enquete
I
)"

issue "Check AWS CloudTrail" "type:feature" "M2 — Cloud" "$(cat <<'I'
CloudTrail active et exploitable.

**Acceptance**
- [ ] trail multi-region active, management + data events selon besoin
- [ ] retention du bucket verifiee
I
)"

issue "Check forwarding SIEM" "type:feature" "M2 — Cloud" "$(cat <<'I'
Les evenements partent-ils vraiment ?

**Acceptance**
- [ ] verifie qu'un flux est configure (agent / syslog / connecteur)
- [ ] `Gap` si une source cle n'est pas forwardee
I
)"

issue "Scoring de maturite + export PDF" "type:feature" "Backlog" "$(cat <<'I'
Pour livrer une mission d'audit.

**Acceptance**
- [ ] score par domaine (endpoint / AD / cloud)
- [ ] export PDF presentable a un client
I
)"

issue "Rapport client en marque blanche" "type:docs,type:feature" "Backlog" "$(cat <<'I'
Packaging "prestation".

**Acceptance**
- [ ] logo/nom configurables
- [ ] modele de rapport pret a envoyer
I
)"

echo "Termine. Issues ouvertes sur $SLUG."
