# Fixtures de test

Données d'entrée des tests (exports `auditpol`, journaux, réponses Graph...),
rangées par source : `tests/fixtures/windows/`, `tests/fixtures/cloud/`...
`tests/fixtures/hostile/` regroupe les charges hostiles (séquences ANSI et OSC,
HTML, formules de tableur, liens, chaînes de 1 Mo) que chaque rendu doit
neutraliser (#45).

- Uniquement des données synthétiques ou anonymisées : aucun nom d'hôte, compte,
  GUID de tenant ou secret réel.
- Les fichiers sont conservés tels quels (encodage, fins de ligne) : les hooks de
  mise en forme ne touchent pas à ce répertoire.
- `tests/fixtures/ps/` : scripts PowerShell fictifs, jamais exécutés, dont
  l'AST est analysé par `tests/integration/test_scripts_powershell.py` ; tous
  sauf `lecture_conforme.ps1` doivent être refusés, parce qu'ils écrivent sur
  la cible ou parce qu'ils en font sortir le contenu d'un événement.
- `tests/fixtures/facts/evenement_4624.json` : événement 4624 fictif (compte,
  adresse IP et poste inventés), que la collecte doit refuser en entier.
- Les exports bruts vont dans un sous-répertoire `raw/`, ignoré par git et refusé
  par les hooks : ils ne sont jamais commités.
