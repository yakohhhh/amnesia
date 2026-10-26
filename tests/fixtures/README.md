# Fixtures de test

Données d'entrée des tests (exports `auditpol`, journaux, réponses Graph...),
rangées par source : `tests/fixtures/windows/`, `tests/fixtures/cloud/`...

- Uniquement des données synthétiques ou anonymisées : aucun nom d'hôte, compte,
  GUID de tenant ou secret réel.
- Les fichiers sont conservés tels quels (encodage, fins de ligne) : les hooks de
  mise en forme ne touchent pas à ce répertoire.
- Les exports bruts vont dans un sous-répertoire `raw/`, ignoré par git et refusé
  par les hooks : ils ne sont jamais commités.
