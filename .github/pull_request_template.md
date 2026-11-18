<!--
Contexte en une phrase : ce que la PR change et pourquoi.
Dépôt public : aucune donnée client (nom d'hôte, domaine, IP, identifiant de
tenant, rapport, collecte) dans la PR, ses commits ni ses fichiers.
Une faille de sécurité se signale en privé (SECURITY.md), jamais dans une PR.
-->

## Changements

-

## Vérifications

| Cas | Résultat |
|---|---|
| `uv run nox -s lint typecheck tests` | |

## Checklist

- [ ] Issue liée : une seule par PR, avec « Closes #<numéro> » en fin de description.
- [ ] Tests ajoutés ou mis à jour (`tests/unit/` pour le code d'amnesia), annotés pour `mypy --strict`.
- [ ] Fixtures anonymisées : aucun nom d'hôte, domaine, IP, compte ni identifiant de tenant réel (`tests/fixtures/README.md`).
- [ ] CHANGELOG : entrée dans « [Unreleased] » si un utilisateur ou un intégrateur voit le changement (`docs/RELEASING.md`).
- [ ] Documentation à jour (README, `docs/`, docstrings).
- [ ] Lecture seule respectée : rien n'est écrit ni modifié sur la cible auditée.
- [ ] Modèle de menace (`docs/threat-model.md`) mis à jour en cas de nouveau transport ou connecteur.
- [ ] ADR : Cette PR nécessite-t-elle un ADR ? Oui si elle change une frontière entre modules, un transport, un format ou une garantie de sécurité (`docs/adr/README.md`) : l'ADR est dans la PR, ou son numéro est cité.

Closes #
