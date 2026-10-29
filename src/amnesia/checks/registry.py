"""Registre des checks : classes enregistrées, métadonnées validées, ids uniques.

Un check est une sous-classe de ``Check`` décorée par ``@register``. Le registre
garde la **classe**, jamais une instance : ``create_all()`` instancie des checks
neufs à chaque audit, si bien qu'aucun état stocké sur une instance ne passe
d'un audit à l'autre.

Les métadonnées sont validées dès l'enregistrement, donc à l'import du module :
un check mal déclaré casse ``amnesia list-checks`` et la suite de tests, pas un
audit chez un client.

Ids
---
L'id est un contrat public (rapports, sélection #74, exceptions #143, diff
#142) : il ne change pas sans raison, et jamais en silence.

- forme ``domaine.nom`` : ``^[a-z][a-z0-9]*(\\.[a-z0-9_]+)+$`` ;
- préfixe imposé par le domaine : ``win.``, ``ad.``, ``m365.``, ``aws.``,
  ``siem.`` ;
- unicité : un second check déclarant un id déjà pris lève
  ``DuplicateCheckError``, qui nomme les deux classes et leurs modules. Seule
  exception : une classe de même module et même nom qualifié remplace
  l'ancienne, car c'est la même déclaration réimportée (nouvel essai après un
  import en échec, ``importlib.reload``).

Chargement
----------
Paresseux : importer ``amnesia.checks`` ne charge aucun check. Le registre
importe, au premier besoin, chaque paquet de domaine (``checks/windows/``,
``checks/ad/``...) et tous ses modules, un module par check. Un module de check
n'importe aucun SDK à son niveau (boto3, Graph, WinRM...) : les SDK relèvent des
collecteurs (#20, #44), et ``list-checks`` doit fonctionner sans les extras.

Chaque registre recueille les checks des modules qu'il charge : pendant
l'import, ``@register`` enregistre dans le registre qui charge, et un module
déjà importé est relu (classes décorées qu'il définit). Un module de check qui
ne déclare aucun check lève ``CheckRegistrationError`` : un ``@register`` oublié
ferait sinon disparaître un contrôle du rapport sans le moindre bruit.

Exemple :

>>> from amnesia.checks import Check, Domain, Registry
>>> from amnesia.target import Kind
>>> class Exemple(Check):
...     id = "win.exemple"
...     title = "Check d'exemple"
...     description = "Illustre la déclaration d'un check."
...     domain = Domain.WINDOWS
...     target_kinds = (Kind.WINDOWS_HOST,)
...     version = 1
...     default_severity = "low"
>>> registre = Registry()
>>> registre.register(Exemple) is Exemple
True
>>> [(m.id, m.domain.value, m.implemented) for m in registre.metas()]
[('win.exemple', 'windows', False)]
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
import re
import weakref
from collections.abc import Iterable
from contextvars import ContextVar
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, NoReturn, TypeVar

from ..target import Kind
from .base import Check

logger = logging.getLogger(__name__)


class Domain(StrEnum):
    """Domaine d'un check ; étendu par les cibles cloud (#95)."""

    WINDOWS = "windows"
    AD = "ad"
    M365 = "m365"
    AWS = "aws"
    SIEM = "siem"

    @property
    def prefix(self) -> str:
        """Premier segment imposé aux ids des checks de ce domaine."""
        return _PREFIXE_DU_DOMAINE[self]


_PREFIXE_DU_DOMAINE: dict[Domain, str] = {
    Domain.WINDOWS: "win",
    Domain.AD: "ad",
    Domain.M365: "m365",
    Domain.AWS: "aws",
    Domain.SIEM: "siem",
}

# niveaux de Severity (#16), du plus grave au moins grave ; default_severity
# passera a cet enum quand il existera
SEVERITES = ("critical", "high", "medium", "low", "info")

# fullmatch et non match : « $ » accepterait un saut de ligne final
_FORMAT_ID = re.compile(r"[a-z][a-z0-9]*(?:\.[a-z0-9_]+)+")

# methode d'evaluation dont la surcharge rend un check « implemente » (evaluate
# avec #20)
_METHODE_EVALUATION = "run"

# paquets de domaine charges par le registre par defaut ; un nouveau domaine
# (checks/m365/, #95) s'ajoute ici, et un test verifie qu'aucun n'est oublie
PAQUETS = ("amnesia.checks.windows", "amnesia.checks.ad")


class CheckRegistrationError(ValueError):
    """Check refusé à l'enregistrement."""


class InvalidCheckError(CheckRegistrationError):
    """Métadonnées absentes ou invalides (id, domaine, titre...)."""


class DuplicateCheckError(CheckRegistrationError):
    """Deux classes de checks déclarent le même id."""


def _nom(cls: type) -> str:
    return f"{cls.__module__}.{cls.__qualname__}"


@dataclass(frozen=True, slots=True)
class CheckMeta:
    """Métadonnées validées d'un check, figées à l'enregistrement.

    ``implemented`` est dérivé : vrai si la classe surcharge la méthode
    d'évaluation. ``module`` et ``class_name`` situent la déclaration.
    """

    id: str
    title: str
    description: str
    domain: Domain
    target_kinds: tuple[Kind, ...]
    version: int
    default_severity: str
    requires_facts: tuple[str, ...]
    question_ids: tuple[str, ...]
    implemented: bool
    module: str
    class_name: str

    @classmethod
    def from_class(cls, check: type[Check]) -> CheckMeta:
        """Lit et valide les attributs de classe ; lève InvalidCheckError."""
        if not (isinstance(check, type) and issubclass(check, Check)):
            raise InvalidCheckError(f"{check!r} n'est pas une sous-classe de Check")
        lecteur = _Lecteur(check)
        domain = lecteur.attribut("domain", Domain, "un Domain")
        check_id = lecteur.attribut("id", str, "une chaîne")
        if not _FORMAT_ID.fullmatch(check_id):
            lecteur.refuser(
                f"id {check_id!r} invalide (attendu : domaine.nom en minuscules, "
                "par ex. win.audit_policy)"
            )
        prefixe = check_id.split(".", 1)[0]
        if prefixe != domain.prefix:
            lecteur.refuser(
                f"id {check_id!r} incohérent avec le domaine {domain.value} "
                f"(préfixe attendu : {domain.prefix}.)"
            )
        version = lecteur.attribut("version", int, "un entier")
        if isinstance(version, bool) or version < 1:
            lecteur.refuser(f"version invalide : {version!r} (entier >= 1 attendu)")
        severite = lecteur.attribut("default_severity", str, "une chaîne")
        if severite not in SEVERITES:
            lecteur.refuser(
                f"default_severity invalide : {severite!r} "
                f"(attendu : {', '.join(SEVERITES)})"
            )
        target_kinds = lecteur.uplet("target_kinds", Kind, vide_permis=False)
        evaluation = getattr(check, _METHODE_EVALUATION)
        return cls(
            id=check_id,
            title=lecteur.texte("title"),
            description=lecteur.texte("description"),
            domain=domain,
            target_kinds=target_kinds,
            version=version,
            default_severity=severite,
            requires_facts=lecteur.uplet("requires_facts", str),
            question_ids=lecteur.uplet("question_ids", str),
            implemented=evaluation is not getattr(Check, _METHODE_EVALUATION),
            module=check.__module__,
            class_name=check.__qualname__,
        )


class _Lecteur:
    """Lecture typée des attributs d'une classe de check, avec messages situés."""

    def __init__(self, check: type[Check]) -> None:
        self.check = check

    def refuser(self, motif: str) -> NoReturn:
        raise InvalidCheckError(f"check {_nom(self.check)} : {motif}")

    def attribut(self, nom: str, attendu: type[Any], libelle: str) -> Any:
        if not hasattr(self.check, nom):
            self.refuser(f"attribut {nom} manquant")
        valeur = getattr(self.check, nom)
        if not isinstance(valeur, attendu):
            self.refuser(f"{nom} doit être {libelle} : {valeur!r}")
        return valeur

    def texte(self, nom: str) -> str:
        valeur: str = self.attribut(nom, str, "une chaîne")
        # rendu tel quel dans le terminal et le rapport : ni ANSI, ni saut de ligne
        if not valeur.strip() or not valeur.isprintable():
            self.refuser(f"{nom} vide ou non imprimable : {valeur!r}")
        return valeur

    def uplet(
        self, nom: str, attendu: type[Any], *, vide_permis: bool = True
    ) -> tuple[Any, ...]:
        # un tuple, pas une chaine : « abc » serait lu caractere par caractere
        valeur: tuple[Any, ...] = self.attribut(nom, tuple, "un tuple")
        if not valeur and not vide_permis:
            self.refuser(f"{nom} ne doit pas être vide")
        for element in valeur:
            if not isinstance(element, attendu) or element == "":
                self.refuser(f"{nom} : élément invalide {element!r}")
        if len(set(valeur)) != len(valeur):
            self.refuser(f"{nom} : doublon dans {valeur!r}")
        return valeur


_C = TypeVar("_C", bound=type[Check])


class Registry:
    """Classes de checks par id, chargées paresseusement depuis leurs paquets."""

    def __init__(self, packages: Iterable[str] = ()) -> None:
        self._paquets = tuple(packages)
        self._classes: dict[str, type[Check]] = {}
        self._metas: dict[str, CheckMeta] = {}
        self._charge = False

    @property
    def packages(self) -> tuple[str, ...]:
        """Paquets de domaine importés au chargement."""
        return self._paquets

    def register(self, check: _C) -> _C:
        """Valide puis enregistre une classe ; utilisable en décorateur.

        Rien n'est enregistré si la validation échoue. Réenregistrer la même
        classe est sans effet ; une classe de même module et même nom qualifié
        remplace l'ancienne (même déclaration réimportée).
        """
        meta = CheckMeta.from_class(check)
        deja = self._classes.get(meta.id)
        if deja is check:
            return check
        if deja is not None and _nom(deja) != _nom(check):
            raise DuplicateCheckError(
                f"id {meta.id!r} déclaré deux fois : classe {deja.__qualname__} "
                f"du module {deja.__module__}, et classe {check.__qualname__} "
                f"du module {check.__module__}"
            )
        self._classes[meta.id] = check
        self._metas[meta.id] = meta
        return check

    def load(self) -> None:
        """Importe chaque paquet de domaine et ses modules (une seule fois)."""
        if self._charge:
            return
        for nom in self._paquets:
            paquet = importlib.import_module(nom)
            # ordre trie : enregistrement reproductible d'une machine a l'autre
            modules = sorted(m.name for m in pkgutil.iter_modules(paquet.__path__))
            for module in modules:
                self._charger_module(f"{nom}.{module}")
        self._charge = True
        logger.debug("registre : %d check(s) chargé(s)", len(self._classes))

    def _charger_module(self, nom: str) -> None:
        """Importe un module de check et enregistre ici les checks qu'il déclare."""
        # pendant l'import, @register ecrit dans ce registre et non dans REGISTRY
        jeton = _REGISTRE_EN_CHARGEMENT.set(self)
        try:
            module = importlib.import_module(nom)
        finally:
            _REGISTRE_EN_CHARGEMENT.reset(jeton)
        # module deja importe (par un autre registre ou un import direct) : le
        # decorateur ne repasse pas, on relit les classes qu'il a marquees ;
        # une classe seulement importee par le module n'en fait pas partie
        declarees = [
            objet
            for objet in vars(module).values()
            if isinstance(objet, type)
            and issubclass(objet, Check)
            and objet in _DECLAREES
            and objet.__module__ == nom
        ]
        if not declarees:
            raise CheckRegistrationError(
                f"module {nom} : aucun check déclaré (décorateur @register oublié ?)"
            )
        for check in declarees:
            self.register(check)

    def classes(self) -> list[type[Check]]:
        """Classes enregistrées, triées par id."""
        self.load()
        return [self._classes[i] for i in sorted(self._classes)]

    def metas(self) -> list[CheckMeta]:
        """Métadonnées des checks enregistrés, triées par id."""
        self.load()
        return [self._metas[i] for i in sorted(self._metas)]

    def create_all(self) -> list[Check]:
        """Une instance neuve de chaque check, triée par id."""
        return [cls() for cls in self.classes()]


REGISTRY = Registry(PAQUETS)

# registre qui importe un module de check (Registry.load), sinon None
_REGISTRE_EN_CHARGEMENT: ContextVar[Registry | None] = ContextVar(
    "_REGISTRE_EN_CHARGEMENT", default=None
)

# classes passees par @register : Registry.load les retrouve dans un module deja
# importe ; references faibles, pour ne pas retenir une classe abandonnee
_DECLAREES: weakref.WeakSet[type[Check]] = weakref.WeakSet()


def register(check: _C) -> _C:
    """Décorateur : enregistre la classe dans le registre qui charge son module.

    Hors chargement (import direct du module), c'est le registre par défaut.
    """
    registre = _REGISTRE_EN_CHARGEMENT.get()
    (REGISTRY if registre is None else registre).register(check)
    _DECLAREES.add(check)
    return check
