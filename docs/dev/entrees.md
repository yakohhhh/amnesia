# Fichiers importés : `amnesia.inputs`

amnesia lit des fichiers produits ailleurs : configuration Sysmon (XML), exports
et sauvegardes de GPO (`gpreport.xml`, `Backup.xml`, `Registry.pol`,
`audit.csv`), bundle de collecte hors ligne (#48, #52), fichier de mission
(#36). Ils viennent peut-être d'un SI compromis (hypothèse H4 du
[modèle de menace](../threat-model.md)) : ce sont des entrées hostiles, qui
visent le poste de l'auditeur (menaces M03 et M04).

**Tout format importé se lit par `amnesia.inputs`, et par lui seul.** Aucun
autre module de `src/amnesia/` n'importe `xml.*`, `zipfile` ni `tarfile`, ni
n'appelle `shutil.unpack_archive` : `tests/test_architecture.py` le vérifie.
Le module n'a aucune dépendance, ni interne ni tierce.

## Lire un fichier

| Format | Fichier | Octets déjà en mémoire | Rend |
|---|---|---|---|
| XML | `load_xml(chemin)` | `loads_xml(octets)` | l'élément racine (`XmlElement`) |
| JSON | `load_json(chemin)` | `loads_json(octets)` | la valeur |
| TOML | `load_toml(chemin)` | `loads_toml(octets)` | la table |
| CSV | `load_csv(chemin, columns=7)` | `loads_csv(octets, ...)` | les lignes, en-tête comprise |
| Registry.pol | `load_registry_pol(chemin)` | `loads_registry_pol(octets)` | des `PolEntry` |
| ZIP | `with extract_zip(chemin) as dossier:` | — | le dossier d'extraction |
| brut | `read_bytes(chemin)` | — | les octets, plafonnés |

Les variantes `loads_*` servent au contenu qui arrive par un transport (une
configuration Sysmon lue par WinRM est aussi hostile qu'un fichier).

```python
from amnesia.inputs import UnsafeInputError, XmlElement, extract_zip, load_xml


def lire_sysmon(bundle: Path) -> XmlElement | None:
    try:
        with extract_zip(bundle) as dossier:
            return load_xml(dossier / "sysmon" / "config.xml")
    except UnsafeInputError:
        return None  # le fait devient indisponible : voir « Erreurs »
```

Le dossier rendu par `extract_zip` est créé en 0700 (fichiers en 0600) dans le
dossier temporaire du système, et supprimé à la sortie du `with` : ce qui doit
survivre se lit avant.

## Ce qui est refusé

Communs à tous les formats :

- tout ce qui n'est pas un fichier ordinaire : FIFO, périphérique, dossier
  (contrôle fait sur le descripteur ouvert, sans bloquer) ;
- un fichier au-delà de `Limits.max_bytes` : refusé sans être lu si sa taille
  est annoncée, et au premier octet de trop sinon. La lecture est plafonnée en
  flux, pas par un seul `stat()` ;
- un encodage autre que l'UTF-8 (BOM toléré) ou l'UTF-16 avec BOM, celui que
  Windows PowerShell 5.1 écrit par défaut ; `load_csv(encoding="cp1252")`
  désigne la page de code d'un fichier ANSI, et un XML sans BOM peut déclarer
  `iso-8859-1` ou `windows-1252`.

| Format | Refus propres au format |
|---|---|
| XML | toute déclaration `DOCTYPE`, donc toute DTD, entité ou référence externe (XXE, *billion laughs*) ; UTF-16 sans BOM ; plus de `max_depth` niveaux, ou de `max_records` éléments et attributs (un attribut compte comme un élément) |
| ZIP | chemin absolu, `..`, lecteur ou flux Windows (`C:`, `fichier:flux`), nom de périphérique Windows (règle de `ntpath.isreserved` : `NUL .txt`, `COM¹`), caractère de contrôle, chemin de plus de `max_depth` composants ; lien symbolique et fichier spécial ; nom en double (casse et forme Unicode confondues) ; entrée chiffrée, compression autre que *stored* ou *deflate*, ZIP64, archive en plusieurs volumes, octets après la fin de répertoire, entrées superposées ; plus de `max_entries` fichiers et dossiers (entrées déclarées et dossiers intermédiaires qu'elles impliquent), de `max_bytes` par entrée, de `max_total_bytes` au total ou un ratio de compression supérieur à `max_ratio` |
| JSON | plus de `max_depth` niveaux (comptés avant l'analyse : jamais de `RecursionError`), clé en double, `NaN`, `Infinity` et tout nombre non fini (`1e999`), plus de `max_records` objets et tableaux |
| TOML | plus de `max_toml_bytes` octets (1 Mio, tenu avant l'analyse : `tomllib` construit tout le document, de l'ordre de cent fois la taille du texte, avant qu'un conteneur soit compté) ; plus de `max_depth` niveaux ou de `max_records` tables et tableaux ; `inf` et `nan` |
| CSV | champ de plus de `max_field_chars` caractères (`csv.field_size_limit`, posé puis remis en place), nombre de colonnes différent de `columns` ou de celui de la première ligne, plus de `max_columns` colonnes ou de `max_records` lignes |
| Registry.pol | signature autre que `PReg`, version autre que 1, entrée tronquée, longueur annoncée supérieure aux octets restants, plus de `max_records` entrées |

Une archive est contrôlée en entier avant la première écriture : une seule
entrée piégée fait refuser toute l'archive, et rien n'est extrait. Les plafonds
d'une archive portent sur les octets réellement décompressés ; les tailles
annoncées par les en-têtes, qui peuvent mentir, ne servent qu'à refuser plus
tôt.

Les plafonds par défaut sont larges (200 Mio par fichier). `max_records` borne
ce que l'analyse construit, pas la mémoire que l'analyseur occupe pendant
qu'il lit : expat remet tous les attributs d'un élément d'un seul coup, avant
que le module puisse les compter. Un appelant qui connaît son format passe
donc un `Limits(max_bytes=...)` serré : quelques Mio suffisent à une
configuration Sysmon ou à un `gpreport.xml`.

TAR n'est pas pris en charge. Il ne le sera que si le format de bundle (#52)
l'exige : avec `tarfile` et `filter="data"` (PEP 706), dans `amnesia.inputs`,
et en refusant l'extraction quand `hasattr(tarfile, "data_filter")` est faux.

Jamais de pickle, marshal, shelve, `eval` ni `exec` sur un fichier importé, et
YAML seulement par `yaml.safe_load` : les règles ruff S102, S202, S301, S302,
S307, S313 à S319 et S506 sont actives partout
(`tests/test_regles_ruff.py`).

## Plafonds

`Limits` porte les plafonds ; `DEFAULT_LIMITS` vaut pour tout appel qui n'en
passe pas.

| Champ | Défaut | Porte sur |
|---|---|---|
| `max_bytes` | 200 Mio | octets lus par fichier, et écrits par entrée d'archive |
| `max_records` | 1 000 000 | éléments et attributs XML, objets et tableaux JSON ou TOML, lignes CSV, entrées de Registry.pol |
| `max_depth` | 64 | imbrication XML, JSON, TOML ; composants du chemin d'une entrée d'archive |
| `max_columns` | 256 | colonnes d'une ligne CSV |
| `max_field_chars` | 131 072 | caractères d'un champ CSV |
| `max_entries` | 10 000 | fichiers et dossiers créés par une archive : entrées déclarées et dossiers intermédiaires que leurs chemins impliquent |
| `max_total_bytes` | 1 Gio | octets décompressés par archive |
| `max_ratio` | 100 | octets décompressés par octet d'archive, au-delà de 1 Mio |
| `max_toml_bytes` | 1 Mio | octets d'un document TOML, en plus de `max_bytes` |

Un format plus petit se lit avec des plafonds plus serrés :

```python
from amnesia.inputs import Limits, load_json

MANIFESTE = Limits(max_bytes=1024 * 1024, max_depth=8)
manifeste = load_json(chemin, limits=MANIFESTE)
```

## Erreurs

Tout refus lève `UnsafeInputError` (une `ValueError`), y compris un fichier
absent ou illisible : l'appelant n'a qu'une exception à traiter.

- `code` est le motif (`Rejection` : `too_large`, `too_deep`, `forbidden`,
  `unsafe_path`, `link`, `duplicate`, `malformed`...), stable ; `message` est un
  texte français affichable.
- **Le message ne reproduit jamais le contenu du fichier** : ni texte, ni nom
  d'entrée d'archive, ni message d'un analyseur, ni chemin. Il ne porte qu'un
  motif, des positions (ligne, colonne, numéro d'entrée) et des plafonds.
  L'exception ne chaîne aucune autre exception : celle d'un analyseur peut
  porter le document entier.
- **Un fichier refusé n'est jamais « conforme »** : le collecteur qui importe le
  fichier rend le fait correspondant indisponible
  (`Fact.unavailable(..., UnavailableReason.NOT_COLLECTED)`), et `resolve()` en
  fait un résultat `skipped` / `not_collected`. Une `UnsafeInputError` qui
  parviendrait quand même au moteur reçoit le même résultat, sans trace
  d'exécution, même avec `--debug`.

Le contenu accepté reste une donnée hostile : un texte lu dans un fichier
importé est neutralisé avant d'entrer dans un résultat (`assainir`) et échappé
à l'affichage (#45), comme toute valeur venue d'une cible.
