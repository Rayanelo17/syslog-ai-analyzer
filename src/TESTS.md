# Tests automatisés

Ce dossier contient 48 tests couvrant le parsing, le nettoyage et le
regroupement en incidents. Ils permettent de vérifier rapidement que le
pipeline fonctionne toujours correctement après une modification.

## Installation

```bash
pip install pytest
```

## Lancer tous les tests

```bash
cd src
pytest -v
```

## Lancer un seul fichier

```bash
pytest test_syslog_parser.py -v
pytest test_incident_grouper.py -v
pytest test_clean_data.py -v
```

## Ce qui est couvert

| Fichier | Ce qu'il vérifie |
|---|---|
| `test_syslog_parser.py` | Reconnaissance des 3 formats syslog, résolution hybride sévérité/catégorie, robustesse (rien n'est perdu) |
| `test_incident_grouper.py` | Extraction d'entité (interface, IPv4, IPv6), regroupement temporel, détection de flapping, **non-régression du bug de fragmentation des rafales IPv6** |
| `test_clean_data.py` | Doublons, valeurs invalides, normalisation du texte, messages suspects |

## Pourquoi ces tests existent

Plusieurs bugs réels ont été trouvés en confrontant le système à de vrais
logs réels de production (sévérité mal devinée, catégorie erronée, rafale d'événements
éclatée en plusieurs incidents). Ces tests figent le comportement correct
une fois corrigé, pour qu'une modification future ne réintroduise pas
silencieusement la même erreur.