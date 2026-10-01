# Syslog AI Analyzer — Classification Syslog & Diagnostic LLM pour NOC Télécom

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Streamlit-1.30%2B-FF4B4B.svg)](https://streamlit.io/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.3%2B-F7931E.svg)](https://scikit-learn.org/)
[![LLM](https://img.shields.io/badge/Ollama-Mistral%20%2F%20Llama-black.svg)](https://ollama.com/)

Plateforme de traitement intelligent et de corrélation d'événements réseau pour centres d'opérations télécom (NOC).

Le projet s'articule en deux sous-systèmes complémentaires :
- **Projet 1** — **Classification multi-niveaux des logs syslog** (parsing multi-format, nettoyage de données, classification hybride règle + ML pour sévérité, catégorie et anomalie).
- **Projet 2** — **Corrélation d'incidents & diagnostic LLM local** (détection de flapping, regroupement d'incidents temporels, diagnostic automatique et recommandations d'actions NOC via Ollama).

---

## Architecture du Pipeline

```
Flux Syslog (RFC 5424, RFC 3164, Cisco IOS)
    │
    ▼
[ syslog_parser.py ] ─── Parsing & Résolution Hybride (Règles + Machine Learning)
    │
    ├── 1. Sévérité (Critical, Error, Warning, Info)
    ├── 2. Catégorie (Routing, Interface, Security, Hardware, System, etc.)
    └── 3. Détection d'anomalies
    │
    ▼
[ incident_grouper.py ] ─── Corrélation temporelle, extraction d'entités & Flapping
    │
    ▼
[ llm_analyzer.py ] ────── Diagnostic assisté par LLM local (Ollama / Mistral)
    │
    ▼
[ app.py ] ────────────── Dashboard interactif de supervision NOC (Streamlit)
```

---

## Structure du Répertoire

```
syslog-ai-analyzer/
├── data/
│   ├── raw/               # Datasets bruts
│   ├── processed/         # Datasets nettoyés prêts pour le ML
│   └── cleaning_report.txt# Rapport d'audit qualité des données
├── src/                   # Code source de la solution
│   ├── syslog_parser.py   # Parser multi-format & moteur hybride
│   ├── incident_grouper.py# Corrélation d'incidents & détection de flapping
│   ├── llm_analyzer.py    # Diagnostic automatisé via LLM local (Ollama)
│   ├── app.py             # Dashboard complet Streamlit
│   ├── clean_data.py      # Pipeline de nettoyage
│   ├── train_*.py         # Entraînement des classifieurs ML (sévérité, catégorie, anomalie)
│   └── test_*.py          # Suite de tests automatisés pytest
├── models/                # Modèles entraînés (.joblib)
├── outputs/               # Matrices de confusion et rapports
├── recap final.md         # Synthèse détaillée des résultats et performances
└── requirements.txt       # Dépendances Python
```

---

## Installation & Démarrage Rapide

### 1. Prérequis
- Python 3.10+
- *(Optionnel pour le module LLM)* : [Ollama](https://ollama.com) avec le modèle `mistral` (`ollama pull mistral`)

### 2. Installation
```bash
git clone https://github.com/Rayanelo17/syslog-ai-analyzer.git
cd syslog-ai-analyzer
pip install -r requirements.txt
```

### 3. Lancer l'interface NOC
```bash
cd src
streamlit run app.py
```

---

## Performances & Résultats Clés

Le système intègre un **moteur de résolution hybride** : il extrait prioritairement les informations explicites contenues dans les en-têtes normalisés et délègue au Machine Learning (TF-IDF + Régression Logistique) le traitement des messages non standardisés.

| Jeu de test | Sévérité | Catégorie | Anomalie (Recall) |
|---|---|---|---|
| **Logs de test internes** | **99,3%** | **99,8%** | **99,5%** |
| **Logs avec bruit & erreurs injectées (30%)** | **92 - 95%** | — | — |
| **Logs réels de production réseau (Hybride)** | **100%** | **100%** | — |

---

## Tests & Validation

Pour exécuter la suite de tests automatisée (parsing, non-régression IPv6, logique de regroupement d'incidents) :

```bash
cd src
pytest
```
