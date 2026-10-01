# Récapitulatif final — Syslog AI Analyzer & Diagnostic LLM

## Contexte

Projet appliqué pour un opérateur télécom d'envergure, en 2 sous-projets liés :
- **Projet 1** — Classification automatique des logs syslog
- **Projet 2** — Diagnostic assisté par LLM des incidents détectés

**Problématique** : automatiser la détection et l'interprétation des événements critiques dans les logs système, pour réduire le temps de diagnostic des équipes techniques.

**Statut** : les deux projets sont terminés, fonctionnels, et **validés sur de vrais logs télécom de production** (137 lignes réelles).

---

## PROJET 1 — Classification syslog

### Pipeline

```
Génération → Parsing → Nettoyage → Classification (×3) → Restitution
```

| Étape | Script | Rôle |
|---|---|---|
| Génération | `generate_dataset.py`, `live_log_generator.py` | Crée des logs Cisco de test (2000 pour l'entraînement, flux temps réel pour les tests) |
| Parsing | `syslog_parser.py` | Découpe chaque ligne en champs, 3 formats gérés (Cisco IOS, RFC 5424, RFC 3164/BSD, + variante sans hostname) |
| Nettoyage | `clean_data.py` | 6 vérifications qualité sur le dataset d'entraînement |
| Classification | `train_severity_classifier.py`, `train_category_classifier.py`, `train_anomaly_classifier.py` | 3 modèles ML (TF-IDF + régression logistique) |
| Restitution | `run_project1_pipeline.py`, `analyze_live_logs.py`, `app.py` | Tableaux, graphiques, dashboard |

### Innovation clé : résolution hybride

**Problème découvert** en confrontant le système à un vrai log de production (`%BGP-4-VPN_NH_IF`) : le modèle ML devinait une sévérité déjà écrite dans le log lui-même, et se trompait.

**Solution** : au lieu de toujours faire deviner par le modèle, le système lit d'abord l'information dans le log quand elle existe (déterministe, fiable à 100%), et ne fait appel au ML qu'en son absence.

```
Sévérité présente dans le header  →  la lire directement
Facility connue (BGP, LINK...)     →  en déduire la catégorie
Sinon                               →  modèle ML en secours
```

### Résultats

| Test | Sévérité | Catégorie | Anomalie |
|---|---|---|---|
| Jeu de test interne (données synthétiques) | 99,3% | 99,8% | recall 99,5% |
| Logs live avec 30% d'erreurs injectées | 92-95% | — | — |
| **137 vrais logs télécom de production (approche hybride)** | **100%** | **100%** | — |
| 137 vrais logs télécom de production (ML seul, avant correction) | 82% | 92% | — |

La correction hybride évite 18% d'erreurs de sévérité et 8% d'erreurs de catégorie sur données réelles.

---

## PROJET 2 — Diagnostic par LLM

### Pipeline

```
Logs classifiés → Regroupement en incidents → Prompt enrichi → LLM local → Diagnostic
```

| Étape | Script | Rôle |
|---|---|---|
| Regroupement | `incident_grouper.py` | Rassemble les logs liés (fenêtre temporelle, entité commune, rafales cross-entité) en incidents |
| Analyse | `llm_analyzer.py` | Construit le prompt, interroge Mistral via Ollama, structure la réponse |

### Choix technique : LLM local

**Mistral 7B via Ollama**, exécuté entièrement sur la machine — aucune donnée réseau ne quitte l'infrastructure. Décision cohérente avec la sensibilité des logs télécom (topologie, adressage interne).

### Le regroupement en incidents

Trois mécanismes combinés :
1. **Fenêtre temporelle + même entité** — regroupement de base
2. **Consolidation des rafales** — des logs proches dans le temps mais avec des identifiants différents (interface, IP, mnémonique) sont fusionnés s'ils appartiennent à la même cascade d'événements
3. **Consolidation des récurrents** — un même type d'événement répété sur des entités différentes devient un seul incident récurrent

**Bug corrigé** : une cascade BFD→BGP (8 logs sur 8 secondes) référençant tantôt un voisin IPv6, tantôt une interface, tantôt aucun identifiant, était éclatée en 5 incidents distincts. Corrigé par une passe de consolidation par proximité temporelle, indépendante de l'entité.

Sur 137 vrais logs de production : **12 incidents avant correction → 4 incidents cohérents après**.

### Enrichissement du prompt

Base de connaissances de 18 mnémoniques Cisco (signification + causes typiques), injectée dans le prompt selon les mnémoniques réellement présents dans l'incident.

**Effet mesuré** :

| | Sans base de connaissances | Avec base de connaissances |
|---|---|---|
| Cause probable | "problème de communication ou de configuration" | "défaut physique — câble, SFP, atténuation optique" |
| Action | "vérifier la configuration" | "vérifier câble, connecteur, module SFP, atténuation" |
| Priorité (cas VPN_NH_IF) | haute (incorrect) | moyenne (correct — c'est un choix de conception, pas une panne) |

### Résultat sur les vrais logs de production télécom

```
137 logs → 4 incidents → diagnostic rédigé pour les plus graves
```

Exemple (incident de flapping GigabitEthernet0/23) :
> **Diagnostic** : L'interface présente des changements d'état répétés et des pertes d'adjacence ISIS.
> **Cause probable** : Instabilité du lien — défaut physique, atténuation ou puissance optique hors seuil.
> **Priorité** : haute
> **Action** : Vérifier le câble, le connecteur et le module optique SFP.

---

## Le dashboard (app.py) — 5 onglets

| Onglet | Contenu |
|---|---|
| 🎛️ Supervision en direct | Génération de logs, KPI, jauge de santé réseau, statut système animé, flux terminal filtrable, graphiques, carte réseau |
| 📝 Analyse manuelle | Coller/importer des logs, classification + analyse statistique approfondie (palmarès équipements, croisement catégorie×sévérité, détection de rafales) |
| 🧠 Diagnostic IA | Regroupement en incidents + diagnostic Mistral, avec avertissement sur les limites du LLM |
| 📈 Performance des modèles | Les 3 matrices de confusion |
| 🧭 Architecture du pipeline | Vue d'ensemble visuelle des 5 étapes |

Thème visuel sobre et professionnel (bleu marine/gris), seuil de détection d'anomalie ajustable, filtres, export Excel.

---

## Qualité et tests

**48 tests automatisés** (pytest), tous passants :

| Fichier | Tests | Couvre |
|---|---|---|
| `test_syslog_parser.py` | 27 | Les 4 formats, résolution hybride, robustesse |
| `test_incident_grouper.py` | 12 | Extraction d'entité, regroupement, flapping, **non-régression du bug de fragmentation** |
| `test_clean_data.py` | 9 | Doublons, validation, normalisation |

---

## Structure du projet

```
syslog-ai-analyzer/
├── data/
│   ├── raw/                          dataset brut (2000 logs)
│   └── processed/                     dataset nettoyé
├── src/
│   ├── .streamlit/config.toml
│   ├── app.py                         dashboard (5 onglets)
│   ├── syslog_parser.py               parsing + résolution hybride
│   ├── clean_data.py
│   ├── generate_dataset.py
│   ├── live_log_generator.py
│   ├── train_severity_classifier.py
│   ├── train_category_classifier.py
│   ├── train_anomaly_classifier.py
│   ├── incident_grouper.py            Projet 2 — regroupement
│   ├── llm_analyzer.py                Projet 2 — diagnostic LLM
│   ├── run_project1_pipeline.py
│   ├── analyze_live_logs.py
│   ├── test_*.py                      48 tests
│   └── TESTS.md
├── models/                             3 modèles .joblib
├── outputs/                             3 matrices de confusion
└── requirements.txt
```

---

## Outils utilisés

| Catégorie | Outils |
|---|---|
| Langage | Python 3.13 |
| Données | pandas, openpyxl |
| Machine Learning | scikit-learn (TF-IDF + régression logistique), joblib |
| LLM | Ollama, Mistral 7B (local) |
| Visualisation | matplotlib, plotly |
| Interface | Streamlit |
| Tests | pytest |
| Environnement | venv, VS Code |

---

## Limites connues

1. **Dataset d'entraînement synthétique** — les scores ~99% en interne reflètent la structure du générateur. La validation sur 137 vrais logs reste le test le plus fiable, mais le volume est limité.
2. **Un seul vendeur** — Cisco uniquement. L'architecture est extensible (parsers additionnels, table de correspondance facility→catégorie) mais non implémentée pour d'autres vendeurs.
3. **`is_anomaly` peu indépendant** de la sévérité par construction. Le seuil ajustable atténue le problème côté usage.
4. **Regroupement en incidents** — heuristique (fenêtre temporelle, entité, catégorie), pas une vraie corrélation causale. Fonctionne bien sur les cas observés, mais pourrait manquer des liens plus subtils entre incidents éloignés dans le temps.
5. **LLM local, qualité 7B** — corrects sur les cas testés une fois le prompt enrichi, mais peut rester approximatif sur des incidents inédits. D'où l'avertissement affiché à chaque diagnostic.

---

## Perspectives

- Étendre la base de connaissances Cisco et le parser à d'autres vendeurs (Huawei, Nokia)
- Persistance des résultats et vue de tendance (24h/7j) de l'indice de santé
- Boucle de feedback humain sur les diagnostics LLM (validation/correction), en vue d'un futur ré-entraînement
- Volume plus important de logs de production réels pour une validation statistique plus solide
- Alerting actif (email, Slack) au-delà de l'affichage dans le dashboard