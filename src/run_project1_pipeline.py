"""
Exécution complète du Projet 1 (démonstration bout-en-bout).

Enchaîne toutes les étapes sur un nouveau lot de logs jamais vus :
    1. Génération de logs bruts
    2. Parsing (extraction des champs)
    3. Classification : sévérité, catégorie, anomalie
    4. Résumé final

Usage :
    python run_project1_pipeline.py --count 30
"""

import argparse
import random
import pandas as pd
import joblib
from syslog_parser import parse_log

# Réutilise les mêmes templates que live_log_generator.py
from live_log_generator import generate_one_log


def generate_batch(n):
    print(f"[1/4] Génération de {n} nouveaux logs...")
    logs = [generate_one_log() for _ in range(n)]
    for l in logs[:3]:
        print(f"      {l}")
    if n > 3:
        print(f"      ... et {n - 3} autres")
    return logs


def parse_batch(logs):
    print(f"\n[2/4] Parsing des {len(logs)} logs...")
    records = [parse_log(l) for l in logs]
    df = pd.DataFrame(records)
    formats = df["format_detected"].value_counts()
    print(f"      Formats détectés : {dict(formats)}")
    return df


def classify_batch(df):
    print(f"\n[3/4] Classification (sévérité, catégorie, anomalie)...")

    severity_model = joblib.load("../models/severity_classifier.joblib")
    category_model = joblib.load("../models/category_classifier.joblib")
    anomaly_model = joblib.load("../models/anomaly_classifier.joblib")

    df["pred_severity"] = severity_model.predict(df["message"])
    df["pred_category"] = category_model.predict(df["message"])
    df["pred_anomaly"] = anomaly_model.predict(df["message"])

    print("      Modèles appliqués avec succès.")
    return df


def summarize(df):
    print(f"\n[4/4] Résumé de l'exécution")
    print("=" * 60)
    print(f"Total logs traités : {len(df)}")
    print(f"\nRépartition par sévérité prédite :")
    print(df["pred_severity"].value_counts().to_string())
    print(f"\nRépartition par catégorie prédite :")
    print(df["pred_category"].value_counts().to_string())
    print(f"\nAnomalies détectées : {df['pred_anomaly'].sum()} / {len(df)}")
    print("=" * 60)

    print("\nAperçu des résultats (5 premières lignes) :")
    preview = df[["hostname", "message", "pred_severity", "pred_category", "pred_anomaly"]].head(5)
    print(preview.to_string(index=False))


def main():
    parser = argparse.ArgumentParser(description="Exécute le pipeline complet du Projet 1.")
    parser.add_argument("--count", type=int, default=30, help="Nombre de logs à traiter")
    parser.add_argument("--output", type=str, default="../data/pipeline_run_result.xlsx")
    args = parser.parse_args()

    print("EXÉCUTION DU PIPELINE - PROJET 1")
    print("=" * 60)

    logs = generate_batch(args.count)
    df = parse_batch(logs)
    df = classify_batch(df)
    summarize(df)

    df.to_excel(args.output, index=False, sheet_name="Résultats")
    print(f"\nRésultat complet sauvegardé -> {args.output}")
    print("(Ouvrable directement avec Excel, colonnes déjà bien séparées)")


if __name__ == "__main__":
    main()