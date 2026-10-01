"""
Détecteur d'anomalie pour les logs Cisco (Projet 1 - Télécom NOC).

Objectif : prédire is_anomaly (0/1) à partir du texte du message.

Note de conception : dans ce dataset, is_anomaly est défini comme
severity <= 4 (donc quasi équivalent à la sévérité). En conditions
réelles, une vraie détection d'anomalie irait plus loin qu'un simple
seuil de sévérité (ex: détection de séquences inhabituelles, de
fréquences anormales d'un même type d'événement, etc. -- voir la
section "perspectives" du rapport). Ce classifieur reste utile comme
brique de base : une alerte binaire simple et rapide à calculer,
qui peut ensuite être raffinée par le LLM (Projet 2) pour la
corrélation et le diagnostic.

Métriques : on privilégie le recall (rappel) sur la classe anomalie --
rater une vraie anomalie (faux négatif) coûte plus cher en exploitation
qu'une fausse alerte (faux positif).
"""

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, recall_score, precision_score
import matplotlib.pyplot as plt
import joblib

DATA_PATH = "../data/processed/cisco_syslog_dataset_v2_clean.xlsx"
TARGET = "is_anomaly"
TEXT_COL = "message"


def load_data(path):
    return pd.read_excel(path)


def build_pipeline():
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),
            min_df=2,
            sublinear_tf=True,
        )),
        ("clf", LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
        )),
    ])


def main():
    df = load_data(DATA_PATH)
    df = df.dropna(subset=[TEXT_COL, TARGET])

    X = df[TEXT_COL]
    y = df[TARGET]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)

    print(f"Accuracy (test set) : {acc:.3f}")
    print(f"Recall (anomalies détectées) : {recall:.3f}")
    print(f"Precision (fiabilité des alertes) : {precision:.3f}")
    print()
    print("Classification report:")
    print(classification_report(y_test, y_pred, target_names=["normal", "anomalie"]))

    cm = confusion_matrix(y_test, y_pred)
    labels = ["normal", "anomalie"]

    fig, ax = plt.subplots(figsize=(5.5, 5))
    im = ax.imshow(cm, cmap="Reds")
    ax.set_xticks(range(2))
    ax.set_yticks(range(2))
    ax.set_xticklabels(labels)
    ax.set_yticklabels(labels)
    ax.set_xlabel("Prédiction")
    ax.set_ylabel("Vraie valeur")
    ax.set_title("Matrice de confusion - Détection d'anomalie")

    for i in range(2):
        for j in range(2):
            ax.text(j, i, cm[i, j], ha="center", va="center",
                     color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=14)

    fig.colorbar(im, ax=ax, label="Nombre de logs")
    plt.tight_layout()
    plt.savefig("../outputs/confusion_matrix_anomaly.png", dpi=150)
    print("\nMatrice de confusion sauvegardée -> ../outputs/confusion_matrix_anomaly.png")

    joblib.dump(pipeline, "../models/anomaly_classifier.joblib")
    print("Modèle sauvegardé -> ../models/anomaly_classifier.joblib")


if __name__ == "__main__":
    main()
