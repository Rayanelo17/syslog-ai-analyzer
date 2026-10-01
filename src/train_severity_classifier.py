"""
Classifieur de sévérité pour les logs Cisco (Projet 1 - Télécom NOC).

Objectif : prédire severity_label (critical / error / warning / info)
à partir du texte du message (colonne 'message'), sans utiliser
facility/mnemonic qui seraient une fuite d'information (leakage) --
ils déterminent la sévérité de façon quasi déterministe dans ce
dataset, ce qui donnerait un score artificiellement parfait et un
modèle inutile sur des logs texte libre / non structurés.

Pipeline : TF-IDF (n-grams mots + caractères) -> Régression logistique
"""

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import matplotlib.pyplot as plt
import numpy as np
import joblib

DATA_PATH = "../data/processed/cisco_syslog_dataset_v2_clean.xlsx"
TARGET = "severity_label"
TEXT_COL = "message"


def load_data(path):
    df = pd.read_excel(path)
    return df


def build_pipeline():
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),
            min_df=2,
            sublinear_tf=True,
        )),
        ("clf", LogisticRegression(
            max_iter=1000,
            class_weight="balanced",  # compense le déséquilibre entre classes
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
    print(f"Accuracy (test set): {acc:.3f}")
    print()
    print("Classification report:")
    print(classification_report(y_test, y_pred))

    # Matrice de confusion
    labels = sorted(y.unique())
    cm = confusion_matrix(y_test, y_pred, labels=labels)

    fig, ax = plt.subplots(figsize=(6, 5))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(labels)))
    ax.set_yticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.set_yticklabels(labels)
    ax.set_xlabel("Prédiction")
    ax.set_ylabel("Vraie valeur")
    ax.set_title("Matrice de confusion - Classification de sévérité")

    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(j, i, cm[i, j], ha="center", va="center",
                     color="white" if cm[i, j] > cm.max() / 2 else "black")

    fig.colorbar(im, ax=ax, label="Nombre de logs")
    plt.tight_layout()
    plt.savefig("../outputs/confusion_matrix_severity.png", dpi=150)
    print("\nMatrice de confusion sauvegardée -> ../outputs/confusion_matrix_severity.png")

    # Sauvegarde du modèle entraîné pour réutilisation
    joblib.dump(pipeline, "../models/severity_classifier.joblib")
    print("Modèle sauvegardé -> ../models/severity_classifier.joblib")


if __name__ == "__main__":
    main()
