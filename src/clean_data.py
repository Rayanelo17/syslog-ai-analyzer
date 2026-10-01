"""
Nettoyage du dataset syslog (Projet 1 -  PFA).

Étapes couvertes (standard pour un pipeline de logs) :
1. Valeurs manquantes
2. Doublons (raw_log exact, et message seul en avertissement)
3. Normalisation du texte (espaces multiples, espaces en début/fin)
4. Validation des types et plages de valeurs (severity 0-7, timestamp valide)
5. Cohérence facility/severity/category (une même paire doit toujours
   donner la même sévérité/catégorie -- sinon incohérence à corriger)
6. Détection des messages suspects (trop courts = probablement tronqués)

Produit : un fichier nettoyé + un rapport texte des actions effectuées.
Conçu pour être réutilisé tel quel sur de vrais logs télécom plus tard.
"""

import pandas as pd
import re

INPUT_PATH = "../data/raw/cisco_syslog_dataset_v2.xlsx"
OUTPUT_PATH = "../data/processed/cisco_syslog_dataset_v2_clean.xlsx"
REPORT_PATH = "../data/cleaning_report.txt"

MIN_MESSAGE_LENGTH = 10  # en dessous, message probablement tronqué/inutile


def load_data(path):
    return pd.read_excel(path)


def clean_dataset(df: pd.DataFrame):
    report = []
    report.append(f"Lignes en entrée : {len(df)}")

    # -------------------------------------------------------------
    # 1. Valeurs manquantes
    # -------------------------------------------------------------
    n_missing = df.isnull().any(axis=1).sum()
    if n_missing > 0:
        report.append(f"Lignes avec valeurs manquantes supprimées : {n_missing}")
        df = df.dropna()
    else:
        report.append("Aucune valeur manquante détectée.")

    # -------------------------------------------------------------
    # 2. Doublons exacts (raw_log identique)
    # -------------------------------------------------------------
    n_dup_exact = df.duplicated(subset=["raw_log"]).sum()
    df = df.drop_duplicates(subset=["raw_log"], keep="first")
    report.append(f"Doublons exacts (raw_log) supprimés : {n_dup_exact}")

    # Doublons de message seul : on les garde (plusieurs équipements
    # peuvent légitimement générer le même message), mais on le signale
    n_dup_msg = df.duplicated(subset=["message"]).sum()
    report.append(f"Messages identiques mais contextes différents (conservés) : {n_dup_msg}")

    # -------------------------------------------------------------
    # 3. Normalisation du texte
    # -------------------------------------------------------------
    def normalize_text(s):
        if not isinstance(s, str):
            return s
        s = s.strip()
        s = re.sub(r"\s+", " ", s)  # espaces multiples -> un seul espace
        return s

    before = df["message"].copy()
    df["message"] = df["message"].apply(normalize_text)
    df["raw_log"] = df["raw_log"].apply(normalize_text)        
    n_normalized = (before != df["message"]).sum()
    report.append(f"Messages avec espaces normalisés : {n_normalized}")

    # -------------------------------------------------------------
    # 4. Validation des types et plages
    # -------------------------------------------------------------
    # Severity doit être un entier entre 0 et 7 (norme syslog/Cisco)
    invalid_severity = ~df["severity"].between(0, 7)
    n_invalid_sev = invalid_severity.sum()
    if n_invalid_sev > 0:
        report.append(f"Lignes avec severity hors plage [0-7] supprimées : {n_invalid_sev}")
        df = df[~invalid_severity]
    else:
        report.append("Toutes les valeurs de severity sont valides (0-7).")

    # Timestamp doit être parsable
    ts_parsed = pd.to_datetime(df["timestamp"], errors="coerce")
    n_invalid_ts = ts_parsed.isnull().sum()
    if n_invalid_ts > 0:
        report.append(f"Lignes avec timestamp invalide supprimées : {n_invalid_ts}")
        df = df[~ts_parsed.isnull()]
    else:
        report.append("Tous les timestamps sont valides.")

    # -------------------------------------------------------------
    # 5. Cohérence facility + mnemonic -> severity/category
    #    (une même combinaison doit toujours donner la même classe ;
    #    sinon c'est un signal d'erreur d'étiquetage à vérifier)
    # -------------------------------------------------------------
    grouped = df.groupby(["facility", "mnemonic"])[["severity", "category"]].nunique()
    inconsistent = grouped[(grouped["severity"] > 1) | (grouped["category"] > 1)]
    if len(inconsistent) > 0:
        report.append(
            f"ATTENTION : {len(inconsistent)} paires (facility, mnemonic) ont des "
            f"labels incohérents (severity ou category variable) -- à vérifier manuellement :"
        )
        report.append(str(inconsistent))
    else:
        report.append("Cohérence facility/mnemonic -> severity/category : OK.")

    # -------------------------------------------------------------
    # 6. Messages suspects (trop courts, probablement tronqués)
    # -------------------------------------------------------------
    too_short = df["message"].str.len() < MIN_MESSAGE_LENGTH
    n_too_short = too_short.sum()
    report.append(
        f"Messages trop courts (< {MIN_MESSAGE_LENGTH} caractères), "
        f"marqués via la colonne 'is_suspect' : {n_too_short}"
    )
    df["is_suspect"] = too_short.astype(int)

    report.append(f"Lignes en sortie : {len(df)}")
    return df, report


def main():
    df = load_data(INPUT_PATH)
    df_clean, report = clean_dataset(df)

    df_clean.to_excel(OUTPUT_PATH, index=False)

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write("Rapport de nettoyage - dataset syslog\n")
        f.write("=" * 50 + "\n\n")
        f.write("\n".join(report))

    print("\n".join(report))
    print(f"\nFichier nettoyé -> {OUTPUT_PATH}")
    print(f"Rapport -> {REPORT_PATH}")


if __name__ == "__main__":
    main()
