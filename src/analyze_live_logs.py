"""
Pipeline complet : parse les logs live -> classifie sévérité, catégorie, anomalie.

Prend le fichier de logs bruts généré par live_log_generator.py,
les fait passer par le parser multi-format, puis applique les 3
classifieurs déjà entraînés pour prédire sévérité/catégorie/anomalie
à partir du texte du message.

Pour CHACUN des 3 modèles, on compare la prédiction à la vraie valeur :
- Sévérité : extraite directement du header du log par le parser
- Catégorie et anomalie : retrouvées via une table de correspondance
  (facility, mnemonic) -> (category, is_anomaly), construite à partir
  des mêmes TEMPLATES que ceux utilisés par live_log_generator.py.

Objectif : valider que la chaîne parsing -> classification fonctionne
de bout en bout sur des logs "nouveaux" (jamais vus à l'entraînement),
avec un pourcentage de précision pour les 3 modèles.

Usage :
    python analyze_live_logs.py ../data/live_logs.txt
"""

import sys
import joblib
import pandas as pd
from syslog_parser import parse_log

SEVERITY_MODEL_PATH = "../models/severity_classifier.joblib"
CATEGORY_MODEL_PATH = "../models/category_classifier.joblib"
ANOMALY_MODEL_PATH = "../models/anomaly_classifier.joblib"

SEVERITY_TO_LABEL = {
    0: "critical", 1: "critical", 2: "critical",
    3: "error",
    4: "warning",
    5: "info", 6: "info", 7: "info",
}

# Table de correspondance (facility, mnemonic) -> category,
# construite à partir des mêmes TEMPLATES que live_log_generator.py.
# Permet de connaître la "vraie" catégorie/anomalie de chaque log
# généré, pour pouvoir comparer aux prédictions des modèles.
FACILITY_MNEMONIC_TO_CATEGORY = {
    ("LINK", "UPDOWN"): "interface",
    ("LINEPROTO", "UPDOWN"): "interface",
    ("LINK", "FLAPPED"): "interface",
    ("BGP", "ADJCHANGE"): "routing",
    ("BGP", "MAXPFXEXCEED"): "routing",
    ("OSPF", "ADJCHG"): "routing",
    ("SEC", "IPACCESSLOGP"): "security",
    ("SEC_LOGIN", "LOGIN_SUCCESS"): "security",
    ("SEC_LOGIN", "LOGIN_FAILED"): "security",
    ("ENVMON", "FAN"): "hardware",
    ("PLATFORM", "PS_FAIL"): "hardware",
    ("SYS", "MALLOCFAIL"): "hardware",
    ("SYS", "RELOAD"): "system",
    ("SYS", "CPUHOG"): "system",
    ("QOS", "QUEUE_DROPS"): "qos",
    ("SPANTREE", "BLOCK_BPDUGUARD"): "stp",
    ("NTP", "PEER_UNREACH"): "services",
}


def compute_true_category(row):
    key = (row["facility"], row["mnemonic"])
    return FACILITY_MNEMONIC_TO_CATEGORY.get(key, "unknown")


def main():
    if len(sys.argv) < 2:
        print("Usage : python analyze_live_logs.py <chemin_vers_live_logs.txt>")
        sys.exit(1)

    log_path = sys.argv[1]

    # --- 1. Parsing ---
    records = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            rec = parse_log(line)
            if rec:
                records.append(rec)

    print(f"Lignes parsées : {len(records)}")
    formats = pd.Series([r["format_detected"] for r in records]).value_counts()
    print("Formats détectés :")
    print(formats.to_string())

    df = pd.DataFrame(records)

    # --- Rapport de robustesse : combien de lignes ont pu être exploitées ---
    n_total = len(df)
    n_unparsed = (df["format_detected"] == "unparsed").sum()
    n_empty_message = (df["message"].isna() | (df["message"].fillna("").str.strip() == "")).sum()

    print("\n" + "=" * 60)
    print("ROBUSTESSE DU PARSING")
    print("=" * 60)
    print(f"Lignes totales reçues     : {n_total}")
    print(f"Reconnues comme Cisco     : {n_total - n_unparsed} ({(n_total - n_unparsed)/n_total:.0%})")
    print(f"Non reconnues (unparsed)  : {n_unparsed} ({n_unparsed/n_total:.0%})")
    print(f"Messages vides/manquants  : {n_empty_message}")
    print("(Ces lignes restent dans le fichier final, marquées 'non_classifiable',")
    print(" plutôt que d'être silencieusement supprimées.)")

    # On garde TOUTES les lignes -- on sépare juste celles qu'on peut
    # classifier (message exploitable) de celles qu'on ne peut pas.
    has_message = df["message"].notna() & (df["message"].str.strip() != "")
    classifiable = df[has_message].copy()
    unclassifiable = df[~has_message].copy()

    # --- 2. Valeurs vraies (à partir du header extrait par le parser) ---
    classifiable["severity_true"] = classifiable["severity"].map(SEVERITY_TO_LABEL)
    classifiable["category_true"] = classifiable.apply(compute_true_category, axis=1)
    classifiable["anomaly_true"] = (classifiable["severity"] <= 4).astype(int)

    # --- 3. Classification : sévérité ---
    severity_model = joblib.load(SEVERITY_MODEL_PATH)
    classifiable["severity_pred"] = severity_model.predict(classifiable["message"])
    classifiable["severity_correct"] = classifiable["severity_true"] == classifiable["severity_pred"]

    # --- 4. Classification : catégorie ---
    category_model = joblib.load(CATEGORY_MODEL_PATH)
    classifiable["category_pred"] = category_model.predict(classifiable["message"])
    classifiable["category_correct"] = classifiable["category_true"] == classifiable["category_pred"]

    # --- 5. Classification : anomalie ---
    anomaly_model = joblib.load(ANOMALY_MODEL_PATH)
    classifiable["anomaly_pred"] = anomaly_model.predict(classifiable["message"])
    classifiable["anomaly_correct"] = classifiable["anomaly_true"] == classifiable["anomaly_pred"]

    # --- 6. Résumé de précision pour les 3 modèles (sur les lignes classifiables uniquement) ---
    n_classified = len(classifiable)
    severity_acc = classifiable["severity_correct"].mean() if n_classified else 0
    category_acc = classifiable["category_correct"].mean() if n_classified else 0
    anomaly_acc = classifiable["anomaly_correct"].mean() if n_classified else 0

    print("\n" + "=" * 60)
    print("PRÉCISION SUR LOGS LIVE (jamais vus à l'entraînement)")
    print("=" * 60)
    print(f"Base : {n_classified}/{n_total} lignes classifiables "
          f"({n_total - n_classified} lignes non classifiables exclues, mais gardées dans le fichier)")
    print(f"Sévérité  : {severity_acc:.1%}  ({classifiable['severity_correct'].sum()}/{n_classified})")
    print(f"Catégorie : {category_acc:.1%}  ({classifiable['category_correct'].sum()}/{n_classified})")
    print(f"Anomalie  : {anomaly_acc:.1%}  ({classifiable['anomaly_correct'].sum()}/{n_classified})")
    print("=" * 60)

    # --- 7. Réassemblage : toutes les lignes, classifiées ou non ---
    for col in ["severity_true", "severity_pred", "severity_correct",
                "category_true", "category_pred", "category_correct",
                "anomaly_true", "anomaly_pred", "anomaly_correct"]:
        if col not in unclassifiable.columns:
            unclassifiable[col] = "non_classifiable"

    full_df = pd.concat([classifiable, unclassifiable], ignore_index=True)
    full_df = full_df.sort_index()

    # --- 8. Sauvegarde en Excel, avec un onglet résumé + le détail complet ---
    out_path = log_path.replace(".txt", "_classified.xlsx")

    summary_df = pd.DataFrame([
        {"modèle": "Sévérité", "précision": severity_acc, "corrects": classifiable["severity_correct"].sum() if n_classified else 0, "base": n_classified},
        {"modèle": "Catégorie", "précision": category_acc, "corrects": classifiable["category_correct"].sum() if n_classified else 0, "base": n_classified},
        {"modèle": "Anomalie", "précision": anomaly_acc, "corrects": classifiable["anomaly_correct"].sum() if n_classified else 0, "base": n_classified},
        {"modèle": "(info) Lignes totales", "précision": None, "corrects": n_total, "base": n_total},
        {"modèle": "(info) Non classifiables", "précision": None, "corrects": n_total - n_classified, "base": n_total},
    ])

    detail_cols = ["raw_log", "hostname", "message", "format_detected", "facility", "mnemonic",
                    "severity_true", "severity_pred", "severity_correct",
                    "category_true", "category_pred", "category_correct",
                    "anomaly_true", "anomaly_pred", "anomaly_correct"]
    detail_cols = [c for c in detail_cols if c in full_df.columns]

    with pd.ExcelWriter(out_path, engine="openpyxl") as writer:
        summary_df.to_excel(writer, sheet_name="Résumé précision", index=False)
        full_df[detail_cols].to_excel(writer, sheet_name="Détail par log", index=False)

    print(f"\nRésultats sauvegardés -> {out_path}")
    print(f"({len(full_df)} lignes au total dans 'Détail par log', "
          f"identique aux {n_total} lignes reçues en entrée)")
    print("(2 onglets : 'Résumé précision' et 'Détail par log')")


if __name__ == "__main__":
    main()