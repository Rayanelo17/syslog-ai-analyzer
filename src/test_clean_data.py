"""
Tests du nettoyage de données (clean_data.py).

Usage : pytest test_clean_data.py -v
"""

import pandas as pd
from clean_data import clean_dataset


def _base_row(**overrides):
    row = {
        "raw_log": "Jul 27 09:14:22 R1-CORE %LINK-3-UPDOWN: Interface Gi0/1, changed state to down",
        "timestamp": "2026-07-27 09:14:22",
        "hostname": "R1-CORE",
        "facility": "LINK",
        "severity": 3,
        "severity_label": "error",
        "mnemonic": "UPDOWN",
        "category": "interface",
        "message": "Interface Gi0/1, changed state to down",
        "is_anomaly": 1,
    }
    row.update(overrides)
    return row


def test_lignes_valides_conservees():
    df = pd.DataFrame([_base_row(), _base_row(raw_log="autre log")])
    clean, report = clean_dataset(df)
    assert len(clean) == 2


def test_doublon_exact_supprime():
    df = pd.DataFrame([_base_row(), _base_row()])  # raw_log identique
    clean, report = clean_dataset(df)
    assert len(clean) == 1


def test_severite_hors_plage_supprimee():
    df = pd.DataFrame([
        _base_row(),
        _base_row(raw_log="log invalide", severity=9),  # hors plage 0-7
    ])
    clean, report = clean_dataset(df)
    assert len(clean) == 1
    assert clean["severity"].max() <= 7


def test_espaces_multiples_normalises():
    df = pd.DataFrame([
        _base_row(message="Interface   Gi0/1,   changed state to down  "),
    ])
    clean, report = clean_dataset(df)
    assert clean.iloc[0]["message"] == "Interface Gi0/1, changed state to down"


def test_message_court_marque_suspect_mais_conserve():
    """Un message trop court doit être signalé (colonne is_suspect),
    pas supprimé -- décision de conception : ne rien perdre sans
    validation humaine."""
    df = pd.DataFrame([_base_row(message="court")])  # 5 caractères, sous le seuil de 10
    clean, report = clean_dataset(df)
    assert len(clean) == 1
    assert "is_suspect" in clean.columns
    assert clean.iloc[0]["is_suspect"] == 1


def test_message_normal_pas_marque_suspect():
    df = pd.DataFrame([_base_row()])
    clean, report = clean_dataset(df)
    assert clean.iloc[0]["is_suspect"] == 0


def test_valeur_manquante_supprimee():
    df = pd.DataFrame([
        _base_row(),
        _base_row(raw_log="log incomplet", message=None),
    ])
    clean, report = clean_dataset(df)
    assert len(clean) == 1
    assert clean["message"].isnull().sum() == 0


def test_timestamp_invalide_supprime():
    df = pd.DataFrame([
        _base_row(),
        _base_row(raw_log="log date cassee", timestamp="pas une date"),
    ])
    clean, report = clean_dataset(df)
    assert len(clean) == 1


def test_rapport_contient_le_compte_dentree_et_de_sortie():
    df = pd.DataFrame([_base_row()])
    clean, report = clean_dataset(df)
    texte = "\n".join(report)
    assert "Lignes en entrée : 1" in texte
    assert "Lignes en sortie : 1" in texte