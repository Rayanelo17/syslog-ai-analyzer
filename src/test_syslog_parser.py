"""
Tests du parser multi-format (syslog_parser.py).

Usage : pytest test_syslog_parser.py -v
"""

import pytest
from syslog_parser import (
    parse_log, resolve_severity, resolve_category,
    RFC5424Parser, CiscoParser, CiscoDeviceParser, BSDParser,
)


# ---------------------------------------------------------------
# Reconnaissance de format : un cas par format supporté
# ---------------------------------------------------------------

def test_rfc5424_reconnu():
    line = ("<134>1 2026-08-10T14:07:15.003Z mymachine.example.com su "
            "12345 ID47 - 'su root' failed for user")
    rec = parse_log(line)
    assert rec["format_detected"] == "rfc5424"
    assert rec["hostname"] == "mymachine.example.com"


def test_cisco_ios_reconnu():
    line = "Jul 27 09:14:22 R1-CORE %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down"
    rec = parse_log(line)
    assert rec["format_detected"] == "cisco_ios"
    assert rec["hostname"] == "R1-CORE"
    assert rec["facility"] == "LINK"
    assert rec["severity"] == 3
    assert rec["mnemonic"] == "UPDOWN"


def test_cisco_device_sans_hostname_reconnu():
    """Format lu directement sur l'équipement (show logging) : timestamp
    avec millisecondes/fuseau, sans hostname. Cas découvert sur un vrai
    log réel (%BGP-4-VPN_NH_IF)."""
    line = ("Jun 27 19:22:47.093 UTC: %BGP-4-VPN_NH_IF: Nexthop :: may not "
            "be reachable from neigbor 198.19.35.97 - not a loopback.")
    rec = parse_log(line)
    assert rec["format_detected"] == "cisco_device"
    assert rec["hostname"] is None
    assert rec["facility"] == "BGP"
    assert rec["severity"] == 4


def test_bsd_reconnu():
    line = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
    rec = parse_log(line)
    assert rec["format_detected"] == "rfc3164_bsd"
    assert rec["hostname"] == "mymachine"


def test_cisco_iosxr_reconnu():
    """Format IOS-XR (routeurs cœur de réseau) : préfixe de localisation
    matérielle + nom de processus + header à 4 segments
    (%FACILITY-SOUS_COMPOSANT-SEV-MNEMONIC), différent d'IOS classique."""
    line = ("RP/0/RP0/CPU0:Aug 26 00:03:32.693 UTC: l2rib[295]: "
            "%L2-L2RIB-3-ERR_STATIC_TO_LOCAL : Local host in topology 0 (3) "
            "with MAC address (98a2.c048.6787) detected")
    rec = parse_log(line)
    assert rec["format_detected"] == "cisco_iosxr"
    assert rec["hostname"] == "RP/0/RP0/CPU0"
    assert rec["facility"] == "L2"
    assert rec["severity"] == 3
    assert rec["mnemonic"] == "ERR_STATIC_TO_LOCAL"


def test_ligne_non_reconnue_conservee_pas_perdue():
    """Le fallback doit garder la ligne, jamais la faire disparaître."""
    line = "ceci n'est pas un log syslog reconnaissable"
    rec = parse_log(line)
    assert rec["format_detected"] == "unparsed"
    assert rec["message"] == line


def test_ligne_vide_retourne_none():
    assert parse_log("") is None
    assert parse_log("   ") is None


# ---------------------------------------------------------------
# Ordre de priorité des parsers : Cisco doit être tenté avant BSD
# générique, sinon BSD absorbe aussi les lignes Cisco.
# ---------------------------------------------------------------

def test_cisco_priorise_sur_bsd_generique():
    line = "Jul 27 09:14:22 R1-CORE %LINK-3-UPDOWN: Interface Gi0/1, changed state to down"
    assert CiscoParser.detect(line) is True
    rec = parse_log(line)
    # Si BSD passait en premier, le mnémonique ne serait jamais extrait
    assert rec["format_detected"] == "cisco_ios"
    assert rec["mnemonic"] == "UPDOWN"


# ---------------------------------------------------------------
# Résolution hybride de la sévérité : header en priorité, ML en secours.
#
# Corrige un bug réel : un modèle ML entraîné sur un vocabulaire limité
# classait %BGP-4-VPN_NH_IF en 'info' au lieu de 'warning', alors que le
# '4' est explicitement écrit dans le log. Sur 137 logs réels de production, cette
# erreur touchait 18% des lignes avant correction.
# ---------------------------------------------------------------

class _FakeModel:
    """Simule un classifieur ML pour tester le secours sans dépendre
    d'un vrai modèle entraîné (pas de fichier .joblib requis pour les tests)."""
    def predict(self, messages):
        return ["info"] * len(messages)


def test_severite_lue_dans_le_header_prioritaire():
    rec = {"severity": 4, "message": "Nexthop may not be reachable"}
    label, source = resolve_severity(rec, ml_model=_FakeModel())
    assert label == "warning"
    assert source == "header"


def test_severite_bascule_sur_ml_si_header_absent():
    rec = {"severity": None, "message": "un message quelconque"}
    label, source = resolve_severity(rec, ml_model=_FakeModel())
    assert label == "info"
    assert source == "modele_ml"


def test_severite_sans_modele_ni_header_retourne_none():
    rec = {"severity": None, "message": "un message"}
    label, source = resolve_severity(rec, ml_model=None)
    assert label is None


@pytest.mark.parametrize("code,attendu", [
    (0, "critical"), (2, "critical"),
    (3, "error"),
    (4, "warning"),
    (5, "info"), (7, "info"),
])
def test_mapping_severite_complet(code, attendu):
    rec = {"severity": code, "message": "peu importe"}
    label, source = resolve_severity(rec)
    assert label == attendu
    assert source == "header"


# ---------------------------------------------------------------
# Résolution hybride de la catégorie : facility en priorité, ML en secours.
# Corrige la même classe de bug pour la catégorie (BGP classé 'security'
# au lieu de 'routing' à cause des adresses IP dans le message).
# ---------------------------------------------------------------

def test_categorie_deduite_de_la_facility_bgp():
    rec = {"facility": "BGP", "message": "neighbor down"}
    cat, source = resolve_category(rec, ml_model=_FakeModel())
    assert cat == "routing"
    assert source == "facility"


def test_categorie_facility_inconnue_bascule_sur_ml():
    class _FakeCatModel:
        def predict(self, messages):
            return ["security"] * len(messages)

    rec = {"facility": "TOTALEMENT_INCONNU", "message": "message quelconque"}
    cat, source = resolve_category(rec, ml_model=_FakeCatModel())
    assert cat == "security"
    assert source == "modele_ml"


@pytest.mark.parametrize("facility,attendu", [
    ("BFD", "routing"), ("BFDFSM", "routing"), ("OSPF", "routing"),
    ("LINK", "interface"), ("IFDAMP", "interface"),
    ("SEC_LOGIN", "security"),
    ("ENVMON", "hardware"),
    ("SPANTREE", "stp"),
])
def test_categorie_facilities_reelles_jamais_vues_a_lentrainement(facility, attendu):
    """Ces facilities (BFD, BFDFSM, IFDAMP...) n'existent pas dans le
    dataset d'entraînement synthétique -- validées sur les vrais logs de production."""
    rec = {"facility": facility, "message": "peu importe"}
    cat, source = resolve_category(rec)
    assert cat == attendu
    assert source == "facility"


# ---------------------------------------------------------------
# Robustesse : aucune ligne d'un lot ne doit être perdue, même
# mélangée avec des lignes corrompues.
# ---------------------------------------------------------------

def test_aucune_ligne_perdue_sur_lot_mixte():
    lignes = [
        "Jul 27 09:14:22 R1-CORE %LINK-3-UPDOWN: Interface Gi0/1, changed state to down",
        "texte cassé sans structure",
        "",  # ligne vide, filtrée en amont normalement
        "<34>Oct 11 22:14:15 mymachine su: authentication failure",
    ]
    resultats = [parse_log(l) for l in lignes if l.strip()]
    resultats = [r for r in resultats if r]
    assert len(resultats) == 3  # la ligne vide ne compte pas, les 3 autres doivent survivre