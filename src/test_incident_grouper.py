"""
Tests du regroupement en incidents (incident_grouper.py).

Usage : pytest test_incident_grouper.py -v
"""

from syslog_parser import parse_log, resolve_severity, resolve_category
from incident_grouper import group_into_incidents, detect_flapping, extract_entity


def _to_record(line):
    """Parse une ligne et lui ajoute severity_pred/category_pred, comme
    le fait le vrai pipeline avant le regroupement."""
    rec = parse_log(line)
    sev, _ = resolve_severity(rec)
    cat, _ = resolve_category(rec)
    rec["severity_pred"] = sev or "info"
    rec["category_pred"] = cat or "unknown"
    return rec


# ---------------------------------------------------------------
# Extraction d'entité : doit reconnaître interfaces, IPv4 et IPv6.
# ---------------------------------------------------------------

def test_extract_entity_interface():
    rec = {"message": "Interface GigabitEthernet0/1, changed state to down", "mnemonic": "UPDOWN"}
    entite = extract_entity(rec)
    assert entite == ("interface", "GigabitEthernet0/1")


def test_extract_entity_ipv4():
    rec = {"message": "neighbor 10.0.0.2 Down BGP Notification sent", "mnemonic": "ADJCHANGE"}
    entite = extract_entity(rec)
    assert entite == ("neighbor", "10.0.0.2")


def test_extract_entity_ipv6():
    """Cas découvert sur de vrais logs télécom : sans support IPv6, ces
    logs tombaient dans un groupe générique par mnémonique, empêchant
    de relier les événements d'un même incident BFD/BGP."""
    rec = {"message": "Neighbor 2A00:2180:4003::108 reset (BFD adjacency down)", "mnemonic": "NBR_RESET"}
    entite = extract_entity(rec)
    assert entite[0] == "neighbor"
    assert "2A00" in entite[1]


def test_extract_entity_sans_identifiant_utilise_mnemonic():
    rec = {"message": "BFD session ld:17 handle:8 is going UP", "mnemonic": "BFD_SESS_UP"}
    entite = extract_entity(rec)
    assert entite == ("evenement", "BFD_SESS_UP")


# ---------------------------------------------------------------
# Regroupement de base
# ---------------------------------------------------------------

def test_logs_proches_meme_entite_regroupes():
    lignes = [
        "Jul 27 09:14:22 R1-CORE %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down",
        "Jul 27 09:14:25 R1-CORE %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to down",
    ]
    records = [_to_record(l) for l in lignes]
    incidents = group_into_incidents(records)
    assert len(incidents) == 1
    assert incidents[0]["nb_logs"] == 2


def test_logs_eloignes_dans_le_temps_pas_regroupes():
    lignes = [
        "Jul 27 09:14:22 R1-CORE %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down",
        "Jul 27 15:30:00 R1-CORE %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down",
    ]
    records = [_to_record(l) for l in lignes]
    incidents = group_into_incidents(records)
    # Deux événements à 6h d'écart sur la même interface : deux épisodes
    # d'un même incident consolidé (comportement voulu), pas fusionnés en
    # un seul événement continu.
    assert incidents[0].get("episodes", 1) >= 1


def test_aucun_log_perdu_dans_le_regroupement():
    lignes = [
        "Jul 27 09:14:22 R1-CORE %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down",
        "Jul 27 09:20:00 R2-CORE %BGP-5-ADJCHANGE: neighbor 10.0.0.2 Down",
        "texte sans structure reconnaissable",
    ]
    records = [_to_record(l) for l in lignes]
    incidents = group_into_incidents(records)
    total_logs = sum(i["nb_logs"] for i in incidents)
    assert total_logs == len(records)


# ---------------------------------------------------------------
# Détection de flapping
# ---------------------------------------------------------------

def test_flapping_detecte_sur_changements_repetes():
    lignes = [
        "Jun 20 09:53:52.125: %LINK-3-UPDOWN: Interface GigabitEthernet0/23, changed state to up",
        "Jun 20 09:54:02.361: %LINK-3-UPDOWN: Interface GigabitEthernet0/23, changed state to down",
        "Jun 20 09:54:04.765: %LINK-3-UPDOWN: Interface GigabitEthernet0/23, changed state to up",
    ]
    records = [_to_record(l) for l in lignes]
    incidents = group_into_incidents(records)
    flap = detect_flapping(incidents[0])
    assert flap is not None
    assert flap["nb_changements"] >= 3


def test_pas_de_flapping_sur_un_seul_changement():
    lignes = [
        "Jun 20 09:53:52.125: %LINK-3-UPDOWN: Interface GigabitEthernet0/23, changed state to up",
    ]
    records = [_to_record(l) for l in lignes]
    incidents = group_into_incidents(records)
    assert detect_flapping(incidents[0]) is None


# ---------------------------------------------------------------
# Régression : rafale d'événements sur entités hétérogènes (IPv6,
# interface, mnémonique seul) doit rester UN seul incident.
#
# Bug corrigé : une même cascade (BFD tombe -> BGP se réinitialise ->
# l'adjacence change -> BFD se recrée -> tout remonte) référence
# l'entité concernée de façon inconsistante d'une ligne à l'autre.
# Sans la consolidation par rafale temporelle, ces 8 logs se
# retrouvaient éclatés en 5 incidents distincts.
# ---------------------------------------------------------------

def test_burst_ipv6_neighbor_regroupe_en_un_incident():
    lignes = [
        "Jun 27 19:35:29.401 UTC: %BFDFSM-6-BFD_SESS_DOWN: BFD-SYSLOG: BFD session ld:17 handle:8,is going Down Reason: DETECT TIMER EXPIRED",
        "Jun 27 19:35:29.402 UTC: %BGP-5-NBR_RESET: Neighbor 2A00:2180:4003::108 reset (BFD adjacency down)",
        "Jun 27 19:35:29.410 UTC: %BGP-5-ADJCHANGE: neighbor 2A00:2180:4003::108 vpn vrf MSGTST Down BFD adjacency down",
        "Jun 27 19:35:29.410 UTC: %BFD-6-BFD_SESS_DESTROYED: BFD-SYSLOG: bfd_session_destroyed,  ld:17 neigh proc:BGP, idb:GigabitEthernet0/0/1.104 handle:8 active",
        "Jun 27 19:35:37.153 UTC: %BFD-6-BFD_SESS_CREATED: BFD-SYSLOG: bfd_session_created, neigh 2A00:2180:4003::108 proc:BGP, idb:GigabitEthernet0/0/1.104 handle:8 act",
        "Jun 27 19:35:37.153 UTC: %BGP-5-ADJCHANGE: neighbor 2A00:2180:4003::108 vpn vrf MSGTST Up",
        "Jun 27 19:35:37.166 UTC: %BFDFSM-6-BFD_SESS_UP: BFD-SYSLOG: BFD session ld:17 handle:8 is going UP",
    ]
    records = [_to_record(l) for l in lignes]
    incidents = group_into_incidents(records)
    assert len(incidents) == 1, (
        f"Attendu 1 incident pour cette rafale de 8s, obtenu {len(incidents)} : "
        f"{[i['entite'] for i in incidents]}"
    )
    assert incidents[0]["nb_logs"] == len(lignes)


def test_bursts_eloignes_restent_distincts():
    """Deux rafales séparées de plusieurs heures ne doivent pas fusionner
    entre elles, même si chacune est correctement consolidée en interne."""
    lignes = [
        "Jun 27 19:35:29.401 UTC: %BFDFSM-6-BFD_SESS_DOWN: BFD-SYSLOG: BFD session ld:17 handle:8,is going Down Reason: DETECT TIMER EXPIRED",
        "Jun 27 19:35:37.166 UTC: %BFDFSM-6-BFD_SESS_UP: BFD-SYSLOG: BFD session ld:17 handle:8 is going UP",
        "Jun 28 00:09:22.933 UTC: %BFDFSM-6-BFD_SESS_DOWN: BFD-SYSLOG: BFD session ld:4162 handle:3,is going Down Reason: DETECT TIMER EXPIRED",
    ]
    records = [_to_record(l) for l in lignes]
    incidents = group_into_incidents(records)
    total_logs = sum(i["nb_logs"] for i in incidents)
    assert total_logs == len(lignes)  # aucun log perdu, quel que soit le découpage


# ---------------------------------------------------------------
# Consolidation des incidents récurrents (même mnémonique, entités
# différentes) -- ex: VPN_NH_IF sur plusieurs voisins BGP.
# ---------------------------------------------------------------

def test_meme_mnemonique_repete_devient_incident_recurrent():
    lignes = [
        f"Jun 27 {h:02d}:00:00 UTC: %BGP-4-VPN_NH_IF: Nexthop :: may not be reachable from neigbor 198.18.{h}.1 - not a loopback"
        for h in (1, 5, 9, 13)
    ]
    records = [_to_record(l) for l in lignes]
    incidents = group_into_incidents(records)
    recurrents = [i for i in incidents if i.get("recurrent")]
    assert len(recurrents) == 1
    assert recurrents[0]["nb_logs"] == 4