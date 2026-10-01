"""
Générateur de logs syslog en temps réel (flux continu).

Contrairement à generate_dataset.py (qui produit un fichier fixe d'un coup),
ce script simule un flux syslog réel : un message toutes les X secondes,
avec le timestamp du moment, écrit au fur et à mesure dans un fichier.

Usage :
    python live_log_generator.py                      # 1 log toutes les 3s, en continu
    python live_log_generator.py --interval 1          # 1 log par seconde
    python live_log_generator.py --count 50             # s'arrête après 50 logs
    python live_log_generator.py --output ../data/live_logs.txt

Arrêt : Ctrl+C
"""

import argparse
import random
import time
from datetime import datetime

random.seed()  # aléatoire réel, pas reproductible (contrairement au dataset statique)

# ---------------------------------------------------------------
# Mêmes templates que generate_dataset.py (facility, severity,
# mnemonic, category, [formulations possibles])
# ---------------------------------------------------------------
TEMPLATES = [
    ("LINK", 3, "UPDOWN", "interface", [
        "Interface {iface}, changed state to down",
        "Interface {iface} went down unexpectedly",
        "Link down detected on {iface}",
    ]),
    ("LINK", 5, "UPDOWN", "interface", [
        "Interface {iface}, changed state to up",
        "Interface {iface} came back up",
    ]),
    ("LINEPROTO", 5, "UPDOWN", "interface", [
        "Line protocol on Interface {iface}, changed state to down",
    ]),
    ("LINK", 4, "FLAPPED", "interface", [
        "Interface {iface} flapped {n} times in the last 60 seconds",
    ]),
    ("BGP", 5, "ADJCHANGE", "routing", [
        "neighbor {ip} Down BGP Notification sent",
        "BGP peer {ip} went down, session terminated",
    ]),
    ("BGP", 5, "ADJCHANGE", "routing", [
        "neighbor {ip} Up",
    ]),
    ("BGP", 4, "MAXPFXEXCEED", "routing", [
        "No. of prefix received from {ip} (afi 0) exceeds the max count",
    ]),
    ("OSPF", 5, "ADJCHG", "routing", [
        "Process 1, Nbr {ip} on {iface} from FULL to DOWN, Neighbor Down: Dead timer expired",
    ]),
    ("SEC", 6, "IPACCESSLOGP", "security", [
        "list 101 denied tcp {ip}({port}) -> {ip2}(80), {n} packets",
    ]),
    ("SEC", 4, "IPACCESSLOGP", "security", [
        "list 105 denied tcp {ip}({port}) -> {ip2}(22), {n} packets",
    ]),
    ("SEC_LOGIN", 5, "LOGIN_SUCCESS", "security", [
        "Login Success [user: {user}] [Source: {ip}] [localport: 22]",
    ]),
    ("SEC_LOGIN", 4, "LOGIN_FAILED", "security", [
        "Login failed [user: {user}] [Source: {ip}] [localport: 22] [Reason: Invalid login]",
    ]),
    ("ENVMON", 2, "FAN", "hardware", [
        "Fan array failure detected, shutdown likely in 2 minutes",
    ]),
    ("PLATFORM", 1, "PS_FAIL", "hardware", [
        "power supply {psid} failed",
    ]),
    ("SYS", 2, "MALLOCFAIL", "hardware", [
        "Memory allocation of {bytes} bytes failed from 0x{addr}, Pool Processor, alignment 0",
    ]),
    ("SYS", 5, "RELOAD", "system", [
        "Reload requested by {user}",
    ]),
    ("SYS", 3, "CPUHOG", "system", [
        "Task ran for {ms}ms ({limit}ms), process = IP Input, PC = 0x{addr}",
    ]),
    ("QOS", 4, "QUEUE_DROPS", "qos", [
        "Queue drops detected on interface {iface}, drop count: {drops}",
    ]),
    ("SPANTREE", 2, "BLOCK_BPDUGUARD", "stp", [
        "Received BPDU on port {iface} with BPDU Guard enabled. Disabling port.",
    ]),
    ("NTP", 4, "PEER_UNREACH", "services", [
        "NTP peer {ip} became unreachable, synchronization lost",
    ]),
]

HOSTS = ["R1-CORE", "R2-CORE", "R3-EDGE", "SW-ACCESS1", "SW-ACCESS2",
         "SW-DIST1", "BR-GW1", "PE-RABAT1", "PE-CASA1", "PE-TANGER1"]

IFACES = ["GigabitEthernet0/0/1", "GigabitEthernet0/0/2", "TenGigE0/0/0/1",
          "TenGigE0/1/0/3", "FastEthernet0/1", "Bundle-Ether10"]

USERS = ["admin", "netops1", "operateur2", "root", "supervisor"]


def rand_ip():
    return f"{random.randint(10,203)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def generate_one_log() -> str:
    """Génère une ligne de log Cisco avec le timestamp actuel réel."""
    facility, severity, mnemonic, category, variants = random.choice(TEMPLATES)
    msg_tpl = random.choice(variants)
    fields = {
        "iface": random.choice(IFACES),
        "ip": rand_ip(),
        "ip2": rand_ip(),
        "port": random.randint(1024, 65000),
        "user": random.choice(USERS),
        "psid": random.choice([1, 2]),
        "bytes": random.choice([1024, 2048, 4096, 8192]),
        "addr": "".join(random.choices("0123456789ABCDEF", k=8)),
        "ms": random.randint(1500, 6000),
        "limit": random.choice([2000, 3000, 5000]),
        "drops": random.randint(100, 9999),
        "n": random.randint(2, 8),
    }
    message = msg_tpl.format(**fields)
    host = random.choice(HOSTS)
    timestamp = datetime.now().strftime("%b %d %H:%M:%S")
    return f"{timestamp} {host} %{facility}-{severity}-{mnemonic}: {message}"


# ---------------------------------------------------------------
# Générateurs de logs volontairement CASSÉS, pour tester la
# robustesse du parsing, du nettoyage et des classifieurs.
# Chaque fonction simule un type de problème rencontré en vrai
# sur un réseau (coupure réseau, bug d'équipement, log tronqué...).
# ---------------------------------------------------------------

def error_truncated_line() -> str:
    """Simule un log coupé en plein milieu (buffer réseau plein, etc.)."""
    full = generate_one_log()
    cut = random.randint(10, len(full) - 5)
    return full[:cut]


def error_missing_mnemonic() -> str:
    """Header syslog cassé : il manque le mnémonique après le 2e tiret."""
    host = random.choice(HOSTS)
    timestamp = datetime.now().strftime("%b %d %H:%M:%S")
    facility = random.choice(["LINK", "BGP", "SEC", "SYS"])
    severity = random.randint(0, 7)
    return f"{timestamp} {host} %{facility}-{severity}-: message incomplet"


def error_garbage_text() -> str:
    """Ligne totalement hors format (corruption, bruit sur la ligne série...)."""
    junk = "".join(random.choices("ABCDEFGHIJ0123456789#@%&", k=random.randint(20, 60)))
    return junk


def error_empty_message() -> str:
    """Header valide mais message vide (bug d'équipement connu)."""
    host = random.choice(HOSTS)
    timestamp = datetime.now().strftime("%b %d %H:%M:%S")
    facility, severity, mnemonic, _, _ = random.choice(TEMPLATES)
    return f"{timestamp} {host} %{facility}-{severity}-{mnemonic}: "


def error_invalid_severity() -> str:
    """Sévérité hors plage valide (0-7) -- doit être détecté par le nettoyage."""
    host = random.choice(HOSTS)
    timestamp = datetime.now().strftime("%b %d %H:%M:%S")
    facility, _, mnemonic, _, variants = random.choice(TEMPLATES)
    message = random.choice(variants).format(
        iface="GigabitEthernet0/0/1", ip=rand_ip(), ip2=rand_ip(), port=1234,
        user="admin", psid=1, bytes=1024, addr="DEADBEEF", ms=2000, limit=3000,
        drops=100, n=3,
    )
    bad_severity = random.choice([8, 9, 15, -1])
    return f"{timestamp} {host} %{facility}-{bad_severity}-{mnemonic}: {message}"


def error_no_timestamp() -> str:
    """Ligne sans date du tout (perte de synchronisation NTP sur l'équipement)."""
    host = random.choice(HOSTS)
    facility, severity, mnemonic, _, variants = random.choice(TEMPLATES)
    message = random.choice(variants).format(
        iface="TenGigE0/0/0/1", ip=rand_ip(), ip2=rand_ip(), port=1234,
        user="admin", psid=1, bytes=1024, addr="DEADBEEF", ms=2000, limit=3000,
        drops=100, n=3,
    )
    return f"{host} %{facility}-{severity}-{mnemonic}: {message}"


ERROR_GENERATORS = [
    error_truncated_line,
    error_missing_mnemonic,
    error_garbage_text,
    error_empty_message,
    error_invalid_severity,
    error_no_timestamp,
]


def generate_one_line(error_rate: float) -> tuple[str, bool]:
    """Génère une ligne normale, ou une ligne d'erreur selon error_rate.
    Retourne (ligne, est_une_erreur_injectee)."""
    if random.random() < error_rate:
        error_fn = random.choice(ERROR_GENERATORS)
        return error_fn(), True
    return generate_one_log(), False


def main():
    parser = argparse.ArgumentParser(description="Génère des logs syslog en temps réel.")
    parser.add_argument("--interval", type=float, default=3.0,
                         help="Secondes entre chaque log (défaut : 3)")
    parser.add_argument("--count", type=int, default=None,
                         help="Nombre de logs à générer (défaut : infini, Ctrl+C pour arrêter)")
    parser.add_argument("--output", type=str, default=None,
                         help="Fichier où écrire les logs (append). Si absent : affichage écran uniquement.")
    parser.add_argument("--error-rate", type=float, default=0.0,
                         help="Proportion de logs volontairement cassés, entre 0 et 1 "
                              "(ex: 0.2 = 20%% de logs mal formés, pour tester la robustesse "
                              "du parsing/nettoyage/classification). Défaut : 0 (aucune erreur).")
    args = parser.parse_args()

    print(f"Génération d'un log toutes les {args.interval}s "
          f"({'infini, Ctrl+C pour arrêter' if args.count is None else f'{args.count} logs'})")
    if args.output:
        print(f"Écriture dans : {args.output}")
    if args.error_rate > 0:
        print(f"Taux d'erreurs injectées : {args.error_rate:.0%}")
    print("-" * 60)

    i = 0
    n_errors = 0
    try:
        while args.count is None or i < args.count:
            log_line, is_error = generate_one_line(args.error_rate)
            marker = "  [ERREUR INJECTÉE]" if is_error else ""
            print(log_line + marker)
            if is_error:
                n_errors += 1

            if args.output:
                with open(args.output, "a", encoding="utf-8") as f:
                    f.write(log_line + "\n")

            i += 1
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass

    print(f"\nArrêté après {i} logs générés ({n_errors} erreurs injectées volontairement, "
          f"{i - n_errors} logs normaux).")


if __name__ == "__main__":
    main()