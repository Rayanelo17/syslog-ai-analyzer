"""
Générateur v2 du dataset syslog Cisco (Télécom NOC).

Différences avec v1 :
- Plusieurs formulations (phrasing) possibles par type d'événement,
  au lieu d'un seul message figé -> le vocabulaire ne trahit plus
  la classe aussi facilement.
- Bruit textuel réaliste appliqué à une fraction des messages :
  fautes de frappe, troncature, abréviations -> simule des logs
  imparfaits comme dans la vraie vie.
- Objectif : éviter le score de 100% "trop facile" obtenu en v1,
  qui reflétait la structure des templates plus que la difficulté
  réelle de la tâche.
"""

import csv
import random
from datetime import datetime, timedelta

random.seed(7)

# ---------------------------------------------------------------
# Templates : (facility, severity, mnemonic, category, [variantes de message])
# Plusieurs formulations par événement -> vocabulaire moins rigide
# ---------------------------------------------------------------
TEMPLATES = [
    # --- Interfaces (category: interface) ---
    ("LINK", 3, "UPDOWN", "interface", [
        "Interface {iface}, changed state to down",
        "Interface {iface} went down unexpectedly",
        "Link down detected on {iface}",
    ]),
    ("LINK", 5, "UPDOWN", "interface", [
        "Interface {iface}, changed state to up",
        "Interface {iface} came back up",
        "Link restored on {iface}",
    ]),
    ("LINEPROTO", 5, "UPDOWN", "interface", [
        "Line protocol on Interface {iface}, changed state to down",
        "Line protocol down on {iface}",
    ]),
    ("LINK", 4, "FLAPPED", "interface", [
        "Interface {iface} flapped {n} times in the last 60 seconds",
        "Intermittent flapping detected on {iface}, may indicate a cabling issue",
        "{iface} unstable, multiple up/down transitions observed",
    ]),

    # --- Routing (category: routing) ---
    ("BGP", 5, "ADJCHANGE", "routing", [
        "neighbor {ip} Down BGP Notification sent",
        "BGP peer {ip} went down, session terminated",
        "Adjacency lost with neighbor {ip}",
    ]),
    ("BGP", 5, "ADJCHANGE", "routing", [
        "neighbor {ip} Up",
        "BGP session established with {ip}",
    ]),
    ("BGP", 3, "NOTIFICATION", "routing", [
        "sent to neighbor {ip} 6/2 (Cease/Administrative Shutdown)",
        "BGP notification sent to {ip}, administrative shutdown",
    ]),
    ("BGP", 4, "MAXPFXEXCEED", "routing", [
        "No. of prefix received from {ip} (afi 0) exceeds the max count",
        "Prefix limit nearly reached for neighbor {ip}, may indicate route leak",
    ]),
    ("OSPF", 5, "ADJCHG", "routing", [
        "Process 1, Nbr {ip} on {iface} from FULL to DOWN, Neighbor Down: Dead timer expired",
        "OSPF neighbor {ip} on {iface} declared down, dead timer expired",
    ]),
    ("OSPF", 5, "ADJCHG", "routing", [
        "Process 1, Nbr {ip} on {iface} from LOADING to FULL, Loading Done",
        "OSPF adjacency with {ip} reached FULL state",
    ]),

    # --- Security (category: security) ---
    ("SEC", 6, "IPACCESSLOGP", "security", [
        "list 101 denied tcp {ip}({port}) -> {ip2}(80), {n} packets",
        "ACL 101 blocked connection from {ip} to {ip2} on port 80",
    ]),
    ("SEC", 4, "IPACCESSLOGP", "security", [
        "list 105 denied tcp {ip}({port}) -> {ip2}(22), {n} packets",
        "Repeated denied SSH attempts from {ip} to {ip2}, may indicate scanning",
    ]),
    ("SYS", 5, "CONFIG_I", "security", [
        "Configured from console by {user} on vty0 ({ip})",
        "Configuration change applied by {user} from {ip}",
    ]),
    ("SEC_LOGIN", 5, "LOGIN_SUCCESS", "security", [
        "Login Success [user: {user}] [Source: {ip}] [localport: 22]",
        "User {user} logged in successfully from {ip}",
    ]),
    ("SEC_LOGIN", 4, "LOGIN_FAILED", "security", [
        "Login failed [user: {user}] [Source: {ip}] [localport: 22] [Reason: Invalid login]",
        "Failed login attempt for {user} from {ip}, invalid credentials",
    ]),
    ("SEC_LOGIN", 3, "LOGIN_FAILED", "security", [
        "Login failed [user: {user}] [Source: {ip}] [Reason: Too many failed attempts]",
        "Account {user} temporarily locked after repeated failed logins from {ip}",
    ]),

    # --- Hardware (category: hardware) ---
    ("ENVMON", 2, "FAN", "hardware", [
        "Fan array failure detected, shutdown likely in 2 minutes",
        "Cooling fan failure, imminent thermal shutdown risk",
    ]),
    ("ENVMON", 1, "TEMP", "hardware", [
        "Temperature Warning: chassis temperature has reached {temp}C, exceeding threshold",
        "Chassis overheating, {temp}C recorded, immediate action required",
    ]),
    ("PLATFORM", 1, "PS_FAIL", "hardware", [
        "power supply {psid} failed",
        "Power supply unit {psid} has stopped functioning",
    ]),
    ("PLATFORM", 6, "PS_OK", "hardware", [
        "power supply {psid} restored to normal operation",
        "Power supply {psid} back to normal",
    ]),
    ("SYS", 2, "MALLOCFAIL", "hardware", [
        "Memory allocation of {bytes} bytes failed from 0x{addr}, Pool Processor, alignment 0",
        "Critical memory allocation failure, {bytes} bytes requested",
    ]),

    # --- System (category: system) ---
    ("SYS", 5, "RELOAD", "system", [
        "Reload requested by {user}",
        "System reload triggered by {user}",
    ]),
    ("SYS", 6, "BOOTTIME", "system", [
        "Time taken to reboot after reload = {seconds} seconds",
        "Boot completed in {seconds} seconds",
    ]),
    ("SYS", 3, "CPUHOG", "system", [
        "Task ran for {ms}ms ({limit}ms), process = IP Input, PC = 0x{addr}",
        "High CPU usage detected, process IP Input exceeded {limit}ms",
    ]),
    ("SYS", 1, "RESTART", "system", [
        "System restarted -- Cisco IOS Software, Version 15.7",
        "Unexpected system restart, IOS version 15.7",
    ]),

    # --- QoS (category: qos) ---
    ("QOS", 4, "QUEUE_DROPS", "qos", [
        "Queue drops detected on interface {iface}, drop count: {drops}",
        "Packet drops observed on {iface}, may indicate congestion, count {drops}",
    ]),
    ("QOS", 6, "STATS", "qos", [
        "Policy map statistics updated on interface {iface}",
        "QoS counters refreshed for {iface}",
    ]),

    # --- Spanning Tree (category: stp) ---
    ("SPANTREE", 2, "BLOCK_BPDUGUARD", "stp", [
        "Received BPDU on port {iface} with BPDU Guard enabled. Disabling port.",
        "BPDU Guard triggered on {iface}, port disabled to prevent loop",
    ]),
    ("SPANTREE", 6, "PORT_STATE", "stp", [
        "Port {iface} moved from listening to forwarding state",
        "STP state transition on {iface}: listening to forwarding",
    ]),

    # --- Services (category: services) ---
    ("DHCPD", 6, "ADDRESS_ASSIGN", "services", [
        "Interface {iface} assigned DHCP address {ip} to client {mac}",
        "DHCP lease {ip} granted to {mac} on {iface}",
    ]),
    ("NTP", 4, "PEER_UNREACH", "services", [
        "NTP peer {ip} became unreachable, synchronization lost",
        "Lost contact with NTP peer {ip}, clock drift risk",
    ]),
    ("NTP", 6, "SYNC", "services", [
        "System clock synchronized to NTP peer {ip}",
        "Clock sync OK with peer {ip}",
    ]),
]

HOSTS = ["R1-CORE", "R2-CORE", "R3-EDGE", "R4-EDGE", "SW-ACCESS1", "SW-ACCESS2",
         "SW-DIST1", "BR-GW1", "BR-GW2", "PE-RABAT1", "PE-CASA1", "PE-TANGER1"]

IFACES = ["GigabitEthernet0/0/1", "GigabitEthernet0/0/2", "TenGigE0/0/0/1",
          "TenGigE0/0/0/2", "TenGigE0/1/0/3", "FastEthernet0/1",
          "GigabitEthernet1/0/5", "Bundle-Ether10", "Loopback0"]

USERS = ["admin", "netops1", "operateur2", "root", "supervisor", "monitoring_svc"]


def rand_ip():
    return f"{random.randint(10,203)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def rand_mac():
    return ":".join(f"{random.randint(0,255):02x}" for _ in range(6))


def add_noise(text: str) -> str:
    """Applique un bruit réaliste à ~30% des messages."""
    r = random.random()
    if r < 0.10:
        # Faute de frappe : inverse deux caractères adjacents
        if len(text) > 5:
            i = random.randint(1, len(text) - 2)
            text = text[:i] + text[i+1] + text[i] + text[i+2:]
    elif r < 0.18:
        # Troncature (log coupé, buffer overflow, etc.)
        cut = random.randint(int(len(text) * 0.6), len(text))
        text = text[:cut]
    elif r < 0.26:
        # Abréviations courantes
        text = (text.replace("Interface", "Int")
                     .replace("interface", "int")
                     .replace("detected", "det.")
                     .replace("changed state", "chg state"))
    elif r < 0.30:
        # Espaces multiples parasites
        words = text.split(" ")
        idx = random.randint(0, len(words) - 1)
        words[idx] = words[idx] + "  "
        text = " ".join(words)
    return text


def build_message(template):
    facility, severity, mnemonic, category, variants = template
    msg_tpl = random.choice(variants)
    fields = {
        "iface": random.choice(IFACES),
        "ip": rand_ip(),
        "ip2": rand_ip(),
        "port": random.randint(1024, 65000),
        "user": random.choice(USERS),
        "temp": random.randint(65, 95),
        "psid": random.choice([1, 2]),
        "bytes": random.choice([1024, 2048, 4096, 8192]),
        "addr": "".join(random.choices("0123456789ABCDEF", k=8)),
        "seconds": random.randint(120, 400),
        "ms": random.randint(1500, 6000),
        "limit": random.choice([2000, 3000, 5000]),
        "drops": random.randint(100, 9999),
        "mac": rand_mac(),
        "n": random.randint(2, 8),
    }
    message = msg_tpl.format(**fields)
    message = add_noise(message)
    return facility, severity, mnemonic, category, message


def severity_label(sev):
    if sev <= 2:
        return "critical"
    elif sev == 3:
        return "error"
    elif sev == 4:
        return "warning"
    else:
        return "info"


def main(n_rows=2000, out_path="../data/raw/cisco_syslog_dataset_v2.csv"):
    start = datetime(2026, 7, 1, 0, 0, 0)
    rows = []
    for i in range(n_rows):
        template = random.choice(TEMPLATES)
        facility, severity, mnemonic, category, message = build_message(template)
        host = random.choice(HOSTS)
        ts = start + timedelta(seconds=random.randint(0, 60 * 60 * 24 * 30))
        timestamp = ts.strftime("%b %d %H:%M:%S")
        raw_log = f"{timestamp} {host} %{facility}-{severity}-{mnemonic}: {message}"
        is_anomaly = 1 if severity <= 4 else 0

        rows.append({
            "raw_log": raw_log,
            "timestamp": ts.isoformat(),
            "hostname": host,
            "facility": facility,
            "severity": severity,
            "severity_label": severity_label(severity),
            "mnemonic": mnemonic,
            "category": category,
            "message": message,
            "is_anomaly": is_anomaly,
        })

    rows.sort(key=lambda r: r["timestamp"])

    fieldnames = ["raw_log", "timestamp", "hostname", "facility", "severity",
                  "severity_label", "mnemonic", "category", "message", "is_anomaly"]

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Generated {len(rows)} rows -> {out_path}")


if __name__ == "__main__":
    main()
