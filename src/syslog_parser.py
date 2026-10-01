"""
Parser multi-format de logs syslog.

Design : chaque format est une classe avec detect() et parse().
Le routeur (parse_log) essaie chaque parser dans l'ordre, et retombe
sur un parser générique si rien ne matche (aucune ligne n'est perdue).

Ajouter un vendeur (Huawei, Nokia, Juniper...) = ajouter une classe
et l'enregistrer dans PARSERS. Rien d'autre à modifier.
"""

import re
from typing import Optional


def make_record(raw, format_name, timestamp=None, hostname=None,
                 facility=None, severity=None, mnemonic=None,
                 message=None, vendor=None):
    return {
        "raw_log": raw,
        "format_detected": format_name,
        "timestamp": timestamp,
        "hostname": hostname,
        "facility": facility,
        "severity": severity,
        "mnemonic": mnemonic,
        "message": message,
        "vendor": vendor,
    }


class RFC5424Parser:
    name = "rfc5424"
    PATTERN = re.compile(
        r"^(?:<(?P<pri>\d+)>)?"
        r"(?P<version>\d)\s+"
        r"(?P<timestamp>\S+)\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<app>\S+)\s+"
        r"(?P<procid>\S+)\s+"
        r"(?P<msgid>\S+)\s+"
        r"(?P<sd>-|\[.*?\])\s*"
        r"(?P<message>.*)$"
    )

    @classmethod
    def detect(cls, line: str) -> bool:
        return bool(cls.PATTERN.match(line))

    @classmethod
    def parse(cls, line: str) -> Optional[dict]:
        m = cls.PATTERN.match(line)
        if not m:
            return None
        pri = m.group("pri")
        severity = int(pri) % 8 if pri else None
        facility = int(pri) // 8 if pri else None
        return make_record(
            raw=line, format_name=cls.name,
            timestamp=m.group("timestamp"), hostname=m.group("hostname"),
            facility=facility, severity=severity, mnemonic=m.group("app"),
            message=m.group("message"), vendor="generic",
        )


class CiscoParser:
    name = "cisco_ios"
    PATTERN = re.compile(
        r"^(?:<(?P<pri>\d+)>)?"
        r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"%(?P<facility>[A-Z0-9_]+)-(?P<severity>\d)-(?P<mnemonic>[A-Z0-9_]+):\s*"
        r"(?P<message>.*)$"
    )

    @classmethod
    def detect(cls, line: str) -> bool:
        return bool(cls.PATTERN.match(line))

    @classmethod
    def parse(cls, line: str) -> Optional[dict]:
        m = cls.PATTERN.match(line)
        if not m:
            return None
        return make_record(
            raw=line, format_name=cls.name,
            timestamp=m.group("timestamp"), hostname=m.group("hostname"),
            facility=m.group("facility"), severity=int(m.group("severity")),
            mnemonic=m.group("mnemonic"), message=m.group("message"),
            vendor="cisco",
        )


class CiscoDeviceParser:
    """Variante Cisco lue directement sur l'équipement (show logging) :
    timestamp avec millisecondes et fuseau, suivi de ':' et SANS hostname.
    Ex: Jun 27 19:22:47.093 UTC: %BGP-4-VPN_NH_IF: Nexthop :: may not be...
    """
    name = "cisco_device"
    PATTERN = re.compile(
        r"^(?:<(?P<pri>\d+)>)?"
        r"(?:\*|\.)?"
        r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+\w+)?)\s*:\s*"
        r"%(?P<facility>[A-Z0-9_]+)-(?P<severity>\d)-(?P<mnemonic>[A-Z0-9_]+):\s*"
        r"(?P<message>.*)$"
    )

    @classmethod
    def detect(cls, line: str) -> bool:
        return bool(cls.PATTERN.match(line))

    @classmethod
    def parse(cls, line: str) -> Optional[dict]:
        m = cls.PATTERN.match(line)
        if not m:
            return None
        return make_record(
            raw=line, format_name=cls.name,
            timestamp=m.group("timestamp"), hostname=None,
            facility=m.group("facility"), severity=int(m.group("severity")),
            mnemonic=m.group("mnemonic"), message=m.group("message"),
            vendor="cisco",
        )


class CiscoIOSXRParser:
    """Variante Cisco IOS-XR (routeurs cœur de réseau) : préfixe de
    localisation matérielle, nom de processus, et header à 4 segments
    (%FACILITY-SOUS_COMPOSANT-SEV-MNEMONIC au lieu de %FACILITY-SEV-MNEMONIC).
    Ex: RP/0/RP0/CPU0:Aug 26 00:03:32.693 UTC: l2rib[295]: %L2-L2RIB-3-
        ERR_STATIC_TO_LOCAL : Local host in topology 0 ...
    """
    name = "cisco_iosxr"
    PATTERN = re.compile(
        r"^(?P<location>[A-Z]+/\d+/[A-Z0-9]+/CPU\d+):"
        r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+\w+)?)\s*:\s*"
        r"(?P<process>[\w\-]+)\[\d+\]:\s*"
        r"%(?P<facility>[A-Z0-9]+)-(?P<subcomponent>[A-Z0-9_]+)-(?P<severity>\d)-(?P<mnemonic>[A-Z0-9_]+)\s*:\s*"
        r"(?P<message>.*)$"
    )

    @classmethod
    def detect(cls, line: str) -> bool:
        return bool(cls.PATTERN.match(line))

    @classmethod
    def parse(cls, line: str):
        m = cls.PATTERN.match(line)
        if not m:
            return None
        return make_record(
            raw=line, format_name=cls.name,
            timestamp=m.group("timestamp"), hostname=m.group("location"),
            facility=m.group("facility"), severity=int(m.group("severity")),
            mnemonic=m.group("mnemonic"), message=m.group("message"),
            vendor="cisco",
        )


class BSDParser:
    name = "rfc3164_bsd"
    PATTERN = re.compile(
        r"^(?:<(?P<pri>\d+)>)?"
        r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<tag>[^:]+):\s*"
        r"(?P<message>.*)$"
    )

    @classmethod
    def detect(cls, line: str) -> bool:
        return bool(cls.PATTERN.match(line))

    @classmethod
    def parse(cls, line: str) -> Optional[dict]:
        m = cls.PATTERN.match(line)
        if not m:
            return None
        pri = m.group("pri")
        severity = int(pri) % 8 if pri else None
        facility = int(pri) // 8 if pri else None
        return make_record(
            raw=line, format_name=cls.name,
            timestamp=m.group("timestamp"), hostname=m.group("hostname"),
            facility=facility, severity=severity,
            mnemonic=m.group("tag").strip(), message=m.group("message"),
            vendor="generic",
        )


class FallbackParser:
    name = "unparsed"

    @classmethod
    def parse(cls, line: str) -> dict:
        return make_record(raw=line, format_name=cls.name,
                            message=line, vendor="unknown")


# Ordre important : les formats Cisco (plus spécifiques) sont testés avant
# BSD générique, qui matcherait sinon aussi les lignes Cisco en perdant le
# découpage facility/severity/mnemonic.
PARSERS = [RFC5424Parser, CiscoIOSXRParser, CiscoParser, CiscoDeviceParser, BSDParser]


def parse_log(line: str) -> Optional[dict]:
    """Détecte le format et extrait les champs. Ne perd jamais une ligne."""
    line = line.strip()
    if not line:
        return None
    for parser in PARSERS:
        if parser.detect(line):
            record = parser.parse(line)
            if record:
                return record
    return FallbackParser.parse(line)


def parse_file(path: str) -> list:
    records = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            rec = parse_log(line)
            if rec:
                records.append(rec)
    return records


# ---------------------------------------------------------------
# Résolution hybride de la sévérité.
#
# Principe : la sévérité est SOUVENT déjà écrite dans le log lui-même
# (le "4" dans %BGP-4-VPN_NH_IF, ou le champ PRI en RFC 5424/3164).
# Quand elle est là, on la lit -- c'est fiable à 100%.
# Le modèle ML ne sert que de secours, pour les logs où aucune sévérité
# explicite n'est disponible.
#
# Faire deviner par un modèle une information déjà présente dans la donnée
# introduit des erreurs évitables : un log Cisco jamais vu à l'entraînement
# (ex: %BGP-4-VPN_NH_IF) sera mal classé, alors que son header dit
# explicitement "4" = warning.
# ---------------------------------------------------------------

SEVERITY_CODE_TO_LABEL = {
    0: "critical", 1: "critical", 2: "critical",
    3: "error",
    4: "warning",
    5: "info", 6: "info", 7: "info",
}


def severity_from_header(record: dict):
    """Retourne (label, source) si la sévérité est lisible dans le log,
    sinon (None, None).

    source vaut 'header' quand la valeur vient du log lui-même.
    """
    sev = record.get("severity")
    if sev is None:
        return None, None
    try:
        sev = int(sev)
    except (TypeError, ValueError):
        return None, None
    if sev not in SEVERITY_CODE_TO_LABEL:
        return None, None
    return SEVERITY_CODE_TO_LABEL[sev], "header"


def resolve_severity(record: dict, ml_model=None):
    """Sévérité finale d'un log : header en priorité, modèle ML en secours.

    Retourne (label, source) où source ∈ {'header', 'modele_ml', None}.
    """
    label, source = severity_from_header(record)
    if label is not None:
        return label, source

    message = record.get("message")
    if ml_model is not None and message and str(message).strip():
        return str(ml_model.predict([message])[0]), "modele_ml"

    return None, None


# ---------------------------------------------------------------
# Résolution hybride de la catégorie.
#
# Même principe que pour la sévérité : la facility Cisco (le "BGP" dans
# %BGP-4-VPN_NH_IF) indique déjà le sous-système concerné. Quand elle est
# connue, on en déduit la catégorie par règle -- c'est déterministe et
# fiable. Le modèle ML ne sert que pour les facilities inconnues.
#
# Validé sur logs réels de production : le modèle seul classait %BGP-4-VPN_NH_IF
# en 'security' (à cause des adresses IP, associées aux logs ACL du jeu
# d'entraînement) au lieu de 'routing'.
# ---------------------------------------------------------------

FACILITY_TO_CATEGORY = {
    # Routage
    "BGP": "routing", "BGP_SESSION": "routing", "OSPF": "routing",
    "OSPFv3": "routing", "EIGRP": "routing", "ISIS": "routing",
    "RIP": "routing", "CLNS": "routing", "MPLS": "routing",
    "LDP": "routing", "BFD": "routing", "BFDFSM": "routing",
    "ROUTING": "routing", "IPRT": "routing", "VPN": "routing",
    # Interfaces / liens
    "LINK": "interface", "LINEPROTO": "interface", "IFDAMP": "interface",
    "ETHERNET": "interface", "ETH": "interface", "PORT": "interface",
    "TRUNK": "interface", "EC": "interface", "ILPOWER": "interface",
    # Sécurité
    "SEC": "security", "SEC_LOGIN": "security", "AAA": "security",
    "AUTHMGR": "security", "DOT1X": "security", "CRYPTO": "security",
    "IPSEC": "security", "FW": "security", "ACLLOG": "security",
    # Matériel / environnement
    "ENVMON": "hardware", "PLATFORM": "hardware", "POWER": "hardware",
    "FAN": "hardware", "TEMP": "hardware", "HARDWARE": "hardware",
    "IOSXE_PEM": "hardware", "CMRP": "hardware",
    # Système
    "SYS": "system", "OS": "system", "IOSXE": "system",
    "PARSER": "system", "SNMP": "system", "CPU": "system",
    # Spanning tree
    "SPANTREE": "stp", "STP": "stp", "SPANTREE_FAST": "stp",
    # Services
    "DHCPD": "services", "DHCP": "services", "NTP": "services",
    "DNS": "services", "TFTP": "services",
    # QoS
    "QOS": "qos", "POLICY": "qos", "SHAPING": "qos",
}


def category_from_facility(record: dict):
    """Retourne (categorie, source) si la facility est connue, sinon (None, None)."""
    facility = record.get("facility")
    if not facility or not isinstance(facility, str):
        return None, None
    category = FACILITY_TO_CATEGORY.get(facility.upper())
    if category is None:
        return None, None
    return category, "facility"


def resolve_category(record: dict, ml_model=None):
    """Catégorie finale d'un log : facility en priorité, modèle ML en secours.

    Retourne (categorie, source) où source ∈ {'facility', 'modele_ml', None}.
    """
    category, source = category_from_facility(record)
    if category is not None:
        return category, source

    message = record.get("message")
    if ml_model is not None and message and str(message).strip():
        return str(ml_model.predict([message])[0]), "modele_ml"

    return None, None


if __name__ == "__main__":
    samples = [
        "<134>1 2026-08-10T14:07:15.003Z mymachine.example.com su 12345 ID47 - 'su root' failed for user",
        "Jul 27 09:14:22 R1-CORE %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down",
        "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
        "ceci n'est pas un log syslog reconnaissable",
    ]
    for line in samples:
        record = parse_log(line)
        print(f"[{record['format_detected']:12s}] vendor={record['vendor']:8s} "
              f"host={record['hostname']} sev={record['severity']} msg={record['message'][:50]}")