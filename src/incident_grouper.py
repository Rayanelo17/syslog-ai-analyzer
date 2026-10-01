"""
Regroupement des logs en incidents (Projet 2, étape 1).

Le Projet 1 classe les logs un par un. Or un incident réseau produit
généralement plusieurs logs : une interface qui tombe génère un LINK,
puis un LINEPROTO, puis éventuellement une chute de session BGP.
Traiter ces logs séparément fait perdre le lien entre eux.

Ce module regroupe les logs susceptibles d'appartenir au même incident,
selon des critères déterministes (pas de LLM à ce stade) :
  - proximité temporelle (fenêtre glissante)
  - même équipement, ou même interface mentionnée dans le message

Il détecte aussi les motifs répétitifs (flapping) que la classification
par log ne peut structurellement pas voir : chaque log pris isolément
est banal, c'est la répétition qui constitue l'anomalie.

Usage :
    from incident_grouper import group_into_incidents, detect_flapping
"""

import re
from datetime import datetime, timedelta
from collections import Counter

# Fenêtre par défaut : deux logs séparés de moins de 60 secondes
# peuvent appartenir au même incident.
DEFAULT_WINDOW_SECONDS = 60

# Seuil de flapping : au moins 3 changements d'état de la même
# entité dans la fenêtre indiquent une instabilité, pas un événement isolé.
FLAPPING_MIN_EVENTS = 3
FLAPPING_WINDOW_SECONDS = 120

SEVERITY_RANK = {"critical": 3, "error": 2, "warning": 1, "info": 0}


def parse_timestamp(ts_str):
    """Convertit un timestamp Cisco en datetime. Retourne None si illisible.

    Gère les formats rencontrés dans les logs réels :
      'Jun 20 09:53:52.125 UTC', 'Jun 20 09:53:52.125', 'Aug 24 09:14:22'
    L'année n'étant pas présente dans le format Cisco classique, on utilise
    l'année courante -- suffisant pour calculer des écarts entre logs.
    """
    if not ts_str or not isinstance(ts_str, str):
        return None
    cleaned = ts_str.strip()
    # Retire un éventuel fuseau en fin de chaîne
    cleaned = re.sub(r"\s+[A-Z]{2,4}$", "", cleaned)
    year = datetime.now().year
    for fmt in ("%b %d %H:%M:%S.%f", "%b %d %H:%M:%S"):
        try:
            dt = datetime.strptime(cleaned, fmt)
            return dt.replace(year=year)
        except ValueError:
            continue
    return None


def extract_entity(record):
    """Identifie l'entité concernée par un log : interface, voisin BGP, etc.

    Permet de regrouper des logs qui parlent du même objet même s'ils
    viennent de sous-systèmes différents (LINK, LINEPROTO, IFDAMP parlent
    tous de GigabitEthernet0/23 ; BFDFSM, BGP, BGP_SESSION parlent tous
    du même voisin quand ils le mentionnent).
    """
    message = str(record.get("message") or "")
    mnemonic = str(record.get("mnemonic") or "")

    # Interface, y compris sous-interfaces (GigabitEthernet0/0/1.104,
    # TenGigE0/0/0/1, Bundle-Ether10...)
    m = re.search(
        r"\b((?:Gigabit|TenGig|FastEther|Ten-?Gig|Hundred-?Gig|Forty-?Gig|Bundle-)"
        r"[A-Za-z]*[\d/\.\-]+)", message)
    if m:
        return ("interface", m.group(1))

    # Voisin BGP en IPv6 (ex: neighbor 2A00:2180:4003::108).
    # Recherché avant l'IPv4 : une adresse IPv6 ne doit pas être scindée
    # par la regex IPv4 qui matcherait un groupe de chiffres à l'intérieur.
    m = re.search(r"\b((?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4})\b", message)
    if m:
        return ("neighbor", m.group(1))

    # Voisin BGP / adresse IP en IPv4
    m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", message)
    if m:
        return ("neighbor", m.group(1))

    # Sans entité identifiable : on regroupe par type d'événement, pour
    # éviter de créer un incident distinct par log isolé.
    if mnemonic:
        return ("evenement", mnemonic)

    return ("autre", record.get("hostname") or "inconnu")


def group_into_incidents(records, window_seconds=DEFAULT_WINDOW_SECONDS):
    """Regroupe une liste de logs parsés en incidents.

    Deux logs appartiennent au même incident s'ils concernent la même
    entité (interface, voisin) et sont séparés de moins de window_seconds.

    Retourne une liste d'incidents, chacun étant un dict :
        {
          'id': 1,
          'entite': ('interface', 'GigabitEthernet0/23'),
          'debut': datetime, 'fin': datetime, 'duree_s': float,
          'nb_logs': 12,
          'severite_max': 'error',
          'categories': ['interface'],
          'hostnames': ['R1-CORE'],
          'logs': [...]
        }
    """
    enriched = []
    for r in records:
        rec = dict(r)
        rec["_dt"] = parse_timestamp(rec.get("timestamp"))
        rec["_entity"] = extract_entity(rec)
        enriched.append(rec)

    # Les logs sans timestamp exploitable ne peuvent pas être corrélés
    # temporellement : on les isole plutôt que de les rattacher au hasard.
    datables = [r for r in enriched if r["_dt"] is not None]
    orphans = [r for r in enriched if r["_dt"] is None]

    datables.sort(key=lambda r: r["_dt"])

    # Regroupement : par entité, puis par proximité temporelle
    buckets = {}
    for rec in datables:
        buckets.setdefault(rec["_entity"], []).append(rec)

    incidents = []
    for entity, logs in buckets.items():
        current = [logs[0]]
        for prev, cur in zip(logs, logs[1:]):
            gap = (cur["_dt"] - prev["_dt"]).total_seconds()
            if gap <= window_seconds:
                current.append(cur)
            else:
                incidents.append(_build_incident(entity, current))
                current = [cur]
        incidents.append(_build_incident(entity, current))

    if orphans:
        incidents.append(_build_incident(("non_dates", "-"), orphans))

    incidents = _consolidate_burst(incidents)
    incidents = _consolidate_same_entity(incidents)
    incidents = _consolidate_recurring(incidents)

    incidents.sort(key=lambda i: (SEVERITY_RANK.get(i["severite_max"], 0), i["nb_logs"]),
                    reverse=True)
    for i, inc in enumerate(incidents, start=1):
        inc["id"] = i

    return incidents


# Écart maximal entre deux incidents pour les considérer comme la même
# rafale d'événements cascadés (ex: BFD down -> BGP reset -> ADJCHANGE ->
# BFD recreated -> ADJCHANGE up, en quelques secondes).
BURST_GAP_SECONDS = 15
# Taille au-delà de laquelle un incident n'est plus fusionné dans une rafale :
# évite d'agréger un gros incident (flapping, récurrence) avec un voisin
# temporel sans rapport réel.
BURST_MAX_SIZE = 15


def _consolidate_burst(incidents):
    """Fusionne les incidents disjoints par entité mais très proches dans le
    temps, dans la même catégorie -- une rafale d'événements cascadés.

    L'extraction d'entité classe chaque log dans un seul groupe (interface,
    voisin, ou mnémonique) : une même séquence causale (BFD tombe -> BGP se
    réinitialise -> l'adjacence change -> BFD se recrée -> tout remonte)
    peut ainsi se retrouver éclatée en plusieurs incidents distincts, alors
    que la proximité temporelle extrême (quelques secondes) et les mêmes
    logs traversant plusieurs facilities liées (BFD/BFDFSM/BGP/BGP_SESSION)
    indiquent un seul événement qui se propage à travers les sous-systèmes.
    """
    candidats = [i for i in incidents
                 if i["nb_logs"] <= BURST_MAX_SIZE and not i.get("recurrent")
                 and i["debut"] is not None]
    autres = [i for i in incidents if i not in candidats]

    candidats.sort(key=lambda i: i["debut"])

    fusions = []
    courant = None
    for inc in candidats:
        if courant is None:
            courant = [inc]
            continue
        dernier = courant[-1]
        gap = (inc["debut"] - dernier["fin"]).total_seconds()
        meme_categorie = bool(set(inc["categories"]) & set(dernier["categories"]))
        if gap <= BURST_GAP_SECONDS and meme_categorie:
            courant.append(inc)
        else:
            fusions.append(courant)
            courant = [inc]
    if courant:
        fusions.append(courant)

    result = list(autres)
    for groupe in fusions:
        if len(groupe) == 1:
            result.append(groupe[0])
            continue
        merged_logs = [l for inc in groupe for l in inc["logs"]]
        # L'entité représentative : la plus fréquente parmi celles du groupe,
        # pour un libellé lisible plutôt qu'un simple "evenement".
        entites = Counter(inc["entite"] for inc in groupe)
        entite_repr = entites.most_common(1)[0][0]
        merged = _build_incident(entite_repr, merged_logs)
        merged["burst"] = True
        merged["burst_entites"] = sorted({inc["entite"][1] for inc in groupe})
        result.append(merged)

    return result


def _consolidate_same_entity(incidents, min_episodes=2):
    """Fusionne les incidents séparés qui concernent la même entité.

    Une session BGP instable produit plusieurs épisodes espacés de quelques
    minutes : la fenêtre temporelle les sépare en incidents distincts, alors
    qu'opérationnellement c'est un seul problème récurrent sur le même voisin.
    Les regrouper donne le vrai diagnostic ("session instable, 4 épisodes")
    plutôt qu'une liste d'événements sans lien apparent.
    """
    by_entity = {}
    for inc in incidents:
        by_entity.setdefault(inc["entite"], []).append(inc)

    result = []
    for entity, group in by_entity.items():
        if len(group) < min_episodes:
            result.extend(group)
            continue

        merged_logs = [l for inc in group for l in inc["logs"]]
        merged = _build_incident(entity, merged_logs)
        merged["episodes"] = len(group)
        merged["episodes_details"] = sorted(
            [{"debut": inc["debut"], "nb_logs": inc["nb_logs"],
              "duree_s": inc["duree_s"]} for inc in group],
            key=lambda e: (e["debut"] is None, e["debut"]),
        )
        # La détection de flapping doit rester évaluée épisode par épisode :
        # fusionner des épisodes espacés de plusieurs heures ferait disparaître
        # une instabilité pourtant bien réelle à l'intérieur d'un épisode.
        flapping_episodes = [detect_flapping(inc) for inc in group]
        flapping_episodes = [f for f in flapping_episodes if f]
        if flapping_episodes:
            merged["flapping_episodes"] = flapping_episodes
        # La durée totale n'a pas de sens sur des épisodes disjoints :
        # on retient la durée du plus long épisode.
        merged["duree_s"] = max((inc["duree_s"] for inc in group), default=0.0)
        result.append(merged)

    return result


def _consolidate_recurring(incidents, min_occurrences=3):
    """Fusionne les incidents de même nature en un incident récurrent.

    Un même avertissement de configuration (ex: %BGP-4-VPN_NH_IF) émis pour
    dix voisins différents ne constitue pas dix incidents distincts, mais un
    seul problème récurrent. Les regrouper évite de noyer les vrais incidents
    dans une liste de doublons.

    On ne fusionne que les incidents dont tous les logs partagent le même
    mnémonique unique : un incident mêlant plusieurs types d'événements
    (ex: UPDOWN + ADJCHANGE sur une interface qui flappe) décrit une vraie
    séquence causale et doit rester distinct.
    """
    mono = [i for i in incidents
            if len(i["mnemonics"]) == 1 and not i.get("flapping_episodes")]
    others = [i for i in incidents if i not in mono]

    by_mnemonic = {}
    for inc in mono:
        key = next(iter(inc["mnemonics"]), None)
        by_mnemonic.setdefault(key, []).append(inc)

    result = list(others)
    for mnemonic, group in by_mnemonic.items():
        if mnemonic and len(group) >= min_occurrences:
            merged_logs = [l for inc in group for l in inc["logs"]]
            entites = sorted({str(inc["entite"][1]) for inc in group})
            merged = _build_incident(("recurrent", mnemonic), merged_logs)
            merged["recurrent"] = True
            merged["entites_concernees"] = entites
            merged["duree_s"] = max((inc["duree_s"] for inc in group), default=0.0)
            result.append(merged)
        else:
            result.extend(group)

    return result


def _build_incident(entity, logs):
    dts = [l["_dt"] for l in logs if l.get("_dt")]
    debut = min(dts) if dts else None
    fin = max(dts) if dts else None
    duree = (fin - debut).total_seconds() if debut and fin else 0.0

    severites = [l.get("severity_pred") or l.get("severity_label") for l in logs]
    severites = [s for s in severites if s]
    severite_max = max(severites, key=lambda s: SEVERITY_RANK.get(s, 0)) if severites else "info"

    categories = sorted({l.get("category_pred") for l in logs if l.get("category_pred")})
    hostnames = sorted({l.get("hostname") for l in logs if l.get("hostname")})
    mnemonics = Counter(l.get("mnemonic") for l in logs if l.get("mnemonic"))

    return {
        "entite": entity,
        "debut": debut,
        "fin": fin,
        "duree_s": duree,
        "nb_logs": len(logs),
        "severite_max": severite_max,
        "categories": categories,
        "hostnames": hostnames,
        "mnemonics": dict(mnemonics),
        "logs": logs,
    }


def detect_flapping(incident,
                     min_events=FLAPPING_MIN_EVENTS,
                     window_seconds=FLAPPING_WINDOW_SECONDS):
    """Détecte une instabilité répétitive (flapping) dans un incident.

    Cherche des transitions up/down répétées sur la même entité.
    C'est le type d'anomalie invisible à la classification par log :
    chaque %LINK-3-UPDOWN isolé est banal, trois en quinze secondes
    signalent un lien instable.

    Retourne un dict de diagnostic, ou None si pas de flapping.
    """
    # Incident consolidé : le flapping a déjà été évalué épisode par épisode.
    # On retourne le résumé du plus significatif plutôt que de réévaluer sur
    # l'ensemble, ce qui diluerait l'instabilité dans un intervalle trop large.
    pre = incident.get("flapping_episodes")
    if pre:
        pire = max(pre, key=lambda f: f["nb_changements"])
        if len(pre) > 1:
            return {**pire,
                    "nb_episodes": len(pre),
                    "resume": (f"{len(pre)} épisodes d'instabilité, le plus marqué : "
                                f"{pire['nb_changements']} changements d'état en "
                                f"{pire['duree_s']:.0f} secondes sur {incident['entite'][1]}")}
        return pire

    transitions = []
    for log in incident["logs"]:
        msg = str(log.get("message") or "").lower()
        dt = log.get("_dt")
        if dt is None:
            continue
        # On ne retient que les vraies transitions d'état, pas tout log
        # contenant "up" ou "down" (BFD_SESS_UP décrit un état, pas
        # nécessairement un changement dans une séquence instable).
        if re.search(r"(changed state to|state to|going|turned into the|update .*state to)\s+down", msg) \
                or re.search(r"\bdown\b.*\b(notification|reset|expired)\b", msg):
            transitions.append((dt, "down"))
        elif re.search(r"(changed state to|state to|going|turned into the|update .*state to)\s+up", msg):
            transitions.append((dt, "up"))

    if len(transitions) < min_events:
        return None

    transitions.sort(key=lambda t: t[0])

    # Compte les vrais changements d'état (ignore les répétitions consécutives
    # du même état, qui viennent des sous-systèmes multiples : LINK, LINEPROTO,
    # IFDAMP signalent tous le même changement)
    changes = []
    last_state = None
    for dt, state in transitions:
        if state != last_state:
            changes.append((dt, state))
            last_state = state

    if len(changes) < min_events:
        return None

    span = (changes[-1][0] - changes[0][0]).total_seconds()
    if span > window_seconds:
        return None

    return {
        "detecte": True,
        "nb_changements": len(changes),
        "duree_s": span,
        "sequence": [s for _, s in changes],
        "resume": (f"{len(changes)} changements d'état en {span:.0f} secondes "
                    f"sur {incident['entite'][1]}"),
    }


def summarize_incidents(incidents):
    """Statistiques globales sur un ensemble d'incidents."""
    flapping = [i for i in incidents if detect_flapping(i)]
    return {
        "nb_incidents": len(incidents),
        "nb_logs_total": sum(i["nb_logs"] for i in incidents),
        "nb_flapping": len(flapping),
        "incidents_critiques": sum(1 for i in incidents
                                    if i["severite_max"] in ("critical", "error")),
    }


if __name__ == "__main__":
    import sys
    from syslog_parser import parse_log, resolve_severity, resolve_category

    path = sys.argv[1] if len(sys.argv) > 1 else None
    if not path:
        print("Usage : python incident_grouper.py <fichier_de_logs.txt>")
        sys.exit(1)

    with open(path, encoding="utf-8", errors="replace") as f:
        lines = [l.strip() for l in f if l.strip()]

    records = []
    for line in lines:
        rec = parse_log(line)
        if not rec:
            continue
        sev, _ = resolve_severity(rec)
        cat, _ = resolve_category(rec)
        rec["severity_pred"] = sev or "info"
        rec["category_pred"] = cat or "unknown"
        records.append(rec)

    incidents = group_into_incidents(records)
    stats = summarize_incidents(incidents)

    print(f"{stats['nb_logs_total']} logs regroupés en {stats['nb_incidents']} incidents")
    print(f"({stats['incidents_critiques']} incidents de sévérité error ou critical, "
          f"{stats['nb_flapping']} cas de flapping)")
    print()

    for inc in incidents:
        flap = detect_flapping(inc)
        marqueur = "  [FLAPPING]" if flap else ""
        if inc.get("recurrent"):
            marqueur += "  [RECURRENT]"
        if inc.get("episodes", 0) > 1:
            marqueur += f"  [{inc['episodes']} EPISODES]"
        print(f"Incident {inc['id']} · {inc['entite'][1]} · {inc['severite_max'].upper()}{marqueur}")
        if inc.get("recurrent"):
            print(f"  {inc['nb_logs']} occurrences réparties dans le temps · "
                  f"{', '.join(inc['categories']) or '-'} · "
                  f"mnémoniques : {', '.join(inc['mnemonics'].keys())}")
        elif inc.get("episodes", 0) > 1:
            print(f"  {inc['nb_logs']} logs · épisode le plus long : {inc['duree_s']:.0f}s · "
                  f"{', '.join(inc['categories']) or '-'} · "
                  f"mnémoniques : {', '.join(inc['mnemonics'].keys())}")
        else:
            print(f"  {inc['nb_logs']} logs sur {inc['duree_s']:.0f}s · "
                  f"{', '.join(inc['categories']) or '-'} · "
                  f"mnémoniques : {', '.join(inc['mnemonics'].keys())}")
        if inc.get("episodes", 0) > 1:
            heures = [e["debut"].strftime("%H:%M:%S") for e in inc["episodes_details"]
                      if e["debut"]]
            print(f"  -> {inc['episodes']} épisodes distincts : {', '.join(heures[:6])}"
                  f"{' ...' if len(heures) > 6 else ''}")
        if inc.get("entites_concernees") and len(inc["entites_concernees"]) > 1:
            n = len(inc["entites_concernees"])
            print(f"  -> même événement sur {n} entités : "
                  f"{', '.join(inc['entites_concernees'][:4])}"
                  f"{' ...' if n > 4 else ''}")
        if flap:
            print(f"  -> {flap['resume']}")
        print()