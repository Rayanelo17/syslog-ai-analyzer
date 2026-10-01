"""
Analyse des incidents par LLM local (Projet 2, étapes 2-3).

Prend les incidents produits par incident_grouper.py et demande à un
modèle local (via Ollama) de rédiger un diagnostic : cause probable,
niveau de priorité, action recommandée.

Choix d'un modèle local plutôt qu'une API externe : les logs réseau
contiennent de la topologie et de l'adressage interne, qui ne doivent
pas quitter l'infrastructure.

Prérequis :
    - Ollama installé et lancé (https://ollama.com)
    - Un modèle téléchargé : ollama pull mistral

Usage :
    python llm_analyzer.py ../data/mon_fichier.txt
    python llm_analyzer.py ../data/mon_fichier.txt --model llama3.1
"""

import json
import re
import urllib.request
import urllib.error

OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "mistral"
TIMEOUT_SECONDS = 300  # les incidents volumineux (plusieurs mnémoniques,
                        # base de connaissances étendue) peuvent dépasser
                        # 180s sur un CPU chargé -- observé sur un incident
                        # de 68 logs avec 6 mnémoniques différents

# Nombre de logs d'exemple envoyés au modèle par incident.
# Envoyer les 45 logs d'un incident de flapping serait inutile et coûteux :
# les premiers suffisent à caractériser le motif.
MAX_LOGS_IN_PROMPT = 12


SYSTEM_CONTEXT = """Tu es un ingénieur réseau expérimenté travaillant dans le \
centre d'opérations (NOC) d'un opérateur télécom. Tu analyses des incidents \
détectés automatiquement à partir de logs syslog d'équipements Cisco.

Ton rôle est de produire un diagnostic court et actionnable, destiné à un \
technicien qui doit décider s'il intervient.

Règles :
- Reste factuel : ne suppose rien qui ne soit pas dans les logs fournis.
- Appuie-toi sur le contexte technique fourni pour identifier la cause la plus probable.
- Évite les formulations vagues du type "problème de configuration ou de communication" : \
sois précis sur ce qui doit être vérifié.
- Si les logs ne permettent pas de conclure, dis-le explicitement.
- Sois concis : 3 à 5 phrases maximum.
- Réponds en français, en gardant les termes techniques en anglais \
(nexthop, loopback, flapping, adjacency...)."""


# ---------------------------------------------------------------------
# Base de connaissances des mnémoniques Cisco rencontrés.
#
# Un modèle 7B connaît le vocabulaire réseau général mais pas les
# conventions Cisco : sans ce contexte, il produit des diagnostics vagues
# ("problème de configuration ou de communication"). Lui fournir la
# signification et les causes typiques de chaque mnémonique présent dans
# l'incident améliore nettement la précision du diagnostic.
# ---------------------------------------------------------------------

CISCO_KNOWLEDGE = {
    "UPDOWN": {
        "signification": "Changement d'état d'une interface ou d'un protocole de ligne (up/down).",
        "causes": "Répété sur une courte période (flapping) : défaut physique en premier lieu "
                   "— câble, connecteur, module optique SFP, atténuation ou puissance optique hors "
                   "seuil. Plus rarement : négociation duplex/vitesse, ou coupure côté distant.",
    },
    "FLAPPED": {
        "signification": "Interface signalée comme instable par le système.",
        "causes": "Défaut physique du lien, module optique défaillant, ou instabilité côté distant.",
    },
    "ADJCHANGE": {
        "signification": "Changement d'état d'une adjacence de protocole de routage "
                          "(ISIS, OSPF ou BGP selon la facility).",
        "causes": "Conséquence habituelle d'une perte du lien sous-jacent ou d'une session BFD "
                   "tombée. Le motif 'bfd neighbor down' indique que c'est BFD qui a détecté la "
                   "coupure en premier, donc une cause au niveau du lien plutôt que du protocole.",
    },
    "NBR_RESET": {
        "signification": "Réinitialisation d'une session avec un voisin BGP.",
        "causes": "Perte de connectivité vers le voisin, expiration du hold timer, session BFD "
                   "tombée, ou réinitialisation administrative.",
    },
    "VPN_NH_IF": {
        "signification": "Avertissement BGP : le next-hop annoncé par un voisin n'est pas une "
                          "adresse de loopback.",
        "causes": "Choix de configuration, pas une panne. En MPLS/VPN, la bonne pratique est "
                   "d'utiliser une loopback comme next-hop : elle reste joignable même si une "
                   "interface physique tombe. Un next-hop sur interface physique rend le service "
                   "vulnérable à toute coupure de cette interface. Priorité généralement basse à "
                   "moyenne : à corriger lors d'une fenêtre de maintenance, pas en urgence.",
    },
    "BFD_SESS_DOWN": {
        "signification": "Session BFD tombée. BFD détecte les pertes de connectivité en quelques "
                          "millisecondes, bien plus vite que les timers des protocoles de routage.",
        "causes": "Coupure réelle du lien, ou timers BFD trop agressifs par rapport à la latence "
                   "réelle du lien (faux positifs). Le motif 'echo function failed' ou 'detect "
                   "timer expired' oriente vers la seconde hypothèse.",
    },
    "BFD_SESS_UP": {
        "signification": "Session BFD rétablie.",
        "causes": "Retour à la normale après une coupure. Répété fréquemment : instabilité du lien.",
    },
    "BFD_SESS_CREATED": {
        "signification": "Nouvelle session BFD créée.",
        "causes": "Établissement normal d'une session, ou recréation après destruction.",
    },
    "BFD_SESS_DESTROYED": {
        "signification": "Session BFD détruite.",
        "causes": "Suppression de configuration, ou perte prolongée du voisin. Alterné avec "
                   "BFD_SESS_CREATED de façon répétée : instabilité de session.",
    },
    "PS_FAIL": {
        "signification": "Défaillance d'une alimentation.",
        "causes": "Panne matérielle de l'alimentation, ou coupure de la source électrique. "
                   "Vérifier la redondance : si la seconde alimentation est également touchée, "
                   "l'équipement risque l'arrêt.",
    },
    "FAN": {
        "signification": "Défaillance du système de ventilation.",
        "causes": "Ventilateur bloqué ou hors service. Risque de surchauffe puis d'arrêt "
                   "thermique de l'équipement. Intervention urgente.",
    },
    "TEMP": {
        "signification": "Température hors seuil.",
        "causes": "Ventilation défaillante, obstruction des grilles d'aération, ou température "
                   "ambiante trop élevée dans le local technique.",
    },
    "MALLOCFAIL": {
        "signification": "Échec d'allocation mémoire.",
        "causes": "Fuite mémoire d'un processus, table de routage trop volumineuse, ou attaque. "
                   "Peut précéder un redémarrage inopiné.",
    },
    "CPUHOG": {
        "signification": "Un processus a monopolisé le CPU au-delà du seuil autorisé.",
        "causes": "Pic de trafic traité en process-switching, boucle de routage, ou bug logiciel.",
    },
    "LOGIN_FAILED": {
        "signification": "Tentative d'authentification échouée.",
        "causes": "Erreur de saisie légitime, ou tentative d'accès non autorisée si répétée "
                   "depuis la même source.",
    },
    "IPACCESSLOGP": {
        "signification": "Paquet bloqué par une liste de contrôle d'accès (ACL).",
        "causes": "Fonctionnement normal de l'ACL. Volume élevé depuis une même source : "
                   "possible balayage ou tentative d'intrusion.",
    },
    "MAXPFXEXCEED": {
        "signification": "Nombre de préfixes reçus d'un voisin BGP proche ou au-delà de la limite.",
        "causes": "Fuite de routes chez le voisin, erreur de filtrage, ou limite configurée trop "
                   "basse. Risque de coupure de la session si la limite stricte est atteinte.",
    },
    "BLOCK_BPDUGUARD": {
        "signification": "BPDU reçu sur un port protégé par BPDU Guard, port désactivé.",
        "causes": "Équipement non autorisé (switch, borne) branché sur un port d'accès, ou "
                   "erreur de câblage créant une boucle potentielle.",
    },
    "PEER_UNREACH": {
        "signification": "Serveur NTP injoignable, synchronisation horaire perdue.",
        "causes": "Panne du serveur NTP, problème de routage vers celui-ci, ou filtrage. "
                   "Impact : dérive d'horloge, horodatage des logs peu fiable.",
    },
}


def build_knowledge_section(incident):
    """Assemble le contexte technique pour les mnémoniques de l'incident."""
    blocs = []
    for mnemonic in incident["mnemonics"]:
        info = CISCO_KNOWLEDGE.get(mnemonic)
        if not info:
            continue
        blocs.append(f"**{mnemonic}** : {info['signification']}\n"
                      f"Causes typiques : {info['causes']}")
    if not blocs:
        return ""
    return ("\n## Contexte technique\n\n"
            "Informations de référence sur les événements présents dans cet incident :\n\n"
            + "\n\n".join(blocs) + "\n")


def check_ollama(model=DEFAULT_MODEL):
    """Vérifie qu'Ollama est joignable et que le modèle est disponible.

    Retourne (ok: bool, message: str).
    """
    try:
        req = urllib.request.Request("http://localhost:11434/api/tags")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        models = [m.get("name", "") for m in data.get("models", [])]
        if not models:
            return False, "Ollama répond mais aucun modèle n'est installé (ollama pull mistral)."
        # Ollama nomme les modèles 'mistral:latest'
        if not any(m.split(":")[0] == model.split(":")[0] for m in models):
            return False, (f"Modèle '{model}' introuvable. Modèles disponibles : "
                            f"{', '.join(models)}")
        return True, f"Ollama opérationnel, modèle '{model}' disponible."
    except urllib.error.URLError:
        return False, ("Ollama ne répond pas sur localhost:11434. "
                        "Vérifie qu'il est bien lancé.")
    except Exception as e:
        return False, f"Erreur de connexion à Ollama : {e}"


def build_prompt(incident, flapping=None):
    """Construit le prompt décrivant un incident au modèle."""
    entite_type, entite_nom = incident["entite"]
    logs = incident["logs"][:MAX_LOGS_IN_PROMPT]

    lignes = []
    for log in logs:
        ts = log.get("timestamp") or "?"
        fac = log.get("facility") or "?"
        sev = log.get("severity")
        mne = log.get("mnemonic") or "?"
        msg = log.get("message") or ""
        lignes.append(f"{ts} %{fac}-{sev}-{mne}: {msg}")

    tronque = ""
    if incident["nb_logs"] > len(logs):
        tronque = f"\n(... {incident['nb_logs'] - len(logs)} logs supplémentaires du même type)"

    contexte = [
        f"Entité concernée : {entite_nom} ({entite_type})",
        f"Nombre de logs : {incident['nb_logs']}",
        f"Sévérité la plus élevée : {incident['severite_max']}",
        f"Catégories : {', '.join(incident['categories']) or 'non déterminée'}",
        f"Types d'événements : {', '.join(incident['mnemonics'].keys())}",
    ]
    if incident.get("episodes", 0) > 1:
        contexte.append(f"Récurrence : {incident['episodes']} épisodes distincts "
                         f"(épisode le plus long : {incident['duree_s']:.0f}s)")
    else:
        contexte.append(f"Durée : {incident['duree_s']:.0f} secondes")

    if incident.get("recurrent") and incident.get("entites_concernees"):
        contexte.append(f"Même événement observé sur {len(incident['entites_concernees'])} "
                         f"entités différentes")

    if flapping:
        contexte.append(f"Instabilité détectée : {flapping['resume']}")

    return f"""{SYSTEM_CONTEXT}

## Incident détecté

{chr(10).join('- ' + c for c in contexte)}
{build_knowledge_section(incident)}
## Logs bruts

{chr(10).join(lignes)}{tronque}

## Ta réponse

Réponds strictement dans ce format, sans rien ajouter avant ou après :

DIAGNOSTIC : <ce qui se passe concrètement, en une ou deux phrases>
CAUSE PROBABLE : <l'explication la plus vraisemblable, en t'appuyant sur le contexte technique>
PRIORITE : <haute, moyenne ou basse>
ACTION : <ce que le technicien doit vérifier précisément, pas une consigne générique>"""


def query_ollama(prompt, model=DEFAULT_MODEL, timeout=TIMEOUT_SECONDS):
    """Envoie un prompt au modèle local et retourne sa réponse texte."""
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.2},  # faible : on veut du factuel, pas de la créativité
    }).encode("utf-8")

    req = urllib.request.Request(
        OLLAMA_URL, data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data.get("response", "").strip()


def parse_llm_response(text):
    """Extrait les champs structurés de la réponse du modèle.

    Le modèle ne respecte pas toujours le format demandé : on récupère ce
    qu'on peut et on conserve la réponse brute pour ne rien perdre.
    """
    champs = {"diagnostic": None, "cause": None, "priorite": None, "action": None}
    # Les petits modèles respectent mal la casse et l'espacement du format
    # demandé ("Cause probable:" au lieu de "CAUSE PROBABLE :"). Le
    # délimiteur ci-dessous accepte toutes ces variantes.
    stop = r"(?=\n\s*(?:DIAGNOSTIC|CAUSE(?:\s+PROBABLE)?|PRIORIT[EÉ]|ACTION)\s*:|\Z)"
    motifs = {
        "diagnostic": r"DIAGNOSTIC\s*:\s*(.+?)" + stop,
        "cause": r"CAUSE(?:\s+PROBABLE)?\s*:\s*(.+?)" + stop,
        "priorite": r"PRIORIT[EÉ]\s*:\s*(.+?)" + stop,
        "action": r"ACTION\s*:\s*(.+?)" + stop,
    }
    for cle, motif in motifs.items():
        m = re.search(motif, text, re.IGNORECASE | re.DOTALL)
        if m:
            champs[cle] = " ".join(m.group(1).split())

    # Normalise la priorité sur trois valeurs attendues
    if champs["priorite"]:
        p = champs["priorite"].lower()
        if "haute" in p or "élevée" in p or "elevee" in p:
            champs["priorite"] = "haute"
        elif "basse" in p or "faible" in p:
            champs["priorite"] = "basse"
        elif "moyenne" in p:
            champs["priorite"] = "moyenne"

    champs["reponse_brute"] = text
    return champs


def analyze_incident(incident, flapping=None, model=DEFAULT_MODEL):
    """Analyse un incident et retourne le diagnostic structuré."""
    prompt = build_prompt(incident, flapping)
    try:
        reponse = query_ollama(prompt, model=model)
    except urllib.error.URLError as e:
        return {"erreur": f"Ollama injoignable : {e}"}
    except Exception as e:
        return {"erreur": f"Erreur lors de l'appel au modèle : {e}"}
    return parse_llm_response(reponse)


def analyze_incidents(incidents, model=DEFAULT_MODEL, limit=None, verbose=True):
    """Analyse une liste d'incidents, du plus grave au moins grave.

    limit permet de ne traiter que les N premiers : sur un modèle local,
    chaque analyse prend plusieurs secondes.
    """
    from incident_grouper import detect_flapping

    a_traiter = incidents[:limit] if limit else incidents
    resultats = []
    for i, inc in enumerate(a_traiter, start=1):
        if verbose:
            print(f"[{i}/{len(a_traiter)}] Analyse de l'incident {inc['id']} "
                  f"({inc['entite'][1]})...", flush=True)
        flap = detect_flapping(inc)
        diag = analyze_incident(inc, flap, model=model)
        resultats.append({"incident": inc, "diagnostic": diag})
    return resultats


if __name__ == "__main__":
    import sys
    import argparse

    from syslog_parser import parse_log, resolve_severity, resolve_category
    from incident_grouper import group_into_incidents, detect_flapping

    ap = argparse.ArgumentParser(description="Analyse des incidents par LLM local.")
    ap.add_argument("fichier", help="Fichier de logs à analyser")
    ap.add_argument("--model", default=DEFAULT_MODEL, help="Modèle Ollama (défaut : mistral)")
    ap.add_argument("--limit", type=int, default=3,
                     help="Nombre d'incidents à analyser (défaut : 3, les plus graves)")
    args = ap.parse_args()

    ok, message = check_ollama(args.model)
    print(message)
    if not ok:
        sys.exit(1)
    print()

    with open(args.fichier, encoding="utf-8", errors="replace") as f:
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
    print(f"{len(records)} logs regroupés en {len(incidents)} incidents.")
    print(f"Analyse des {min(args.limit, len(incidents))} plus graves par '{args.model}'...")
    print()

    resultats = analyze_incidents(incidents, model=args.model, limit=args.limit)

    print()
    print("=" * 70)
    for r in resultats:
        inc, diag = r["incident"], r["diagnostic"]
        print(f"\nINCIDENT {inc['id']} · {inc['entite'][1]} · "
              f"{inc['severite_max'].upper()} · {inc['nb_logs']} logs")
        print("-" * 70)
        if diag.get("erreur"):
            print(f"  {diag['erreur']}")
            continue
        for cle, libelle in [("diagnostic", "Diagnostic"), ("cause", "Cause probable"),
                              ("priorite", "Priorité"), ("action", "Action")]:
            valeur = diag.get(cle)
            if valeur:
                print(f"  {libelle:15s}: {valeur}")
        if not any(diag.get(c) for c in ("diagnostic", "cause", "priorite", "action")):
            print("  (format non reconnu, réponse brute)")
            print(f"  {diag.get('reponse_brute', '')[:400]}")
    print()