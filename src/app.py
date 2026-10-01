"""
Interface graphique du Projet 1 (Télécom NOC) -- thème "salle de supervision réseau".

Une interface web locale, pensée comme un mini centre de supervision (NOC) :
génération de logs en direct, classification par les 3 modèles ML,
visualisation sous forme de cartes, graphiques et carte du réseau.

Lancement :
    streamlit run app.py

(Depuis src/, avec le venv activé. Ouvre automatiquement une page
dans ton navigateur -- ferme le terminal ou Ctrl+C pour l'arrêter.)
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import joblib
import random
import math
from pathlib import Path
from datetime import datetime

from syslog_parser import parse_log, resolve_severity, resolve_category
from live_log_generator import generate_one_line, HOSTS

st.set_page_config(page_title="Telecom · NOC Dashboard", layout="wide", page_icon="🛰️")

SEVERITY_TO_LABEL = {
    0: "critical", 1: "critical", 2: "critical",
    3: "error",
    4: "warning",
    5: "info", 6: "info", 7: "info",
}

FACILITY_MNEMONIC_TO_CATEGORY = {
    ("LINK", "UPDOWN"): "interface", ("LINEPROTO", "UPDOWN"): "interface", ("LINK", "FLAPPED"): "interface",
    ("BGP", "ADJCHANGE"): "routing", ("BGP", "MAXPFXEXCEED"): "routing", ("OSPF", "ADJCHG"): "routing",
    ("SEC", "IPACCESSLOGP"): "security", ("SEC_LOGIN", "LOGIN_SUCCESS"): "security", ("SEC_LOGIN", "LOGIN_FAILED"): "security",
    ("ENVMON", "FAN"): "hardware", ("PLATFORM", "PS_FAIL"): "hardware", ("SYS", "MALLOCFAIL"): "hardware",
    ("SYS", "RELOAD"): "system", ("SYS", "CPUHOG"): "system",
    ("QOS", "QUEUE_DROPS"): "qos",
    ("SPANTREE", "BLOCK_BPDUGUARD"): "stp",
    ("NTP", "PEER_UNREACH"): "services",
}

SEVERITY_COLOR = {
    "critical": "#e5484d",
    "error":    "#f0883e",
    "warning":  "#e8c547",
    "info":     "#4c9aff",
}

# ---------------------------------------------------------------------
# THÈME VISUEL -- sobre et professionnel : bleu marine / gris,
# typographie neutre, sans effets néon.
# ---------------------------------------------------------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

html, body, [class*="css"]  { font-family: 'Inter', sans-serif; }
.stApp { background: #10151f; }

/* Bandeau de titre */
.noc-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 20px 28px; border-radius: 10px; margin-bottom: 20px;
    background: #161d2b;
    border: 1px solid #26314a;
}
.noc-title { font-size: 22px; font-weight: 700; color: #e8edf5; letter-spacing: 0.2px; }
.noc-sub { font-family: 'JetBrains Mono', monospace; font-size: 11.5px; color: #7b8aa3; margin-top: 4px; letter-spacing: 0.3px; }
.noc-live {
    font-family: 'Inter', sans-serif; font-size: 12px; font-weight: 600; color: #4ade9b;
    border: 1px solid #2d4a3d; padding: 6px 14px; border-radius: 6px;
    background: #16241d;
}
.noc-live-dot {
    display:inline-block; width:7px; height:7px; border-radius:50%;
    background:#4ade9b; margin-right:7px;
    animation: pulse 2s infinite;
}
@keyframes pulse { 0%{opacity:1;} 50%{opacity:0.4;} 100%{opacity:1;} }

/* Cartes KPI */
.kpi-card {
    border-radius: 10px; padding: 16px 18px; height: 108px;
    background: #161d2b; border: 1px solid #26314a;
    position: relative; overflow: hidden;
}
.kpi-card::before {
    content: ""; position: absolute; left:0; top:0; bottom:0; width: 3px;
}
.kpi-label { font-family: 'Inter', sans-serif; font-size: 11.5px; color: #7b8aa3; text-transform: uppercase; letter-spacing: 0.6px; font-weight: 600; }
.kpi-value { font-size: 28px; font-weight: 700; margin-top: 6px; color: #e8edf5; }
.kpi-sub   { font-size: 12px; color: #5c6b85; margin-top: 2px; }

/* Tags de sévérité dans le tableau custom */
.sev-badge {
    font-family: 'JetBrains Mono', monospace; font-size: 11px; font-weight: 600;
    padding: 3px 9px; border-radius: 999px; display: inline-block;
}

section[data-testid="stSidebar"] { background: #0a0e17; border-right: 1px solid rgba(255,255,255,0.06); }

/* Le masquage du bouton Deploy / menu est géré par .streamlit/config.toml
   (toolbarMode = "minimal"). On masque juste le footer ici, sans toucher
   au bouton d'ouverture de la sidebar. */
footer {visibility: hidden;}
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def load_models():
    return (
        joblib.load("../models/severity_classifier.joblib"),
        joblib.load("../models/category_classifier.joblib"),
        joblib.load("../models/anomaly_classifier.joblib"),
    )


@st.cache_data
def host_positions(hosts):
    """Place les équipements sur un cercle, pour la carte réseau."""
    n = len(hosts)
    pos = {}
    for i, h in enumerate(hosts):
        angle = 2 * math.pi * i / n
        pos[h] = (math.cos(angle), math.sin(angle))
    return pos


# =======================================================================
# BANDEAU DE TITRE
# =======================================================================
st.markdown(f"""
<div class="noc-header">
    <div>
        <div class="noc-title">🛰️ Telecom · NOC Intelligence Dashboard</div>
        <div class="noc-sub">PROJET 1 — CLASSIFICATION SYSLOG · PARSING → NETTOYAGE → ML (SÉVÉRITÉ / CATÉGORIE / ANOMALIE)</div>
    </div>
    <div class="noc-live"><span class="noc-live-dot"></span>SYSTÈME PRÊT</div>
</div>
""", unsafe_allow_html=True)

tab1, tab2, tab5, tab3, tab4 = st.tabs([
    "🎛️  Supervision en direct",
    "📝  Analyse manuelle",
    "🧠  Diagnostic IA",
    "📈  Performance des modèles",
    "🧭  Architecture du pipeline",
])

# =======================================================================
# ONGLET 1 : SUPERVISION EN DIRECT
# =======================================================================
with tab1:
    with st.sidebar:
        st.markdown("### ⚙️ Paramètres de simulation")
        n_logs = st.slider("Nombre de logs", 10, 500, 120, step=10)
        error_rate = st.slider("Taux d'erreurs injectées", 0.0, 0.5, 0.1, step=0.05,
                                help="Simule des logs corrompus/tronqués pour tester la robustesse du pipeline")

        st.markdown("---")
        st.markdown("##### Seuil de détection d'anomalie")
        anomaly_threshold = st.slider(
            "Seuil de probabilité", 0.10, 0.90, 0.50, step=0.05,
            help="Un log est signalé comme anomalie si la probabilité prédite dépasse ce seuil. "
                 "Seuil bas = plus d'alertes (meilleur rappel, plus de faux positifs). "
                 "Seuil haut = moins d'alertes (meilleure précision, risque de rater des incidents).",
        )
        if anomaly_threshold < 0.4:
            st.caption("⚠️ Seuil bas : privilégie le rappel — peu d'incidents ratés, mais plus de fausses alertes.")
        elif anomaly_threshold > 0.65:
            st.caption("⚠️ Seuil haut : privilégie la précision — alertes plus fiables, mais risque de rater des incidents.")
        else:
            st.caption("Seuil équilibré (comportement par défaut du modèle).")
        run = st.button("▶️  Lancer la supervision", type="primary", use_container_width=True)
        st.caption("Chaque lancement génère de nouveaux logs aléatoires, jamais vus par les modèles à l'entraînement.")

    if run:
        with st.spinner("📡 Réception et analyse du flux de logs..."):
            records = []
            for _ in range(n_logs):
                line, is_error = generate_one_line(error_rate)
                rec = parse_log(line)
                if rec:
                    rec["error_injected"] = is_error
                    records.append(rec)

            df = pd.DataFrame(records)
            has_message = df["message"].notna() & (df["message"].str.strip() != "")
            classifiable = df[has_message].copy()
            unclassifiable = df[~has_message].copy()

            severity_model, category_model, anomaly_model = load_models()

            classifiable["severity_true"] = classifiable["severity"].map(SEVERITY_TO_LABEL)
            classifiable["category_true"] = classifiable.apply(
                lambda r: FACILITY_MNEMONIC_TO_CATEGORY.get((r["facility"], r["mnemonic"]), "unknown"), axis=1
            )
            classifiable["anomaly_true"] = (classifiable["severity"] <= 4).astype(int)

            # Sévérité hybride : lue dans le header du log quand elle existe,
            # devinée par le modèle ML seulement en dernier recours.
            _sev = classifiable.apply(
                lambda r: resolve_severity(r.to_dict(), severity_model), axis=1)
            classifiable["severity_pred"] = [s[0] if s[0] else "info" for s in _sev]
            classifiable["severity_source"] = [s[1] if s[1] else "inconnu" for s in _sev]
            # Catégorie hybride : déduite de la facility Cisco quand elle est
            # connue, devinée par le modèle ML sinon.
            _cat = classifiable.apply(
                lambda r: resolve_category(r.to_dict(), category_model), axis=1)
            classifiable["category_pred"] = [c[0] if c[0] else "unknown" for c in _cat]
            classifiable["category_source"] = [c[1] if c[1] else "inconnu" for c in _cat]

            # Détection d'anomalie avec seuil ajustable : on récupère la probabilité
            # de la classe 1 (anomalie) plutôt que la classe prédite par défaut (seuil 0.5).
            anomaly_proba = anomaly_model.predict_proba(classifiable["message"])[:, 1]
            classifiable["anomaly_proba"] = anomaly_proba
            classifiable["anomaly_pred"] = (anomaly_proba >= anomaly_threshold).astype(int)
            classifiable["anomaly_pred_label"] = classifiable["anomaly_pred"].map({0: "normal", 1: "anormal"})

            classifiable["severity_correct"] = classifiable["severity_true"] == classifiable["severity_pred"]
            classifiable["category_correct"] = classifiable["category_true"] == classifiable["category_pred"]
            classifiable["anomaly_correct"] = classifiable["anomaly_true"] == classifiable["anomaly_pred"]

            n_total, n_classified = len(df), len(classifiable)
            unclassifiable["anomaly_pred_label"] = "non_classifiable"
            full_df = pd.concat([classifiable, unclassifiable], ignore_index=True).sort_index()

        st.session_state["full_df"] = full_df
        st.session_state["classifiable"] = classifiable
        st.session_state["n_total"] = n_total
        st.session_state["n_classified"] = n_classified

    if "full_df" in st.session_state:
        full_df = st.session_state["full_df"]
        classifiable = st.session_state["classifiable"]
        n_total = st.session_state["n_total"]
        n_classified = st.session_state["n_classified"]

        sev_acc = classifiable["severity_correct"].mean() if n_classified else 0
        cat_acc = classifiable["category_correct"].mean() if n_classified else 0
        ano_acc = classifiable["anomaly_correct"].mean() if n_classified else 0
        n_anom = int((classifiable["anomaly_pred"] == 1).sum()) if n_classified else 0

        # --- Cartes KPI ---
        k1, k2, k3, k4, k5 = st.columns(5)
        kpi_defs = [
            (k1, "Logs analysés", f"{n_total}", f"{n_total - n_classified} rejetés", "#4c9aff"),
            (k2, "Précision sévérité", f"{sev_acc:.0%}", "vs vraie valeur", "#4ade9b"),
            (k3, "Précision catégorie", f"{cat_acc:.0%}", "vs vraie valeur", "#4ade9b"),
            (k4, "Précision anomalie", f"{ano_acc:.0%}", "vs vraie valeur", "#4ade9b"),
            (k5, "Anomalies détectées", f"{n_anom}", f"sur {n_classified} logs", "#e5484d"),
        ]
        for col, label, value, sub, color in kpi_defs:
            with col:
                st.markdown(f"""
                <div class="kpi-card" style="border-left: 4px solid {color};">
                    <div class="kpi-label">{label}</div>
                    <div class="kpi-value" style="color:{color};">{value}</div>
                    <div class="kpi-sub">{sub}</div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # --- Jauge de santé réseau ---
        pct_critical = (classifiable["severity_pred"] == "critical").mean() if n_classified else 0
        pct_error = (classifiable["severity_pred"] == "error").mean() if n_classified else 0
        health_score = max(0, 100 - (pct_critical * 100 * 1.6) - (pct_error * 100 * 0.9))

        # --- Indicateur d'état système -- animation discrète, ton professionnel ---
        if health_score >= 85:
            mood_emoji, mood_color, mood_pulse = "●", "#4ade9b", "3s"
            quotes = [
                "Fonctionnement nominal, aucune action requise.",
                "Réseau stable, indicateurs dans les normes.",
            ]
        elif health_score >= 60:
            mood_emoji, mood_color, mood_pulse = "●", "#4c9aff", "2.4s"
            quotes = [
                "Activité normale, quelques avertissements mineurs.",
                "Situation sous contrôle, surveillance standard.",
            ]
        elif health_score >= 35:
            mood_emoji, mood_color, mood_pulse = "●", "#e8c547", "1.4s"
            quotes = [
                "Hausse des incidents, surveillance renforcée recommandée.",
                "Plusieurs erreurs détectées, vérification conseillée.",
            ]
        else:
            mood_emoji, mood_color, mood_pulse = "●", "#e5484d", "0.8s"
            quotes = [
                "Seuil critique atteint, intervention recommandée.",
                "Incidents critiques multiples détectés.",
            ]
        quote = random.choice(quotes)

        gcol0, gcol1, gcol2 = st.columns([0.85, 1, 2.15])
        with gcol0:
            st.markdown(f"""
            <div class="kpi-card" style="height:210px; display:flex; flex-direction:column;
                        align-items:center; justify-content:center; text-align:center;
                        border-left:3px solid {mood_color};">
                <div style="width:56px; height:56px; border-radius:50%;
                            background: {mood_color}1a;
                            border: 1.5px solid {mood_color}; display:flex; align-items:center;
                            justify-content:center; font-size:20px; color:{mood_color};
                            animation: status-pulse {mood_pulse} infinite;">
                    {mood_emoji}
                </div>
                <div style="font-family:'Inter',sans-serif; font-size:10.5px; color:#7b8aa3;
                            margin-top:12px; letter-spacing:0.6px; font-weight:600; text-transform:uppercase;">Statut système</div>
                <div style="font-size:12.5px; color:#c3ccdb; margin-top:8px; padding:0 8px;">
                    {quote}
                </div>
            </div>
            <style>
            @keyframes status-pulse {{
                0% {{ opacity: 1; }}
                50% {{ opacity: 0.45; }}
                100% {{ opacity: 1; }}
            }}
            </style>
            """, unsafe_allow_html=True)

        with gcol1:
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=health_score,
                number={"suffix": " / 100", "font": {"size": 30, "color": "#eaf6ff"}},
                gauge={
                    "axis": {"range": [0, 100], "tickcolor": "#6a7f9c", "tickfont": {"size": 9}},
                    "bar": {"color": "#4c9aff", "thickness": 0.28},
                    "bgcolor": "rgba(0,0,0,0)",
                    "borderwidth": 0,
                    "steps": [
                        {"range": [0, 40], "color": "rgba(255,59,107,0.25)"},
                        {"range": [40, 75], "color": "rgba(255,210,63,0.20)"},
                        {"range": [75, 100], "color": "rgba(63,255,160,0.20)"},
                    ],
                    "threshold": {"line": {"color": "#e5484d", "width": 3}, "thickness": 0.8, "value": health_score},
                },
            ))
            fig_gauge.update_layout(height=210, margin=dict(l=20, r=20, t=25, b=10),
                                     paper_bgcolor="rgba(0,0,0,0)", font_color="#cfe3f5",
                                     title={"text": "Indice de santé réseau", "font": {"size": 13, "color": "#8fa3c0"}})
            st.plotly_chart(fig_gauge, use_container_width=True)
            with st.expander("Comment ce score est calculé"):
                st.markdown(f"""
```
score = 100 − (% critical × 1,6) − (% error × 0,9)
```
Sur cette exécution :
- **{pct_critical:.1%}** de logs *critical* → −{pct_critical*100*1.6:.1f} pts
- **{pct_error:.1%}** de logs *error* → −{pct_error*100*0.9:.1f} pts
- Score final : **{health_score:.0f}/100**

Les coefficients (1,6 et 0,9) sont un choix de conception propre à ce projet,
pas un standard de l'industrie : ils traduisent le fait qu'un incident *critical*
pèse davantage qu'une simple *error*. Les logs *warning* et *info* n'entrent
pas dans le calcul.
                """)

        with gcol2:
            st.markdown("**Flux en direct**")

            f1, f2 = st.columns(2)
            with f1:
                sev_filter = st.multiselect(
                    "Filtrer par sévérité", ["critical", "error", "warning", "info"],
                    default=[], placeholder="Toutes les sévérités", label_visibility="collapsed",
                )
            with f2:
                available_hosts = sorted(classifiable["hostname"].dropna().unique()) if "hostname" in classifiable.columns else []
                host_filter = st.multiselect(
                    "Filtrer par équipement", available_hosts,
                    default=[], placeholder="Tous les équipements", label_visibility="collapsed",
                )

            feed_df = classifiable.copy()
            if sev_filter:
                feed_df = feed_df[feed_df["severity_pred"].isin(sev_filter)]
            if host_filter:
                feed_df = feed_df[feed_df["hostname"].isin(host_filter)]

            feed_rows = feed_df.sort_values("timestamp", ascending=False).head(9) if "timestamp" in feed_df.columns else feed_df.head(9)

            feed_html = '<div style="background:#0d1220; border:1px solid #26314a; border-radius:8px; padding:12px 16px; height:158px; overflow-y:auto; font-family:\'JetBrains Mono\',monospace; font-size:12px; line-height:1.9;">'
            if len(feed_rows) == 0:
                feed_html += '<div style="color:#5c6b85;">Aucun log ne correspond aux filtres sélectionnés.</div>'
            for _, r in feed_rows.iterrows():
                sev = r.get("severity_pred", "info")
                color = SEVERITY_COLOR.get(sev, "#8fa3c0")
                host = r.get("hostname", "?")
                msg = str(r.get("message", ""))[:70]
                feed_html += (f'<div><span style="color:#4a5c74;">{r.get("timestamp","")[-8:] if isinstance(r.get("timestamp",""), str) else ""}</span> '
                              f'<span style="color:{color}; font-weight:600;">[{sev.upper() if isinstance(sev,str) else sev}]</span> '
                              f'<span style="color:#9fb8d0;">{host}</span> '
                              f'<span style="color:#cfe3f5;">{msg}</span></div>')
            feed_html += "</div>"
            st.markdown(feed_html, unsafe_allow_html=True)
            st.caption(f"{len(feed_df)} log(s) après filtrage · 9 plus récents affichés")

        st.markdown("<br>", unsafe_allow_html=True)

        # --- Graphiques + carte réseau ---
        g1, g2, g3 = st.columns([1.1, 1.1, 1.3])

        with g1:
            st.markdown("**Répartition par sévérité**")
            sev_counts = classifiable["severity_pred"].value_counts().reindex(
                ["critical", "error", "warning", "info"]).fillna(0)
            fig = go.Figure(go.Pie(
                labels=sev_counts.index, values=sev_counts.values, hole=0.62,
                marker=dict(colors=[SEVERITY_COLOR[s] for s in sev_counts.index]),
                textinfo="label+percent", textfont=dict(size=11, color="white"),
            ))
            fig.update_layout(showlegend=False, height=260, margin=dict(l=0, r=0, t=10, b=0),
                               paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                               font_color="#cfe3f5")
            st.plotly_chart(fig, use_container_width=True)

        with g2:
            st.markdown("**Répartition par catégorie**")
            cat_counts = classifiable["category_pred"].value_counts()
            fig2 = go.Figure(go.Bar(
                x=cat_counts.values, y=cat_counts.index, orientation="h",
                marker=dict(color=cat_counts.values, colorscale=[[0, "#1c3b57"], [1, "#4c9aff"]]),
            ))
            fig2.update_layout(height=260, margin=dict(l=0, r=10, t=10, b=0),
                                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                                font_color="#cfe3f5", xaxis=dict(gridcolor="rgba(255,255,255,0.06)"))
            st.plotly_chart(fig2, use_container_width=True)

        with g3:
            st.markdown("**Carte du réseau (statut le plus grave par équipement)**")
            worst_rank = {"critical": 3, "error": 2, "warning": 1, "info": 0}
            classifiable["_rank"] = classifiable["severity_pred"].map(worst_rank)
            worst_per_host = classifiable.loc[classifiable.groupby("hostname")["_rank"].idxmax()]
            pos = host_positions(tuple(HOSTS))

            node_x, node_y, node_color, node_text = [], [], [], []
            for h in HOSTS:
                x, y = pos[h]
                node_x.append(x); node_y.append(y)
                row = worst_per_host[worst_per_host["hostname"] == h]
                sev = row["severity_pred"].values[0] if len(row) else "info"
                node_color.append(SEVERITY_COLOR.get(sev, "#4c9aff"))
                node_text.append(h)

            fig3 = go.Figure()
            for i in range(len(HOSTS)):
                for j in range(i + 1, len(HOSTS)):
                    fig3.add_trace(go.Scatter(
                        x=[node_x[i], node_x[j]], y=[node_y[i], node_y[j]],
                        mode="lines", line=dict(color="rgba(255,255,255,0.05)", width=1),
                        showlegend=False, hoverinfo="skip"))
            fig3.add_trace(go.Scatter(
                x=node_x, y=node_y, mode="markers+text",
                marker=dict(size=26, color=node_color, line=dict(width=2, color="#0a0e17")),
                text=node_text, textposition="bottom center",
                textfont=dict(size=9, color="#9fb8d0"), hoverinfo="text",
            ))
            fig3.update_layout(height=260, margin=dict(l=10, r=10, t=10, b=10),
                                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                                xaxis=dict(visible=False), yaxis=dict(visible=False), showlegend=False)
            st.plotly_chart(fig3, use_container_width=True)

        # --- Tableau détaillé, coloré par sévérité ---
        st.markdown("**Flux détaillé**")

        def sev_badge(val):
            color = SEVERITY_COLOR.get(val, "#8fa3c0")
            return f'background-color:{color}22; color:{color}; font-weight:600;'

        display_cols = ["hostname", "message", "severity_pred", "category_pred", "anomaly_pred_label"]
        show_df = full_df[[c for c in display_cols if c in full_df.columns]].rename(columns={
            "hostname": "Machine", "message": "Message", "severity_pred": "Sévérité",
            "category_pred": "Catégorie", "anomaly_pred_label": "Statut",
        })
        styled = show_df.style.map(sev_badge, subset=["Sévérité"]) if "Sévérité" in show_df.columns else show_df.style
        st.dataframe(styled, use_container_width=True, height=340)

        buffer_path = "../data/interface_export.xlsx"
        full_df.to_excel(buffer_path, index=False)
        with open(buffer_path, "rb") as f:
            st.download_button("📥 Exporter le rapport (Excel)", f, file_name="resultat_classification.xlsx")
    else:
        st.info("👈 Configure les paramètres dans la barre latérale, puis clique sur **Lancer la supervision**.")

# =======================================================================
# ONGLET 2 : ANALYSE MANUELLE (coller ou importer de vrais logs)
# =======================================================================
with tab2:
    st.markdown("### Analyser de vrais logs")
    st.caption("Colle des logs syslog ou importe un fichier — le système les parse et les classifie "
               "avec les mêmes modèles, sans passer par le générateur.")

    src_col1, src_col2 = st.columns([1.4, 1])

    with src_col1:
        pasted = st.text_area(
            "Coller des logs (une ligne par log)",
            height=180,
            placeholder="Aug 24 09:14:22 R1-CORE %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down\n"
                        "Aug 24 09:15:03 R1-CORE %BGP-5-ADJCHANGE: neighbor 10.0.0.2 Down BGP Notification sent",
        )

    with src_col2:
        uploaded = st.file_uploader("…ou importer un fichier", type=["txt", "log", "csv"])
        st.caption("Formats reconnus : Cisco IOS, RFC 5424, RFC 3164/BSD. "
                   "Les lignes non reconnues sont conservées et signalées.")

    analyse = st.button("🔎  Analyser ces logs", type="primary")

    if analyse:
        raw_lines = []
        if uploaded is not None:
            content = uploaded.read().decode("utf-8", errors="replace")
            raw_lines.extend([l for l in content.splitlines() if l.strip()])
        if pasted and pasted.strip():
            raw_lines.extend([l for l in pasted.splitlines() if l.strip()])

        if not raw_lines:
            st.warning("Aucun log fourni — colle du texte ou importe un fichier avant de lancer l'analyse.")
        else:
            with st.spinner(f"Analyse de {len(raw_lines)} lignes..."):
                records = [parse_log(l) for l in raw_lines]
                records = [r for r in records if r]
                mdf = pd.DataFrame(records)

                has_msg = mdf["message"].notna() & (mdf["message"].str.strip() != "")
                m_ok = mdf[has_msg].copy()
                m_ko = mdf[~has_msg].copy()

                severity_model, category_model, anomaly_model = load_models()

                if len(m_ok):
                    _msev = m_ok.apply(
                        lambda r: resolve_severity(r.to_dict(), severity_model), axis=1)
                    m_ok["severity_pred"] = [s[0] if s[0] else "info" for s in _msev]
                    m_ok["severity_source"] = [s[1] if s[1] else "inconnu" for s in _msev]
                    _mcat = m_ok.apply(
                        lambda r: resolve_category(r.to_dict(), category_model), axis=1)
                    m_ok["category_pred"] = [c[0] if c[0] else "unknown" for c in _mcat]
                    m_ok["category_source"] = [c[1] if c[1] else "inconnu" for c in _mcat]
                    m_ok["anomaly_pred"] = anomaly_model.predict(m_ok["message"])
                    m_ok["anomaly_pred_label"] = m_ok["anomaly_pred"].map({0: "normal", 1: "anormal"})

                m_ko["severity_pred"] = "non_classifiable"
                m_ko["severity_source"] = "non_classifiable"
                m_ko["category_pred"] = "non_classifiable"
                m_ko["category_source"] = "non_classifiable"
                m_ko["anomaly_pred_label"] = "non_classifiable"

                m_full = pd.concat([m_ok, m_ko], ignore_index=True).sort_index()

            n_in, n_ok = len(mdf), len(m_ok)
            n_recognized = int((mdf["format_detected"] != "unparsed").sum())
            n_anomalies = int((m_ok["anomaly_pred"] == 1).sum()) if n_ok else 0

            a1, a2, a3, a4, a5 = st.columns(5)
            n_header = int((m_ok["severity_source"] == "header").sum()) if n_ok else 0
            n_facility = int((m_ok["category_source"] == "facility").sum()) if n_ok else 0
            cards = [
                (a1, "Lignes analysées", f"{n_in}", "reçues en entrée", "#4c9aff"),
                (a2, "Format reconnu", f"{n_recognized}/{n_in}", "parsing réussi", "#4ade9b"),
                (a3, "Sévérité au parsing", f"{n_header}/{n_ok}", "reste : modèle ML", "#4c9aff"),
                (a4, "Catégorie au parsing", f"{n_facility}/{n_ok}", "reste : modèle ML", "#4c9aff"),
                (a5, "Anomalies", f"{n_anomalies}", f"sur {n_ok} classifiées", "#e5484d"),
            ]
            for col, label, value, sub, color in cards:
                with col:
                    st.markdown(f"""
                    <div class="kpi-card" style="border-left: 3px solid {color};">
                        <div class="kpi-label">{label}</div>
                        <div class="kpi-value" style="color:{color};">{value}</div>
                        <div class="kpi-sub">{sub}</div>
                    </div>
                    """, unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            if n_ok:
                b1, b2 = st.columns(2)
                with b1:
                    st.markdown("**Répartition par sévérité**")
                    sc = m_ok["severity_pred"].value_counts().reindex(
                        ["critical", "error", "warning", "info"]).fillna(0)
                    figm = go.Figure(go.Bar(
                        x=sc.index, y=sc.values,
                        marker=dict(color=[SEVERITY_COLOR[s] for s in sc.index]),
                    ))
                    figm.update_layout(height=240, margin=dict(l=0, r=0, t=10, b=0),
                                        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                                        font_color="#c3ccdb",
                                        yaxis=dict(gridcolor="rgba(255,255,255,0.06)"))
                    st.plotly_chart(figm, use_container_width=True)
                with b2:
                    st.markdown("**Répartition par catégorie**")
                    cc = m_ok["category_pred"].value_counts()
                    figm2 = go.Figure(go.Bar(
                        x=cc.values, y=cc.index, orientation="h",
                        marker=dict(color=cc.values, colorscale=[[0, "#1f3352"], [1, "#4c9aff"]]),
                    ))
                    figm2.update_layout(height=240, margin=dict(l=0, r=10, t=10, b=0),
                                         paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                                         font_color="#c3ccdb",
                                         xaxis=dict(gridcolor="rgba(255,255,255,0.06)"))
                    st.plotly_chart(figm2, use_container_width=True)

            # =========================================================
            # ANALYSE APPROFONDIE
            # =========================================================
            if n_ok >= 3:
                st.markdown("---")
                st.markdown("### Analyse approfondie")

                sev_weight = {"critical": 3, "error": 2, "warning": 1, "info": 0}
                m_ok["_poids"] = m_ok["severity_pred"].map(sev_weight).fillna(0)

                d1, d2 = st.columns([1, 1])

                # --- Palmarès des équipements les plus touchés ---
                with d1:
                    st.markdown("**Équipements les plus touchés**")
                    if "hostname" in m_ok.columns and m_ok["hostname"].notna().any():
                        host_stats = m_ok.groupby("hostname").agg(
                            total=("message", "count"),
                            score=("_poids", "sum"),
                            critiques=("severity_pred", lambda s: (s == "critical").sum()),
                        ).sort_values("score", ascending=False).head(8)

                        fig_h = go.Figure(go.Bar(
                            x=host_stats["score"], y=host_stats.index, orientation="h",
                            marker=dict(color=host_stats["score"],
                                        colorscale=[[0, "#1f3352"], [1, "#e5484d"]]),
                            text=[f"{int(t)} logs · {int(c)} crit." for t, c in
                                  zip(host_stats["total"], host_stats["critiques"])],
                            textposition="auto", textfont=dict(size=10),
                        ))
                        fig_h.update_layout(height=260, margin=dict(l=0, r=10, t=10, b=0),
                                             paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                                             font_color="#c3ccdb",
                                             xaxis=dict(title="Score de gravité cumulé",
                                                        gridcolor="rgba(255,255,255,0.06)"),
                                             yaxis=dict(autorange="reversed"))
                        st.plotly_chart(fig_h, use_container_width=True)
                        st.caption("Score = somme des poids de gravité (critical=3, error=2, warning=1, info=0)")
                    else:
                        st.info("Pas de nom d'équipement exploitable dans ces logs.")

                # --- Croisement catégorie × sévérité ---
                with d2:
                    st.markdown("**Croisement catégorie × sévérité**")
                    cross = pd.crosstab(m_ok["category_pred"], m_ok["severity_pred"])
                    for c in ["critical", "error", "warning", "info"]:
                        if c not in cross.columns:
                            cross[c] = 0
                    cross = cross[["critical", "error", "warning", "info"]]

                    fig_x = go.Figure(go.Heatmap(
                        z=cross.values, x=cross.columns, y=cross.index,
                        colorscale=[[0, "#131a28"], [0.5, "#2d5580"], [1, "#4c9aff"]],
                        text=cross.values, texttemplate="%{text}",
                        textfont=dict(size=11), showscale=False,
                    ))
                    fig_x.update_layout(height=260, margin=dict(l=0, r=10, t=10, b=0),
                                         paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                                         font_color="#c3ccdb")
                    st.plotly_chart(fig_x, use_container_width=True)
                    st.caption("Quel type d'incident concentre les cas les plus graves")

                # --- Répartition temporelle + rafales ---
                st.markdown("**Répartition dans le temps**")
                ts = pd.to_datetime(m_ok["timestamp"], errors="coerce", format="%b %d %H:%M:%S")
                if ts.notna().sum() >= 3:
                    tdf = m_ok.copy()
                    tdf["_ts"] = ts
                    tdf = tdf.dropna(subset=["_ts"]).sort_values("_ts")

                    fig_t = go.Figure()
                    for sev in ["critical", "error", "warning", "info"]:
                        sub = tdf[tdf["severity_pred"] == sev]
                        if len(sub):
                            fig_t.add_trace(go.Scatter(
                                x=sub["_ts"], y=[sev] * len(sub), mode="markers",
                                marker=dict(size=9, color=SEVERITY_COLOR[sev],
                                            line=dict(width=1, color="#10151f")),
                                name=sev,
                                hovertext=sub["hostname"].astype(str) + " · " + sub["message"].astype(str).str[:60],
                                hoverinfo="text",
                            ))
                    fig_t.update_layout(height=220, margin=dict(l=0, r=10, t=10, b=0),
                                         paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                                         font_color="#c3ccdb", showlegend=True,
                                         legend=dict(orientation="h", y=-0.25),
                                         xaxis=dict(gridcolor="rgba(255,255,255,0.06)"),
                                         yaxis=dict(categoryorder="array",
                                                    categoryarray=["info", "warning", "error", "critical"]))
                    st.plotly_chart(fig_t, use_container_width=True)

                    # Détection de rafales : >= 3 logs graves en moins de 60s
                    graves = tdf[tdf["severity_pred"].isin(["critical", "error"])].copy()
                    bursts = []
                    if len(graves) >= 3:
                        times = graves["_ts"].tolist()
                        for i in range(len(times) - 2):
                            window = (times[i + 2] - times[i]).total_seconds()
                            if 0 <= window <= 60:
                                bursts.append((times[i], times[i + 2]))
                    if bursts:
                        st.warning(f"⚠️ {len(bursts)} rafale(s) détectée(s) : au moins 3 incidents graves "
                                    f"en moins de 60 secondes — signe possible d'un incident unique se "
                                    f"propageant plutôt que d'événements isolés.")
                    else:
                        st.caption("Aucune rafale détectée (3+ incidents graves en moins de 60 secondes).")
                else:
                    st.info("Horodatages insuffisants ou non exploitables pour l'analyse temporelle.")

                # --- Synthèse chiffrée ---
                st.markdown("**Synthèse**")
                s1, s2, s3, s4 = st.columns(4)
                top_host = m_ok.groupby("hostname")["_poids"].sum().idxmax() if m_ok["hostname"].notna().any() else "—"
                top_cat = m_ok["category_pred"].value_counts().idxmax()
                pct_grave = (m_ok["severity_pred"].isin(["critical", "error"])).mean()
                nb_hosts = m_ok["hostname"].nunique()

                synth = [
                    (s1, "Équipement le plus critique", str(top_host)),
                    (s2, "Catégorie dominante", str(top_cat)),
                    (s3, "Part d'incidents graves", f"{pct_grave:.0%}"),
                    (s4, "Équipements concernés", str(nb_hosts)),
                ]
                for col, label, value in synth:
                    with col:
                        st.markdown(f"""
                        <div class="kpi-card" style="height:92px; border-left:3px solid #4c9aff;">
                            <div class="kpi-label">{label}</div>
                            <div class="kpi-value" style="font-size:19px; color:#e8edf5;">{value}</div>
                        </div>
                        """, unsafe_allow_html=True)

                st.markdown("<br>", unsafe_allow_html=True)

            st.markdown("**Résultat détaillé**")
            mcols = ["raw_log", "format_detected", "hostname", "message",
                      "severity_pred", "severity_source", "category_pred",
                      "category_source", "anomaly_pred_label"]
            mshow = m_full[[c for c in mcols if c in m_full.columns]].rename(columns={
                "raw_log": "Log brut", "format_detected": "Format", "hostname": "Machine",
                "message": "Message", "severity_pred": "Sévérité",
                "severity_source": "Source sévérité",
                "category_pred": "Catégorie", "category_source": "Source catégorie",
                "anomaly_pred_label": "Statut",
            })
            st.dataframe(mshow, use_container_width=True, height=320)

            export_path = "../data/analyse_manuelle.xlsx"
            m_full.to_excel(export_path, index=False)
            with open(export_path, "rb") as f:
                st.download_button("📥  Exporter l'analyse (Excel)", f,
                                    file_name="analyse_logs_reels.xlsx")

    st.divider()

    # --- Export d'un fichier de logs d'exemple, pour tester rapidement ---
    st.markdown("#### Besoin d'un fichier d'exemple ?")
    st.caption("Génère un fichier de logs Cisco réalistes, à réimporter ci-dessus "
               "ou à utiliser comme modèle de format.")

    ex_col1, ex_col2 = st.columns([1, 3])
    with ex_col1:
        n_export = st.number_input("Nombre de logs", 10, 1000, 100, step=10)

    sample_lines = [generate_one_line(0.0)[0] for _ in range(int(n_export))]
    sample_text = "\n".join(sample_lines)
    st.download_button(
        "📄  Télécharger un fichier de logs (.txt)",
        sample_text,
        file_name=f"logs_exemple_{int(n_export)}.txt",
        mime="text/plain",
    )

# =======================================================================
# ONGLET 5 : DIAGNOSTIC IA (Projet 2)
# =======================================================================
with tab5:
    st.markdown("### Diagnostic assisté par IA")
    st.caption("Les logs sont regroupés en incidents, puis analysés par un modèle "
               "de langage exécuté localement — les données ne quittent pas la machine.")

    from incident_grouper import group_into_incidents, detect_flapping
    from llm_analyzer import check_ollama, analyze_incident, DEFAULT_MODEL

    # --- Source des logs ---
    src = st.radio("Source des logs", ["Coller des logs", "Importer un fichier"],
                    horizontal=True, label_visibility="collapsed")

    logs_text = ""
    if src == "Coller des logs":
        logs_text = st.text_area(
            "Logs à analyser", height=150,
            placeholder="Jun 20 09:53:52.125: %LINK-3-UPDOWN: Interface GigabitEthernet0/23, changed state to down\n"
                        "Jun 20 09:54:02.361: %LINK-3-UPDOWN: Interface GigabitEthernet0/23, changed state to up",
            label_visibility="collapsed",
        )
    else:
        up = st.file_uploader("Fichier de logs", type=["txt", "log"], key="llm_upload")
        if up is not None:
            logs_text = up.read().decode("utf-8", errors="replace")

    c1, c2 = st.columns([1, 2])
    with c1:
        n_analyses = st.number_input("Incidents à analyser", 1, 10, 3,
                                      help="Les plus graves d'abord. Chaque analyse prend "
                                           "plusieurs secondes sur un modèle local.")
    with c2:
        st.markdown("&nbsp;", unsafe_allow_html=True)
        lancer = st.button("🧠  Lancer le diagnostic", type="primary")

    ok, msg = (check_ollama(DEFAULT_MODEL) if lancer else (False, ""))
    pret = lancer and logs_text.strip() and ok

    if lancer and not logs_text.strip():
        st.warning("Aucun log fourni.")
    elif lancer and not ok:
        st.error(msg)
        st.caption("Vérifie qu'Ollama est lancé, puis que le modèle est installé "
                    "(`ollama pull mistral`).")

    if pret:
        # --- Parsing + classification ---
        with st.spinner("Parsing et regroupement des logs..."):
            records = []
            for line in logs_text.splitlines():
                if not line.strip():
                    continue
                rec = parse_log(line)
                if not rec:
                    continue
                sev, sev_src = resolve_severity(rec)
                cat, cat_src = resolve_category(rec)
                rec["severity_pred"] = sev or "info"
                rec["category_pred"] = cat or "unknown"
                records.append(rec)

            incidents = group_into_incidents(records)

        if not incidents:
            st.warning("Aucun incident identifié dans ces logs.")
            incidents = []

    if pret and incidents:
        g1, g2, g3 = st.columns(3)
        graves = sum(1 for i in incidents if i["severite_max"] in ("critical", "error"))
        flapping = sum(1 for i in incidents if detect_flapping(i))
        for col, label, value, color in [
            (g1, "Logs analysés", str(len(records)), "#4c9aff"),
            (g2, "Incidents identifiés", str(len(incidents)), "#4ade9b"),
            (g3, "Dont graves / instables", f"{graves} / {flapping}", "#e5484d"),
        ]:
            with col:
                st.markdown(f"""
                <div class="kpi-card" style="border-left:3px solid {color};">
                    <div class="kpi-label">{label}</div>
                    <div class="kpi-value" style="color:{color};">{value}</div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # --- Analyse LLM, incident par incident ---
        a_traiter = incidents[:int(n_analyses)]
        progress = st.progress(0.0, text="Analyse en cours...")

        PRIORITE_COULEUR = {"haute": "#e5484d", "moyenne": "#e8c547", "basse": "#4ade9b"}

        for idx, inc in enumerate(a_traiter):
            progress.progress((idx) / len(a_traiter),
                               text=f"Analyse de l'incident {inc['id']} "
                                    f"({inc['entite'][1]})... {idx + 1}/{len(a_traiter)}")

            flap = detect_flapping(inc)
            diag = analyze_incident(inc, flap, model=DEFAULT_MODEL)

            sev_color = SEVERITY_COLOR.get(inc["severite_max"], "#8fa3c0")
            badges = []
            if flap:
                badges.append("INSTABILITÉ")
            if inc.get("recurrent"):
                badges.append("RÉCURRENT")
            if inc.get("episodes", 0) > 1:
                badges.append(f"{inc['episodes']} ÉPISODES")
            badge_html = " ".join(
                f'<span style="font-size:10px; padding:2px 8px; border-radius:4px; '
                f'background:{sev_color}22; color:{sev_color}; font-weight:600;">{b}</span>'
                for b in badges)

            with st.container(border=True):
                st.markdown(f"""
                <div style="display:flex; align-items:center; gap:10px; margin-bottom:4px;">
                    <span style="font-size:15px; font-weight:700; color:#e8edf5;">
                        Incident {inc['id']} · {inc['entite'][1]}</span>
                    <span style="font-size:11px; padding:2px 8px; border-radius:4px;
                                 background:{sev_color}22; color:{sev_color}; font-weight:600;">
                        {inc['severite_max'].upper()}</span>
                    {badge_html}
                </div>
                <div style="font-size:12px; color:#7b8aa3; margin-bottom:10px;">
                    {inc['nb_logs']} logs · {', '.join(inc['mnemonics'].keys())}
                </div>
                """, unsafe_allow_html=True)

                if diag.get("erreur"):
                    st.error(diag["erreur"])
                    continue

                prio = (diag.get("priorite") or "").lower()
                prio_color = PRIORITE_COULEUR.get(prio, "#7b8aa3")

                if diag.get("diagnostic"):
                    st.markdown(f"**Diagnostic** — {diag['diagnostic']}")
                if diag.get("cause"):
                    st.markdown(f"**Cause probable** — {diag['cause']}")
                if diag.get("action"):
                    st.markdown(f"**Action recommandée** — {diag['action']}")
                if prio:
                    st.markdown(
                        f'<span style="font-size:11px; color:#7b8aa3;">PRIORITÉ </span>'
                        f'<span style="font-size:12px; padding:3px 10px; border-radius:4px; '
                        f'background:{prio_color}22; color:{prio_color}; font-weight:600;">'
                        f'{prio.upper()}</span>',
                        unsafe_allow_html=True)

                if not any(diag.get(k) for k in ("diagnostic", "cause", "action")):
                    st.warning("Le modèle n'a pas respecté le format attendu.")
                    st.caption(diag.get("reponse_brute", "")[:500])
                else:
                    st.markdown(
                        '<div style="margin-top:10px; padding:8px 12px; border-radius:6px; '
                        'background:#1a1f2e; border-left:3px solid #e8c547; font-size:11.5px; '
                        'color:#9fb0c9;">⚠️ Généré automatiquement par un modèle de langage local '
                        '(Mistral) — peut contenir des erreurs ou des approximations. À valider '
                        'par un opérateur avant toute action, notamment pour les incidents de '
                        'priorité haute. Les logs bruts ci-dessous restent la source de vérité.'
                        '</div>', unsafe_allow_html=True)

                with st.expander("Voir les logs bruts de cet incident"):
                    for log in inc["logs"][:20]:
                        st.code(log.get("raw_log", ""), language=None)
                    if inc["nb_logs"] > 20:
                        st.caption(f"... et {inc['nb_logs'] - 20} logs supplémentaires")

        progress.progress(1.0, text=f"Analyse terminée · {len(a_traiter)} incidents traités")

        if len(incidents) > len(a_traiter):
            st.caption(f"{len(incidents) - len(a_traiter)} incidents moins graves non analysés. "
                        f"Augmente le nombre d'incidents à analyser pour les inclure.")

    if not lancer:
        st.info("Colle des logs ou importe un fichier, puis lance le diagnostic. "
                "Le modèle tourne en local via Ollama — prévoir quelques secondes par incident.")

# =======================================================================
# ONGLET 3 : PERFORMANCE DES MODÈLES
# =======================================================================
with tab3:
    st.markdown("### Performance des modèles entraînés")
    st.caption("Mesurée sur le jeu de test interne (20% des 2000 logs, jamais vus à l'entraînement)")

    images = {
        "Sévérité": ("../outputs/confusion_matrix_severity.png", "#f0883e"),
        "Catégorie": ("../outputs/confusion_matrix_category.png", "#4c9aff"),
        "Anomalie": ("../outputs/confusion_matrix_anomaly.png", "#e5484d"),
    }
    cols = st.columns(3)
    for col, (name, (path, color)) in zip(cols, images.items()):
        with col:
            st.markdown(f'<div style="border-left:4px solid {color}; padding-left:10px; margin-bottom:8px;">'
                         f'<b>{name}</b></div>', unsafe_allow_html=True)
            if Path(path).exists():
                st.image(path, use_container_width=True)
            else:
                st.warning(f"Image introuvable : {path}")

# =======================================================================
# ONGLET 4 : ARCHITECTURE
# =======================================================================
with tab4:
    st.markdown("### Pipeline du Projet 1")
    steps = [
        ("1", "Génération", "Invente des logs Cisco réalistes à partir de templates", "#4c9aff"),
        ("2", "Parsing", "Découpe chaque ligne en champs (date, host, sévérité, message)", "#4ade9b"),
        ("3", "Nettoyage", "Vérifie la qualité des données (doublons, valeurs invalides)", "#e8c547"),
        ("4", "Classification", "3 modèles ML devinent sévérité / catégorie / anomalie", "#f0883e"),
        ("5", "Restitution", "Dashboard + export Excel", "#e5484d"),
    ]
    cols = st.columns(5)
    for col, (num, title, desc, color) in zip(cols, steps):
        with col:
            st.markdown(f"""
            <div class="kpi-card" style="height:150px; border-left:4px solid {color};">
                <div style="font-family:'JetBrains Mono',monospace; color:{color}; font-size:22px; font-weight:700;">{num}</div>
                <div style="font-weight:700; margin-top:4px;">{title}</div>
                <div style="font-size:12px; color:#8fa3c0; margin-top:6px;">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
    **Les 3 modèles de classification :**
    - **Sévérité** : critical / error / warning / info
    - **Catégorie** : interface / routing / security / hardware / system / qos / stp / services
    - **Anomalie** : normal / anormal

    Chaque modèle lit uniquement le texte du message (TF-IDF + régression logistique)
    et devine une étiquette, sans connaître les autres champs déjà extraits par le parsing.
    """)