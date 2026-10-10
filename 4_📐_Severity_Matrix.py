"""
Severity Matrix & Escalation Protocols Reference Page.
"""

from pathlib import Path
import sys
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.db_manager import DatabaseManager
from engine.rules_engine import RulesEngine
from engine.ui_helpers import inject_soc_theme, render_sidebar, SEVERITY_THEMES


st.set_page_config(page_title="Severity Matrix | Decision Engine", page_icon="📐", layout="wide")

inject_soc_theme()
db = DatabaseManager()
engine = RulesEngine()
cfg = engine.config
render_sidebar(db)

# Page Header
st.markdown(
    """
    <div class="soc-header">
        <h1>📐 Incident Severity Matrix & SOP Protocols</h1>
        <p>Declarative scoring rubrics, mathematical bounds, and live interactive 'What-If' simulation sandbox.</p>
    </div>
    """,
    unsafe_allow_html=True
)

# Interactive What-If Sandbox (Top section for live viva demonstration)
st.markdown("### 🧪 Interactive 'What-If' Scoring Sandbox")
st.caption("Adjust any factor below to observe how points, severity tier, and escalation SLAs shift dynamically:")

sim_c1, sim_c2, sim_c3, sim_c4, sim_c5 = st.columns(5)
with sim_c1:
    sim_impact = st.selectbox("Impact Tier", ["Low", "Medium", "High", "Critical"], index=1)
with sim_c2:
    sim_assets = st.number_input("Assets Count", min_value=1, max_value=500, value=5, step=1)
with sim_c3:
    sim_conf = st.slider("Confidence (%)", 0.0, 100.0, 80.0, step=5.0)
with sim_c4:
    sim_pers = st.radio("Persistence?", ["No", "Yes"], index=0, horizontal=True)
with sim_c5:
    sim_exp = st.radio("Data Exposed?", ["No", "Yes"], index=0, horizontal=True)

# Live calculation
sim_trace = engine.evaluate_incident({
    "title": "Live What-If Simulation",
    "incident_type": "Simulation",
    "business_impact": sim_impact,
    "affected_assets": sim_assets,
    "confidence": sim_conf,
    "persistence": sim_pers == "Yes",
    "data_exposure": sim_exp == "Yes",
})

theme = SEVERITY_THEMES.get(sim_trace.final_severity, SEVERITY_THEMES["LOW"])

st.markdown(
    f"""
    <div style="background-color: {theme['bg']}; border: 1px solid {theme['border']}; border-left: 6px solid {theme['color']}; border-radius: 8px; padding: 1.1rem 1.4rem; margin: 0.8rem 0 1.2rem 0;">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
            <div>
                <span style="font-size: 0.8rem; font-weight: 700; text-transform: uppercase; color: #475569;">Simulated Outcome</span>
                <h3 style="color: {theme['color']}; margin: 0.2rem 0;">{theme['icon']} {sim_trace.final_severity} Severity ({sim_trace.total_score} / 15 Points)</h3>
                <p style="margin: 0; color: #334155; font-size: 0.9rem;"><strong>Formula:</strong> <code>{sim_trace.score_formula}</code></p>
            </div>
            <div style="text-align: right;">
                <span style="font-size: 0.8rem; font-weight: 700; text-transform: uppercase; color: #475569;">Mandated Escalation</span>
                <h4 style="color: #0f172a; margin: 0.2rem 0;">{sim_trace.final_escalation}</h4>
                <span style="background: #ffffff; border: 1px solid #cbd5e1; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.82rem; font-weight: 700;">
                    ⏱️ SLA: {sim_trace.sla_response_time}
                </span>
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

st.markdown("---")

# Tabbed view: Rubric vs SOP vs Formula
tab1, tab2, tab3 = st.tabs(["📊 Factor Scoring Rubrics", "🚨 Escalation SOP & SLAs", "🧮 Mathematical Formulation"])

with tab1:
    st.markdown("#### 1. Business Impact Scoring (+1 to +4 pts)")
    impact_rows = [
        {"Impact Tier": k, "Points Contributed": f"+{v['points']} pts", "Operational Criteria": v["description"]}
        for k, v in cfg["business_impact"].items()
    ]
    st.table(impact_rows)

    st.markdown("#### 2. Affected Assets Scoring (+0 to +3 pts)")
    assets_rows = [
        {"Asset Bracket": b["bracket_label"], "Points Contributed": f"+{b['points']} pts", "Scope Description": b["description"]}
        for b in cfg["affected_assets_brackets"]
    ]
    st.table(assets_rows)

    st.markdown("#### 3. Detection Confidence Scoring (+0 to +3 pts)")
    conf_rows = [
        {"Confidence Range": b["bracket_label"], "Points Contributed": f"+{b['points']} pts", "Telemetry Corroboration": b["description"]}
        for b in cfg["confidence_brackets"]
    ]
    st.table(conf_rows)

    c_left, c_right = st.columns(2)
    with c_left:
        st.markdown("#### 4. Threat Persistence (+0 or +2 pts)")
        st.table([
            {"Detected": "No", "Points": "+0 pts", "Description": "Ephemeral or in-memory execution."},
            {"Detected": "Yes", "Points": "+2 pts", "Description": "Survives reboot via scheduled task, service, registry."},
        ])

    with c_right:
        st.markdown("#### 5. Data Exposure (+0 or +3 pts)")
        st.table([
            {"Exposed": "No", "Points": "+0 pts", "Description": "No confidential/PII data accessed or staged."},
            {"Exposed": "Yes", "Points": "+3 pts", "Description": "Confirmed leak, exfiltration, or unauthorized dump."},
        ])

with tab2:
    st.markdown("#### Severity Classification & Mandatory Escalation SOPs")
    st.caption("Each composite score tier maps directly to a predefined operational protocol:")

    thresholds = cfg["severity_thresholds"]
    escs = cfg["escalation_procedures"]

    for t in thresholds:
        sev = t["severity"]
        esc = escs.get(sev, {})
        color = t["color"]
        range_str = f"{t['min_score']}–{t['max_score'] if t['max_score'] is not None else '15'} points"

        st.markdown(
            f"""
            <div style="border-left: 6px solid {color}; background-color: #ffffff; padding: 1.1rem 1.4rem; border-radius: 8px; margin-bottom: 1rem; border: 1px solid #e2e8f0; border-left-width: 6px; border-left-color: {color};">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
                    <h4 style="margin: 0; color: {color}; font-size: 1.15rem;">{sev} Severity ({range_str})</h4>
                    <span style="background-color: {color}15; color: {color}; font-weight: 700; padding: 0.25rem 0.75rem; border-radius: 6px; font-size: 0.85rem; border: 1px solid {color}30;">
                        Escalation: {esc.get('level', 'N/A')}
                    </span>
                </div>
                <p style="margin: 0.4rem 0 0.8rem 0; color: #475569; font-size: 0.9rem;">{t['summary']}</p>
                <div style="background: #f8fafc; padding: 0.8rem 1rem; border-radius: 6px; border: 1px solid #e2e8f0; font-size: 0.88rem;">
                    <p style="margin: 0 0 0.3rem 0;">⏱️ <strong>Mandated SLA:</strong> <code>{esc.get('sla_response_time', 'N/A')}</code></p>
                    <p style="margin: 0 0 0.3rem 0;">📋 <strong>Operational Directive:</strong> {esc.get('action_directive', 'N/A')}</p>
                    <p style="margin: 0;">👥 <strong>Notified Stakeholders:</strong> {', '.join(esc.get('notified_roles', []))}</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

with tab3:
    st.markdown("#### Mathematical Formulation")
    st.latex(r"\text{Total Score} = S_{\text{impact}} + S_{\text{assets}} + S_{\text{confidence}} + S_{\text{persistence}} + S_{\text{exposure}}")

    st.markdown(
        r"""
        #### Bounded Range Properties:
        - **Minimum Theoretical Score:**
          $$\min(\text{Score}) = 1 \text{ (Low Impact)} + 0 + 0 + 0 + 0 = 1 \quad (\rightarrow \text{LOW})$$
        - **Maximum Theoretical Score:**
          $$\max(\text{Score}) = 4 \text{ (Critical Impact)} + 3 \text{ (26+ Assets)} + 3 \text{ (90-100\% Conf)} + 2 \text{ (Persistence)} + 3 \text{ (Exposure)} = 15 \quad (\rightarrow \text{CRITICAL})$$
        
        #### Why Additive Weighting?
        In high-velocity Security Operations Centers (SOCs), additive linear scoring avoids exponential blowups while guaranteeing that:
        1. Any critical business impact event ($+4$) with data exposure ($+3$) and persistence ($+2$) automatically triggers **CRITICAL** ($\ge 9$), regardless of asset count.
        2. High-volume unverified alerts (confidence $< 50\%$) receive $0$ confidence contribution, preventing alert amplification.
        """
    )
