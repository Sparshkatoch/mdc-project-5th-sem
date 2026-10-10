"""
Analyze Incident Page - Interactive Cyber Incident Triage & Decision Audit Engine.
"""

from pathlib import Path
import sys
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.db_manager import DatabaseManager
from data.synthetic_cases import get_all_scenarios
from engine.rules_engine import RulesEngine
from engine.validator import ValidationError
from engine.ui_helpers import inject_soc_theme, render_sidebar, SEVERITY_THEMES


st.set_page_config(page_title="Analyze Incident | Decision Engine", page_icon="🔍", layout="wide")

inject_soc_theme()
db = DatabaseManager()
engine = RulesEngine()
render_sidebar(db)

# Page Header
st.markdown(
    """
    <div class="soc-header">
        <h1>🔍 Incident Analysis & Triage Engine</h1>
        <p>Input security incident telemetry to deterministically calculate severity, assign escalation SLAs, and generate an auditable decision trace.</p>
    </div>
    """,
    unsafe_allow_html=True
)

# Quick Preset Loader
scenarios = get_all_scenarios()
scenario_options = ["-- Custom Incident Input (Or choose a verified scenario below) --"] + [
    f"{s['id']}: {s['title']} [{s['expected_severity']} - {s['expected_score']} pts]"
    for s in scenarios
]

selected_option = st.selectbox(
    "⚡ Scenario Auto-Loader (Pre-fills synthetic incidents for rapid viva demonstration):",
    options=scenario_options,
    index=0
)

# Auto-fill preset values
preset = {}
if not selected_option.startswith("--"):
    syn_id = selected_option.split(":")[0].strip()
    for s in scenarios:
        if s["id"] == syn_id:
            preset = s
            break

# Intake Form Container
with st.form("incident_triage_form"):
    st.markdown("#### 1. Incident Characteristics & Blast Radius")
    col1, col2 = st.columns(2)

    with col1:
        title = st.text_input(
            "Incident Title / Subject *",
            value=preset.get("title", "Suspicious Active Directory Activity"),
            help="Descriptive title of the security event."
        )
        
        all_types = [
            "Ransomware Outbreak",
            "Phishing Campaign",
            "Data Exposure",
            "Credential Stuffing",
            "Privilege Escalation",
            "Command & Control",
            "Denial of Service",
            "Insider Threat",
            "Supply Chain Attack",
            "Malicious Cryptomining",
            "Network Reconnaissance",
            "Suspicious Execution",
            "Vulnerability Exposure",
            "Asset Loss",
            "Other / Uncategorized"
        ]
        
        type_idx = all_types.index(preset.get("incident_type", "Privilege Escalation")) if preset.get("incident_type") in all_types else 0
        incident_type = st.selectbox(
            "Threat Archetype / Type *",
            options=all_types,
            index=type_idx
        )

        impact_options = ["Low", "Medium", "High", "Critical"]
        impact_idx = impact_options.index(preset.get("business_impact", "Medium")) if preset.get("business_impact") in impact_options else 1
        business_impact = st.selectbox(
            "Business Impact Level *",
            options=impact_options,
            index=impact_idx,
            format_func=lambda x: {
                "Low": "Low (+1 pt) — Minimal service disruption",
                "Medium": "Medium (+2 pts) — Secondary system degradation",
                "High": "High (+3 pts) — Mission-critical service outage",
                "Critical": "Critical (+4 pts) — Catastrophic enterprise failure"
            }.get(x, x),
            help="Scoring: Low (+1), Medium (+2), High (+3), Critical (+4)"
        )

    with col2:
        affected_assets = st.number_input(
            "Affected Assets (Endpoints / Servers) *",
            min_value=1,
            max_value=100000,
            value=int(preset.get("affected_assets", 5)),
            step=1,
            help="Brackets: 1–2 assets (+0 pts) | 3–10 (+1 pt) | 11–25 (+2 pts) | 26+ (+3 pts)"
        )
        if affected_assets <= 2:
            st.caption("ℹ️ 1–2 assets contributes **+0 points** (isolated blast radius).")
        elif affected_assets <= 10:
            st.caption("ℹ️ 3–10 assets contributes **+1 point** (departmental blast radius).")
        elif affected_assets <= 25:
            st.caption("ℹ️ 11–25 assets contributes **+2 points** (multi-zone subnet impact).")
        else:
            st.caption("ℹ️ 26+ assets contributes **+3 points** (enterprise-wide compromise).")

        analyst_notes = st.text_input(
            "Analyst Notes / Telemetry Ref",
            value=preset.get("analyst_notes", ""),
            placeholder="e.g. SIEM Alert ID #88412, host quarantined..."
        )

    st.markdown("#### 2. Detection Fidelity & Threat Flags")
    col3, col4, col5 = st.columns(3)

    with col3:
        confidence = st.slider(
            "Detection Confidence (%) *",
            min_value=0.0,
            max_value=100.0,
            value=float(preset.get("confidence", 85.0)),
            step=1.0,
            help="Brackets: <50% (+0 pts) | 50–74% (+1 pt) | 75–89% (+2 pts) | 90–100% (+3 pts)"
        )
        if confidence < 50:
            st.caption("Fidelity: `<50%` (**+0 pts**, uncorroborated)")
        elif confidence < 75:
            st.caption("Fidelity: `50–74%` (**+1 pt**, single sensor)")
        elif confidence < 90:
            st.caption("Fidelity: `75–89%` (**+2 pts**, cross-correlated)")
        else:
            st.caption("Fidelity: `90–100%` (**+3 pts**, verified forensic)")

    with col4:
        persistence = st.radio(
            "Threat Persistence Detected? *",
            options=["No", "Yes"],
            index=1 if preset.get("persistence", False) else 0,
            horizontal=True,
            format_func=lambda x: "No (+0 pts)" if x == "No" else "Yes (+2 pts) — Survives reboot",
            help="Survives reboot via registry, scheduled tasks, cron, etc. (Yes = +2 pts)"
        )

    with col5:
        data_exposure = st.radio(
            "Data Compromised / Exfiltrated? *",
            options=["No", "Yes"],
            index=1 if preset.get("data_exposure", False) else 0,
            horizontal=True,
            format_func=lambda x: "No (+0 pts)" if x == "No" else "Yes (+3 pts) — Confirmed breach",
            help="Confirmed breach or exfiltration of sensitive organizational data (Yes = +3 pts)"
        )

    st.markdown("<br>", unsafe_allow_html=True)
    submit_button = st.form_submit_button("⚡ Evaluate Incident & Generate Decision Trace", type="primary", use_container_width=True)

# Process Evaluation
if submit_button:
    payload = {
        "title": title,
        "incident_type": incident_type,
        "business_impact": business_impact,
        "affected_assets": affected_assets,
        "confidence": confidence,
        "persistence": persistence,
        "data_exposure": data_exposure,
        "analyst_notes": analyst_notes,
    }

    try:
        trace = engine.evaluate_incident(payload)
        st.session_state["current_trace"] = trace
        st.session_state["evaluated_payload"] = payload
        st.success(f"Incident `{trace.incident_id}` triaged successfully!")
    except ValidationError as ve:
        st.error(f"Validation Error: {ve}")
    except Exception as e:
        st.error(f"Engine Evaluation Error: {e}")

# Requirement 9 & 10: Prominent Severity & Escalation Result with Clear Decision Trace
if "current_trace" in st.session_state:
    trace = st.session_state["current_trace"]
    theme = SEVERITY_THEMES.get(trace.final_severity, SEVERITY_THEMES["LOW"])

    st.markdown("---")
    st.subheader(f"🛡️ Auditable Decision Trace: `{trace.incident_id}`")

    # Requirement 9: Prominent Final Severity and Escalation
    st.markdown(
        f"""
        <div style="background-color: {theme['bg']}; border-left: 8px solid {theme['border']}; border: 1px solid {theme['border']}40; padding: 1.5rem; border-radius: 10px; margin-bottom: 1.25rem;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
                <div>
                    <span style="font-size: 0.8rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.8px; color: #475569;">Calculated Severity Tier</span>
                    <h2 style="color: {theme['color']}; margin: 0.2rem 0; font-size: 2rem;">{theme['icon']} {trace.final_severity} ({trace.total_score} / 15 Points)</h2>
                    <p style="margin: 0; color: #1e293b; font-size: 0.95rem;">{trace.severity_reason}</p>
                </div>
                <div style="text-align: right; min-width: 260px; background: #ffffff; padding: 1rem 1.25rem; border-radius: 8px; border: 1px solid #e2e8f0;">
                    <span style="font-size: 0.8rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.8px; color: #64748b;">Designated Escalation</span>
                    <h3 style="color: #0f172a; margin: 0.2rem 0; font-size: 1.2rem;">{trace.final_escalation}</h3>
                    <span style="background-color: {theme['bg']}; color: {theme['text']}; border: 1px solid {theme['border']}; padding: 0.25rem 0.65rem; border-radius: 6px; font-size: 0.82rem; font-weight: 700;">
                        ⏱️ Mandated SLA: {trace.sla_response_time}
                    </span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Severity Range Spectrum Indicators
    spec_c1, spec_c2, spec_c3, spec_c4 = st.columns(4)
    with spec_c1:
        is_curr = trace.final_severity == "LOW"
        st.markdown(
            f"<div style='background: {'#dcfce7' if is_curr else '#f8fafc'}; border: 2px solid {'#16a34a' if is_curr else '#e2e8f0'}; padding: 0.6rem; border-radius: 6px; text-align: center; font-weight: 700; color: {'#14532d' if is_curr else '#64748b'}; font-size: 0.88rem;'>"
            f"🟢 LOW (0–2 pts) {'👈' if is_curr else ''}</div>",
            unsafe_allow_html=True
        )
    with spec_c2:
        is_curr = trace.final_severity == "MEDIUM"
        st.markdown(
            f"<div style='background: {'#fef3c7' if is_curr else '#f8fafc'}; border: 2px solid {'#d97706' if is_curr else '#e2e8f0'}; padding: 0.6rem; border-radius: 6px; text-align: center; font-weight: 700; color: {'#78350f' if is_curr else '#64748b'}; font-size: 0.88rem;'>"
            f"🟡 MEDIUM (3–5 pts) {'👈' if is_curr else ''}</div>",
            unsafe_allow_html=True
        )
    with spec_c3:
        is_curr = trace.final_severity == "HIGH"
        st.markdown(
            f"<div style='background: {'#ffedd5' if is_curr else '#f8fafc'}; border: 2px solid {'#ea580c' if is_curr else '#e2e8f0'}; padding: 0.6rem; border-radius: 6px; text-align: center; font-weight: 700; color: {'#7c2d12' if is_curr else '#64748b'}; font-size: 0.88rem;'>"
            f"🟠 HIGH (6–8 pts) {'👈' if is_curr else ''}</div>",
            unsafe_allow_html=True
        )
    with spec_c4:
        is_curr = trace.final_severity == "CRITICAL"
        st.markdown(
            f"<div style='background: {'#fee2e2' if is_curr else '#f8fafc'}; border: 2px solid {'#dc2626' if is_curr else '#e2e8f0'}; padding: 0.6rem; border-radius: 6px; text-align: center; font-weight: 700; color: {'#7f1d1d' if is_curr else '#64748b'}; font-size: 0.88rem;'>"
            f"🔴 CRITICAL (9+ pts) {'👈' if is_curr else ''}</div>",
            unsafe_allow_html=True
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # Requirement 10: Visually Clear Decision Trace
    st.markdown("#### 1. Factor-by-Factor Rule Attribution")
    trace_rows = []
    for c in trace.contributions:
        trace_rows.append({
            "Evaluation Factor": c.factor,
            "Raw Telemetry": str(c.input_value),
            "Matched Bracket": c.matched_bracket,
            "Points Awarded": f"+{c.points} pts",
            "Deterministic Rule Justification": c.reason,
        })
    st.table(trace_rows)

    st.markdown("#### 2. Composite Score Derivation")
    st.markdown(
        f"""
        <div style="background: #ffffff; border: 1px solid #cbd5e1; border-radius: 6px; padding: 0.9rem 1.2rem; font-family: monospace; font-size: 0.95rem; color: #0f172a; margin-bottom: 1rem;">
            📐 <strong>Formula:</strong> {trace.score_formula}
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("#### 3. Standard Operating Procedure (SOP) Action Directive")
    st.markdown(
        f"""
        <div class="sop-directive-box">
            <p style="margin: 0 0 0.4rem 0; font-size: 0.95rem; color: #0f172a;">
                📋 <strong>Action Directive:</strong> {trace.action_directive}
            </p>
            <p style="margin: 0; font-size: 0.88rem; color: #475569;">
                👥 <strong>Notified Stakeholders:</strong> <code>{', '.join(trace.notified_roles)}</code>
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Persistence & Actions
    save_col1, save_col2 = st.columns([1, 4])
    with save_col1:
        if st.button("💾 Save Incident to SQLite Database", type="primary", use_container_width=True):
            record_id = db.save_incident(trace)
            st.success(f"Incident saved to database with record ID #{record_id}!")
    with save_col2:
        with st.expander("🔍 View Raw Forensic JSON Trace"):
            st.json(trace.to_dict())
