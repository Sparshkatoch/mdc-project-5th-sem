"""
Tabletop Testing & Simulation Lab - 15 Synthetic Cyber Scenarios.
"""

from pathlib import Path
import sys
import pandas as pd
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.db_manager import DatabaseManager
from data.synthetic_cases import get_all_scenarios, get_scenario_by_id
from engine.rules_engine import RulesEngine
from engine.ui_helpers import inject_soc_theme, render_sidebar, SEVERITY_THEMES


st.set_page_config(page_title="Tabletop Testing | Decision Engine", page_icon="🧪", layout="wide")

inject_soc_theme()
db = DatabaseManager()
engine = RulesEngine()
scenarios = get_all_scenarios()
render_sidebar(db)

# Page Header
st.markdown(
    """
    <div class="soc-header">
        <h1>🧪 Tabletop Incident Response Testing Lab</h1>
        <p>Automated simulation drills validating deterministic engine accuracy across 15 synthetic cyber attack scenarios.</p>
    </div>
    """,
    unsafe_allow_html=True
)

tab1, tab2 = st.tabs(["🚀 Automated Batch Test Suite", "🎯 Scenario-by-Scenario Drilldown"])

with tab1:
    st.markdown("#### Batch Verification of All 15 Synthetic Scenarios")
    st.caption("Executes all scenarios simultaneously and compares computed scores against ground-truth values:")

    if st.button("▶️ Execute Batch Test on All 15 Scenarios", type="primary", use_container_width=True):
        results = []
        passed_count = 0

        for s in scenarios:
            trace = engine.evaluate_incident({
                "incident_id": s["id"],
                "title": s["title"],
                "incident_type": s["incident_type"],
                "business_impact": s["business_impact"],
                "affected_assets": s["affected_assets"],
                "confidence": s["confidence"],
                "persistence": s["persistence"],
                "data_exposure": s["data_exposure"],
                "analyst_notes": s["analyst_notes"],
            })

            score_match = trace.total_score == s["expected_score"]
            sev_match = trace.final_severity == s["expected_severity"]
            esc_match = trace.final_escalation == s["expected_escalation"]
            is_pass = score_match and sev_match and esc_match

            if is_pass:
                passed_count += 1

            results.append({
                "ID": s["id"],
                "Scenario Title": s["title"],
                "Threat Type": s["incident_type"],
                "Expected Score": f"{s['expected_score']} pts",
                "Engine Score": f"{trace.total_score} pts",
                "Expected Severity": s["expected_severity"],
                "Engine Severity": trace.final_severity,
                "Escalation SOP": trace.final_escalation,
                "Status": "✅ PASS" if is_pass else "❌ FAIL",
            })

        st.session_state["batch_results"] = results
        st.session_state["passed_count"] = passed_count

    if "batch_results" in st.session_state:
        passed = st.session_state["passed_count"]
        total = len(scenarios)

        if passed == total:
            st.success(f"🎉 **Batch Verification Complete: {passed}/{total} Scenarios Passed (100% Deterministic Fidelity)**")
        else:
            st.warning(f"⚠️ **Batch Verification Result: {passed}/{total} Passed.**")

        df_res = pd.DataFrame(st.session_state["batch_results"])
        st.dataframe(df_res, use_container_width=True, hide_index=True)

        col_save_all, col_clear = st.columns([2, 3])
        with col_save_all:
            if st.button("💾 Persist All 15 Evaluated Scenarios to Database", type="secondary"):
                for s in scenarios:
                    trace = engine.evaluate_incident({
                        "incident_id": s["id"],
                        "title": s["title"],
                        "incident_type": s["incident_type"],
                        "business_impact": s["business_impact"],
                        "affected_assets": s["affected_assets"],
                        "confidence": s["confidence"],
                        "persistence": s["persistence"],
                        "data_exposure": s["data_exposure"],
                        "analyst_notes": s["analyst_notes"],
                    })
                    db.save_incident(trace)
                st.toast("Saved all 15 scenarios to SQLite database!")

with tab2:
    st.markdown("#### Interactive Scenario Drilldown")
    st.caption("Inspect tactical telemetry, MITRE ATT&CK context, and the complete decision trace for any scenario:")

    # Severity Filter
    f_sev = st.radio("Filter Scenarios by Severity:", ["All", "LOW", "MEDIUM", "HIGH", "CRITICAL"], horizontal=True)
    filtered_scenarios = scenarios if f_sev == "All" else [s for s in scenarios if s["expected_severity"] == f_sev]

    selected_id = st.selectbox(
        "Choose a synthetic scenario to inspect:",
        options=[s["id"] for s in filtered_scenarios],
        format_func=lambda sid: f"{sid}: {get_scenario_by_id(sid)['title']} [{get_scenario_by_id(sid)['expected_severity']} - {get_scenario_by_id(sid)['expected_score']} pts]"
    )

    if selected_id:
        scenario = get_scenario_by_id(selected_id)
        theme = SEVERITY_THEMES.get(scenario["expected_severity"], SEVERITY_THEMES["LOW"])

        c_scen_left, c_scen_right = st.columns([3, 2])
        with c_scen_left:
            st.markdown(f"### {scenario['title']}")
            st.markdown(
                f"<span style='background-color: {theme['badge_bg']}; color: {theme['text']}; border: 1px solid {theme['badge_border']}; padding: 0.2rem 0.6rem; border-radius: 4px; font-weight: bold; font-size: 0.85rem;'>"
                f"{theme['icon']} {scenario['expected_severity']} TIER ({scenario['expected_score']} PTS)</span> "
                f"<span style='background: #f1f5f9; color: #334155; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.85rem;'>Threat: {scenario['incident_type']}</span>",
                unsafe_allow_html=True
            )
            st.markdown("<br>", unsafe_allow_html=True)
            st.info(f"📖 **Incident Narrative:**\n\n{scenario['description']}")
            st.caption(f"**Triage Notes:** {scenario['analyst_notes']}")

        with c_scen_right:
            st.markdown("#### Telemetry Inputs")
            st.markdown(
                f"""
                <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1rem; font-size: 0.9rem;">
                    <p style="margin: 0 0 0.4rem 0;"><strong>Business Impact:</strong> <code>{scenario['business_impact']}</code></p>
                    <p style="margin: 0 0 0.4rem 0;"><strong>Affected Assets:</strong> <code>{scenario['affected_assets']} endpoints</code></p>
                    <p style="margin: 0 0 0.4rem 0;"><strong>Confidence:</strong> <code>{scenario['confidence']}%</code></p>
                    <p style="margin: 0 0 0.4rem 0;"><strong>Persistence:</strong> <code>{'Yes' if scenario['persistence'] else 'No'}</code></p>
                    <p style="margin: 0;"><strong>Data Exposure:</strong> <code>{'Yes' if scenario['data_exposure'] else 'No'}</code></p>
                </div>
                """,
                unsafe_allow_html=True
            )

        # Evaluate this scenario live
        trace = engine.evaluate_incident({
            "incident_id": scenario["id"],
            "title": scenario["title"],
            "incident_type": scenario["incident_type"],
            "business_impact": scenario["business_impact"],
            "affected_assets": scenario["affected_assets"],
            "confidence": scenario["confidence"],
            "persistence": scenario["persistence"],
            "data_exposure": scenario["data_exposure"],
            "analyst_notes": scenario["analyst_notes"],
        })

        st.markdown("---")
        st.markdown(trace.to_markdown_summary())
