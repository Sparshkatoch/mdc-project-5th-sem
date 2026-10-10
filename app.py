"""
Incident Severity & Escalation Decision Engine - Main Entry Point.

Academic Cybersecurity Decision-Support System
College Minor Degree Project
"""

import sys
from pathlib import Path
import streamlit as st

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.db_manager import DatabaseManager
from engine.rules_engine import RulesEngine
from engine.ui_helpers import inject_soc_theme, render_sidebar


# Set Streamlit page configuration
st.set_page_config(
    page_title="Cyber Incident Decision Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Apply unified professional SOC theme
inject_soc_theme()


def load_services():
    """Initializes core engine and database services."""
    try:
        engine = RulesEngine()
        db = DatabaseManager()
        return engine, db, None
    except Exception as e:
        return None, None, str(e)


def main():
    engine, db, init_err = load_services()
    render_sidebar(db)

    # Hero Header Banner
    st.markdown(
        """
        <div class="soc-header">
            <h1>🛡️ Incident Severity & Escalation Decision Engine</h1>
            <p>An auditable, rule-driven cybersecurity decision-support system built for college minor degree project evaluation.
            Transforms synthetic security telemetry into <strong>deterministic severity scores</strong>, assigns 
            <strong>Standard Operating Procedure (SOP) escalations</strong> with SLAs, and produces an 
            <strong>explainable decision trace</strong> for forensic compliance.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if init_err:
        st.error(f"Initialization Error: {init_err}")
        return

    # Dashboard Metric Cards
    metrics = db.get_summary_metrics()
    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.markdown(
            f"""
            <div class="soc-metric-card" style="border-left-color: #0284c7;">
                <div class="soc-metric-title">Total Incidents</div>
                <div class="soc-metric-value">{metrics['total_incidents']}</div>
                <div class="soc-metric-subtext">Triaged & stored in SQLite</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with c2:
        st.markdown(
            f"""
            <div class="soc-metric-card" style="border-left-color: #dc2626;">
                <div class="soc-metric-title">Critical Incidents</div>
                <div class="soc-metric-value" style="color: #dc2626;">{metrics['critical_count']}</div>
                <div class="soc-metric-subtext">Immediate SLA (&lt; 15 min)</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with c3:
        st.markdown(
            f"""
            <div class="soc-metric-card" style="border-left-color: #ea580c;">
                <div class="soc-metric-title">High Incidents</div>
                <div class="soc-metric-value" style="color: #ea580c;">{metrics['high_count']}</div>
                <div class="soc-metric-subtext">CSIRT SLA (&lt; 1 hour)</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with c4:
        st.markdown(
            f"""
            <div class="soc-metric-card" style="border-left-color: #475569;">
                <div class="soc-metric-title">Average Threat Score</div>
                <div class="soc-metric-value">{metrics['avg_score']} <span style="font-size: 1rem; color: #64748b;">/ 15</span></div>
                <div class="soc-metric-subtext">Composite threat index</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # 3-Step Lifecycle
    st.markdown("### 💡 Triage Decision Pipeline")
    s1, s2, s3 = st.columns(3)
    with s1:
        st.markdown(
            """
            <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1.1rem; height: 100%;">
                <strong style="color: #0284c7; font-size: 0.95rem;">STEP 1: Ingest Telemetry</strong>
                <p style="color: #475569; font-size: 0.88rem; margin: 0.4rem 0 0 0; line-height: 1.45;">
                    Captures 5 standard parameters: Business Impact, Affected Assets count, Detection Confidence, Threat Persistence, and Data Exposure.
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )
    with s2:
        st.markdown(
            """
            <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1.1rem; height: 100%;">
                <strong style="color: #0284c7; font-size: 0.95rem;">STEP 2: Deterministic Rules</strong>
                <p style="color: #475569; font-size: 0.88rem; margin: 0.4rem 0 0 0; line-height: 1.45;">
                    Evaluates inputs against declarative weights in <code>config/rules.yaml</code>. Sums points linearly (Range: 1 to 15).
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )
    with s3:
        st.markdown(
            """
            <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1.1rem; height: 100%;">
                <strong style="color: #0284c7; font-size: 0.95rem;">STEP 3: Auditable Trace & SOP</strong>
                <p style="color: #475569; font-size: 0.88rem; margin: 0.4rem 0 0 0; line-height: 1.45;">
                    Classifies severity (LOW to CRITICAL), sets mandatory escalation SLAs, and outputs an auditable decision trace for compliance.
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # Application Modules Grid
    st.markdown("### 🚀 Application Modules")
    row1_c1, row1_c2, row1_c3 = st.columns(3)

    with row1_c1:
        st.markdown(
            """
            <div style="background: #ffffff; border: 1px solid #e2e8f0; border-top: 4px solid #0284c7; border-radius: 8px; padding: 1.25rem; height: 160px; display: flex; flex-direction: column; justify-content: space-between;">
                <div>
                    <h4 style="margin: 0 0 0.4rem 0; color: #0f172a;">📊 1. SOC Dashboard</h4>
                    <p style="color: #475569; font-size: 0.88rem; margin: 0;">Operational overview, severity distribution charts, and recent incident logs.</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        if st.button("Open Dashboard", key="btn_nav_dash", use_container_width=True):
            st.switch_page("pages/1_📊_Dashboard.py")

    with row1_c2:
        st.markdown(
            """
            <div style="background: #ffffff; border: 1px solid #e2e8f0; border-top: 4px solid #0284c7; border-radius: 8px; padding: 1.25rem; height: 160px; display: flex; flex-direction: column; justify-content: space-between;">
                <div>
                    <h4 style="margin: 0 0 0.4rem 0; color: #0f172a;">🔍 2. Analyze Incident</h4>
                    <p style="color: #475569; font-size: 0.88rem; margin: 0;">Interactive triage form. Evaluates parameters, assigns severity, and generates trace.</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        if st.button("Analyze an Incident", key="btn_nav_eval", use_container_width=True):
            st.switch_page("pages/2_🔍_Analyze_Incident.py")

    with row1_c3:
        st.markdown(
            """
            <div style="background: #ffffff; border: 1px solid #e2e8f0; border-top: 4px solid #0284c7; border-radius: 8px; padding: 1.25rem; height: 160px; display: flex; flex-direction: column; justify-content: space-between;">
                <div>
                    <h4 style="margin: 0 0 0.4rem 0; color: #0f172a;">📜 3. Incident History</h4>
                    <p style="color: #475569; font-size: 0.88rem; margin: 0;">Searchable, filterable audit log of evaluated incidents with CSV export.</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        if st.button("View Incident History", key="btn_nav_hist", use_container_width=True):
            st.switch_page("pages/3_📜_Incident_History.py")

    st.markdown("<br>", unsafe_allow_html=True)
    row2_c1, row2_c2, row2_c3 = st.columns(3)

    with row2_c1:
        st.markdown(
            """
            <div style="background: #ffffff; border: 1px solid #e2e8f0; border-top: 4px solid #0284c7; border-radius: 8px; padding: 1.25rem; height: 160px; display: flex; flex-direction: column; justify-content: space-between;">
                <div>
                    <h4 style="margin: 0 0 0.4rem 0; color: #0f172a;">📐 4. Severity Matrix</h4>
                    <p style="color: #475569; font-size: 0.88rem; margin: 0;">Interactive What-If live sandbox, scoring rubrics, and SOP escalation directives.</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        if st.button("Inspect Severity Matrix", key="btn_nav_mat", use_container_width=True):
            st.switch_page("pages/4_📐_Severity_Matrix.py")

    with row2_c2:
        st.markdown(
            """
            <div style="background: #ffffff; border: 1px solid #e2e8f0; border-top: 4px solid #0284c7; border-radius: 8px; padding: 1.25rem; height: 160px; display: flex; flex-direction: column; justify-content: space-between;">
                <div>
                    <h4 style="margin: 0 0 0.4rem 0; color: #0f172a;">🧪 5. Tabletop Testing</h4>
                    <p style="color: #475569; font-size: 0.88rem; margin: 0;">Batch execution across 15 synthetic attack scenarios with 100% ground-truth verification.</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        if st.button("Launch Tabletop Drills", key="btn_nav_tab", use_container_width=True):
            st.switch_page("pages/5_🧪_Tabletop_Testing.py")

    with row2_c3:
        st.markdown(
            """
            <div style="background: #ffffff; border: 1px solid #e2e8f0; border-top: 4px solid #0284c7; border-radius: 8px; padding: 1.25rem; height: 160px; display: flex; flex-direction: column; justify-content: space-between;">
                <div>
                    <h4 style="margin: 0 0 0.4rem 0; color: #0f172a;">💡 6. About & Viva Guide</h4>
                    <p style="color: #475569; font-size: 0.88rem; margin: 0;">College viva defense cheat sheet, architecture diagram, and NIST SP 800-61 alignment.</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        if st.button("Read Viva Defense Guide", key="btn_nav_abt", use_container_width=True):
            st.switch_page("pages/6_💡_About_Project.py")

    st.markdown("---")
    st.info(
        "🎓 **Academic Evaluation Note:** This application uses 100% synthetic data for educational, defensive decision-support research. "
        "No offensive tools, exploits, malware, or production credentials are used."
    )


if __name__ == "__main__":
    main()
