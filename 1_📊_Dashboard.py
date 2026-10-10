"""
SOC Analytics Dashboard - Real-time Incident Metrics & Visualizations.
"""

from pathlib import Path
import sys
import altair as alt
import pandas as pd
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.db_manager import DatabaseManager
from data.synthetic_cases import get_all_scenarios
from engine.rules_engine import RulesEngine
from engine.ui_helpers import inject_soc_theme, render_sidebar, SEVERITY_THEMES


st.set_page_config(page_title="SOC Dashboard | Decision Engine", page_icon="📊", layout="wide")

inject_soc_theme()
db = DatabaseManager()
engine = RulesEngine()
render_sidebar(db)

# Page Header
st.markdown(
    """
    <div class="soc-header">
        <h1>📊 Security Operations Center (SOC) Dashboard</h1>
        <p>Operational incident telemetry overview, severity classifications, and mandatory escalation directive distributions.</p>
    </div>
    """,
    unsafe_allow_html=True
)

metrics = db.get_summary_metrics()

# Requirement 5: Dashboard Metric Cards
# - Total Incidents
# - Critical Incidents
# - High Incidents
# - Average Threat Score
m_col1, m_col2, m_col3, m_col4 = st.columns(4)

with m_col1:
    st.markdown(
        f"""
        <div class="soc-metric-card" style="border-left-color: #0284c7;">
            <div class="soc-metric-title">Total Incidents</div>
            <div class="soc-metric-value">{metrics['total_incidents']}</div>
            <div class="soc-metric-subtext">Evaluated & logged in SQLite</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with m_col2:
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

with m_col3:
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

with m_col4:
    st.markdown(
        f"""
        <div class="soc-metric-card" style="border-left-color: #475569;">
            <div class="soc-metric-title">Average Threat Score</div>
            <div class="soc-metric-value">{metrics['avg_score']} <span style="font-size: 1rem; color: #64748b;">/ 15</span></div>
            <div class="soc-metric-subtext">Calculated threat index</div>
        </div>
        """,
        unsafe_allow_html=True
    )

st.markdown("<br>", unsafe_allow_html=True)

# Requirement 6 & 7: Severity distribution chart with clear visual indicators for LOW, MEDIUM, HIGH, CRITICAL
if metrics["total_incidents"] == 0:
    st.info(
        "👋 **No incidents recorded in the database yet.**\n\n"
        "You can evaluate an incident on the **Analyze Incident** page, or click below to populate the database "
        "with all **15 synthetic cyber incident test cases** for an immediate live demonstration!"
    )
    if st.button("🚀 Pre-populate with 15 Synthetic Incident Scenarios", type="primary"):
        scenarios = get_all_scenarios()
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
        st.success("Successfully loaded all 15 synthetic incident scenarios into SQLite!")
        st.rerun()

else:
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.subheader("Severity Distribution")
        st.caption("Distribution across defined severity thresholds:")

        sev_counts = metrics["severity_counts"]
        sev_tiers = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        sev_palette = [
            SEVERITY_THEMES["LOW"]["color"],
            SEVERITY_THEMES["MEDIUM"]["color"],
            SEVERITY_THEMES["HIGH"]["color"],
            SEVERITY_THEMES["CRITICAL"]["color"],
        ]
        
        sev_df = pd.DataFrame({
            "Severity": sev_tiers,
            "Count": [sev_counts.get(s, 0) for s in sev_tiers]
        })
        
        chart_sev = (
            alt.Chart(sev_df)
            .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4, size=40)
            .encode(
                x=alt.X("Severity:N", sort=sev_tiers, title="Severity Classification", axis=alt.Axis(labelAngle=0)),
                y=alt.Y("Count:Q", title="Incident Count", axis=alt.Axis(tickMinStep=1)),
                color=alt.Color(
                    "Severity:N",
                    scale=alt.Scale(domain=sev_tiers, range=sev_palette),
                    legend=None
                ),
                tooltip=[
                    alt.Tooltip("Severity:N", title="Severity Tier"),
                    alt.Tooltip("Count:Q", title="Incident Count")
                ]
            )
            .properties(height=260)
        )
        st.altair_chart(chart_sev, use_container_width=True)

    with chart_col2:
        st.subheader("Mandatory Escalation Workflows")
        st.caption("Incidents categorized by designated Standard Operating Procedure:")

        esc_counts = metrics["escalation_counts"]
        if esc_counts:
            esc_df = pd.DataFrame({
                "Escalation": list(esc_counts.keys()),
                "Count": list(esc_counts.values())
            })
            chart_esc = (
                alt.Chart(esc_df)
                .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4, size=35)
                .encode(
                    x=alt.X("Escalation:N", sort="-y", title="Escalation Protocol", axis=alt.Axis(labelAngle=-25)),
                    y=alt.Y("Count:Q", title="Incident Count", axis=alt.Axis(tickMinStep=1)),
                    color=alt.value("#0284c7"),
                    tooltip=[
                        alt.Tooltip("Escalation:N", title="Escalation"),
                        alt.Tooltip("Count:Q", title="Incident Count")
                    ]
                )
                .properties(height=260)
            )
            st.altair_chart(chart_esc, use_container_width=True)
        else:
            st.info("No escalation data recorded yet.")

    st.markdown("---")

    # Recent Incidents Table
    st.subheader("Recent Incident Triage Feed")
    st.caption("Latest security incidents triaged and persisted in the SQLite audit log:")

    recent = db.get_all_incidents(limit=15)
    if recent:
        df_feed = pd.DataFrame(recent)[
            ["incident_id", "title", "incident_type", "business_impact", "total_score", "severity", "escalation", "created_at"]
        ]
        
        st.dataframe(
            df_feed,
            use_container_width=True,
            hide_index=True,
            column_config={
                "incident_id": "Incident ID",
                "title": "Incident Title",
                "incident_type": "Threat Type",
                "business_impact": "Impact",
                "total_score": st.column_config.ProgressColumn(
                    "Threat Score",
                    min_value=0,
                    max_value=15,
                    format="%d / 15 pts"
                ),
                "severity": "Severity",
                "escalation": "Escalation Procedure",
                "created_at": "Logged Time (UTC)"
            }
        )
    else:
        st.caption("No incidents logged.")

    col_btn1, col_btn2 = st.columns([1, 4])
    with col_btn1:
        if st.button("🗑️ Reset Database", help="Clear all stored incidents for a clean presentation demo"):
            db.clear_all()
            st.toast("Database reset successfully.")
            st.rerun()
    with col_btn2:
        st.caption("Clears SQLite table records. You can reload the 15 synthetic cases anytime for viva demonstration.")
