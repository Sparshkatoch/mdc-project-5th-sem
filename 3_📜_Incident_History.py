"""
Incident History Page - Audit Trail, Filterable Records & Trace Inspector.
"""

import json
from pathlib import Path
import sys
import pandas as pd
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.db_manager import DatabaseManager
from engine.trace import DecisionTrace
from engine.ui_helpers import inject_soc_theme, render_sidebar, SEVERITY_THEMES


st.set_page_config(page_title="Incident History | Decision Engine", page_icon="📜", layout="wide")

inject_soc_theme()
db = DatabaseManager()
render_sidebar(db)

# Page Header
st.markdown(
    """
    <div class="soc-header">
        <h1>📜 Incident Audit Trail & History</h1>
        <p>Immutable forensic record of triaged security incidents, severity calculations, and auditable decision traces.</p>
    </div>
    """,
    unsafe_allow_html=True
)

# Filter Controls
f_col1, f_col2, f_col3, f_col4 = st.columns(4)

with f_col1:
    sev_filter = st.selectbox(
        "Filter by Severity",
        options=["All", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        index=0
    )

with f_col2:
    esc_filter = st.selectbox(
        "Filter by Escalation Level",
        options=[
            "All",
            "Normal Monitoring",
            "Security Analyst Review",
            "Incident Response Team",
            "Immediate Escalation"
        ],
        index=0
    )

with f_col3:
    all_incidents = db.get_all_incidents()
    type_options = ["All"] + sorted(list(set(r["incident_type"] for r in all_incidents if r.get("incident_type")))) if all_incidents else ["All"]
    type_filter = st.selectbox(
        "Filter by Threat Type",
        options=type_options,
        index=0
    )

with f_col4:
    search_query = st.text_input("Search Title / ID / Notes", placeholder="e.g. Ransomware, INC-2026...")

# Fetch filtered incidents
records = db.filter_incidents(
    severity=sev_filter,
    escalation=esc_filter,
    incident_type=type_filter,
    search_query=search_query
)

st.markdown(f"**Records Found:** `{len(records)} incidents` matching current filter criteria.")

if not records:
    st.info("No incident records found matching the current filters. Go to 'Analyze Incident' or 'Tabletop Testing' to record incidents.")
else:
    df = pd.DataFrame(records)
    display_cols = [
        "incident_id", "title", "incident_type", "business_impact",
        "affected_assets", "confidence", "total_score", "severity", "escalation", "created_at"
    ]
    st.dataframe(
        df[display_cols],
        use_container_width=True,
        hide_index=True,
        column_config={
            "incident_id": "Incident ID",
            "title": "Incident Title",
            "incident_type": "Threat Type",
            "business_impact": "Impact",
            "affected_assets": "Assets",
            "confidence": st.column_config.NumberColumn("Confidence", format="%.1f%%"),
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

    # Export to CSV
    csv_data = df.drop(columns=["decision_trace_json"], errors="ignore").to_csv(index=False).encode('utf-8')
    st.download_button(
        label=f"📥 Export {len(records)} Records to CSV",
        data=csv_data,
        file_name="incident_decision_audit_log.csv",
        mime="text/csv",
    )

    st.markdown("---")
    st.subheader("🔍 Deep-Dive: Inspect Stored Decision Trace")
    st.caption("Select any recorded incident to inspect its immutable mathematical audit record:")

    incident_options = [f"{r['incident_id']} - {r['title']} [{r['severity']}]" for r in records]
    selected_option = st.selectbox("Select an incident:", incident_options)

    if selected_option:
        sel_id = selected_option.split(" - ")[0].strip()
        selected_record = db.get_incident(sel_id)

        if selected_record and selected_record.get("decision_trace_json"):
            try:
                trace = DecisionTrace.from_json(selected_record["decision_trace_json"])
                st.markdown(trace.to_markdown_summary())

                col_act1, col_act2 = st.columns([1, 4])
                with col_act1:
                    if st.button(f"🗑️ Delete Record {sel_id}", type="secondary"):
                        db.delete_incident(sel_id)
                        st.toast(f"Deleted incident {sel_id}")
                        st.rerun()
                with col_act2:
                    with st.expander("Show Raw Stored JSON Payload (Forensics)"):
                        st.json(json.loads(selected_record["decision_trace_json"]))

            except Exception as ex:
                st.error(f"Error parsing stored decision trace: {ex}")
