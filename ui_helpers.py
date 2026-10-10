"""
UI Helpers & Component Styling for Incident Decision Engine.

Provides unified SOC theme styling, responsive layout containers,
standardized sidebar diagnostics, and severity badge components.
"""

from typing import Optional
import streamlit as st


# Professional Cybersecurity / SOC Color Palette
SEVERITY_THEMES = {
    "LOW": {
        "color": "#16a34a",       # Forest / Emerald Green
        "bg": "#f0fdf4",          # Light Green Tint
        "border": "#22c55e",
        "text": "#14532d",
        "badge_bg": "#dcfce7",
        "badge_border": "#86efac",
        "icon": "🟢"
    },
    "MEDIUM": {
        "color": "#d97706",       # Amber / Dark Yellow
        "bg": "#fffbeb",          # Light Amber Tint
        "border": "#f59e0b",
        "text": "#78350f",
        "badge_bg": "#fef3c7",
        "badge_border": "#fde68a",
        "icon": "🟡"
    },
    "HIGH": {
        "color": "#ea580c",       # Deep Orange
        "bg": "#fff7ed",          # Light Orange Tint
        "border": "#f97316",
        "text": "#7c2d12",
        "badge_bg": "#ffedd5",
        "badge_border": "#fed7aa",
        "icon": "🟠"
    },
    "CRITICAL": {
        "color": "#dc2626",       # Crimson Red
        "bg": "#fef2f2",          # Light Red Tint
        "border": "#ef4444",
        "text": "#7f1d1d",
        "badge_bg": "#fee2e2",
        "badge_border": "#fca5a5",
        "icon": "🔴"
    }
}


def inject_soc_theme():
    """Injects professional, responsive SOC styling across Streamlit pages."""
    st.markdown(
        """
        <style>
        /* Base typography & container adjustments */
        .main .block-container {
            padding-top: 1.8rem;
            padding-bottom: 2.5rem;
            max-width: 1300px;
        }
        
        /* Professional SOC Header Banner */
        .soc-header {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 60%, #334155 100%);
            border-left: 6px solid #0284c7;
            border-radius: 10px;
            padding: 1.4rem 1.8rem;
            color: #ffffff;
            margin-bottom: 1.5rem;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
        }
        .soc-header h1 {
            color: #ffffff !important;
            font-size: 1.85rem !important;
            font-weight: 700 !important;
            margin: 0 0 0.4rem 0 !important;
            letter-spacing: -0.3px;
        }
        .soc-header p {
            color: #cbd5e1 !important;
            font-size: 0.98rem !important;
            margin: 0 !important;
            line-height: 1.5;
        }
        
        /* Metric Cards */
        .soc-metric-card {
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 1rem 1.2rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.03);
            border-left: 4px solid #0284c7;
            height: 100%;
        }
        .soc-metric-title {
            font-size: 0.82rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.6px;
            color: #64748b;
            margin-bottom: 0.3rem;
        }
        .soc-metric-value {
            font-size: 1.65rem;
            font-weight: 700;
            color: #0f172a;
            margin-bottom: 0.2rem;
        }
        .soc-metric-subtext {
            font-size: 0.8rem;
            color: #475569;
        }
        
        /* Result & Decision Trace Banners */
        .result-banner {
            border-radius: 10px;
            padding: 1.4rem 1.6rem;
            margin: 1.2rem 0;
            border-width: 1px;
            border-style: solid;
        }
        
        /* Severity Pills */
        .severity-pill {
            display: inline-block;
            font-weight: 700;
            font-size: 0.82rem;
            padding: 0.25rem 0.65rem;
            border-radius: 6px;
            letter-spacing: 0.4px;
        }
        
        /* Standard Operating Procedure Box */
        .sop-directive-box {
            background-color: #f8fafc;
            border: 1px solid #cbd5e1;
            border-left: 5px solid #0284c7;
            border-radius: 8px;
            padding: 1rem 1.25rem;
            margin: 1rem 0;
        }
        
        /* Compact clean button styles */
        .stButton>button {
            border-radius: 6px;
            font-weight: 600;
            transition: all 0.15s ease-in-out;
        }
        
        /* Subheading styling */
        h2, h3 {
            color: #0f172a;
            letter-spacing: -0.2px;
        }
        </style>
        """,
        unsafe_allow_html=True
    )


def render_sidebar(db=None):
    """Renders a standardized, professional sidebar across all application pages."""
    with st.sidebar:
        st.markdown("### 🛡️ **SOC Decision Hub**")
        st.markdown(
            "<span style='background:#e0f2fe; color:#0369a1; padding:0.2rem 0.5rem; border-radius:4px; font-size:0.75rem; font-weight:700;'>"
            "COLLEGE MINOR PROJECT"
            "</span>",
            unsafe_allow_html=True
        )
        st.caption("Incident Severity & Escalation Engine v1.0")
        st.divider()

        st.markdown("#### **System Diagnostics**")
        st.markdown("🟢 **Rule Policy:** `rules.yaml` (Active)")
        st.markdown("🟢 **Database:** `SQLite` (Connected)")
        st.markdown("🟢 **Standard:** `NIST SP 800-61`")
        st.markdown("🟢 **Telemetry:** 100% Synthetic & Safe")

        if db:
            try:
                metrics = db.get_summary_metrics()
                st.divider()
                st.markdown("#### **Database Telemetry**")
                st.write(f"- Total Triaged: **{metrics['total_incidents']}**")
                st.write(f"- Critical Alerts: **{metrics['critical_count']}**")
                st.write(f"- High Alerts: **{metrics['high_count']}**")
                st.write(f"- Avg Threat Score: **{metrics['avg_score']} / 15**")
            except Exception:
                pass

        st.divider()
        st.markdown("#### **Quick Navigation**")
        st.markdown(
            """
            * 📊 [Dashboard](Dashboard)
            * 🔍 [Analyze Incident](Analyze_Incident)
            * 📜 [Incident History](Incident_History)
            * 📐 [Severity Matrix](Severity_Matrix)
            * 🧪 [Tabletop Testing](Tabletop_Testing)
            * 💡 [About & Viva Guide](About_Project)
            """
        )
        st.caption("College Viva Presentation Edition • Safe Defensive Cybersecurity")


def render_severity_pill(severity: str, score: Optional[int] = None) -> str:
    """Returns HTML for a standardized, high-contrast severity pill."""
    sev = severity.upper()
    theme = SEVERITY_THEMES.get(sev, SEVERITY_THEMES["LOW"])
    score_txt = f" ({score} pts)" if score is not None else ""
    return (
        f"<span style='background-color: {theme['badge_bg']}; color: {theme['text']}; "
        f"border: 1px solid {theme['badge_border']}; font-weight: 700; font-size: 0.85rem; "
        f"padding: 0.25rem 0.65rem; border-radius: 6px; display: inline-block;'>"
        f"{theme['icon']} {sev}{score_txt}</span>"
    )
