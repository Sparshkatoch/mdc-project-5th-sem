"""
Database Manager Module for Incident Decision Engine.

Provides an SQLite persistence layer for logging evaluated security incidents,
storing full auditable decision trace JSON records, and powering dashboard metrics.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional

from engine.trace import DecisionTrace


DEFAULT_DB_PATH = Path(__file__).resolve().parent / "incidents.db"


class DatabaseManager:
    """Manages SQLite operations for security incident audit trails."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = str(db_path or DEFAULT_DB_PATH)
        self.init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Creates a connection with row factory enabled."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> None:
        """Initializes the database schema if tables do not exist."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT UNIQUE NOT NULL,
                    title TEXT NOT NULL,
                    incident_type TEXT NOT NULL,
                    business_impact TEXT NOT NULL,
                    affected_assets INTEGER NOT NULL,
                    confidence REAL NOT NULL,
                    persistence INTEGER NOT NULL,
                    data_exposure INTEGER NOT NULL,
                    total_score INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    escalation TEXT NOT NULL,
                    sla_response_time TEXT NOT NULL,
                    action_directive TEXT,
                    decision_trace_json TEXT NOT NULL,
                    analyst_notes TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            # Create indexes for fast filtering and lookup
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_severity ON incidents(severity);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incident_type ON incidents(incident_type);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_created_at ON incidents(created_at);")
            conn.commit()

    def save_incident(self, trace: DecisionTrace, raw_input: Optional[Dict[str, Any]] = None) -> int:
        """
        Persists an evaluated incident and its complete decision trace.
        Returns the inserted record's database ID.
        """
        # Extract fields from trace or contributions
        contrib_map = {c.factor: c for c in trace.contributions}
        impact = contrib_map.get("Business Impact", None)
        impact_val = impact.input_value if impact else "Low"

        assets = contrib_map.get("Affected Assets", None)
        # Parse assets integer from "X assets" or raw input
        assets_val = 1
        if assets:
            try:
                assets_val = int(str(assets.input_value).split()[0])
            except Exception:
                assets_val = 1

        conf = contrib_map.get("Confidence Level", None)
        conf_val = 50.0
        if conf:
            try:
                conf_val = float(str(conf.input_value).replace("%", ""))
            except Exception:
                conf_val = 50.0

        pers = contrib_map.get("Persistence", None)
        pers_val = 1 if (pers and str(pers.input_value).lower() in ["yes", "true", "1"]) else 0

        exp = contrib_map.get("Data Exposure", None)
        exp_val = 1 if (exp and str(exp.input_value).lower() in ["yes", "true", "1"]) else 0

        trace_json = trace.to_json()
        created_at = trace.timestamp or datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO incidents (
                    incident_id, title, incident_type, business_impact, affected_assets,
                    confidence, persistence, data_exposure, total_score, severity,
                    escalation, sla_response_time, action_directive, decision_trace_json,
                    analyst_notes, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    trace.incident_id,
                    trace.title,
                    trace.incident_type,
                    str(impact_val),
                    assets_val,
                    conf_val,
                    pers_val,
                    exp_val,
                    trace.total_score,
                    trace.final_severity,
                    trace.final_escalation,
                    trace.sla_response_time,
                    trace.action_directive,
                    trace_json,
                    trace.analyst_notes,
                    created_at,
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single incident record by its incident_id."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def get_all_incidents(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Retrieves all stored incidents ordered by creation time descending."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,))
            return [dict(r) for r in cursor.fetchall()]

    def filter_incidents(
        self,
        severity: Optional[str] = None,
        escalation: Optional[str] = None,
        incident_type: Optional[str] = None,
        search_query: Optional[str] = None,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        """Filters stored incidents by multiple security attributes."""
        query = "SELECT * FROM incidents WHERE 1=1"
        params: List[Any] = []

        if severity and severity != "All":
            query += " AND severity = ?"
            params.append(severity.upper())

        if escalation and escalation != "All":
            query += " AND escalation = ?"
            params.append(escalation)

        if incident_type and incident_type != "All":
            query += " AND incident_type = ?"
            params.append(incident_type)

        if search_query and search_query.strip():
            query += " AND (title LIKE ? OR incident_id LIKE ? OR analyst_notes LIKE ?)"
            term = f"%{search_query.strip()}%"
            params.extend([term, term, term])

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [dict(r) for r in cursor.fetchall()]

    def get_summary_metrics(self) -> Dict[str, Any]:
        """Calculates aggregate metrics for the SOC Dashboard."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Total count
            cursor.execute("SELECT COUNT(*) FROM incidents")
            total = cursor.fetchone()[0]

            if total == 0:
                return {
                    "total_incidents": 0,
                    "avg_score": 0.0,
                    "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
                    "escalation_counts": {
                        "Normal Monitoring": 0,
                        "Security Analyst Review": 0,
                        "Incident Response Team": 0,
                        "Immediate Escalation": 0,
                    },
                    "critical_count": 0,
                    "high_count": 0,
                }

            # Severity counts
            cursor.execute("SELECT severity, COUNT(*) FROM incidents GROUP BY severity")
            sev_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
            for row in cursor.fetchall():
                sev_counts[row[0]] = row[1]

            # Escalation counts
            cursor.execute("SELECT escalation, COUNT(*) FROM incidents GROUP BY escalation")
            esc_counts = {}
            for row in cursor.fetchall():
                esc_counts[row[0]] = row[1]

            # Average score
            cursor.execute("SELECT AVG(total_score) FROM incidents")
            avg_score = round(cursor.fetchone()[0] or 0.0, 2)

            return {
                "total_incidents": total,
                "avg_score": avg_score,
                "severity_counts": sev_counts,
                "escalation_counts": esc_counts,
                "critical_count": sev_counts.get("CRITICAL", 0),
                "high_count": sev_counts.get("HIGH", 0),
            }

    def delete_incident(self, incident_id: str) -> bool:
        """Deletes an incident record by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM incidents WHERE incident_id = ?", (incident_id,))
            conn.commit()
            return cursor.rowcount > 0

    def clear_all(self) -> None:
        """Clears all records from the incidents table (useful for tabletop testing reset)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM incidents")
            conn.commit()
