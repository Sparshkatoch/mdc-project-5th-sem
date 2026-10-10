"""
Unit tests for the SQLite Database Manager.
"""

from pathlib import Path
import tempfile
import pytest

from database.db_manager import DatabaseManager
from engine.rules_engine import RulesEngine


@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        temp_path = Path(tf.name)
    db = DatabaseManager(temp_path)
    yield db
    if temp_path.exists():
        temp_path.unlink()


def test_db_save_and_retrieve(temp_db):
    engine = RulesEngine()
    incident = {
        "title": "DB Test Case",
        "incident_type": "Malware",
        "business_impact": "High",
        "affected_assets": 12,
        "confidence": 80.0,
        "persistence": True,
        "data_exposure": False,
        "analyst_notes": "Test analyst note.",
    }
    trace = engine.evaluate_incident(incident)
    rec_id = temp_db.save_incident(trace)
    assert rec_id > 0

    fetched = temp_db.get_incident(trace.incident_id)
    assert fetched is not None
    assert fetched["incident_id"] == trace.incident_id
    assert fetched["title"] == "DB Test Case"
    assert fetched["total_score"] == trace.total_score
    assert fetched["severity"] == trace.final_severity
    assert fetched["escalation"] == trace.final_escalation
    assert fetched["analyst_notes"] == "Test analyst note."


def test_db_metrics_and_filter(temp_db):
    engine = RulesEngine()

    # Save a LOW incident
    trace_low = engine.evaluate_incident({
        "title": "Low Alert",
        "incident_type": "Reconnaissance",
        "business_impact": "Low",
        "affected_assets": 1,
        "confidence": 30.0,
        "persistence": False,
        "data_exposure": False,
    })
    temp_db.save_incident(trace_low)

    # Save a CRITICAL incident
    trace_crit = engine.evaluate_incident({
        "title": "Critical Outbreak",
        "incident_type": "Ransomware",
        "business_impact": "Critical",
        "affected_assets": 50,
        "confidence": 95.0,
        "persistence": True,
        "data_exposure": True,
    })
    temp_db.save_incident(trace_crit)

    metrics = temp_db.get_summary_metrics()
    assert metrics["total_incidents"] == 2
    assert metrics["severity_counts"]["LOW"] == 1
    assert metrics["severity_counts"]["CRITICAL"] == 1
    assert metrics["critical_count"] == 1

    # Test filtering
    filtered_crit = temp_db.filter_incidents(severity="CRITICAL")
    assert len(filtered_crit) == 1
    assert filtered_crit[0]["incident_id"] == trace_crit.incident_id

    # Test deletion
    deleted = temp_db.delete_incident(trace_low.incident_id)
    assert deleted is True
    assert temp_db.get_incident(trace_low.incident_id) is None
