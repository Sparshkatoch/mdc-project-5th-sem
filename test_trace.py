"""
Unit tests for the Auditable Decision Trace data structure and serialization.
"""

from engine.rules_engine import RulesEngine
from engine.trace import DecisionTrace


def test_decision_trace_completeness():
    engine = RulesEngine()
    incident = {
        "title": "Data Leak Test",
        "incident_type": "Data Exposure",
        "business_impact": "High",
        "affected_assets": 5,
        "confidence": 85.0,
        "persistence": False,
        "data_exposure": True,
        "analyst_notes": "Detected via cloud DLP.",
    }
    trace = engine.evaluate_incident(incident)

    # Validate presence of all 5 evaluated factor contributions
    assert len(trace.contributions) == 5
    factors = [c.factor for c in trace.contributions]
    assert "Business Impact" in factors
    assert "Affected Assets" in factors
    assert "Confidence Level" in factors
    assert "Persistence" in factors
    assert "Data Exposure" in factors

    # Math: High(3) + 5 assets(1) + 85%(2) + No(0) + Yes(3) = 9
    assert trace.total_score == 9
    assert trace.final_severity == "CRITICAL"
    assert trace.final_escalation == "Immediate Escalation"
    assert "9 points" in trace.score_formula

    # JSON serialization roundtrip
    json_str = trace.to_json()
    assert isinstance(json_str, str)
    deserialized = DecisionTrace.from_json(json_str)
    assert deserialized.incident_id == trace.incident_id
    assert deserialized.total_score == trace.total_score
    assert deserialized.final_severity == trace.final_severity
    assert len(deserialized.contributions) == 5

    # Markdown representation
    md = trace.to_markdown_summary()
    assert "Audit Decision Trace" in md
    assert "Factor-by-Factor Rule Attribution" in md
    assert "Immediate Escalation" in md
