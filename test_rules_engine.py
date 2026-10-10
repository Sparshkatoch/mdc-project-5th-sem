"""
Unit tests for the Incident Decision Rules Engine.
Tests scoring logic, boundary transitions, and escalation mappings.
"""

import pytest
from engine.rules_engine import RulesEngine


@pytest.fixture
def engine():
    return RulesEngine()


def test_minimum_possible_score(engine):
    """Minimum score possible should be 1 (Low impact + 0 for all other factors)."""
    incident = {
        "title": "Minimal Signal",
        "incident_type": "Test",
        "business_impact": "Low",
        "affected_assets": 1,
        "confidence": 10.0,
        "persistence": False,
        "data_exposure": False,
    }
    trace = engine.evaluate_incident(incident)
    assert trace.total_score == 1
    assert trace.final_severity == "LOW"
    assert trace.final_escalation == "Normal Monitoring"


def test_maximum_possible_score(engine):
    """Maximum score possible should be 15 (4 + 3 + 3 + 2 + 3)."""
    incident = {
        "title": "Catastrophic Breach",
        "incident_type": "Ransomware & Breach",
        "business_impact": "Critical",
        "affected_assets": 100,
        "confidence": 99.0,
        "persistence": True,
        "data_exposure": True,
    }
    trace = engine.evaluate_incident(incident)
    assert trace.total_score == 15
    assert trace.final_severity == "CRITICAL"
    assert trace.final_escalation == "Immediate Escalation"


@pytest.mark.parametrize(
    "impact_str,expected_points",
    [("Low", 1), ("Medium", 2), ("High", 3), ("Critical", 4)],
)
def test_impact_scoring(engine, impact_str, expected_points):
    contrib = engine._evaluate_impact(impact_str)
    assert contrib.points == expected_points


@pytest.mark.parametrize(
    "assets,expected_points",
    [(1, 0), (2, 0), (3, 1), (10, 1), (11, 2), (25, 2), (26, 3), (100, 3)],
)
def test_affected_assets_brackets(engine, assets, expected_points):
    contrib = engine._evaluate_assets(assets)
    assert contrib.points == expected_points


@pytest.mark.parametrize(
    "conf,expected_points",
    [
        (0.0, 0),
        (49.0, 0),
        (50.0, 1),
        (74.0, 1),
        (75.0, 2),
        (89.0, 2),
        (90.0, 3),
        (100.0, 3),
    ],
)
def test_confidence_brackets(engine, conf, expected_points):
    contrib = engine._evaluate_confidence(conf)
    assert contrib.points == expected_points


@pytest.mark.parametrize("persistence,expected_points", [(False, 0), (True, 2)])
def test_persistence_scoring(engine, persistence, expected_points):
    contrib = engine._evaluate_persistence(persistence)
    assert contrib.points == expected_points


@pytest.mark.parametrize("exposure,expected_points", [(False, 0), (True, 3)])
def test_data_exposure_scoring(engine, exposure, expected_points):
    contrib = engine._evaluate_data_exposure(exposure)
    assert contrib.points == expected_points


@pytest.mark.parametrize(
    "score,expected_severity,expected_escalation",
    [
        (1, "LOW", "Normal Monitoring"),
        (2, "LOW", "Normal Monitoring"),
        (3, "MEDIUM", "Security Analyst Review"),
        (5, "MEDIUM", "Security Analyst Review"),
        (6, "HIGH", "Incident Response Team"),
        (8, "HIGH", "Incident Response Team"),
        (9, "CRITICAL", "Immediate Escalation"),
        (12, "CRITICAL", "Immediate Escalation"),
    ],
)
def test_severity_and_escalation_thresholds(engine, score, expected_severity, expected_escalation):
    sev_info = engine._determine_severity(score)
    assert sev_info["severity"] == expected_severity
    esc_info = engine._determine_escalation(expected_severity)
    assert esc_info["level"] == expected_escalation
