"""
Unit tests for the Input Validation module.
"""

from engine.validator import validate_incident_input


def test_valid_input():
    payload = {
        "title": "Phishing Incident",
        "incident_type": "Phishing",
        "business_impact": "Low",
        "affected_assets": 2,
        "confidence": 75.0,
        "persistence": False,
        "data_exposure": False,
    }
    is_valid, clean, errors = validate_incident_input(payload)
    assert is_valid is True
    assert len(errors) == 0
    assert clean["title"] == "Phishing Incident"
    assert clean["affected_assets"] == 2
    assert clean["confidence"] == 75.0


def test_missing_or_blank_fields():
    payload = {
        "title": "   ",
        "incident_type": "",
        "business_impact": "InvalidImpact",
        "affected_assets": 0,
        "confidence": 150.0,
        "persistence": "maybe",
        "data_exposure": None,
    }
    is_valid, clean, errors = validate_incident_input(payload)
    assert is_valid is False
    assert any("Title" in e for e in errors)
    assert any("Type" in e for e in errors)
    assert any("Impact" in e for e in errors)
    assert any("Assets" in e for e in errors)
    assert any("Confidence" in e for e in errors)
    assert any("Persistence" in e for e in errors)
    assert any("Data Exposure" in e for e in errors)


def test_string_boolean_conversions():
    payload = {
        "title": "Test String Booleans",
        "incident_type": "Test",
        "business_impact": "High",
        "affected_assets": "5",
        "confidence": "85.5",
        "persistence": "Yes",
        "data_exposure": "no",
    }
    is_valid, clean, errors = validate_incident_input(payload)
    assert is_valid is True
    assert clean["affected_assets"] == 5
    assert clean["confidence"] == 85.5
    assert clean["persistence"] is True
    assert clean["data_exposure"] is False
