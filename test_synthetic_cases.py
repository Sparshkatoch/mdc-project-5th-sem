"""
Automated validation of all 15 synthetic tabletop cyber incident scenarios.
Verifies that the decision rules engine accurately calculates the expected score,
severity classification, and escalation SOP for every synthetic case.
"""

import pytest
from data.synthetic_cases import get_all_scenarios
from engine.rules_engine import RulesEngine


@pytest.fixture
def engine():
    return RulesEngine()


def test_scenario_count():
    scenarios = get_all_scenarios()
    assert len(scenarios) == 15, "There must be exactly 15 synthetic tabletop test scenarios."


@pytest.mark.parametrize("scenario", get_all_scenarios(), ids=lambda s: s["id"])
def test_each_synthetic_scenario(engine, scenario):
    raw_payload = {
        "title": scenario["title"],
        "incident_type": scenario["incident_type"],
        "business_impact": scenario["business_impact"],
        "affected_assets": scenario["affected_assets"],
        "confidence": scenario["confidence"],
        "persistence": scenario["persistence"],
        "data_exposure": scenario["data_exposure"],
        "analyst_notes": scenario.get("analyst_notes", ""),
    }

    trace = engine.evaluate_incident(raw_payload)

    # 1. Total score verification
    assert trace.total_score == scenario["expected_score"], (
        f"Score mismatch for {scenario['id']} ({scenario['title']}): "
        f"Expected {scenario['expected_score']}, got {trace.total_score}. "
        f"Formula: {trace.score_formula}"
    )

    # 2. Final severity verification
    assert trace.final_severity == scenario["expected_severity"], (
        f"Severity mismatch for {scenario['id']} ({scenario['title']}): "
        f"Expected {scenario['expected_severity']}, got {trace.final_severity}."
    )

    # 3. Escalation directive verification
    assert trace.final_escalation == scenario["expected_escalation"], (
        f"Escalation mismatch for {scenario['id']} ({scenario['title']}): "
        f"Expected {scenario['expected_escalation']}, got {trace.final_escalation}."
    )
