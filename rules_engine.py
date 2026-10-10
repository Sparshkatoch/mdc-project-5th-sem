"""
Core Decision Rules Engine for Incident Severity & Escalation.

Loads policy rules from config/rules.yaml, scores normalized security incident
parameters, classifies incident severity, determines escalation directives,
and generates an auditable DecisionTrace object.
"""

from datetime import datetime, timezone
import os
from pathlib import Path
import random
from typing import Any, Dict, List, Optional
import yaml

from engine.trace import DecisionTrace, RuleContribution
from engine.validator import validate_incident_input, ValidationError


DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "rules.yaml"


class RulesEngine:
    """
    Evaluates incident parameters against declarative YAML rules
    to determine severity, escalation, and transparent decision audit traces.
    """

    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or DEFAULT_CONFIG_PATH
        self.config = self._load_rules()

    def _load_rules(self) -> Dict[str, Any]:
        """Loads and parses the rules configuration from YAML with safe defaults."""
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Rules configuration file not found at: {self.config_path}")

        with open(self.config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if not isinstance(data, dict):
                raise ValueError("Rules configuration YAML root must be a dictionary.")
            return data

    def reload_rules(self) -> None:
        """Reloads the YAML rules from disk to support dynamic policy updates."""
        self.config = self._load_rules()

    @staticmethod
    def generate_incident_id(prefix: str = "INC") -> str:
        """Generates a realistic, chronological incident identifier (e.g. INC-20261003-7482)."""
        now = datetime.now(timezone.utc)
        rand_suffix = random.randint(1000, 9999)
        return f"{prefix}-{now.strftime('%Y%m%d')}-{rand_suffix}"

    def evaluate_incident(self, raw_data: Dict[str, Any]) -> DecisionTrace:
        """
        Validates raw input and executes the complete decision pipeline:
        Scoring -> Severity Thresholding -> Escalation Mapping -> Trace Construction.
        """
        is_valid, clean_data, errors = validate_incident_input(raw_data)
        if not is_valid:
            raise ValidationError(errors)

        incident_id = clean_data.get("incident_id") or self.generate_incident_id()
        title = clean_data["title"]
        incident_type = clean_data["incident_type"]
        analyst_notes = clean_data.get("analyst_notes", "")

        contributions: List[RuleContribution] = []

        # 1. Business Impact Scoring
        impact_c = self._evaluate_impact(clean_data["business_impact"])
        contributions.append(impact_c)

        # 2. Affected Assets Scoring
        assets_c = self._evaluate_assets(clean_data["affected_assets"])
        contributions.append(assets_c)

        # 3. Confidence Level Scoring
        conf_c = self._evaluate_confidence(clean_data["confidence"])
        contributions.append(conf_c)

        # 4. Persistence Scoring
        pers_c = self._evaluate_persistence(clean_data["persistence"])
        contributions.append(pers_c)

        # 5. Data Exposure Scoring
        exp_c = self._evaluate_data_exposure(clean_data["data_exposure"])
        contributions.append(exp_c)

        # Sum total points
        total_score = sum(c.points for c in contributions)

        # Construct formula string for auditability
        formula_parts = [f"{c.points} ({c.factor})" for c in contributions]
        score_formula = " + ".join(formula_parts) + f" = {total_score} points"

        # Determine severity
        severity_info = self._determine_severity(total_score)
        severity = severity_info["severity"]
        severity_reason = (
            f"Total score {total_score} falls into {severity} threshold "
            f"({severity_info['range_str']}): {severity_info['summary']}"
        )
        severity_color = severity_info["color"]

        # Determine escalation procedure
        escalation_info = self._determine_escalation(severity)

        return DecisionTrace(
            incident_id=incident_id,
            title=title,
            incident_type=incident_type,
            timestamp=datetime.now(timezone.utc).isoformat(),
            contributions=contributions,
            total_score=total_score,
            score_formula=score_formula,
            final_severity=severity,
            severity_reason=severity_reason,
            severity_color=severity_color,
            final_escalation=escalation_info["level"],
            sla_response_time=escalation_info["sla_response_time"],
            action_directive=escalation_info["action_directive"],
            notified_roles=escalation_info["notified_roles"],
            analyst_notes=analyst_notes
        )

    def _evaluate_impact(self, impact: str) -> RuleContribution:
        impacts_cfg = self.config.get("business_impact", {})
        impact_entry = impacts_cfg.get(impact, {"points": 1, "description": "Default Impact"})
        return RuleContribution(
            factor="Business Impact",
            input_value=impact,
            matched_bracket=f"Impact Tier: {impact}",
            points=int(impact_entry.get("points", 1)),
            reason=impact_entry.get("description", "")
        )

    def _evaluate_assets(self, assets: int) -> RuleContribution:
        brackets = self.config.get("affected_assets_brackets", [])
        for b in brackets:
            b_min = b.get("min", 0)
            b_max = b.get("max")
            if b_max is None:
                if assets >= b_min:
                    return RuleContribution(
                        factor="Affected Assets",
                        input_value=f"{assets} assets",
                        matched_bracket=b.get("bracket_label", f">={b_min}"),
                        points=int(b.get("points", 3)),
                        reason=b.get("description", "")
                    )
            else:
                if b_min <= assets <= b_max:
                    return RuleContribution(
                        factor="Affected Assets",
                        input_value=f"{assets} assets",
                        matched_bracket=b.get("bracket_label", f"{b_min}–{b_max}"),
                        points=int(b.get("points", 0)),
                        reason=b.get("description", "")
                    )
        # Fallback for unexpected boundary
        return RuleContribution(
            factor="Affected Assets",
            input_value=f"{assets} assets",
            matched_bracket="1–2 assets",
            points=0,
            reason="Contained minimal endpoints"
        )

    def _evaluate_confidence(self, conf: float) -> RuleContribution:
        brackets = self.config.get("confidence_brackets", [])
        for b in brackets:
            b_min = float(b.get("min", 0.0))
            b_max = float(b.get("max", 100.0))
            if b_min <= conf <= b_max:
                return RuleContribution(
                    factor="Confidence Level",
                    input_value=f"{conf}%",
                    matched_bracket=b.get("bracket_label", f"{b_min}–{b_max}%"),
                    points=int(b.get("points", 0)),
                    reason=b.get("description", "")
                )
        return RuleContribution(
            factor="Confidence Level",
            input_value=f"{conf}%",
            matched_bracket="Below 50%",
            points=0,
            reason="Uncorroborated alert signal"
        )

    def _evaluate_persistence(self, persistence: bool) -> RuleContribution:
        pers_cfg = self.config.get("persistence", {})
        # Note: YAML boolean keys can be boolean True/False or string "true"/"false"
        entry = pers_cfg.get(persistence) or pers_cfg.get(str(persistence).lower()) or {}
        points = int(entry.get("points", 2 if persistence else 0))
        label = "Yes" if persistence else "No"
        reason = entry.get("description", "Threat persistence status evaluated")
        return RuleContribution(
            factor="Persistence",
            input_value=label,
            matched_bracket=f"Persistence: {label}",
            points=points,
            reason=reason
        )

    def _evaluate_data_exposure(self, exposure: bool) -> RuleContribution:
        exp_cfg = self.config.get("data_exposure", {})
        entry = exp_cfg.get(exposure) or exp_cfg.get(str(exposure).lower()) or {}
        points = int(entry.get("points", 3 if exposure else 0))
        label = "Yes" if exposure else "No"
        reason = entry.get("description", "Data exposure status evaluated")
        return RuleContribution(
            factor="Data Exposure",
            input_value=label,
            matched_bracket=f"Data Exposure: {label}",
            points=points,
            reason=reason
        )

    def _determine_severity(self, total_score: int) -> Dict[str, Any]:
        thresholds = self.config.get("severity_thresholds", [])
        for t in thresholds:
            s_min = t.get("min_score", 0)
            s_max = t.get("max_score")
            if s_max is None:
                if total_score >= s_min:
                    return {
                        "severity": t["severity"],
                        "color": t.get("color", "#dc3545"),
                        "summary": t.get("summary", ""),
                        "range_str": f"{s_min}+ points"
                    }
            else:
                if s_min <= total_score <= s_max:
                    return {
                        "severity": t["severity"],
                        "color": t.get("color", "#28a745"),
                        "summary": t.get("summary", ""),
                        "range_str": f"{s_min}–{s_max} points"
                    }
        # Fallback
        return {
            "severity": "CRITICAL" if total_score >= 9 else "LOW",
            "color": "#dc3545" if total_score >= 9 else "#28a745",
            "summary": "Severity determined by boundary scoring",
            "range_str": "Standard Range"
        }

    def _determine_escalation(self, severity: str) -> Dict[str, Any]:
        esc_cfg = self.config.get("escalation_procedures", {})
        default_esc = {
            "level": "Security Analyst Review",
            "sla_response_time": "Within 4 hours",
            "action_directive": "Review incident parameters and notify team.",
            "notified_roles": ["Security Analyst"]
        }
        return esc_cfg.get(severity.upper(), default_esc)
