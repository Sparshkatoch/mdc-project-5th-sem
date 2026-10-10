"""
Auditable Decision Trace Module for Incident Decision Engine.

Provides structured trace models that record every triggered rule, point contribution,
arithmetic summation, and escalation rationale to achieve 100% explainability.
"""

from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional


@dataclass
class RuleContribution:
    """Represents a single evaluated factor and its contribution to the final score."""
    factor: str
    input_value: Any
    matched_bracket: str
    points: int
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DecisionTrace:
    """
    Complete auditable decision record for an evaluated security incident.
    Complies with academic explainability and regulatory audit standards.
    """
    incident_id: str
    title: str
    incident_type: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    contributions: List[RuleContribution] = field(default_factory=list)
    total_score: int = 0
    score_formula: str = ""
    final_severity: str = "LOW"
    severity_reason: str = ""
    severity_color: str = "#28a745"
    final_escalation: str = "Normal Monitoring"
    sla_response_time: str = "Within 24 hours"
    action_directive: str = ""
    notified_roles: List[str] = field(default_factory=list)
    analyst_notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DecisionTrace":
        raw_contribs = data.get("contributions", [])
        contrib_objs = [
            RuleContribution(
                factor=c.get("factor", ""),
                input_value=c.get("input_value"),
                matched_bracket=c.get("matched_bracket", ""),
                points=int(c.get("points", 0)),
                reason=c.get("reason", "")
            )
            for c in raw_contribs
        ]
        return cls(
            incident_id=data.get("incident_id", "UNKNOWN"),
            title=data.get("title", "Untitled Incident"),
            incident_type=data.get("incident_type", "General"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            contributions=contrib_objs,
            total_score=int(data.get("total_score", 0)),
            score_formula=data.get("score_formula", ""),
            final_severity=data.get("final_severity", "LOW"),
            severity_reason=data.get("severity_reason", ""),
            severity_color=data.get("severity_color", "#28a745"),
            final_escalation=data.get("final_escalation", "Normal Monitoring"),
            sla_response_time=data.get("sla_response_time", "Within 24 hours"),
            action_directive=data.get("action_directive", ""),
            notified_roles=data.get("notified_roles", []),
            analyst_notes=data.get("analyst_notes", "")
        )

    @classmethod
    def from_json(cls, json_str: str) -> "DecisionTrace":
        return cls.from_dict(json.loads(json_str))

    def to_markdown_summary(self) -> str:
        """Generates a presentation-ready markdown audit log."""
        lines = [
            f"### Audit Decision Trace: `{self.incident_id}`",
            f"**Title:** {self.title} | **Type:** {self.incident_type} | **Timestamp (UTC):** {self.timestamp}",
            "",
            "#### 1. Factor-by-Factor Rule Attribution",
            "| Factor | Input Value | Matched Condition | Points | Rationale |",
            "| :--- | :--- | :--- | :---: | :--- |",
        ]
        for c in self.contributions:
            lines.append(
                f"| **{c.factor}** | `{c.input_value}` | {c.matched_bracket} | **+{c.points}** | {c.reason} |"
            )

        lines.extend([
            "",
            "#### 2. Composite Score Derivation",
            f"- **Formula:** `{self.score_formula}`",
            f"- **Total Calculated Score:** `{self.total_score} points`",
            "",
            "#### 3. Classification & Escalation Outcome",
            f"- **Final Severity:** **{self.final_severity}** ({self.severity_reason})",
            f"- **Escalation Protocol:** **{self.final_escalation}**",
            f"- **Mandated SLA:** `{self.sla_response_time}`",
            f"- **Operational Directive:** {self.action_directive}",
            f"- **Stakeholders Notified:** {', '.join(self.notified_roles)}",
        ])
        if self.analyst_notes:
            lines.extend(["", f"**Analyst Notes:** {self.analyst_notes}"])

        return "\n".join(lines)
