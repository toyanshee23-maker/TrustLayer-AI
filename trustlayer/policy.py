"""Configurable, explainable routing decisions for the local demo."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
from typing import Any


@dataclass
class RiskPolicy:
    version: str = "1"
    low_threshold: int = 30
    high_threshold: int = 65
    block_on_ssn: bool = True
    review_high: bool = True
    high_impact_terms: list[str] = field(
        default_factory=lambda: ["medical", "diagnosis", "treatment", "legal", "lawsuit", "credit", "loan", "employment", "terminate"]
    )

    def validate(self) -> None:
        if not 0 <= self.low_threshold < self.high_threshold <= 100:
            raise ValueError("Risk thresholds must satisfy 0 <= low < high <= 100.")
        if not self.version.strip():
            raise ValueError("Policy version cannot be blank.")
        if len(self.high_impact_terms) > 100:
            raise ValueError("At most 100 high-impact terms may be configured.")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def route_request(
    text: str,
    findings: list[dict[str, Any]],
    verification: dict[str, Any],
    policy: RiskPolicy,
    required_checks_ok: bool = True,
) -> dict[str, Any]:
    """Route safely with explicit reasons; a failed required check always blocks."""
    policy.validate()
    if not required_checks_ok:
        return {
            "level": "BLOCKED", "score": 100, "requires_review": True,
            "blocked": True, "reasons": ["A required safety check failed; operation blocked fail-closed."],
            "actions": ["Do not use this output.", "Investigate the failed safety check."],
        }

    score = 0
    reasons: list[str] = []
    for finding in findings:
        kind = finding.get("kind", "sensitive data")
        points = {"ssn": 60, "email": 12, "phone": 12, "name": 8}.get(kind, 10)
        score += points
        reasons.append(f"Detected {kind} pattern (+{points}); review sanitized content before reuse.")
    unsupported_count = int(verification.get("unsupported_count", 0))
    if unsupported_count:
        points = min(unsupported_count * 30, 100)
        score += points
        reasons.append(f"{unsupported_count} unsupported or contradicted claim(s) (+{points}).")
    if verification.get("needs_review_count") or verification.get("errors") or not verification.get("source_count"):
        score += 25
        reasons.append("Evidence is incomplete or inconclusive (+25); route conservatively.")
    matched_terms = sorted({
        term.strip().lower()
        for term in policy.high_impact_terms
        if term.strip() and re.search(rf"\b{re.escape(term.strip())}\b", text, re.I)
    })
    if matched_terms:
        score += 35
        reasons.append("High-impact content terms detected (+35): " + ", ".join(matched_terms))

    score = min(score, 100)
    critical = policy.block_on_ssn and any(item.get("kind") == "ssn" for item in findings)
    uncertain = bool(
        verification.get("needs_review_count")
        or verification.get("errors")
        or not verification.get("source_count")
    )
    if critical:
        level = "BLOCKED"
        reasons.append("Configured critical privacy rule: SSN detection blocks onward use.")
    elif score >= policy.high_threshold:
        level = "HIGH"
        reasons.append(f"Score {score} meets configured high threshold ({policy.high_threshold}).")
    elif uncertain:
        level = "UNCERTAIN"
        reasons.append("Insufficient evidence prevents a confident automated routing decision.")
    elif score >= policy.low_threshold:
        level = "MEDIUM"
        reasons.append(f"Score {score} meets configured medium threshold ({policy.low_threshold}).")
    else:
        level = "LOW"
        reasons.append(f"Score {score} is below configured low threshold ({policy.low_threshold}).")

    requires_review = (
        level in {"UNCERTAIN", "BLOCKED"}
        or (level == "HIGH" and policy.review_high)
        or (level == "MEDIUM" and unsupported_count > 0)
    )
    if level == "HIGH" and not policy.review_high:
        reasons.append("Configured high-risk human-review rule is disabled; the high-risk flag remains visible.")
    actions = (
        ["Do not forward; resolve critical privacy finding and request human review."]
        if level == "BLOCKED"
        else ["Require authorized human review before downstream use."]
        if requires_review
        else ["Continue with the configured checks; retain the audit record."]
    )
    return {
        "level": level, "score": score, "requires_review": requires_review,
        "blocked": level == "BLOCKED", "reasons": reasons, "actions": actions,
    }
