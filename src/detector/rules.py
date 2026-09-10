"""Detection rules and scoring logic for phishing analysis."""

from dataclasses import dataclass, field


@dataclass
class DetectionResult:
    """Result of a phishing detection analysis."""

    is_phishing: bool
    confidence: float
    risk_level: str
    triggered_rules: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)

    @staticmethod
    def risk_from_score(score: float) -> str:
        if score >= 0.75:
            return "CRITICAL"
        if score >= 0.5:
            return "HIGH"
        if score >= 0.25:
            return "MEDIUM"
        return "LOW"


def score_from_rules(triggered: list[str], weights: dict[str, float]) -> float:
    """Calculate weighted phishing score from triggered rules."""
    if not triggered:
        return 0.0
    total = sum(weights.get(rule, 0.1) for rule in triggered)
    return min(total, 1.0)
