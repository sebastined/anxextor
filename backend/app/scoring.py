from __future__ import annotations

from typing import Iterable, Tuple

from .models import ScanFinding


SEVERITY_PENALTY = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 5,
    "info": 0,
}


def score_from_findings(findings: Iterable[ScanFinding]) -> Tuple[int, str]:
    score = 100
    for finding in findings:
        score -= SEVERITY_PENALTY.get(finding.severity, 0)

    score = max(0, min(100, score))

    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    return score, grade
