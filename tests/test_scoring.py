from backend.app.models import ScanFinding
from backend.app.scoring import score_from_findings


def test_score_from_findings():
    findings = [
        ScanFinding(
            id="missing_csp",
            title="Missing CSP",
            severity="high",
            description="",
            recommendation="",
        ),
        ScanFinding(
            id="missing_hsts",
            title="Missing HSTS",
            severity="medium",
            description="",
            recommendation="",
        ),
    ]

    score, grade = score_from_findings(findings)

    assert score == 70
    assert grade == "C"
