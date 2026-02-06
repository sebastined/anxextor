from backend.app.scanner import _check_headers


def test_missing_frame_ancestors():
    headers = {
        "content-security-policy": "default-src 'self'",
        "referrer-policy": "strict-origin-when-cross-origin",
    }
    findings = _check_headers(headers, [], is_https=True)
    ids = {finding.id for finding in findings}
    assert "missing_frame_ancestors" in ids


def test_weak_referrer_policy():
    headers = {
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "referrer-policy": "origin",
    }
    findings = _check_headers(headers, [], is_https=True)
    ids = {finding.id for finding in findings}
    assert "weak_referrer_policy" in ids
