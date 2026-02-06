from backend.app.scanner import _cookie_findings


def test_cookie_findings_https_missing_secure():
    cookies = ["sessionid=abc; HttpOnly; SameSite=Lax"]
    findings = _cookie_findings(cookies, is_https=True)
    ids = {finding.id for finding in findings}
    assert "cookie_missing_secure" in ids


def test_cookie_findings_missing_httponly_and_samesite():
    cookies = ["id=123; Secure"]
    findings = _cookie_findings(cookies, is_https=True)
    ids = {finding.id for finding in findings}
    assert "cookie_missing_httponly" in ids
    assert "cookie_missing_samesite" in ids


def test_cookie_findings_http_cookie_warning():
    cookies = ["id=123; HttpOnly"]
    findings = _cookie_findings(cookies, is_https=False)
    ids = {finding.id for finding in findings}
    assert "cookies_over_http" in ids


def test_cookie_prefix_violations():
    cookies = [
        "__Secure-id=abc",
        "__Host-sid=def; Secure; Path=/api; Domain=example.com",
    ]
    findings = _cookie_findings(cookies, is_https=True)
    ids = {finding.id for finding in findings}
    assert "cookie_secure_prefix_violation" in ids
    assert "cookie_host_prefix_violation" in ids


def test_samesite_none_without_secure():
    cookies = ["id=123; SameSite=None"]
    findings = _cookie_findings(cookies, is_https=True)
    ids = {finding.id for finding in findings}
    assert "cookie_samesite_none_without_secure" in ids
