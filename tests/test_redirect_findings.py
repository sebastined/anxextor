from backend.app.scanner import _redirect_findings


def test_redirect_chain_long():
    schemes = ["http", "https", "https", "https", "https"]
    findings = _redirect_findings(schemes)
    ids = {finding.id for finding in findings}
    assert "redirect_chain_long" in ids


def test_redirect_downgrade():
    schemes = ["https", "http"]
    findings = _redirect_findings(schemes)
    ids = {finding.id for finding in findings}
    assert "redirect_downgrade" in ids
