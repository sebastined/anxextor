from backend.app.security import normalize_url


def test_normalize_url_wildcard():
    target, hostname, scheme, wildcard = normalize_url("*.example.com")
    assert scheme == "https"
    assert hostname == "*.example.com"
    assert wildcard == "example.com"
    assert target.startswith("https://")
