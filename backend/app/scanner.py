from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime, timezone
from time import perf_counter
from typing import Dict, List, Optional, Tuple

import dns.resolver
import uuid
import httpx

from .config import settings
from .models import ScanFinding, ScanResult
from .scoring import score_from_findings
from .security import TargetValidationError, normalize_url, validate_public_target

USER_AGENT = "anxextor/0.1"
REQUEST_TIMEOUT = settings.http_timeout_seconds
RETRY_COUNT = settings.http_retries


def _finding(
    finding_id: str,
    title: str,
    severity: str,
    description: str,
    recommendation: str,
    cve: str | None = None,
    cvss_score: float | None = None,
    reference_url: str | None = None,
) -> ScanFinding:
    return ScanFinding(
        id=finding_id,
        title=title,
        severity=severity,
        description=description,
        recommendation=recommendation,
        cve=cve,
        cvss_score=cvss_score,
        reference_url=reference_url,
    )


def _check_headers(
    headers: Dict[str, str],
    set_cookies: List[str],
    is_https: bool,
) -> List[ScanFinding]:
    findings: List[ScanFinding] = []

    csp = headers.get("content-security-policy")
    if not csp:
        findings.append(
            _finding(
                "missing_csp",
                "Missing Content-Security-Policy",
                "high",
                "CSP is not present, increasing XSS risk.",
                "Implement Content-Security-Policy with restrictive directives to prevent XSS attacks. Start with 'default-src 'self'' and explicitly allow trusted origins. Avoid 'unsafe-inline' and 'unsafe-eval' where possible.",
                cve="CWE-79",
                cvss_score=6.1,
                reference_url="https://cwe.mitre.org/data/definitions/79.html",
            )
        )
    else:
        if "frame-ancestors" not in csp:
            findings.append(
                _finding(
                    "missing_frame_ancestors",
                    "CSP missing frame-ancestors",
                    "medium",
                    "CSP does not set frame-ancestors.",
                    "Add 'frame-ancestors 'none'' to your CSP to prevent clickjacking attacks. Use 'frame-ancestors 'self'' only if embedding within your own domain is required.",
                    cve="CWE-1021",
                    cvss_score=4.3,
                    reference_url="https://cwe.mitre.org/data/definitions/1021.html",
                )
            )

    hsts = headers.get("strict-transport-security")
    if not hsts:
        findings.append(
            _finding(
                "missing_hsts",
                "Missing Strict-Transport-Security",
                "medium",
                "HSTS is not enabled.",
                "Implement HSTS with 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to enforce HTTPS connections and prevent SSL stripping attacks. Consider HSTS preloading for maximum protection.",
                cve="CWE-319",
                cvss_score=5.9,
                reference_url="https://cwe.mitre.org/data/definitions/319.html",
            )
        )
    elif "max-age" in hsts and "max-age=" in hsts:
        try:
            max_age = int(hsts.split("max-age=")[1].split(";")[0])
            if max_age < 15552000:
                findings.append(
                    _finding(
                        "weak_hsts",
                        "HSTS max-age too low",
                        "low",
                        "HSTS max-age is shorter than 6 months.",
                        "Set max-age to at least 15552000.",
                    )
                )
        except ValueError:
            findings.append(
                _finding(
                    "invalid_hsts",
                    "Invalid HSTS header",
                    "low",
                    "HSTS max-age value could not be parsed.",
                    "Set a valid max-age value.",
                )
            )

    if "x-frame-options" not in headers:
        findings.append(
            _finding(
                "missing_xfo",
                "Missing X-Frame-Options",
                "medium",
                "X-Frame-Options is not present.",
                "Set 'X-Frame-Options: DENY' to prevent clickjacking. Use 'SAMEORIGIN' only if same-origin framing is required. Modern applications should also use CSP frame-ancestors for broader browser support.",
                cve="CWE-1021",
                cvss_score=4.3,
                reference_url="https://cwe.mitre.org/data/definitions/1021.html",
            )
        )

    if "x-content-type-options" not in headers:
        findings.append(
            _finding(
                "missing_xcto",
                "Missing X-Content-Type-Options",
                "low",
                "X-Content-Type-Options is not present.",
                "Set 'X-Content-Type-Options: nosniff' to prevent MIME-sniffing vulnerabilities. This header prevents browsers from interpreting files as a different MIME type than declared.",
            )
        )

    referrer_policy = headers.get("referrer-policy")
    if not referrer_policy:
        findings.append(
            _finding(
                "missing_referrer_policy",
                "Missing Referrer-Policy",
                "low",
                "Referrer-Policy is not present.",
                "Implement Referrer-Policy to control referrer information leakage. Recommended: 'strict-origin-when-cross-origin' balances functionality and privacy. Use 'no-referrer' for maximum privacy.",
            )
        )
    else:
        strong_policies = {
            "no-referrer",
            "strict-origin",
            "strict-origin-when-cross-origin",
        }
        if referrer_policy.lower() not in strong_policies:
            findings.append(
                _finding(
                    "weak_referrer_policy",
                    "Referrer-Policy is weak",
                    "low",
                    f"Referrer-Policy is set to '{referrer_policy}'.",
                    "Use strict-origin-when-cross-origin or no-referrer.",
                )
            )

    if "permissions-policy" not in headers:
        findings.append(
            _finding(
                "missing_permissions_policy",
                "Missing Permissions-Policy",
                "low",
                "Permissions-Policy is not present.",
                "Define Permissions-Policy to control browser feature access (camera, microphone, geolocation, etc.). Deny all features by default and explicitly allow only those required: 'camera=(), microphone=(), geolocation=()'.",
            )
        )

    if "cross-origin-opener-policy" not in headers:
        findings.append(
            _finding(
                "missing_coop",
                "Missing Cross-Origin-Opener-Policy",
                "info",
                "COOP is not present.",
                "Set Cross-Origin-Opener-Policy for isolation.",
            )
        )

    if "cross-origin-embedder-policy" not in headers:
        findings.append(
            _finding(
                "missing_coep",
                "Missing Cross-Origin-Embedder-Policy",
                "info",
                "COEP is not present.",
                "Set Cross-Origin-Embedder-Policy if needed.",
            )
        )

    findings.extend(_cookie_findings(set_cookies, is_https))
    findings.extend(_cache_findings(headers))

    if "server" in headers:
        findings.append(
            _finding(
                "server_header_exposed",
                "Server header exposed",
                "info",
                "The Server header can reveal implementation details.",
                "Remove or minimize the Server header value.",
            )
        )

    return findings


def _cookie_findings(set_cookies: List[str], is_https: bool) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    if not set_cookies:
        return findings

    missing_secure = []
    missing_httponly = []
    missing_samesite = []
    secure_prefix_violations = []
    host_prefix_violations = []

    for cookie in set_cookies:
        parts = [part.strip() for part in cookie.split(";") if part.strip()]
        name = parts[0].split("=", 1)[0] if parts else "unknown"
        attribute_parts = parts[1:]
        attributes = {part.lower() for part in attribute_parts}
        attribute_map = {}
        for attr in attribute_parts:
            if "=" in attr:
                key, value = attr.split("=", 1)
                attribute_map[key.strip().lower()] = value.strip()

        has_secure = "secure" in attributes
        has_httponly = "httponly" in attributes
        has_samesite = any(part.lower().startswith("samesite=") for part in attribute_parts)
        samesite_value = attribute_map.get("samesite", "").lower()
        domain_value = attribute_map.get("domain")
        path_value = attribute_map.get("path")

        if is_https and not has_secure:
            missing_secure.append(name)
        if not has_httponly:
            missing_httponly.append(name)
        if not has_samesite:
            missing_samesite.append(name)

        if name.startswith("__Secure-") and not has_secure:
            secure_prefix_violations.append(name)

        if name.startswith("__Host-"):
            if not has_secure or (path_value and path_value != "/") or domain_value:
                host_prefix_violations.append(name)

        if samesite_value == "none" and not has_secure:
            findings.append(
                _finding(
                    "cookie_samesite_none_without_secure",
                    "SameSite=None without Secure",
                    "high",
                    f"Cookie {name} sets SameSite=None without Secure.",
                    "Cookies with SameSite=None MUST include the Secure attribute to prevent CSRF attacks. This is a browser requirement for cross-site cookie usage. Ensure all such cookies are transmitted only over HTTPS.",
                    cve="CWE-352",
                    cvss_score=8.8,
                    reference_url="https://cwe.mitre.org/data/definitions/352.html",
                )
            )

    if not is_https:
        findings.append(
            _finding(
                "cookies_over_http",
                "Cookies set over HTTP",
                "medium",
                "Cookies were set on a non-HTTPS response.",
                "Serve all cookies exclusively over HTTPS to prevent session hijacking and credential theft. Configure your server to redirect HTTP traffic to HTTPS and enable HSTS.",
                cve="CWE-614",
                cvss_score=5.9,
                reference_url="https://cwe.mitre.org/data/definitions/614.html",
            )
        )

    if missing_secure:
        findings.append(
            _finding(
                "cookie_missing_secure",
                "Cookies missing Secure flag",
                "medium",
                f"Cookies without Secure: {', '.join(missing_secure)}.",
                "Add the Secure attribute to all session and authentication cookies to ensure they are only transmitted over encrypted HTTPS connections. This prevents cookie theft via man-in-the-middle attacks.",
                cve="CWE-614",
                cvss_score=5.9,
                reference_url="https://cwe.mitre.org/data/definitions/614.html",
            )
        )

    if missing_httponly:
        findings.append(
            _finding(
                "cookie_missing_httponly",
                "Cookies missing HttpOnly flag",
                "low",
                f"Cookies without HttpOnly: {', '.join(missing_httponly)}.",
                "Add the HttpOnly attribute to session and authentication cookies to prevent XSS-based cookie theft. Only client-side accessible cookies (e.g., preference cookies) should omit this flag.",
            )
        )

    if missing_samesite:
        findings.append(
            _finding(
                "cookie_missing_samesite",
                "Cookies missing SameSite",
                "low",
                f"Cookies without SameSite: {', '.join(missing_samesite)}.",
                "Set SameSite attribute to prevent CSRF attacks. Use 'SameSite=Lax' for most cookies, 'SameSite=Strict' for highly sensitive operations, or 'SameSite=None; Secure' only when cross-site access is required.",
            )
        )

    if secure_prefix_violations:
        findings.append(
            _finding(
                "cookie_secure_prefix_violation",
                "__Secure- cookies missing Secure",
                "medium",
                f"__Secure- cookies without Secure: {', '.join(secure_prefix_violations)}.",
                "Ensure __Secure- cookies always include Secure.",
            )
        )

    if host_prefix_violations:
        findings.append(
            _finding(
                "cookie_host_prefix_violation",
                "__Host- cookie prefix misuse",
                "medium",
                f"__Host- cookies violating requirements: {', '.join(host_prefix_violations)}.",
                "Ensure __Host- cookies use Secure, Path=/, and no Domain.",
            )
        )

    return findings


def _cache_findings(headers: Dict[str, str]) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    cache_control = headers.get("cache-control", "")

    if not cache_control:
        findings.append(
            _finding(
                "missing_cache_control",
                "Missing Cache-Control",
                "low",
                "Cache-Control header is not present.",
                "Add Cache-Control to define caching behavior.",
            )
        )
        return findings

    if "public" in cache_control:
        findings.append(
            _finding(
                "cache_control_public",
                "Cache-Control is public",
                "medium",
                "Response is marked as public cacheable.",
                "Set 'Cache-Control: private' for user-specific content or 'Cache-Control: no-store' for sensitive data to prevent caching in shared caches (CDNs, proxies). Public caching can expose sensitive information.",
                cve="CWE-524",
                cvss_score=5.3,
                reference_url="https://cwe.mitre.org/data/definitions/524.html",
            )
        )
    elif all(token not in cache_control for token in ["no-store", "private", "no-cache"]):
        findings.append(
            _finding(
                "cache_control_weak",
                "Cache-Control may be permissive",
                "low",
                "Caching directives do not include no-store/private/no-cache.",
                "Review caching directives for sensitive responses.",
            )
        )

    return findings


def _redirect_findings(schemes: List[str]) -> List[ScanFinding]:
    findings: List[ScanFinding] = []

    if len(schemes) <= 1:
        return findings

    if len(schemes) > 4:
        findings.append(
            _finding(
                "redirect_chain_long",
                "Redirect chain is long",
                "low",
                f"Redirect chain length is {len(schemes) - 1}.",
                "Reduce redirect hops for faster and safer navigation.",
            )
        )

    for previous, current in zip(schemes, schemes[1:]):
        if previous == "https" and current == "http":
            findings.append(
                _finding(
                    "redirect_downgrade",
                    "Redirect downgrades HTTPS to HTTP",
                    "medium",
                    "A redirect downgrades from HTTPS to HTTP.",
                    "Never redirect from HTTPS to HTTP as this exposes users to downgrade attacks and session hijacking. Ensure all redirect chains maintain HTTPS throughout.",
                    cve="CWE-319",
                    cvss_score=5.9,
                    reference_url="https://cwe.mitre.org/data/definitions/319.html",
                )
            )
            break

    return findings


def _tls_info(hostname: str) -> Tuple[Optional[Dict[str, str]], List[ScanFinding]]:
    findings: List[ScanFinding] = []
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=REQUEST_TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as sock:
                cert = sock.getpeercert()
                protocol = sock.version() or "unknown"
                cipher = sock.cipher()[0] if sock.cipher() else "unknown"

        not_after = cert.get("notAfter")
        expiry_days = None
        if not_after:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expires = expires.replace(tzinfo=timezone.utc)
            expiry_days = (expires - datetime.now(timezone.utc)).days
            if expiry_days < 0:
                findings.append(
                    _finding(
                        "cert_expired",
                        "TLS certificate expired",
                        "high",
                        "TLS certificate is expired.",
                        "Renew the TLS certificate immediately.",
                    )
                )
            elif expiry_days <= 14:
                findings.append(
                    _finding(
                        "cert_expiring_soon",
                        "TLS certificate expiring soon",
                        "medium",
                        "TLS certificate expires within 14 days.",
                        "Renew the TLS certificate soon.",
                    )
                )

        if protocol in {"TLSv1", "TLSv1.1"}:
            findings.append(
                _finding(
                    "weak_tls",
                    "Weak TLS protocol",
                    "high",
                    f"Server negotiates {protocol}.",
                    "Disable TLS 1.0/1.1 and require TLS 1.2+.",
                )
            )

        tls_data = {
            "protocol": protocol,
            "cipher": cipher,
            "days_until_expiry": expiry_days,
        }
        return tls_data, findings
    except Exception:
        findings.append(
            _finding(
                "tls_error",
                "TLS handshake failed",
                "medium",
                "Could not complete TLS handshake.",
                "Verify TLS/SSL certificate validity, ensure TLS 1.2+ is enabled, check firewall rules for port 443, and validate cipher suite compatibility. Consider using Mozilla SSL Configuration Generator for secure defaults.",
                cve="CWE-295",
                cvss_score=7.4,
                reference_url="https://cwe.mitre.org/data/definitions/295.html",
            )
        )
        return None, findings


def _dns_records(domain: str) -> Dict[str, bool]:
    resolver = dns.resolver.Resolver()

    def has_txt(name: str, prefix: str) -> bool:
        try:
            answers = resolver.resolve(name, "TXT")
            for record in answers:
                value = "".join(segment.decode() for segment in record.strings)
                if value.lower().startswith(prefix):
                    return True
        except Exception:
            return False
        return False

    def has_rr(name: str, rtype: str) -> bool:
        try:
            resolver.resolve(name, rtype)
            return True
        except Exception:
            return False

    return {
        "spf": has_txt(domain, "v=spf1"),
        "dmarc": has_txt(f"_dmarc.{domain}", "v=dmarc1"),
        "caa": has_rr(domain, "CAA"),
        "dnssec": has_rr(domain, "DS"),
    }


def _wildcard_dns_findings(domain: str) -> List[ScanFinding]:
    findings: List[ScanFinding] = []
    random_label = uuid.uuid4().hex[:12]
    test_host = f"{random_label}.{domain}"
    try:
        dns.resolver.resolve(test_host, "A")
        findings.append(
            _finding(
                "wildcard_dns_detected",
                "Wildcard DNS detected",
                "info",
                "Random subdomain resolved, indicating wildcard DNS.",
                "Ensure wildcard DNS is intended and protected by access controls.",
            )
        )
    except Exception:
        return findings
    return findings


def _dns_findings(domain: str, records: Dict[str, bool]) -> List[ScanFinding]:
    findings: List[ScanFinding] = []

    if not records.get("spf"):
        findings.append(
            _finding(
                "missing_spf",
                "Missing SPF record",
                "low",
                "No SPF record detected.",
                "Add an SPF TXT record to specify authorized mail servers: 'v=spf1 include:_spf.google.com ~all' (adjust for your provider). This helps prevent email spoofing.",
            )
        )

    if not records.get("dmarc"):
        findings.append(
            _finding(
                "missing_dmarc",
                "Missing DMARC policy",
                "medium",
                "No DMARC policy detected.",
                "Implement DMARC by adding a TXT record at '_dmarc.yourdomain.com' with policy 'v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@yourdomain.com' to prevent email spoofing and phishing attacks.",
                cve="CWE-345",
                cvss_score=5.3,
                reference_url="https://cwe.mitre.org/data/definitions/345.html",
            )
        )

    if not records.get("caa"):
        findings.append(
            _finding(
                "missing_caa",
                "Missing CAA record",
                "low",
                "No CAA record detected.",
                "Add CAA DNS records to restrict which Certificate Authorities can issue certificates for your domain: '0 issue \"letsencrypt.org\"'. This prevents unauthorized certificate issuance.",
            )
        )

    if not records.get("dnssec"):
        findings.append(
            _finding(
                "dnssec_not_detected",
                "DNSSEC not detected",
                "info",
                "No DS record detected.",
                "Enable DNSSEC if supported by your registrar.",
            )
        )

    findings.append(
        _finding(
            "dkim_not_checked",
            "DKIM selector not checked",
            "info",
            "DKIM requires a selector; not checked in MVP.",
            "Provide a selector-specific DKIM check if needed.",
        )
    )

    return findings


def scan(target: str) -> ScanResult:
    start = perf_counter()
    normalized_url, hostname, _, wildcard_base = normalize_url(target)
    if wildcard_base:
        normalized_url = normalized_url.replace(hostname, wildcard_base, 1)
        hostname = wildcard_base
    validate_public_target(hostname)

    findings: List[ScanFinding] = []

    timeout = httpx.Timeout(REQUEST_TIMEOUT, connect=5.0)
    limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)

    # Try with SSL verification first
    ssl_error = None
    response = None
    
    with httpx.Client(
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
        timeout=timeout,
        limits=limits,
        verify=True,
    ) as client:
        last_error: Optional[Exception] = None
        for attempt in range(RETRY_COUNT + 1):
            try:
                response = client.get(normalized_url)
                break
            except (ssl.SSLError, httpx.ConnectError) as exc:
                # SSL verification failed - record error and retry without verification
                if "CERTIFICATE_VERIFY_FAILED" in str(exc) or "certificate verify failed" in str(exc).lower():
                    ssl_error = exc
                    break
                last_error = exc
                if attempt >= RETRY_COUNT:
                    raise
                time.sleep(0.2 * (attempt + 1))
            except httpx.HTTPError as exc:
                last_error = exc
                if attempt >= RETRY_COUNT:
                    raise
                time.sleep(0.2 * (attempt + 1))
        else:
            if last_error:
                raise last_error
    
    # If SSL verification failed, retry without verification but flag the issue
    if ssl_error and not response:
        findings.append(
            _finding(
                "ssl_verification_failed",
                "SSL certificate verification failed",
                "high",
                f"Certificate verification error: {str(ssl_error)}",
                "Fix SSL certificate chain. Ensure intermediate certificates are properly configured and the certificate is issued by a trusted CA. Use SSL Labs (ssllabs.com/ssltest) to diagnose certificate issues.",
                cve="CWE-295",
                cvss_score=7.4,
                reference_url="https://cwe.mitre.org/data/definitions/295.html",
            )
        )
        
        # Retry without verification to gather other security info
        with httpx.Client(
            headers={"User-Agent": USER_AGENT},
            follow_redirects=True,
            timeout=timeout,
            limits=limits,
            verify=False,
        ) as client:
            last_error = None
            for attempt in range(RETRY_COUNT + 1):
                try:
                    response = client.get(normalized_url)
                    break
                except httpx.HTTPError as exc:
                    last_error = exc
                    if attempt >= RETRY_COUNT:
                        raise
                    time.sleep(0.2 * (attempt + 1))
            else:
                if last_error:
                    raise last_error
    
    if not response:
        raise httpx.HTTPError("Failed to retrieve response")

    set_cookies = response.headers.get_list("set-cookie")
    headers = {key.lower(): value for key, value in response.headers.items()}
    is_https = response.url.scheme == "https"
    findings.extend(_check_headers(headers, set_cookies, is_https))

    redirect_schemes = [item.url.scheme for item in response.history]
    redirect_schemes.append(response.url.scheme)
    findings.extend(_redirect_findings(redirect_schemes))

    tls_data = None
    if response.url.scheme == "https":
        tls_data, tls_findings = _tls_info(hostname)
        findings.extend(tls_findings)

    dns_data = _dns_records(hostname)
    findings.extend(_dns_findings(hostname, dns_data))
    if wildcard_base:
        findings.extend(_wildcard_dns_findings(hostname))

    if response.status_code >= 400:
        findings.append(
            _finding(
                "http_error",
                "HTTP error status",
                "medium",
                f"Server returned HTTP {response.status_code}.",
                "Ensure the URL is reachable and responds with 2xx/3xx.",
            )
        )

    if normalized_url.startswith("http://") and response.url.scheme != "https":
        findings.append(
            _finding(
                "http_not_upgraded",
                "HTTP not upgraded to HTTPS",
                "medium",
                "HTTP request did not redirect to HTTPS.",
                "Redirect HTTP to HTTPS and enable HSTS.",
            )
        )

    score, grade = score_from_findings(findings)
    elapsed = int((perf_counter() - start) * 1000)

    return ScanResult(
        target=normalized_url,
        final_url=str(response.url),
        status_code=response.status_code,
        score=score,
        grade=grade,
        findings=findings,
        headers=headers,
        tls=tls_data,
        dns=dns_data,
        timing_ms=elapsed,
    )


def safe_scan(target: str) -> Tuple[Optional[ScanResult], Optional[str]]:
    try:
        return scan(target), None
    except TargetValidationError as exc:
        return None, str(exc)
    except httpx.HTTPError as exc:
        return None, f"HTTP error: {exc}"
    except Exception as exc:
        return None, f"Unexpected error: {exc}"
