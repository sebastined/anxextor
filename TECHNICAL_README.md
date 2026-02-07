# anxextor technical guide

Technical documentation for developers and operators.

**TLDR**: Run `python -m uvicorn backend.app.main:app --reload` and open http://127.0.0.1:8000.

## Architecture

- FastAPI serves API + static frontend.
- GET / serves the UI.
- POST /api/scan runs the scanner.
- POST /api/scan/batch scans multiple targets.
- GET /health is the readiness probe.

## Scanner pipeline

1. Normalize input and enforce http/https.
2. Resolve hostname and block non-public IPs (SSRF protection).
3. Fetch the target with httpx (redirects + retries).
4. Analyze headers, cookies, TLS, redirects, and DNS.
5. Compute score and grade.

Wildcard targets like `*.abc.xyz` are supported by scanning the base domain and checking for wildcard DNS.

## Checks

Headers:
- CSP missing
- CSP missing frame-ancestors
- HSTS missing/weak/invalid
- X-Frame-Options missing
- X-Content-Type-Options missing
- Referrer-Policy missing/weak
- Permissions-Policy missing
- COOP/COEP missing
- Server header exposed
- Cache-Control missing/public/weak

Cookies:
- Cookies over HTTP
- Missing Secure/HttpOnly/SameSite
- SameSite=None without Secure
- __Secure- and __Host- prefix violations

Redirects:
- Long redirect chain
- HTTPS to HTTP downgrade
- HTTP not upgraded to HTTPS

TLS:
- Expired/expiring cert
- Weak protocol
- Handshake failures

DNS:
- SPF/DMARC/CAA/DNSSEC missing
- DKIM selector not checked (info)

## Scoring

Each finding subtracts from 100:
- critical: -30
- high: -20
- medium: -10
- low: -5
- info: 0

Grades: A (90-100), B (80-89), C (70-79), D (60-69), F (<60).

## Remediation tips

Use this as an operator checklist when findings appear.

Headers:
- Add strict security headers at the app edge or reverse proxy. Defaults are set in the FastAPI middleware.
- CSP: keep `frame-ancestors 'none'` unless you need embeds; explicitly allow trusted script/style/font origins.
- HSTS: enable on HTTPS only, use `max-age=31536000; includeSubDomains; preload` if you are ready.
- X-Frame-Options: `DENY` (or `SAMEORIGIN` if you must embed).
- X-Content-Type-Options: `nosniff`.
- Referrer-Policy: `strict-origin-when-cross-origin` or `no-referrer`.
- Permissions-Policy: start with deny-all and open only what you need.
- COOP/COEP: set `Cross-Origin-Opener-Policy: same-origin`; only set `Cross-Origin-Embedder-Policy: require-corp` if you need cross-origin isolation.
- Cache-Control: `no-store` for dynamic responses; use `private, max-age=0` for user-specific content.

Server header:
- Remove or minimize at the CDN or reverse proxy (Cloudflare, Nginx, etc.). App code usually cannot strip it reliably.

DNS:
- SPF: add a TXT record at apex like `v=spf1 include:_spf.yourmailprovider.com -all`.
- DMARC: add `TXT _dmarc` with `v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain`.
- CAA: add `CAA 0 issue "letsencrypt.org"` (or your CA).
- DNSSEC: enable at your registrar and publish DS records.
- DKIM: add provider-specific selector TXT records (scanner does not check without selector).

TLS:
- Use TLS 1.2+ only, rotate certs before 14 days to avoid "expiring soon".

Redirects:
- Reduce redirect hops, and never downgrade HTTPS to HTTP.

## API reference

### POST /api/scan

Request:

```json
{
  "url": "https://example.com"
}
```

Response:

```json
{
  "target": "https://example.com",
  "final_url": "https://example.com/",
  "status_code": 200,
  "score": 85,
  "grade": "B",
  "findings": [],
  "headers": {},
  "tls": null,
  "dns": {},
  "timing_ms": 412
}
```

### POST /api/scan/batch

Request:

```json
{
  "targets": ["https://example.com", "*.abc.xyz"]
}
```

Response:

```json
{
  "results": [],
  "errors": []
}
```

### GET /health

```json
{
  "status": "ok"
}
```

### GET /api/config

```json
{
  "fingerprint_public_key": "fpjs_public_key",
  "visitor_tracking_enabled": true
}
```

### POST /api/visitor

Headers:

```
X-Fingerprint-ID: <fingerprint>
```

Response:

```json
{
  "enabled": true,
  "snapshot": {
    "fingerprint_id": "fp",
    "ip": "203.0.113.10",
    "country": "NG",
    "city": "Lagos",
    "behind_proxy": false,
    "visit_count": 1,
    "scan_count": 0,
    "last_visit_at": "2026-02-07T14:33:30Z",
    "visit_windows": {
      "5m": 1,
      "30m": 1,
      "1h": 1,
      "1d": 1,
      "1w": 1,
      "1mo": 1,
      "1y": 1
    }
  }
}
```

## Configuration

- ANXEXTOR_API_KEY: optional API key for /api/scan.
- ANXEXTOR_RATE_LIMIT_PER_MINUTE: default 30, set 0 to disable.
- ANXEXTOR_HTTP_TIMEOUT_SECONDS: default 10.
- ANXEXTOR_HTTP_RETRIES: default 2.
- ANXEXTOR_LOG_LEVEL: default INFO.
- ANXEXTOR_BATCH_MAX_TARGETS: default 5.
- ANXEXTOR_SUPABASE_URL: Supabase project URL for visitor tracking.
- ANXEXTOR_SUPABASE_SERVICE_KEY: Supabase service role key (server-side).
- ANXEXTOR_IPINFO_TOKEN: ipinfo.io token for geo and proxy/vpn signals.
- ANXEXTOR_FINGERPRINTJS_PUBLIC_KEY: FingerprintJS Pro public key.
- ANXEXTOR_IP_ENCRYPTION_KEY: Fernet key for encrypting raw IPs.
- ANXEXTOR_IP_HASH_SALT: Salt used when hashing IPs.
- ANXEXTOR_VISITOR_TRACKING_ENABLED: default true.

## Visitor tracking

The UI collects a FingerprintJS ID and the API stores visitor stats in Supabase.
See docs/visitor_tracking.sql for table definitions.

## Local setup

```bash
python -m venv .venv
python -m pip install -r requirements.txt
python -m uvicorn backend.app.main:app --reload
```

## Docker

```bash
docker build -t anxextor:local .
docker run --rm -p 8000:8000 anxextor:local
```

## CI/CD and branching

- slave: push after testing
- house: deploy branch; auto-merge from slave after 3 commits
- master: LTS; monthly merge from house

Promotion helpers:

```bash
python scripts/promote.py house --simulate
python scripts/promote.py master --simulate
python scripts/promote.py house --push
python scripts/promote.py master --push
```
