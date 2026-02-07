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

## Configuration

- ANXEXTOR_API_KEY: optional API key for /api/scan.
- ANXEXTOR_RATE_LIMIT_PER_MINUTE: default 30, set 0 to disable.
- ANXEXTOR_HTTP_TIMEOUT_SECONDS: default 10.
- ANXEXTOR_HTTP_RETRIES: default 2.
- ANXEXTOR_LOG_LEVEL: default INFO.
- ANXEXTOR_BATCH_MAX_TARGETS: default 5.

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
