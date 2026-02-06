# anxextor

anxextor is a Web Security Scanner MVP with a three-branch delivery workflow, a FastAPI backend, and a minimal frontend UI.

## Repository layout

- backend/app: API, scanner logic, and scoring.
- frontend: static UI served by the API.
- scripts: local automation helpers.
- tests: unit tests for scanner logic.
- Jenkinsfile: Kubernetes-based CI/CD pipeline.
- Dockerfile, docker-compose.yml: containerized local runtime.

## Branching model

- slave: push after testing.
- house: deploy branch. Promote from slave after every 3 pushes.
- master: LTS. Promote from house monthly.

### Promotion rules

- slave -> house: when slave is ahead by 3 commits or more.
- house -> master: once per month.

### Promotion helpers (cross-platform)

Use Python 3.8+.

```bash
python scripts/promote.py house --simulate
python scripts/promote.py master --simulate
python scripts/promote.py house --push
python scripts/promote.py master --push
```

## CI/CD (Jenkins + Kubernetes)

The Jenkins pipeline is defined in Jenkinsfile and runs on a Kubernetes agent.

### Required Jenkins setup

- Kubernetes plugin with a Docker-capable agent.
- Credentials:
  - git-bot (username/password or PAT) for branch promotions.
  - docker-registry (username/password) for image push.
  - kubeconfig (file credential) for kubectl access.

### Environment variables

- REGISTRY: container registry host (e.g., ghcr.io).
- IMAGE_NAME: image name (e.g., sebastined/anxextor).
- KUBE_NAMESPACE: target namespace for deploy.
- KUBE_CONTEXT: Kubernetes context name.
- GIT_REMOTE_URL: remote HTTPS URL for push (e.g., https://github.com/sebastined/anxextor.git).

### Pipeline stages

- Checkout: fetch repository.
- Test (slave): install dependencies and run pytest.
- Build + Push (house): build and push container image.
- Deploy (house): apply k8s manifests if present.
- Promote slave -> house: auto-merge when commit threshold is met.
- Promote house -> master (monthly): cron-triggered merge.

## Runtime architecture

- FastAPI serves the API and static frontend.
- GET / serves the UI in frontend/index.html.
- POST /api/scan runs the scanner and returns JSON.
- GET /health returns a simple health status for probes.

## Frontend UI

The UI is a single static page served from the backend.

- Score bar visual and grade display.
- Findings list with severity styling.
- Summary chips for High/Medium/Low/Info counts.
- Copy JSON and Download JSON actions.
- Download CSV and Export PDF actions.
- Remediation list built from unique recommendations.
- Theme toggle for light and dark mode (saved in localStorage).
- Recent scan history stored in localStorage (last 6 hosts). Clicking a history item triggers a fresh scan.

## Scanner pipeline

1. Normalize input and enforce http/https scheme.
2. Resolve hostname and block non-public IPs (SSRF protection).
3. Fetch the target with httpx (follow redirects, retry on transient failures).
4. Analyze headers, cookies, redirect chain, TLS, and DNS records.
5. Compute a score and grade based on findings.

Wildcard targets like `*.abc.xyz` are accepted by scanning the base domain (`abc.xyz`) and checking for wildcard DNS.

### Header checks

- Content-Security-Policy missing.
- CSP missing frame-ancestors.
- Strict-Transport-Security missing, weak, or invalid.
- X-Frame-Options missing.
- X-Content-Type-Options missing.
- Referrer-Policy missing or weak.
- Permissions-Policy missing.
- Cross-Origin-Opener-Policy missing.
- Cross-Origin-Embedder-Policy missing.
- Server header exposed.
- Cache-Control missing, public, or permissive.

### Cookie checks

- Cookies set over HTTP.
- Secure flag missing on HTTPS.
- HttpOnly missing.
- SameSite missing.
- SameSite=None without Secure.
- __Secure- cookies missing Secure.
- __Host- cookies missing Secure, using Domain, or Path not equal to /.

### Redirect checks

- Redirect chain longer than 3 hops.
- Redirect downgrade from HTTPS to HTTP.
- HTTP request not upgraded to HTTPS.

### TLS checks

- TLS certificate expired or expiring soon.
- Weak TLS protocol (TLS 1.0/1.1).
- TLS handshake failures.

### DNS checks

- SPF missing.
- DMARC missing.
- CAA missing.
- DNSSEC missing (DS record).
- DKIM not checked (informational).

## Authentication and rate limiting

The /api/scan endpoint supports optional API key auth and a simple in-memory rate limit.

- If ANXEXTOR_API_KEY is set, clients must send X-API-Key.
- Rate limit defaults to 30 requests per minute per client IP.
- Rate limiting is in-memory and resets on process restart.

Planned: user authentication via Google and GitHub OAuth, with API keys bound to user accounts (no manual input in the UI).

## Reporting and history

Planned: authenticated users will see scan history and can generate a detailed professional report.

The detailed report will include:

- Executive summary for non-technical stakeholders.
- Technical findings with remediation guidance.
- Compliance-oriented mapping and risk notes for audit teams.

## Configuration

All configuration uses environment variables.

- ANXEXTOR_API_KEY: Optional API key for /api/scan.
- ANXEXTOR_RATE_LIMIT_PER_MINUTE: Requests per minute per IP (default 30, set 0 to disable).
- ANXEXTOR_HTTP_TIMEOUT_SECONDS: HTTP timeout for target fetch (default 10.0).
- ANXEXTOR_HTTP_RETRIES: Retry count for transient HTTP errors (default 2).
- ANXEXTOR_LOG_LEVEL: Logging level (default INFO).
- ANXEXTOR_BATCH_MAX_TARGETS: Max targets per batch request (default 5).

## Scoring

Each finding subtracts from a 100-point score based on severity:

- critical: -30
- high: -20
- medium: -10
- low: -5
- info: 0

Grades:

- A: 90-100
- B: 80-89
- C: 70-79
- D: 60-69
- F: below 60

## API reference

### POST /api/scan

Request body:

```json
{
  "url": "https://example.com"
}
```

Optional headers:

- X-API-Key: Required if ANXEXTOR_API_KEY is set.

Success response (200):

```json
{
  "target": "https://example.com",
  "final_url": "https://example.com/",
  "status_code": 200,
  "score": 85,
  "grade": "B",
  "findings": [
    {
      "id": "missing_csp",
      "title": "Missing Content-Security-Policy",
      "severity": "high",
      "description": "CSP is not present, increasing XSS risk.",
      "recommendation": "Add a strict Content-Security-Policy header."
    }
  ],
  "headers": {
    "content-type": "text/html"
  },
  "tls": {
    "protocol": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "days_until_expiry": 120
  },
  "dns": {
    "spf": true,
    "dmarc": true,
    "caa": false,
    "dnssec": false
  },
  "timing_ms": 412
}
```

Error responses:

- 400: invalid target or scan failure.
- 401: missing or invalid API key.
- 429: rate limit exceeded.

### GET /health

```json
{
  "status": "ok"
}
```

### OpenAPI docs

When running locally, browse to /docs for interactive API docs.

### POST /api/scan/batch

Request body:

```json
{
  "targets": ["https://example.com", "*.abc.xyz"]
}
```

Success response (200):

```json
{
  "results": [
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
      "timing_ms": 400
    }
  ],
  "errors": [
    {
      "target": "*.abc.xyz",
      "error": "Hostname did not resolve to any IPs."
    }
  ]
}
```

## Local setup

### Install dependencies

```bash
python -m venv .venv
python -m pip install -r requirements.txt
```

### Run the API + UI

```bash
python -m uvicorn backend.app.main:app --reload
```

Open http://127.0.0.1:8000 in a browser.

### Run a CLI scan

```bash
python scripts/scan_demo.py https://example.com
```

### Run tests

```bash
python -m pytest -q
```

## Docker (local)

```bash
docker build -t anxextor:local .
docker run --rm -p 8000:8000 anxextor:local
```

Health checks use GET /health inside the container.

## Docker Compose

```bash
docker compose up --build
```
