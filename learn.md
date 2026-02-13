# anxextor - How It Works

This document explains how anxextor works end-to-end, from a scan request to report exports. It is intended for operators, developers, and security reviewers.

## Overview

anxextor is a web security scanner that inspects a target for common security misconfigurations across headers, TLS, redirects, cookies, and DNS. It returns a score, grade, and a list of findings with remediation guidance. The app also includes optional visitor tracking and feedback collection to improve product insights.

## Architecture

- Backend: FastAPI application that exposes scan APIs, serves the UI, and applies security headers.
- Frontend: Static HTML/CSS/JS UI served by the backend.
- Scanner: A pipeline that normalizes input, validates target safety, collects signals, and generates findings.
- Reports: JSON/CSV/PDF exports generated in the browser.

High-level request flow:
1. User submits target(s) in the UI.
2. Frontend sends request to the backend scan endpoint.
3. Backend runs the scanner and returns a structured report.
4. Frontend renders the results and allows exports.

## Core Scan Pipeline

1. Normalize input and enforce HTTP/HTTPS schemes.
2. Validate target safety to prevent SSRF (block private or invalid hosts).
3. Resolve DNS and check for wildcard DNS.
4. Fetch the target using httpx with retry and timeout.
5. Analyze response headers and cookies.
6. Analyze redirects (length and HTTPS downgrade checks).
7. Perform TLS checks and extract certificate metadata.
8. Build findings list and compute score/grade.

## Findings Model

Each finding includes:
- id: Internal identifier for the issue.
- title: Human-readable issue title.
- severity: info/low/medium/high.
- description: What was observed and why it matters.
- recommendation: Production-grade remediation guidance.
- cve: CWE reference identifier when applicable.
- cvss_score: Risk score when applicable.
- reference_url: Link to supporting reference.

## Scoring and Grading

Scores start at 100 and each finding subtracts points based on severity:
- high: -20
- medium: -10
- low: -5
- info: 0

Grades:
- A: 90-100
- B: 80-89
- C: 70-79
- D: 60-69
- F: <60

## Frontend Rendering

The UI shows:
- Score and grade
- Finding list with severity, description, remediation
- Remediation summary
- Batch results and history

The findings list also includes CVE/CVSS data where available and a reference link.

## Report Exports

Exports are generated in the browser:
- JSON: Full scan response plus metadata.
- CSV: Finding rows with CVE/CVSS fields and report metadata.
- PDF: Professionally formatted report with styled sections.

Report metadata includes:
- Generated timestamp
- Tool identifier
- Consultant contact

Consultant contact embedded in exports:
- iam@sebastine.com

## Visitor Tracking (Optional)

If enabled, the frontend loads FingerprintJS using dynamic ESM import and retrieves a visitor ID. The backend uses that ID to build a visitor snapshot for:
- Visit counts
- Proxy/VPN signal
- Geo details (if configured)

Visitor tracking is controlled by configuration and can be disabled by setting an env var.

## Feedback System

Users can submit thumbs-up/down feedback. The frontend sends feedback events to the backend, which aggregates counts for display.

## Security Headers

The backend applies a strict set of headers by default:
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-Opener-Policy
- Cross-Origin-Embedder-Policy
- Cache-Control
- Strict-Transport-Security (HTTPS only)

## Deployment

The app is container-ready and can be deployed to any platform that supports Docker or Python app hosting. The frontend is served from the backend container.

## Configuration

Key environment variables:
- ANXEXTOR_API_KEY: Optional API key for /api/scan
- ANXEXTOR_RATE_LIMIT_PER_MINUTE: Request rate limit
- ANXEXTOR_HTTP_TIMEOUT_SECONDS: HTTP timeout
- ANXEXTOR_HTTP_RETRIES: HTTP retries
- ANXEXTOR_BATCH_MAX_TARGETS: Max targets for batch scans
- ANXEXTOR_SUPABASE_URL: Supabase URL (if used)
- ANXEXTOR_SUPABASE_SERVICE_KEY: Supabase service key
- ANXEXTOR_IPINFO_TOKEN: IP info token (geo/proxy)
- ANXEXTOR_FINGERPRINTJS_PUBLIC_KEY: FingerprintJS public key
- ANXEXTOR_FINGERPRINTJS_REGION: FingerprintJS region (us/eu/ap)
- ANXEXTOR_VISITOR_TRACKING_ENABLED: Toggle visitor tracking
- ANXEXTOR_IP_ENCRYPTION_KEY: Key for IP encryption
- ANXEXTOR_IP_HASH_SALT: Salt for IP hashing

## Limitations

- Browser-based fingerprints are probabilistic, not hardware-unique.
- DNS and TLS checks depend on network access to the target.
- Some findings are informational and require context-aware review.

## Support

For security consultation and remediation assistance, contact:
- iam@sebastine.com
