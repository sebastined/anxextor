# anxextor

Web security checks for everyone. Enter a site, click scan, and get a simple score with clear next steps.

**Production URL:** https://anxextor.sebastine.ng

## What it does

- Runs fast checks on security headers, TLS, redirects, cookies, and DNS.
- Produces a score, grade, and plain-language summary.
- Shows remediation steps you can follow immediately.
- Supports scanning multiple sites at once.
- Supports wildcard input like `*.abc.xyz` by scanning the base domain.

## Architecture

- Backend: FastAPI serves API + static frontend.
- Frontend: Static HTML/CSS/JS served by the backend.
- Scanner: Normalizes input, validates target safety, fetches, analyzes, and scores.
- Reports: JSON/CSV/PDF exports generated in the browser.

## Scanner pipeline

1. Normalize input and enforce http/https.
2. Resolve hostname and block non-public IPs (SSRF protection).
3. Fetch target with retries and timeouts.
4. Analyze headers, cookies, redirects, TLS, and DNS.
5. Compute score and grade.

## API summary

- `POST /api/scan` - Scan one target.
- `POST /api/scan/batch` - Scan multiple targets.
- `GET /api/config` - Client configuration (OAuth IDs, tracking flags).
- `POST /api/visitor` - Visitor snapshot (FingerprintJS).
- `POST /api/feedback` - Feedback event.
- `GET /api/feedback/summary` - Feedback summary.
- `GET /health` - Readiness probe.

## Local setup

```bash
python -m venv .venv
python -m pip install -r requirements.txt
python -m uvicorn backend.app.main:app --reload
```

Open http://127.0.0.1:8000.

## Environment variables

```env
ANXEXTOR_API_KEY=
ANXEXTOR_RATE_LIMIT_PER_MINUTE=30
ANXEXTOR_HTTP_TIMEOUT_SECONDS=10
ANXEXTOR_HTTP_RETRIES=2
ANXEXTOR_BATCH_MAX_TARGETS=5

ANXEXTOR_SUPABASE_URL=https://your-project-id.supabase.co
ANXEXTOR_SUPABASE_SERVICE_KEY=your-service-role-key

ANXEXTOR_IPINFO_TOKEN=
ANXEXTOR_FINGERPRINTJS_PUBLIC_KEY=
ANXEXTOR_FINGERPRINTJS_REGION=us
ANXEXTOR_IP_ENCRYPTION_KEY=
ANXEXTOR_IP_HASH_SALT=
ANXEXTOR_VISITOR_TRACKING_ENABLED=true

GOOGLE_CLIENT_ID=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
SECRET_KEY=
```

## OAuth setup (Google + GitHub)

### Google

1. Google Cloud Console -> Credentials -> OAuth Client ID (Web).
2. Authorized JS origins:
	- http://localhost:8000
	- https://anxextor.sebastine.ng
3. Authorized redirect URIs:
	- http://localhost:8000
	- https://anxextor.sebastine.ng

### GitHub

1. GitHub Developer Settings -> OAuth Apps -> New OAuth App.
2. Homepage URL: https://anxextor.sebastine.ng
3. Authorization callback URL: https://anxextor.sebastine.ng/auth-callback

## Database schema (current)

Core tables:

- `users`
- `user_oauth_providers`
- `visitor_profiles`
- `visitor_events`
- `feedback_events`
- `feedback_user_prefs`

### 5NF improvement

The only normalization issue was the `users` table storing multiple OAuth IDs.
The fix is the `user_oauth_providers` table (already created by migration).
After app updates are confirmed, you can drop legacy columns:

```sql
ALTER TABLE users DROP COLUMN IF EXISTS google_id;
ALTER TABLE users DROP COLUMN IF EXISTS github_id;
ALTER TABLE users DROP COLUMN IF EXISTS provider;
```

## Migrations

- `database/migrations/add_github_oauth_and_user_management.sql`
- `database/migrations/normalize_to_5nf.sql`
- `database/migrations/production_hardening.sql`

## Production hardening

Run `database/migrations/production_hardening.sql` to:

- Enable RLS on all app tables.
- Add constraints and audit timestamps.
- Add API indexes.
- Drop unused views (`active_users`, `recently_active_users`).

Note: RLS blocks anon/authenticated access unless you add explicit policies.
The backend uses the service role key and bypasses RLS.

## Deployment (Render)

1. Set environment variables in Render.
2. Deploy from GitHub (auto-deploy).
3. Test:

```bash
curl https://anxextor.sebastine.ng/api/config
```

## Testing

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://anxextor.sebastine.ng/api/auth/me
```

## Notes

- Visitor tracking uses FingerprintJS and optional ipinfo.io enrichment.
- Feedback records are stored separately to preserve privacy.
- Security headers are applied by FastAPI middleware.

## Changelog

- 2026-02-14: Consolidated documentation into README and added production hardening migration.
- 2026-02-14: Added 5NF migration and OAuth provider normalization plan.
- 2026-02-14: Added production hardening migration (RLS, constraints, indexes, audit timestamps).

## Runbook

### Deploy

1. Set/update environment variables in Render.
2. Apply DB migrations in order:
	- add_github_oauth_and_user_management.sql
	- normalize_to_5nf.sql
	- production_hardening.sql
3. Verify /api/config and /health.

### Roll back

1. Revert to previous Git commit on Render.
2. If a migration caused issues, restore from Supabase backup.
3. Re-run health checks.

### Routine checks

- Verify Render logs for errors after deploy.
- Check Supabase logs for slow queries and failures.
- Validate OAuth logins in production.

## Troubleshooting

### OAuth fails

- Confirm redirect URIs match exactly in Google/GitHub settings.
- Verify GOOGLE_CLIENT_ID, GITHUB_CLIENT_ID, and GITHUB_CLIENT_SECRET.
- Check Render logs for token exchange errors.

### Database unavailable

- Confirm ANXEXTOR_SUPABASE_URL and ANXEXTOR_SUPABASE_SERVICE_KEY.
- Check Supabase project status and pause state.
- Check Postgres logs for permission errors.

### RLS blocks access

- Ensure backend uses the service role key.
- Add explicit RLS policies for anon/authenticated if needed.

## Support

For security consultation and remediation assistance:

- iam@sebastine.com
