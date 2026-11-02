# ThreatSentry — Security Model

## Scanner safety invariants

| Invariant | Where enforced |
|---|---|
| No scan without an authenticated user | `get_current_user_id` dependency |
| No scan without verified ownership | `api/scan_policy.py` |
| No request to private/reserved addresses | `scanner/ssrf.py`, `target_validation.py` |
| Re-validation when a scan starts | `create_scan` and `run_scan_job` |
| TLS probe uses the already-validated IP | `passive/tls_checks.py` |
| No automatic redirect following | scanner HTTP client |
| No crawl beyond same origin or configured limits | `crawler.py` |
| Destructive routes are not crawled | `DESTRUCTIVE_KEYWORDS` in `crawler.py` |
| No data extraction or destructive SQL | `active/sqli.py` |
| No browser-executed XSS | marker reflection only |
| ML alone never confirms a vulnerability | `analysis/hybrid.py` |
| Service-role key stays on the backend | frontend only uses the anon key |

## Authentication and isolation

Supabase Auth issues tokens; the API validates them and derives the user id. Ownership is checked on every query (`user_id` filters), and RLS policies protect the tables. Never trust a client-supplied `user_id`.

## Abuse limits

- Per-IP limit on `/api/*` (default 120/min) and per-user limit on scan creation (default 10/hour). Env: `RATE_LIMIT_IP_PER_MINUTE`, `RATE_LIMIT_SCANS_PER_HOUR`. Limits are in-memory and per instance.
- Behind a reverse proxy, run uvicorn with `--proxy-headers` and a correct `FORWARDED_ALLOW_IPS`, otherwise every client appears to share the proxy's IP.
- One active scan per website, and a maximum scan duration (`SCAN_MAX_DURATION_SECONDS`, default 600).
- Production refuses wildcard/localhost CORS origins and `SCAN_ALLOW_LOCAL`.

## Logging

Do not log passwords, tokens, API keys, the service-role key, sensitive form values or raw cookies.

## The lab

`labs/vulnerable_app.py` is intentionally vulnerable and marked `TEST / BENCHMARK ONLY`. Run it only locally or on an isolated network.

## Known gaps

No persistent or distributed rate limiting; evidence is rendered by the dashboard as text, not trusted HTML.
