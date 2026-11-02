# ThreatSentry — Architecture

## Components

| Component | Location | Role |
|---|---|---|
| Dashboard | `apps/dashboard` | React + TypeScript + Vite UI. Signs users in with Supabase Auth and calls the API with the session token. |
| API | `backend/` | FastAPI. Validates the token, enforces ownership, runs scans as in-process background tasks. |
| Scanner | `backend/scanner` | Target validation, SSRF guard, crawler, passive checks, active SQLi/XSS probes, findings, scoring. |
| ML runtime | `backend/ml` | Loads the packaged model once and classifies payload strings as `NORMAL`, `SQLI` or `XSS`. |
| ML pipeline | `ml/` | Offline dataset build, split, training and evaluation scripts. Not part of the production request path. |
| Database | `supabase/migrations` | PostgreSQL schema and Row Level Security. |
| Lab | `labs/` | Intentionally vulnerable test target and the scanner benchmark. **TEST / BENCHMARK ONLY.** |

## Request flow for a Deep Scan

1. The dashboard calls `POST /api/websites/{id}/scans` with the Supabase access token.
2. The API derives the user id from the token and loads the website **owned by that user**.
3. The website must be `VERIFIED`; the target is re-validated against the SSRF rules; only one scan may be active per website; a per-user rate limit applies.
4. A `PENDING` job row is written and `run_scan_job` is started as an asyncio task.
5. The runner advances through `VALIDATING_TARGET → CRAWLING → PASSIVE_CHECKS → ACTIVE_CHECKS → COMPLETE`, writing stage and progress to `scan_jobs` and checking for cancellation between stages.
6. Findings are enriched with ML evidence, de-duplicated by fingerprint, compared with the previous completed scan (`NEW` / `UNCHANGED`, plus a `fixed_findings_count`), scored, and persisted.

## Data model (summary)

`websites` (verification token and status) → `scan_jobs` (status, stage, progress, score, summary) → `findings` (fingerprint, severity, evidence, status). `model_versions` records model metadata. RLS restricts every user-owned table to its owner; the backend uses the service-role key, which must never reach the frontend, so ownership is also enforced in the API (`user_id` filters on every query).

## Design rules

- Scanner logic lives in `backend/scanner`, never in React.
- ML training lives in `ml/`; production only loads the packaged artifact.
- ML output is supporting evidence. It never confirms a vulnerability on its own.
- Security checks (SSRF, ownership, scan limits) are centralised, not duplicated per endpoint.

## Known limitations

- Scans run inside the API process. A restart interrupts running scans, and the in-memory rate limiter and cancellation set are per instance.
