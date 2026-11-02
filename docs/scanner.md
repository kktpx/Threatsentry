# ThreatSentry — Scanner

Only one scan type exists: `DEEP_SCAN`, and only for websites whose ownership has been verified.

## Ownership verification

The user serves `https://<origin>/.well-known/threatsentry.txt` containing `threatsentry-verification=<TOKEN>`. The backend fetches only that path, with SSRF validation, redirect re-validation, a 64 KiB size cap and short timeouts, then compares the token. Outcomes are `VERIFIED` or `FAILED`; failures do not expose network internals. `POST /api/websites/{id}/verification/reset` issues a new token and returns the site to `UNVERIFIED`.

## Pipeline

1. **Target validation / SSRF** (`target_validation.py`, `ssrf.py`): normalises the URL and rejects non-public addresses. Resolution is checked again when the scan starts.
2. **Crawler** (`crawler.py`): same-origin only, bounded pages, depth, concurrency and response size. The runner uses 20 pages, depth 2 and concurrency 3. Routes with destructive keywords (logout, delete, checkout, …) are skipped.
3. **Passive checks** (`scanner/passive/`): see below. No exploitation.
4. **Active checks** (`scanner/active/`): SQL injection and reflected XSS against discovered parameters, only after steps 1–3 and only on verified targets.
5. **Analysis** (`analysis/hybrid.py`): attaches ML evidence to findings.
6. **Findings** (`findings.py`, `fingerprints.py`): fingerprints are SHA-256 over origin, category, method, path, parameter and subtype, so a re-scan matches the same issue. Duplicates are dropped before scoring.
7. **Scoring** (`scoring.py`): `100 − Σ deductions` over unique findings, floored at 0. Deductions: CRITICAL 20, HIGH 10, MEDIUM 5, LOW 2, INFO 0.

## Passive checks

| Area | Module | Examples |
|---|---|---|
| HTTP | `http_checks.py` | Plain HTTP, `Server` / `X-Powered-By` version leakage |
| Headers | `header_checks.py` | Missing CSP, HSTS, X-Frame-Options, … |
| Cookies | `cookie_checks.py` | Missing Secure / HttpOnly / SameSite |
| Exposure | `exposure.py` | Stack traces, directory listings |
| TLS | `tls_checks.py` | Invalid, mismatched or expired certificate, expiry within 14 days, protocol TLS 1.1 or older. Connects to the IP that passed SSRF validation. |
| Technology | `technology.py` | Infers web servers, frameworks and CMSs from headers, `meta generator`, asset paths, script names and cookie **names** (never values). Header/generator hits are `LIKELY`, weaker hits `POTENTIAL`; nothing is `CONFIRMED`. Reported as `INFO` once per origin, so it does not affect the score. |
| DNS | `dns_checks.py` | Missing/permissive SPF, missing DMARC, DMARC `p=none`, missing CAA. Mail findings need an MX record; these are low severity or informational. |

## Active detection

- **SQLi**: baseline request, then a single-quote probe, looking for database error signatures and response differences. No data extraction or destructive statements.
- **Reflected XSS**: a unique harmless marker is sent and the response is checked for unencoded reflection. Nothing is executed in a browser.

## Cancellation and limits

Every scan runs under a hard time limit (`SCAN_MAX_DURATION_SECONDS`, default 600). A scan that exceeds it is marked `FAILED` with error code `SCAN_TIMEOUT`. Cancelling sets the job to `CANCELLED`; the runner checks between stages and between pages. The scanner uses a distinct `ThreatSentry-Scanner` User-Agent and does not follow redirects automatically.

## Not implemented

A dedicated discovery module (robots.txt, sitemap, common paths) is not implemented; discovery is done by the crawler only.
