# ThreatSentry Controlled Lab

**TEST / BENCHMARK ONLY.** This application is intentionally vulnerable. Run it only on a
local or isolated network. Never deploy it on a public or production domain without access
control and isolation.

Start it with `npm run lab` (port 8080).

| Endpoint | Purpose |
|---|---|
| `/vulnerable/products?id=` | SQL injection (string concatenation, error disclosure). `/products` is an alias. |
| `/safe/products?id=` | Parameterised query, no error disclosure. |
| `/vulnerable/search?q=` | Reflected XSS (unencoded reflection). `/search` is an alias. |
| `/safe/search?q=` | HTML-encoded reflection. |
| `/.well-known/threatsentry.txt` | Ownership verification token. |

Every HTML response carries a visible `TEST / BENCHMARK ONLY` banner and an
`X-ThreatSentry-Lab` header. The data is synthetic; no real user data is stored.

## Running one vulnerability at a time

| Command | Port | Reachable |
|---|---|---|
| `npm run lab:xss` | 8081 | `/search`, `/vulnerable/search`, `/safe/search` only |
| `npm run lab:sqli` | 8082 | `/products`, `/vulnerable/products`, `/safe/products` only |
| `npm run lab` | 8080 | everything |

In these two modes the target is otherwise configured sensibly (security headers, `HttpOnly`/`SameSite`
cookie, no server banner), so a scan shows essentially only the demonstrated flaw plus
`UNENCRYPTED_HTTP` (localhost is plain HTTP). The CSP is `frame-ancestors 'none'` only: a script-blocking
CSP would stop the XSS payload from running in the browser. `npm run lab` (mode `all`) keeps the
deliberately sloppy headers/cookies/banners so every passive check has something to report.

The other feature returns 404 and its card is hidden from the home page. Run both commands in
separate terminals to demo them side by side. All three bind to `127.0.0.1` only.

## Showing it to someone else on the same network

`npm run lab:share` binds `0.0.0.0:8080` so another device on the same Wi-Fi/LAN can open
`http://<your-ip>:8080` (plain HTTP). Allow the port through the Windows firewall only for the
demo and close it afterwards. Do not use this on a public network: the app is intentionally
vulnerable. To share one mode: `python -m labs.vulnerable_app --host 0.0.0.0 --mode xss --port 8081`.

## Demo payloads

- XSS: `/vulnerable/search?q=<script>alert(1)</script>` runs in the page; `/safe/search` shows it as text.
- SQLi: `/vulnerable/products?id=1'` shows a database error; `id=1 OR 1=1` returns every product; `/safe/products` does neither.

To let ThreatSentry scan a local lab, run the backend locally with `SCAN_ALLOW_LOCAL=true`; the
deployed Render API cannot reach localhost (SSRF protection).
