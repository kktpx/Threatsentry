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
