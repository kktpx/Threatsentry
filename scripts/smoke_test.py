"""Read-only production smoke test for the ThreatSentry API.

Usage: python scripts/smoke_test.py https://<api-host> https://<dashboard-origin>

It sends only harmless GET/OPTIONS requests and needs no credentials. It cannot test login,
ownership verification or scanning: do those by hand (see docs/deployment.md).
"""

import sys

import httpx


def main(api: str, dashboard: str) -> int:
    api = api.rstrip("/")
    dashboard = dashboard.rstrip("/")
    results: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        results.append((name, ok, detail))

    with httpx.Client(timeout=90, follow_redirects=False) as client:
        try:
            health = client.get(f"{api}/health")
            body = health.json() if health.headers.get("content-type", "").startswith("application/json") else {}
            check("/health returns 200 with status ok", health.status_code == 200 and body.get("status") == "ok", f"HTTP {health.status_code}")
            model = body.get("model", {})
            check("ML model is loaded (not heuristic fallback)", model.get("status") == "ready", f"model status: {model.get('status')}")
        except Exception as exc:
            check("/health reachable", False, type(exc).__name__)
            return report(results)

        for path in ("/api/websites", "/api/websites/00000000-0000-0000-0000-000000000000/scans"):
            response = client.get(f"{api}{path}")
            check(f"GET {path} without a token is rejected", response.status_code in (401, 403), f"HTTP {response.status_code}")

        allowed = client.options(
            f"{api}/health",
            headers={"Origin": dashboard, "Access-Control-Request-Method": "GET"},
        )
        check(
            "CORS allows the dashboard origin",
            allowed.headers.get("access-control-allow-origin") == dashboard,
            f"got {allowed.headers.get('access-control-allow-origin')!r}",
        )

        evil = client.options(
            f"{api}/health",
            headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
        )
        check("CORS does not allow an unrelated origin", evil.headers.get("access-control-allow-origin") != "https://evil.example")

        local = client.options(
            f"{api}/health",
            headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET"},
        )
        check("CORS does not allow localhost in production", local.headers.get("access-control-allow-origin") != "http://localhost:3000")

        try:
            page = client.get(f"{dashboard}/reset-password", follow_redirects=True)
            check("Dashboard SPA route /reset-password serves the app", page.status_code == 200, f"HTTP {page.status_code}")
        except Exception as exc:
            check("Dashboard reachable", False, type(exc).__name__)

    return report(results)


def report(results: list[tuple[str, bool, str]]) -> int:
    for name, ok, detail in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" ({detail})" if detail and not ok else ""))
    failed = sum(1 for _, ok, _ in results if not ok)
    print(f"\n{len(results) - failed}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
