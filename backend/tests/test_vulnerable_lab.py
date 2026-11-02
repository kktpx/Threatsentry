from fastapi.testclient import TestClient

from labs.vulnerable_app import app


def test_vulnerable_lab_home() -> None:
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert "ThreatSentry Test Lab Target" in response.text


def test_vulnerable_lab_verification_token() -> None:
    client = TestClient(app)
    # Set token
    set_resp = client.get("/set-token?token=test_token_123")
    assert set_resp.status_code == 200

    # Get challenge
    challenge_resp = client.get("/.well-known/threatsentry.txt")
    assert challenge_resp.status_code == 200
    assert challenge_resp.text.strip() == "threatsentry-verification=test_token_123"


def test_vulnerable_lab_verification_header_echo() -> None:
    client = TestClient(app)
    # Header-based challenge resolution
    resp = client.get(
        "/.well-known/threatsentry.txt",
        headers={"X-ThreatSentry-Token": "dynamic_ts_token_xyz987"},
    )
    assert resp.status_code == 200
    assert resp.text.strip() == "threatsentry-verification=dynamic_ts_token_xyz987"


def test_vulnerable_lab_reflected_xss() -> None:
    client = TestClient(app)
    marker = "<ts_probe_test>"
    response = client.get(f"/search?q={marker}")
    assert response.status_code == 200
    # Verifies unencoded reflection
    assert marker in response.text


def test_vulnerable_lab_sqli_error() -> None:
    client = TestClient(app)
    # Safe query
    safe_resp = client.get("/products?id=1")
    assert safe_resp.status_code == 200
    assert "Secure Laptop Stand" in safe_resp.text

    # Injected query triggers sqlite3.OperationalError
    injected_resp = client.get("/products?id=1'")
    assert injected_resp.status_code == 500
    assert "sqlite3.OperationalError" in injected_resp.text


def test_lab_pages_are_marked_test_only() -> None:
    from fastapi.testclient import TestClient
    from labs.vulnerable_app import app

    client = TestClient(app)
    for path in ("/", "/vulnerable/search?q=x", "/safe/search?q=x", "/safe/products?id=1"):
        response = client.get(path)
        assert response.headers["x-threatsentry-lab"] == "TEST / BENCHMARK ONLY"
        assert "TEST / BENCHMARK ONLY" in response.text


def test_safe_endpoints_resist_payloads() -> None:
    from fastapi.testclient import TestClient
    from labs.vulnerable_app import app

    client = TestClient(app)
    xss = client.get("/safe/search", params={"q": "<script>alert(1)</script>"})
    assert "<script>alert(1)</script>" not in xss.text
    sqli = client.get("/safe/products", params={"id": "1' OR '1'='1"})
    assert sqli.status_code == 404
    assert "sqlite3" not in sqli.text
    vulnerable = client.get("/vulnerable/search", params={"q": "<script>alert(1)</script>"})
    assert "<script>alert(1)</script>" in vulnerable.text


def test_lab_mode_xss_only(monkeypatch) -> None:
    monkeypatch.setenv("LAB_MODE", "xss")
    client = TestClient(app)
    assert client.get("/vulnerable/search?q=x").status_code == 200
    assert client.get("/safe/search?q=x").status_code == 200
    for path in ("/products?id=1", "/vulnerable/products?id=1", "/safe/products?id=1"):
        assert client.get(path).status_code == 404
    home = client.get("/").text
    assert "Reflected XSS" in home and "SQL Injection" not in home


def test_lab_mode_sqli_only(monkeypatch) -> None:
    monkeypatch.setenv("LAB_MODE", "sqli")
    client = TestClient(app)
    assert client.get("/vulnerable/products?id=1").status_code == 200
    for path in ("/search?q=x", "/vulnerable/search?q=x", "/safe/search?q=x"):
        assert client.get(path).status_code == 404
    home = client.get("/").text
    assert "SQL Injection" in home and "Reflected XSS" not in home


def test_lab_mode_disabled_response_is_still_marked_test_only(monkeypatch) -> None:
    monkeypatch.setenv("LAB_MODE", "xss")
    response = TestClient(app).get("/products?id=1")
    assert response.headers["X-ThreatSentry-Lab"] == "TEST / BENCHMARK ONLY"


def test_lab_mode_unknown_value_falls_back_to_all(monkeypatch) -> None:
    monkeypatch.setenv("LAB_MODE", "bogus")
    client = TestClient(app)
    assert client.get("/search?q=x").status_code == 200
    assert client.get("/products?id=1").status_code == 200


def test_token_pages_do_not_reflect_markup(monkeypatch) -> None:
    monkeypatch.setenv("LAB_MODE", "sqli")
    client = TestClient(app)
    payload = "<script>alert(1)</script>"
    assert payload not in client.get("/set-token", params={"token": payload}).text
    assert payload not in client.get("/").text
    client.get("/set-token", params={"token": "ts_lab_token_demo"})


def _passive_categories(response) -> set[str]:
    from backend.scanner.passive.cookie_checks import evaluate_cookies
    from backend.scanner.passive.header_checks import evaluate_security_headers
    from backend.scanner.passive.http_checks import evaluate_server_banners

    findings = [
        *evaluate_security_headers(response.headers),
        *evaluate_server_banners(response.headers),
        *evaluate_cookies(response.headers.get_list("set-cookie"), is_https=False),
    ]
    return {f.category for f in findings}


def test_single_vulnerability_modes_have_no_passive_findings(monkeypatch) -> None:
    for mode, path in (("xss", "/vulnerable/search?q=x"), ("sqli", "/vulnerable/products?id=1")):
        monkeypatch.setenv("LAB_MODE", mode)
        assert _passive_categories(TestClient(app).get(path)) == set(), mode


def test_all_mode_keeps_passive_findings(monkeypatch) -> None:
    monkeypatch.setenv("LAB_MODE", "all")
    categories = _passive_categories(TestClient(app).get("/"))
    assert {"MISSING_CSP", "MISSING_HSTS", "SERVER_BANNER_LEAKAGE", "COOKIE_MISSING_HTTPONLY"} <= categories
