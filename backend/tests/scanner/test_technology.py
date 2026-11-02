from backend.scanner.passive.orchestrator import run_passive_checks_for_response
from backend.scanner.passive.technology import detect_technologies


def _by_name(**kwargs):
    base = {"headers": {}, "body": "", "raw_cookies": []}
    base.update(kwargs)
    return {t.name: t for t in detect_technologies(**base)}


def test_headers_and_generator_are_likely_with_versions() -> None:
    found = _by_name(
        headers={"Server": "nginx/1.18.0", "X-Powered-By": "PHP/8.1.2"},
        body='<html><head><meta name="generator" content="WordPress 6.4.1"></head></html>',
    )
    assert found["nginx"].confidence == "LIKELY" and found["nginx"].evidence["version"] == "1.18.0"
    assert found["PHP"].evidence["version"] == "8.1.2"
    assert found["WordPress"].confidence == "LIKELY" and found["WordPress"].evidence["version"] == "6.4.1"


def test_weak_signals_stay_potential_and_never_confirmed() -> None:
    found = _by_name(
        body='<script src="/static/jquery-3.6.0.min.js"></script><img src="/wp-content/a.png">',
        raw_cookies=["PHPSESSID=abc123; Path=/"],
    )
    assert found["jQuery"].confidence == "POTENTIAL"
    assert found["WordPress"].confidence == "POTENTIAL"
    assert found["PHP"].confidence == "POTENTIAL"
    assert all(t.confidence != "CONFIRMED" for t in found.values())


def test_strong_signal_upgrades_a_weak_one_and_cookie_values_are_not_leaked() -> None:
    found = _by_name(
        headers={"X-Powered-By": "PHP/8.1.2"},
        raw_cookies=["PHPSESSID=super-secret-value; Path=/"],
    )
    assert found["PHP"].confidence == "LIKELY"
    weak = _by_name(raw_cookies=["PHPSESSID=super-secret-value"])
    assert "super-secret-value" not in str(weak["PHP"].evidence)


def test_plain_page_detects_nothing() -> None:
    assert detect_technologies({}, "<html><body>Hello</body></html>", []) == []


def test_orchestrator_reports_info_findings_once_per_origin() -> None:
    kwargs = dict(headers={"Server": "nginx"}, body="", status_code=200, raw_cookies=[])
    findings = run_passive_checks_for_response("https://example.com/a", **kwargs) + run_passive_checks_for_response(
        "https://example.com/b", **kwargs
    )
    tech = [f for f in findings if f.category == "TECHNOLOGY_DETECTED"]
    assert {f.ensure_fingerprint("https://example.com") for f in tech} == {tech[0].ensure_fingerprint("https://example.com")}
    assert tech[0].severity == "INFO" and tech[0].endpoint == "https://example.com"
