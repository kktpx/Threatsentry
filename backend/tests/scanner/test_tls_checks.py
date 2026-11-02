from datetime import UTC, datetime

from backend.scanner.passive.tls_checks import evaluate_tls_info

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _categories(**kwargs) -> set[str]:
    base = {"hostname": "example.com", "verify_error": None, "cert": None, "protocol": "TLSv1.3", "now": NOW}
    base.update(kwargs)
    return {f.category for f in evaluate_tls_info(**base)}


def test_healthy_tls_has_no_findings() -> None:
    assert _categories(cert={"notAfter": "Jan  1 00:00:00 2027 GMT"}) == set()


def test_expiring_certificate_is_flagged() -> None:
    assert _categories(cert={"notAfter": "Jan  8 00:00:00 2026 GMT"}) == {"TLS_CERT_EXPIRING_SOON"}


def test_hostname_mismatch_and_expired_are_distinguished() -> None:
    assert _categories(verify_error="Hostname mismatch, certificate is not valid for 'example.com'") == {"TLS_HOSTNAME_MISMATCH"}
    assert _categories(verify_error="certificate has expired") == {"TLS_CERT_EXPIRED"}
    assert _categories(verify_error="self-signed certificate") == {"TLS_CERT_INVALID"}


def test_legacy_protocol_is_flagged() -> None:
    assert _categories(protocol="TLSv1.1") == {"TLS_WEAK_PROTOCOL"}
