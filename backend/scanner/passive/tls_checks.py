import asyncio
import ssl
from datetime import UTC, datetime
from typing import Any, Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

EXPIRY_WARNING_DAYS = 14
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


class TlsCheckFinding:
    __slots__ = ("category", "severity", "recommendation", "evidence")

    def __init__(self, category: str, severity: Severity, recommendation: str, evidence: dict[str, Any]) -> None:
        self.category = category
        self.severity = severity
        self.recommendation = recommendation
        self.evidence = evidence


def evaluate_tls_info(
    *,
    hostname: str,
    verify_error: str | None,
    cert: dict[str, Any] | None,
    protocol: str | None,
    now: datetime | None = None,
) -> list[TlsCheckFinding]:
    """Evaluates TLS handshake results. Pure function so it can be tested without a network."""
    findings: list[TlsCheckFinding] = []

    if verify_error:
        lowered = verify_error.lower()
        if "hostname" in lowered or "doesn't match" in lowered:
            category, detail = "TLS_HOSTNAME_MISMATCH", "Certificate does not match the hostname."
        elif "expired" in lowered:
            category, detail = "TLS_CERT_EXPIRED", "Certificate has expired."
        else:
            category, detail = "TLS_CERT_INVALID", "Certificate could not be validated."
        findings.append(
            TlsCheckFinding(
                category=category,
                severity="HIGH",
                recommendation="Install a valid certificate from a trusted CA that covers this hostname.",
                evidence={"hostname": hostname, "detail": detail},
            )
        )

    if cert and cert.get("notAfter"):
        try:
            expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), UTC)
        except ValueError:
            expires = None
        if expires is not None:
            days_left = (expires - (now or datetime.now(UTC))).days
            if 0 <= days_left <= EXPIRY_WARNING_DAYS:
                findings.append(
                    TlsCheckFinding(
                        category="TLS_CERT_EXPIRING_SOON",
                        severity="LOW",
                        recommendation="Renew the certificate and enable automatic renewal.",
                        evidence={"hostname": hostname, "days_left": days_left},
                    )
                )

    if protocol in WEAK_PROTOCOLS:
        findings.append(
            TlsCheckFinding(
                category="TLS_WEAK_PROTOCOL",
                severity="MEDIUM",
                recommendation="Disable legacy protocols and allow only TLS 1.2 or newer.",
                evidence={"hostname": hostname, "protocol": protocol},
            )
        )

    return findings


def _handshake(hostname: str, ip: str, port: int, timeout: float) -> tuple[str | None, dict[str, Any] | None, str | None]:
    """Connects to a pre-validated IP (avoids re-resolving DNS) and reports verification outcome."""
    import socket

    context = ssl.create_default_context()
    verify_error: str | None = None
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls:
                return tls.version(), tls.getpeercert(), None
    except ssl.SSLCertVerificationError as exc:
        verify_error = exc.verify_message or str(exc)

    # Retry without verification only to read the protocol version; the failure is already recorded.
    insecure = ssl.create_default_context()
    insecure.check_hostname = False
    insecure.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with insecure.wrap_socket(sock, server_hostname=hostname) as tls:
                return tls.version(), None, verify_error
    except OSError:
        return None, None, verify_error


async def run_tls_checks(hostname: str, ip: str, port: int = 443, timeout: float = 5.0) -> list[TlsCheckFinding]:
    try:
        protocol, cert, verify_error = await asyncio.to_thread(_handshake, hostname, ip, port, timeout)
    except OSError:
        return []
    return evaluate_tls_info(hostname=hostname, verify_error=verify_error, cert=cert, protocol=protocol)
