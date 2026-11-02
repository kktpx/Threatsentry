import re
from typing import Literal

from bs4 import BeautifulSoup

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class ExposureFinding:
    __slots__ = ("category", "severity", "recommendation", "evidence")

    def __init__(self, category: str, severity: Severity, recommendation: str, evidence: dict[str, str]) -> None:
        self.category = category
        self.severity = severity
        self.recommendation = recommendation
        self.evidence = evidence


STACK_TRACE_PATTERNS = (
    (re.compile(r"Traceback \(most recent call last\):", re.IGNORECASE), "Python traceback detected"),
    (re.compile(r"Fatal error:.*?in\s+/\S+\.php", re.IGNORECASE), "PHP Fatal error with path leakage"),
    (re.compile(r"at\s+[\w\.\$]+\([\w\.]+\.java:\d+\)", re.IGNORECASE), "Java stack trace detected"),
    (re.compile(r"at\s+(?:async\s+)?[\w\.\$]+\s+\([^)]+:\d+:\d+\)", re.IGNORECASE), "Node.js stack trace detected"),
    (re.compile(r"System\.NullReferenceException:", re.IGNORECASE), ".NET exception stack trace detected"),
)

DIRECTORY_LISTING_PATTERNS = (
    re.compile(r"<title>Index of /", re.IGNORECASE),
    re.compile(r"<h1>Index of /", re.IGNORECASE),
    re.compile(r"Directory Listing For /", re.IGNORECASE),
)


SOURCE_MAP_PATTERN = re.compile(r"[#@]\s*sourceMappingURL=(\S+)", re.IGNORECASE)

# Active mixed content can be modified by a network attacker and runs with the page's privileges.
ACTIVE_MIXED_TAGS = {"script": "src", "iframe": "src", "link": "href", "form": "action"}
PASSIVE_MIXED_TAGS = {"img": "src", "audio": "src", "video": "src"}


def _insecure_references(body: str) -> tuple[list[str], list[str]]:
    soup = BeautifulSoup(body, "html.parser")
    active: list[str] = []
    passive: list[str] = []
    for tag in soup.find_all(list({**ACTIVE_MIXED_TAGS, **PASSIVE_MIXED_TAGS})):
        attr = ACTIVE_MIXED_TAGS.get(tag.name) or PASSIVE_MIXED_TAGS[tag.name]
        value = str(tag.get(attr) or "").strip()
        if not value.lower().startswith("http://"):
            continue
        if tag.name == "link" and "stylesheet" not in [r.lower() for r in tag.get("rel", [])]:
            continue
        (active if tag.name in ACTIVE_MIXED_TAGS else passive).append(value[:150])
    return active, passive


def evaluate_redirect_downgrade(url: str, status_code: int, location: str | None) -> list[ExposureFinding]:
    """Flags an HTTPS page that redirects to plain HTTP."""
    if url.startswith("https://") and 300 <= status_code < 400 and (location or "").lower().startswith("http://"):
        return [
            ExposureFinding(
                category="HTTPS_DOWNGRADE_REDIRECT",
                severity="MEDIUM",
                recommendation="Redirect to HTTPS URLs only, and enable HSTS so browsers never fall back to HTTP.",
                evidence={"status_code": str(status_code), "location": (location or "")[:150]},
            )
        ]
    return []


def evaluate_content_exposure(body: str, status_code: int, *, is_https: bool = False) -> list[ExposureFinding]:
    findings: list[ExposureFinding] = []

    # 1. Stack trace detection
    for pattern, desc in STACK_TRACE_PATTERNS:
        match = pattern.search(body)
        if match:
            findings.append(
                ExposureFinding(
                    category="STACK_TRACE_EXPOSURE",
                    severity="HIGH",
                    recommendation="Disable public debug mode and return generic error pages instead of detailed stack traces.",
                    evidence={"match": desc, "status_code": str(status_code)},
                )
            )
            break

    # 2. Directory listing detection
    for pattern in DIRECTORY_LISTING_PATTERNS:
        if pattern.search(body):
            findings.append(
                ExposureFinding(
                    category="DIRECTORY_LISTING",
                    severity="MEDIUM",
                    recommendation="Disable directory indexing / directory listing on web server configuration.",
                    evidence={"snippet": "Directory index page title observed."},
                )
            )
            break

    # 3. Source map reference
    source_map = SOURCE_MAP_PATTERN.search(body)
    if source_map:
        findings.append(
            ExposureFinding(
                category="SOURCE_MAP_EXPOSURE",
                severity="LOW",
                recommendation="Do not publish source maps to production, or restrict them to authenticated developers.",
                evidence={"reference": source_map.group(1)[:150]},
            )
        )

    # 4. Mixed content on HTTPS pages
    if is_https and "http://" in body.lower():
        active, passive = _insecure_references(body)
        if active:
            findings.append(
                ExposureFinding(
                    category="MIXED_CONTENT_ACTIVE",
                    severity="MEDIUM",
                    recommendation="Load scripts, frames, stylesheets and form targets over HTTPS only.",
                    evidence={"count": str(len(active)), "example": active[0]},
                )
            )
        if passive:
            findings.append(
                ExposureFinding(
                    category="MIXED_CONTENT_PASSIVE",
                    severity="LOW",
                    recommendation="Load images and media over HTTPS only.",
                    evidence={"count": str(len(passive)), "example": passive[0]},
                )
            )

    return findings
