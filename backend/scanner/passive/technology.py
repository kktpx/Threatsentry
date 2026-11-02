import re
from dataclasses import dataclass
from http.cookies import SimpleCookie
from typing import Literal, Mapping

from bs4 import BeautifulSoup

Confidence = Literal["POTENTIAL", "LIKELY"]

VERSION_PATTERN = re.compile(r"(\d+(?:\.\d+){1,2})")

# (technology, header value substring) pairs.
SERVER_SIGNATURES = (
    ("nginx", "nginx"),
    ("Apache HTTP Server", "apache"),
    ("Microsoft IIS", "microsoft-iis"),
    ("Cloudflare", "cloudflare"),
    ("LiteSpeed", "litespeed"),
)
POWERED_BY_SIGNATURES = (
    ("PHP", "php"),
    ("ASP.NET", "asp.net"),
    ("Express", "express"),
    ("Next.js", "next.js"),
)
GENERATOR_SIGNATURES = (
    ("WordPress", "wordpress"),
    ("Drupal", "drupal"),
    ("Joomla", "joomla"),
    ("Ghost", "ghost"),
    ("Hugo", "hugo"),
)
# Asset path fragments are weak evidence: a site can copy these paths without running the technology.
ASSET_SIGNATURES = (
    ("WordPress", "/wp-content/"),
    ("WordPress", "/wp-includes/"),
    ("Next.js", "/_next/"),
    ("Drupal", "/sites/default/files/"),
)
SCRIPT_SIGNATURES = (
    ("jQuery", re.compile(r"jquery[.\-\d]*(?:\.min)?\.js", re.I)),
    ("React", re.compile(r"react(?:-dom)?[.\-\d]*(?:\.min)?\.js", re.I)),
    ("Vue.js", re.compile(r"vue[.\-\d]*(?:\.min)?\.js", re.I)),
    ("Bootstrap", re.compile(r"bootstrap[.\-\d]*(?:\.min)?\.js", re.I)),
)
COOKIE_SIGNATURES = (
    ("PHP", "phpsessid"),
    ("Java servlet container", "jsessionid"),
    ("ASP.NET", "asp.net_sessionid"),
    ("Laravel", "laravel_session"),
    ("Express (connect)", "connect.sid"),
)


@dataclass(frozen=True, slots=True)
class DetectedTechnology:
    name: str
    confidence: Confidence
    source: str
    evidence: dict[str, str]


def _version_from(value: str) -> str | None:
    match = VERSION_PATTERN.search(value)
    return match.group(1) if match else None


def detect_technologies(
    headers: Mapping[str, str],
    body: str,
    raw_cookies: list[str],
) -> list[DetectedTechnology]:
    """Infers technologies cautiously. Strong signals are LIKELY; weak ones stay POTENTIAL.

    Nothing here is CONFIRMED: every signal can be spoofed or copied. Cookie values are never read.
    """
    found: dict[str, DetectedTechnology] = {}

    def add(name: str, confidence: Confidence, source: str, evidence: dict[str, str]) -> None:
        existing = found.get(name)
        if existing is None or (existing.confidence == "POTENTIAL" and confidence == "LIKELY"):
            found[name] = DetectedTechnology(name, confidence, source, evidence)

    normalized = {k.lower(): v for k, v in headers.items()}

    server = normalized.get("server", "")
    for name, needle in SERVER_SIGNATURES:
        if needle in server.lower():
            evidence = {"header": "server", "value": server[:100]}
            if version := _version_from(server):
                evidence["version"] = version
            add(name, "LIKELY", "header", evidence)

    powered_by = normalized.get("x-powered-by", "")
    for name, needle in POWERED_BY_SIGNATURES:
        if needle in powered_by.lower():
            evidence = {"header": "x-powered-by", "value": powered_by[:100]}
            if version := _version_from(powered_by):
                evidence["version"] = version
            add(name, "LIKELY", "header", evidence)

    if body:
        soup = BeautifulSoup(body, "html.parser")

        for meta in soup.find_all("meta", attrs={"name": re.compile("^generator$", re.I)}):
            content = str(meta.get("content", ""))
            for name, needle in GENERATOR_SIGNATURES:
                if needle in content.lower():
                    evidence = {"source": "meta generator", "value": content[:100]}
                    if version := _version_from(content):
                        evidence["version"] = version
                    add(name, "LIKELY", "meta", evidence)

        asset_urls = [str(tag.get("src") or tag.get("href") or "") for tag in soup.find_all(["script", "link", "img"])]
        for url in asset_urls:
            for name, fragment in ASSET_SIGNATURES:
                if fragment in url:
                    add(name, "POTENTIAL", "asset-path", {"source": "asset path", "path": url[:150]})

        for tag in soup.find_all("script", src=True):
            src = str(tag["src"])
            for name, pattern in SCRIPT_SIGNATURES:
                if pattern.search(src.rsplit("/", 1)[-1]):
                    add(name, "POTENTIAL", "script", {"source": "script name", "script": src[:150]})

    for raw_header in raw_cookies:
        cookie = SimpleCookie()
        try:
            cookie.load(raw_header)
        except Exception:
            continue
        for cookie_name in cookie:
            for name, needle in COOKIE_SIGNATURES:
                if cookie_name.lower() == needle:
                    add(name, "POTENTIAL", "cookie-name", {"source": "cookie name", "cookie_name": cookie_name})

    return sorted(found.values(), key=lambda t: t.name)
