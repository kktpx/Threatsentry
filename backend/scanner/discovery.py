import re
from urllib.parse import urljoin, urlsplit

import httpx

MAX_DISCOVERY_BYTES = 256 * 1024
MAX_SEEDS = 40

_LOC_PATTERN = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)


def parse_robots(text: str, origin: str) -> tuple[list[str], list[str]]:
    """Returns (paths, sitemap_urls) from robots.txt. Wildcard rules are skipped; only literal paths are useful seeds."""
    paths: list[str] = []
    sitemaps: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if not value:
            continue
        if key == "sitemap":
            sitemaps.append(value)
        elif key in {"allow", "disallow"} and value.startswith("/") and not any(c in value for c in "*$"):
            paths.append(urljoin(origin + "/", value))
    return paths, sitemaps


def parse_sitemap(text: str) -> list[str]:
    """Returns page URLs from a sitemap. Nested sitemap indexes (.xml entries) are ignored to bound the work."""
    return [url for url in _LOC_PATTERN.findall(text) if not urlsplit(url).path.lower().endswith(".xml")]


def _same_origin(url: str, origin: str) -> bool:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}".lower() == origin.lower()


async def _fetch_text(client: httpx.AsyncClient, url: str) -> str:
    try:
        response = await client.get(url)
    except Exception:
        return ""
    if response.status_code != 200 or len(response.content) > MAX_DISCOVERY_BYTES:
        return ""
    return response.text


async def discover_seed_urls(client: httpx.AsyncClient, origin: str, *, max_seeds: int = MAX_SEEDS) -> list[str]:
    """Collects extra same-origin URLs from robots.txt and sitemap.xml.

    Uses the caller's client (no redirects, already pointed at a validated origin). Returned URLs are
    only hints: the crawler still applies SSRF, same-origin and destructive-path checks to each one.
    """
    robots_paths, sitemap_urls = parse_robots(await _fetch_text(client, f"{origin}/robots.txt"), origin)

    candidates_for_sitemap = [u for u in sitemap_urls if _same_origin(u, origin)] or [f"{origin}/sitemap.xml"]
    sitemap_pages: list[str] = []
    for sitemap_url in candidates_for_sitemap[:2]:
        sitemap_pages += parse_sitemap(await _fetch_text(client, sitemap_url))

    seeds: list[str] = []
    for url in [*sitemap_pages, *robots_paths]:
        if _same_origin(url, origin) and url not in seeds:
            seeds.append(url)
        if len(seeds) >= max_seeds:
            break
    return seeds
