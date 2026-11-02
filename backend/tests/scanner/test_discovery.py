import httpx
import pytest

from backend.scanner.crawler import SafeCrawler
from backend.scanner.discovery import discover_seed_urls, parse_robots, parse_sitemap

ORIGIN = "https://example.com"


def test_parse_robots_keeps_literal_paths_and_sitemaps() -> None:
    text = """
    User-agent: *
    Disallow: /admin/
    Disallow: /private*
    Allow: /public
    Disallow:
    Sitemap: https://example.com/sitemap.xml  # main
    """
    paths, sitemaps = parse_robots(text, ORIGIN)
    assert paths == ["https://example.com/admin/", "https://example.com/public"]
    assert sitemaps == ["https://example.com/sitemap.xml"]


def test_parse_sitemap_ignores_nested_sitemaps() -> None:
    xml = "<urlset><url><loc>https://example.com/a</loc></url><loc> https://example.com/b </loc>" \
          "<loc>https://example.com/other.xml</loc></urlset>"
    assert parse_sitemap(xml) == ["https://example.com/a", "https://example.com/b"]


@pytest.mark.asyncio
async def test_discover_seed_urls_filters_foreign_origins_and_missing_files() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="Disallow: /secret\nSitemap: https://evil.test/sitemap.xml")
        if request.url.path == "/sitemap.xml":
            return httpx.Response(200, text="<loc>https://example.com/page</loc><loc>https://evil.test/x</loc>")
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        seeds = await discover_seed_urls(client, ORIGIN)

    assert seeds == ["https://example.com/page", "https://example.com/secret"]


@pytest.mark.asyncio
async def test_discovery_survives_missing_robots_and_sitemap() -> None:
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404))) as client:
        assert await discover_seed_urls(client, ORIGIN) == []


@pytest.mark.asyncio
async def test_crawler_visits_seeds_but_still_blocks_destructive_and_foreign_ones() -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(200, text="<html><body>ok</body></html>", headers={"content-type": "text/html"})

    async def resolver(_: str) -> tuple[str, ...]:
        return ("93.184.216.34",)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        surface = await SafeCrawler(
            ORIGIN,
            client=client,
            resolver=resolver,
            seed_urls=["https://example.com/seeded", "https://example.com/logout", "https://evil.test/x"],
        ).crawl()

    assert "https://example.com/seeded" in surface.pages_crawled
    assert not any("logout" in url or "evil.test" in url for url in requested)
