"""Safe website crawler: collect links and script URLs (async for speed)."""

import asyncio
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from ai_security_agent.config import (
    CRAWL_CONCURRENCY,
    DEFAULT_USER_AGENT,
    MAX_CRAWL_DEPTH,
    MAX_PAGES_PER_DOMAIN,
    REQUEST_TIMEOUT_SECONDS,
)
from ai_security_agent.utils.logger import get_logger

logger = get_logger(__name__)

DEFAULT_HEADERS = {"User-Agent": DEFAULT_USER_AGENT, "Accept": "text/html,*/*;q=0.9"}


def _same_origin(base_url: str, link: str) -> bool:
    """Return True if link is same origin (scheme + netloc) as base_url."""
    try:
        base = urlparse(base_url)
        other = urlparse(link)
        return (base.scheme == other.scheme and
                base.netloc.lower() == other.netloc.lower())
    except Exception:
        return False


def _normalize_url(url: str) -> str:
    """Remove fragment and optionally trailing slash for dedup."""
    parsed = urlparse(url)
    no_frag = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    if parsed.query:
        no_frag += "?" + parsed.query
    return no_frag.rstrip("/") or no_frag


def _extract_links(soup: BeautifulSoup, base_url: str) -> list[str]:
    """Extract same-origin href links from page."""
    links: list[str] = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if not href or href.startswith(("#", "javascript:", "mailto:")):
            continue
        full = urljoin(base_url, href)
        if _same_origin(base_url, full):
            links.append(_normalize_url(full))
    return list(dict.fromkeys(links))


def _extract_script_urls(soup: BeautifulSoup, base_url: str) -> list[str]:
    """Extract same-origin script src URLs."""
    urls: list[str] = []
    for tag in soup.find_all("script", src=True):
        full = urljoin(base_url, tag["src"])
        if _same_origin(base_url, full):
            urls.append(_normalize_url(full))
    return list(dict.fromkeys(urls))


async def _fetch_page(
    client: httpx.AsyncClient,
    url: str,
    semaphore: asyncio.Semaphore,
) -> tuple[str, str, list[str], list[str]]:
    """
    Fetch one page; return (url, html, links, js_urls).
    On failure returns (url, "", [], []).
    """
    async with semaphore:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            if "text/html" not in (resp.headers.get("content-type") or ""):
                return (url, "", [], [])
            soup = BeautifulSoup(resp.text, "html.parser")
            links = _extract_links(soup, url)
            js_urls = _extract_script_urls(soup, url)
            logger.info("Crawled page %s (links=%d, js=%d)", url, len(links), len(js_urls))
            return (url, resp.text, links, js_urls)
        except Exception as e:
            logger.warning("Crawl failed for %s: %s", url, e)
            return (url, "", [], [])


async def crawl_site_async(
    start_url: str,
    max_depth: int = MAX_CRAWL_DEPTH,
    max_pages: int = MAX_PAGES_PER_DOMAIN,
    timeout: float = REQUEST_TIMEOUT_SECONDS,
    concurrency: int = CRAWL_CONCURRENCY,
) -> tuple[list[str], list[str]]:
    """
    Crawl the site starting at start_url using async HTTP.
    Returns (page_urls, js_urls). Same-origin only; concurrent per level.
    """
    start_url = _normalize_url(start_url)
    seen_pages: set[str] = set()
    all_js: set[str] = set()
    semaphore = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=timeout,
        headers=DEFAULT_HEADERS,
    ) as client:
        current_level: set[str] = {start_url}
        depth = 0

        while current_level and len(seen_pages) < max_pages and depth <= max_depth:
            # Dedupe against already seen
            to_fetch = [u for u in current_level if u not in seen_pages][: max_pages - len(seen_pages)]
            if not to_fetch:
                break
            for u in to_fetch:
                seen_pages.add(u)

            results = await asyncio.gather(
                *[_fetch_page(client, u, semaphore) for u in to_fetch],
                return_exceptions=True,
            )

            next_level: set[str] = set()
            for r in results:
                if isinstance(r, Exception):
                    logger.warning("Crawl task failed: %s", r)
                    continue
                _url, _html, links, js_urls = r
                all_js.update(js_urls)
                if depth < max_depth:
                    for link in links:
                        if link not in seen_pages and _same_origin(start_url, link):
                            next_level.add(link)

            current_level = next_level
            depth += 1

    return list(seen_pages), list(all_js)


def crawl_site(
    start_url: str,
    max_depth: int = MAX_CRAWL_DEPTH,
    max_pages: int = MAX_PAGES_PER_DOMAIN,
    timeout: float = REQUEST_TIMEOUT_SECONDS,
) -> tuple[list[str], list[str]]:
    """Sync wrapper around crawl_site_async."""
    return asyncio.run(crawl_site_async(start_url, max_depth, max_pages, timeout))
