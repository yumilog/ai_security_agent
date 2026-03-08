"""Safe website crawler: collect links and script URLs (async for speed)."""

import asyncio
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
import tldextract
from bs4 import BeautifulSoup

from ai_security_agent.config import (
    CRAWL_CONCURRENCY,
    get_http_client_options,
    MAX_CRAWL_DEPTH,
    MAX_PAGES_PER_DOMAIN,
    REQUEST_TIMEOUT_SECONDS,
)
from ai_security_agent.utils.logger import get_logger

logger = get_logger(__name__)

# Crawl uses same auth as rest of scanner (cookie / JWT / Authorization from config)
def _crawl_headers() -> dict[str, str]:
    opts = get_http_client_options(None)
    base = {"Accept": "text/html,*/*;q=0.9"}
    return {**opts["headers"], **base}


def _get_registered_domain(url: str) -> str:
    """Return eTLD+1 (registrable domain) for url, e.g. example.com. Fallback to netloc for IP/localhost."""
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return ""
        ext = tldextract.extract(url)
        rd = getattr(ext, "top_domain_under_public_suffix", None) or getattr(
            ext, "registered_domain", None
        )
        if rd:
            return rd.lower()
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        return parsed.netloc.lower()
    except Exception:
        return urlparse(url).netloc.lower() or ""


def _is_in_scope(url: str, target_registered_domain: str) -> bool:
    """True if url belongs to the same registrable domain (eTLD+1) as target. Allows subdomains."""
    if not target_registered_domain:
        return True
    url_domain = _get_registered_domain(url)
    if not url_domain:
        return False
    return url_domain == target_registered_domain


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


def normalize_url_for_crawl(url: str) -> str:
    """
    Normalize URL for crawl dedup: path + sorted param names (values ignored).
    e.g. /product?id=1, /product?id=2, /product?id=3 -> same key /product?id
    so we only crawl one representative URL per pattern (avoids 10000 URLs).
    """
    parsed = urlparse(url)
    path = (parsed.path or "/").rstrip("/") or "/"
    if not parsed.query:
        return path
    try:
        params = parse_qs(parsed.query, keep_blank_values=True)
        keys = sorted(params.keys())
        if keys:
            return path + "?" + "&".join(keys)
    except Exception:
        pass
    return path


def _extract_links(
    soup: BeautifulSoup,
    base_url: str,
    target_registered_domain: str,
) -> list[str]:
    """Extract in-scope href links (same eTLD+1 as target; subdomains allowed)."""
    links: list[str] = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if not href or href.startswith(("#", "javascript:", "mailto:")):
            continue
        full = urljoin(base_url, href)
        if not _is_in_scope(full, target_registered_domain):
            continue
        links.append(_normalize_url(full))
    return list(dict.fromkeys(links))


def _extract_script_urls(
    soup: BeautifulSoup,
    base_url: str,
    target_registered_domain: str,
) -> list[str]:
    """Extract in-scope script src URLs (same eTLD+1 as target; subdomains allowed)."""
    urls: list[str] = []
    for tag in soup.find_all("script", src=True):
        full = urljoin(base_url, tag["src"])
        if not _is_in_scope(full, target_registered_domain):
            continue
        urls.append(_normalize_url(full))
    return list(dict.fromkeys(urls))


async def _fetch_page(
    client: httpx.AsyncClient,
    url: str,
    semaphore: asyncio.Semaphore,
    target_registered_domain: str,
) -> tuple[str, str, list[str], list[str]]:
    """
    Fetch one page; return (url, html, links, js_urls).
    Links/script URLs are filtered by eTLD+1 scope. On failure returns (url, "", [], []).
    """
    async with semaphore:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            if "text/html" not in (resp.headers.get("content-type") or ""):
                return (url, "", [], [])
            soup = BeautifulSoup(resp.text, "html.parser")
            links = _extract_links(soup, url, target_registered_domain)
            js_urls = _extract_script_urls(soup, url, target_registered_domain)
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
    extra_seed_urls: list[str] | None = None,
) -> tuple[list[str], list[str]]:
    """
    Crawl the site starting at start_url using async HTTP.
    If extra_seed_urls is set (e.g. from CT log subdomains), they are added to the initial crawl queue.
    Returns (page_urls, js_urls). eTLD+1 scope; concurrent per level.
    """
    start_url = _normalize_url(start_url)
    target_registered_domain = _get_registered_domain(start_url)
    if target_registered_domain:
        logger.debug("Crawl scope (eTLD+1): %s (subdomains allowed)", target_registered_domain)

    seen_normalized: set[str] = set()
    seen_pages: list[str] = []
    all_js: set[str] = set()
    semaphore = asyncio.Semaphore(concurrency)

    current_level: set[str] = {start_url}
    if extra_seed_urls:
        for u in extra_seed_urls:
            u = _normalize_url(u)
            if _is_in_scope(u, target_registered_domain):
                current_level.add(u)
        logger.info("Crawl seeds: %d URLs (target + %d extra)", len(current_level), len(extra_seed_urls))

    opts = get_http_client_options(None)
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=timeout,
        headers=_crawl_headers(),
        cookies=opts.get("cookies"),
    ) as client:
        depth = 0

        while current_level and len(seen_pages) < max_pages and depth <= max_depth:
            to_fetch = []
            for u in current_level:
                if len(seen_pages) + len(to_fetch) >= max_pages:
                    break
                if not _is_in_scope(u, target_registered_domain):
                    continue
                norm = normalize_url_for_crawl(u)
                if norm in seen_normalized:
                    continue
                seen_normalized.add(norm)
                to_fetch.append(u)
            if not to_fetch:
                break
            for u in to_fetch:
                seen_pages.append(u)

            results = await asyncio.gather(
                *[_fetch_page(client, u, semaphore, target_registered_domain) for u in to_fetch],
                return_exceptions=True,
            )

            next_level = set()
            for r in results:
                if isinstance(r, Exception):
                    logger.warning("Crawl task failed: %s", r)
                    continue
                _url, _html, links, js_urls = r
                all_js.update(js_urls)
                if depth < max_depth:
                    for link in links:
                        if not _is_in_scope(link, target_registered_domain):
                            continue
                        norm = normalize_url_for_crawl(link)
                        if norm in seen_normalized:
                            continue
                        seen_normalized.add(norm)
                        next_level.add(link)

            current_level = next_level
            depth += 1

    return seen_pages, list(all_js)


def crawl_site(
    start_url: str,
    max_depth: int = MAX_CRAWL_DEPTH,
    max_pages: int = MAX_PAGES_PER_DOMAIN,
    timeout: float = REQUEST_TIMEOUT_SECONDS,
) -> tuple[list[str], list[str]]:
    """Sync wrapper around crawl_site_async."""
    return asyncio.run(crawl_site_async(start_url, max_depth, max_pages, timeout))
