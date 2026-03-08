"""Recon agent: crawl site, collect links and JS URLs (async)."""

import asyncio
from urllib.parse import urlparse

import httpx

from ai_security_agent.config import (
    CT_LOOKUP_ENABLED,
    FETCH_JS_CONCURRENCY,
    get_http_client_options,
    REQUEST_TIMEOUT_SECONDS,
)
from ai_security_agent.tools.crawler import _get_registered_domain, crawl_site_async
from ai_security_agent.tools.ct_logs import fetch_subdomains_from_ct_async
from ai_security_agent.utils.logger import get_logger

logger = get_logger(__name__)


async def run_recon_async(target_url: str) -> tuple[list[str], list[str]]:
    """
    Crawl target website and collect page URLs and JavaScript file URLs.
    If CT_LOOKUP_ENABLED, fetches subdomains from Certificate Transparency logs (crt.sh)
    and adds them as extra seed URLs so they are crawled too.
    Returns (page_urls, js_urls).
    """
    logger.info("Recon started for %s", target_url)
    extra_seed_urls: list[str] = []
    if CT_LOOKUP_ENABLED:
        registered_domain = _get_registered_domain(target_url)
        if registered_domain:
            subdomains = await fetch_subdomains_from_ct_async(registered_domain)
            parsed = urlparse(target_url)
            scheme = parsed.scheme or "https"
            for host in subdomains:
                extra_seed_urls.append(f"{scheme}://{host}/")
            if extra_seed_urls:
                logger.info("CT logs: added %d subdomains as crawl seeds", len(extra_seed_urls))
    page_urls, js_urls = await crawl_site_async(target_url, extra_seed_urls=extra_seed_urls or None)
    logger.info("Recon finished: %d pages, %d JS files", len(page_urls), len(js_urls))
    return page_urls, js_urls


async def fetch_js_content_async(client: httpx.AsyncClient, js_url: str) -> tuple[str, str]:
    """Fetch JavaScript content; returns (js_url, content). Empty content on failure."""
    try:
        resp = await client.get(js_url)
        if resp.status_code == 200:
            return (js_url, resp.text)
    except Exception as e:
        logger.warning("Failed to fetch JS %s: %s", js_url, e)
    return (js_url, "")


async def fetch_all_js_async(
    js_urls: list[str],
    concurrency: int = FETCH_JS_CONCURRENCY,
) -> list[tuple[str, str]]:
    """Fetch multiple JS URLs concurrently; returns list of (url, content)."""
    semaphore = asyncio.Semaphore(concurrency)

    opts = get_http_client_options(None)
    async def fetch_one(url: str) -> tuple[str, str]:
        async with semaphore:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=REQUEST_TIMEOUT_SECONDS,
                headers=opts["headers"],
                cookies=opts.get("cookies"),
            ) as client:
                return await fetch_js_content_async(client, url)

    results = await asyncio.gather(*[fetch_one(u) for u in js_urls], return_exceptions=True)
    out: list[tuple[str, str]] = []
    for r in results:
        if isinstance(r, Exception):
            logger.warning("JS fetch failed: %s", r)
            continue
        url, content = r
        if content:
            out.append((url, content))
    return out


def run_recon(target_url: str) -> tuple[list[str], list[str]]:
    """Sync wrapper: runs run_recon_async via asyncio.run."""
    return asyncio.run(run_recon_async(target_url))


def fetch_js_content(js_url: str) -> str:
    """Sync fetch single JS URL (for backward compatibility)."""
    opts = get_http_client_options(None)
    async def _one() -> str:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=REQUEST_TIMEOUT_SECONDS,
            headers=opts["headers"],
            cookies=opts.get("cookies"),
        ) as client:
            _, content = await fetch_js_content_async(client, js_url)
            return content
    return asyncio.run(_one())
