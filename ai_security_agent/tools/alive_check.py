"""Alive check: filter hosts/URLs by HTTP response (async)."""

import asyncio
from urllib.parse import urlparse

import httpx

from ai_security_agent.config import get_http_client_options, REQUEST_TIMEOUT_SECONDS
from ai_security_agent.utils.logger import get_logger

logger = get_logger(__name__)

# Status codes considered "live"
LIVE_STATUS_CODES = {200, 301, 302, 403}
ALIVE_CHECK_CONCURRENCY = 15


async def check_url_alive(
    client: httpx.AsyncClient,
    url: str,
    use_head: bool = True,
    semaphore: asyncio.Semaphore | None = None,
) -> tuple[str, bool, int]:
    """Return (url, is_alive, status_code). Tries HEAD first, then GET if needed."""
    async def _do() -> tuple[str, bool, int]:
        try:
            if use_head:
                resp = await client.head(url, follow_redirects=True)
            else:
                resp = await client.get(url, follow_redirects=True)
            return (url, resp.status_code in LIVE_STATUS_CODES, resp.status_code)
        except Exception as e:
            if use_head:
                try:
                    resp = await client.get(url, follow_redirects=True)
                    return (url, resp.status_code in LIVE_STATUS_CODES, resp.status_code)
                except Exception:
                    pass
            logger.debug("Alive check failed %s: %s", url, e)
            return (url, False, 0)

    if semaphore:
        async with semaphore:
            return await _do()
    return await _do()


async def filter_live_urls_async(
    urls: list[str],
    concurrency: int = ALIVE_CHECK_CONCURRENCY,
    timeout: float = REQUEST_TIMEOUT_SECONDS,
) -> list[str]:
    """
    Check which URLs respond with 200, 301, 302, or 403.
    Returns only live URLs (deduplicated).
    """
    if not urls:
        return []
    opts = get_http_client_options(None)
    semaphore = asyncio.Semaphore(concurrency)
    live: list[str] = []

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=timeout,
        headers=opts["headers"],
        cookies=opts.get("cookies"),
    ) as client:
        tasks = [check_url_alive(client, u, semaphore=semaphore) for u in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, Exception):
            logger.debug("Alive check error: %s", r)
            continue
        url, is_alive, status = r
        if is_alive:
            live.append(url)

    logger.info("Alive check: %d/%d URLs live", len(live), len(urls))
    return list(dict.fromkeys(live))
