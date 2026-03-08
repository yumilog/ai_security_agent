"""Endpoint wordlist discovery: probe paths like /admin, /internal (async)."""

import asyncio
from urllib.parse import urljoin, urlparse

import httpx

from ai_security_agent.config import get_http_client_options, REQUEST_TIMEOUT_SECONDS
from ai_security_agent.utils.logger import get_logger

logger = get_logger(__name__)

# Built-in path wordlist
ENDPOINT_WORDLIST = [
    "admin",
    "internal",
    "debug",
    "staging",
    "private",
    "graphql",
    "api",
    "v1",
    "v2",
    "config",
    "backup",
    "test",
    "dev",
]

# Consider discovered if status is one of these
DISCOVERED_STATUS = {200, 201, 301, 302, 403, 404}
ENDPOINT_FUZZ_CONCURRENCY = 15


async def fuzz_endpoints_async(
    base_url: str,
    path_wordlist: list[str] | None = None,
    concurrency: int = ENDPOINT_FUZZ_CONCURRENCY,
) -> list[tuple[str, int]]:
    """
    Probe paths like /admin, /internal, /graphql against base_url.
    Returns list of (url, status_code) for paths that respond.
    """
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    paths = path_wordlist or ENDPOINT_WORDLIST
    urls = [urljoin(origin, "/" + p.strip().lstrip("/")) for p in paths if p.strip()]
    if not urls:
        return []
    opts = get_http_client_options(None)
    semaphore = asyncio.Semaphore(concurrency)
    discovered: list[tuple[str, int]] = []

    async def fetch_one(u: str) -> tuple[str, int]:
        async with semaphore:
            try:
                async with httpx.AsyncClient(
                    follow_redirects=True,
                    timeout=REQUEST_TIMEOUT_SECONDS,
                    headers=opts["headers"],
                    cookies=opts.get("cookies"),
                ) as client:
                    resp = await client.get(u)
                    return (u, resp.status_code)
            except Exception as e:
                logger.debug("Endpoint fuzz failed %s: %s", u, e)
                return (u, 0)

    results = await asyncio.gather(*[fetch_one(u) for u in urls], return_exceptions=True)
    for r in results:
        if isinstance(r, Exception):
            continue
        url, status = r
        if status in DISCOVERED_STATUS:
            discovered.append((url, status))

    logger.info("Endpoint fuzz: %d paths responded for %s", len(discovered), origin)
    return discovered
