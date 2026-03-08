"""Parameter discovery: try common parameter names on endpoints (async)."""

import asyncio
from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from ai_security_agent.config import (
    get_http_client_options,
    ID_PARAM_WORDLIST,
    REQUEST_TIMEOUT_SECONDS,
)
from ai_security_agent.utils.logger import get_logger

logger = get_logger(__name__)

PARAM_FUZZ_CONCURRENCY = 10


def _build_param_urls(base_url: str, param_names: list[str] | None = None) -> list[str]:
    """Build URLs with each param set to 1. Uses ID_PARAM_WORDLIST if param_names not given."""
    names = param_names or ID_PARAM_WORDLIST
    parsed = urlparse(base_url)
    path = parsed.path or "/"
    existing = {}
    if parsed.query:
        from urllib.parse import parse_qs
        existing = parse_qs(parsed.query, keep_blank_values=True)
    out: list[str] = []
    for param in names:
        if param in existing:
            continue
        new_params = {**existing, param: ["1"]}
        qs = urlencode(new_params, doseq=True)
        url = urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, qs, parsed.fragment))
        out.append(url)
    return out


async def fuzz_parameters_async(
    base_url: str,
    param_names: list[str] | None = None,
    concurrency: int = PARAM_FUZZ_CONCURRENCY,
) -> list[tuple[str, int, str]]:
    """
    Try common parameters (e.g. user_id=1, account_id=1) on the endpoint.
    Returns list of (url, status_code, body_preview) for analysis.
    """
    urls = _build_param_urls(base_url, param_names)
    if not urls:
        return []
    opts = get_http_client_options(None)
    semaphore = asyncio.Semaphore(concurrency)
    results: list[tuple[str, int, str]] = []

    async def fetch_one(u: str) -> tuple[str, int, str]:
        async with semaphore:
            try:
                async with httpx.AsyncClient(
                    follow_redirects=True,
                    timeout=REQUEST_TIMEOUT_SECONDS,
                    headers=opts["headers"],
                    cookies=opts.get("cookies"),
                ) as client:
                    resp = await client.get(u)
                    body = (resp.text or "")[:2000]
                    return (u, resp.status_code, body)
            except Exception as e:
                logger.debug("Param fuzz failed %s: %s", u, e)
                return (u, 0, str(e))

    out = await asyncio.gather(*[fetch_one(u) for u in urls], return_exceptions=True)
    for r in out:
        if isinstance(r, Exception):
            continue
        results.append(r)
    return results
