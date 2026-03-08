"""HTTP client for safe requests; applies auth from config to every request."""

import asyncio
import time
from typing import Any

import httpx

from ai_security_agent.config import (
    get_http_client_options,
    RATE_LIMIT_REQ_PER_SEC,
    REQUEST_TIMEOUT_SECONDS,
)
from ai_security_agent.utils.logger import get_logger

logger = get_logger(__name__)

# All agents use get_http_client_options() so auth is applied after config is loaded (no import-time cache)

# Rate limiter state (min interval between requests when RATE_LIMIT_REQ_PER_SEC > 0)
_rate_limit_last: float = 0.0
_rate_limit_lock = asyncio.Lock()


async def _rate_limit_acquire() -> None:
    if RATE_LIMIT_REQ_PER_SEC <= 0:
        return
    global _rate_limit_last
    async with _rate_limit_lock:
        now = time.monotonic()
        interval = 1.0 / RATE_LIMIT_REQ_PER_SEC
        elapsed = now - _rate_limit_last
        if elapsed < interval:
            await asyncio.sleep(interval - elapsed)
        _rate_limit_last = time.monotonic()


def _get_options(profile: Any = None) -> dict[str, Any]:
    """Get current request options (headers + cookies) from config; optionally for a profile."""
    return get_http_client_options(profile)


def get_default_headers() -> dict[str, str]:
    """Headers to use for all requests (includes auth from config)."""
    return dict(get_http_client_options(None)["headers"])


def get_default_cookies() -> dict[str, str]:
    """Cookies to use for all requests (from config.auth.cookie)."""
    return dict(get_http_client_options(None).get("cookies") or {})


async def fetch_url_async(
    client: httpx.AsyncClient,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """Fetch a URL using the given async client (client already has auth from config)."""
    opts = _get_options(None)
    merged = {**opts["headers"], **(headers or {})}
    await _rate_limit_acquire()
    try:
        response = await client.request(method, url, headers=merged)
        logger.debug("Fetched %s %s -> %s", method, url, response.status_code)
        return response
    except httpx.HTTPError as e:
        logger.warning("HTTP error for %s: %s", url, e)
        raise


async def request_with_headers_async(
    client: httpx.AsyncClient,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    profile: Any = None,
) -> tuple[httpx.Response, dict[str, str]]:
    """Perform async request; return (response, request_headers_used). Uses config auth unless profile given."""
    opts = _get_options(profile)
    merged = {**opts["headers"], **(headers or {})}
    await _rate_limit_acquire()
    try:
        response = await client.request(method, url, headers=merged, params=params)
        return response, dict(merged)
    except httpx.HTTPError as e:
        logger.warning("HTTP error for %s: %s", url, e)
        raise


def fetch_url(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout: float = REQUEST_TIMEOUT_SECONDS,
) -> httpx.Response:
    """Sync fetch (for backward compatibility). Applies config auth."""
    opts = get_http_client_options(None)
    merged = {**opts["headers"], **(headers or {})}
    with httpx.Client(
        follow_redirects=True,
        timeout=timeout,
        headers=merged,
        cookies=opts.get("cookies"),
    ) as client:
        try:
            response = client.request(method, url)
            logger.debug("Fetched %s %s -> %s", method, url, response.status_code)
            return response
        except httpx.HTTPError as e:
            logger.warning("HTTP error for %s: %s", url, e)
            raise


def request_with_headers(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    timeout: float = REQUEST_TIMEOUT_SECONDS,
) -> tuple[httpx.Response, dict[str, str]]:
    """Sync request with headers (for backward compatibility). Applies config auth."""
    opts = get_http_client_options(None)
    merged = {**opts["headers"], **(headers or {})}
    with httpx.Client(
        follow_redirects=True,
        timeout=timeout,
        headers=merged,
        cookies=opts.get("cookies"),
    ) as client:
        try:
            response = client.request(method, url, params=params)
            return response, dict(merged)
        except httpx.HTTPError as e:
            logger.warning("HTTP error for %s: %s", url, e)
            raise
