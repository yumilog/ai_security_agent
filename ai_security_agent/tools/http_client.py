"""HTTP client for safe requests (async primary, sync kept for compatibility)."""

from typing import Any

import httpx

from ai_security_agent.config import DEFAULT_USER_AGENT, REQUEST_TIMEOUT_SECONDS
from ai_security_agent.utils.logger import get_logger

logger = get_logger(__name__)

DEFAULT_HEADERS = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Accept": "text/html,application/json,application/xhtml+xml,*/*;q=0.9",
    "Accept-Language": "en-US,en;q=0.9",
}


async def fetch_url_async(
    client: httpx.AsyncClient,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """Fetch a URL using the given async client."""
    merged = {**DEFAULT_HEADERS, **(headers or {})}
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
) -> tuple[httpx.Response, dict[str, str]]:
    """Perform async request; return (response, request_headers_used)."""
    merged = {**DEFAULT_HEADERS, **(headers or {})}
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
    """Sync fetch (for backward compatibility or non-async callers)."""
    merged = {**DEFAULT_HEADERS, **(headers or {})}
    with httpx.Client(
        follow_redirects=True,
        timeout=timeout,
        headers=merged,
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
    """Sync request with headers (for backward compatibility)."""
    merged = {**DEFAULT_HEADERS, **(headers or {})}
    with httpx.Client(
        follow_redirects=True,
        timeout=timeout,
        headers=merged,
    ) as client:
        try:
            response = client.request(method, url, params=params)
            return response, dict(merged)
        except httpx.HTTPError as e:
            logger.warning("HTTP error for %s: %s", url, e)
            raise
