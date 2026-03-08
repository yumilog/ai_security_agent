"""Endpoint discovery agent: analyze URLs and JS to find API endpoints."""

import re
from urllib.parse import urljoin, urlparse

from ai_security_agent.models.endpoint import Endpoint, EndpointMethod
from ai_security_agent.tools.js_parser import extract_api_calls_from_js, get_path_pattern
from ai_security_agent.utils.logger import get_logger

logger = get_logger(__name__)

# URL path patterns that suggest API endpoints
API_PATH_RE = re.compile(
    r"^/(api|v1|v2|v3|graphql|rest|user|users|order|orders|admin|auth)(/|$)",
    re.I,
)
ID_SEGMENT_RE = re.compile(r"/(\d+|[0-9a-f-]{36})", re.I)


def _url_to_pattern(path: str) -> str:
    """Replace ID-like segments with {id}."""
    return ID_SEGMENT_RE.sub("/{id}", path)


def _is_api_like_path(path: str) -> bool:
    """True if path looks like an API path."""
    return bool(API_PATH_RE.match(path))


def discover_from_urls(page_urls: list[str], base_url: str) -> list[Endpoint]:
    """Extract API-like endpoints from crawled page URLs."""
    endpoints: list[Endpoint] = []
    base_parsed = urlparse(base_url)
    base_origin = f"{base_parsed.scheme}://{base_parsed.netloc}"

    for url in page_urls:
        parsed = urlparse(url)
        path = parsed.path or "/"
        if not _is_api_like_path(path):
            continue
        pattern = _url_to_pattern(path)
        ep = Endpoint(
            url=url,
            method=EndpointMethod.GET,
            source="crawl",
            path_pattern=pattern,
        )
        if ep not in endpoints:
            endpoints.append(ep)

    return endpoints


def discover_from_js(js_content: str, base_url: str) -> list[Endpoint]:
    """Extract endpoints from JavaScript content."""
    endpoints: list[Endpoint] = []
    base_parsed = urlparse(base_url)
    base_origin = f"{base_parsed.scheme}://{base_parsed.netloc}"

    for url_or_path, method_str in extract_api_calls_from_js(js_content, base_url):
        if not url_or_path.startswith("http"):
            url_or_path = urljoin(base_origin, url_or_path)
        path = urlparse(url_or_path).path or "/"
        if not _is_api_like_path(path):
            continue
        try:
            method = EndpointMethod(method_str.upper())
        except ValueError:
            method = EndpointMethod.GET
        pattern = get_path_pattern(path)
        ep = Endpoint(
            url=url_or_path,
            method=method,
            source="js_parse",
            path_pattern=pattern,
        )
        if ep not in endpoints:
            endpoints.append(ep)

    return endpoints


def run_endpoint_discovery(
    page_urls: list[str],
    js_contents: list[tuple[str, str]],
    base_url: str,
) -> list[Endpoint]:
    """
    Combine crawl URLs and JS-derived URLs into a deduplicated endpoint list.
    js_contents: list of (js_url, content).
    """
    logger.info("Endpoint discovery: %d pages, %d JS files", len(page_urls), len(js_contents))
    all_endpoints: dict[tuple[str, str], Endpoint] = {}

    for ep in discover_from_urls(page_urls, base_url):
        key = (ep.url, ep.method.value)
        all_endpoints[key] = ep

    for _js_url, content in js_contents:
        for ep in discover_from_js(content, base_url):
            key = (ep.url, ep.method.value)
            if key not in all_endpoints:
                all_endpoints[key] = ep

    result = list(all_endpoints.values())
    logger.info("Discovered %d unique endpoints", len(result))
    return result
