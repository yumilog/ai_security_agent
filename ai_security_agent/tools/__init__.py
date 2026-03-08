"""Tools for crawling, HTTP, and JS parsing."""

from ai_security_agent.tools.crawler import crawl_site, crawl_site_async, normalize_url_for_crawl
from ai_security_agent.tools.http_client import (
    fetch_url,
    fetch_url_async,
    request_with_headers,
    request_with_headers_async,
)
from ai_security_agent.tools.js_parser import extract_api_calls_from_js

__all__ = [
    "crawl_site",
    "crawl_site_async",
    "normalize_url_for_crawl",
    "fetch_url",
    "fetch_url_async",
    "request_with_headers",
    "request_with_headers_async",
    "extract_api_calls_from_js",
]
