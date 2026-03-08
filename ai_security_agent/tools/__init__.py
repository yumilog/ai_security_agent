"""Tools for crawling, HTTP, JS parsing, subdomain/alive/parameter/endpoint fuzzing."""

from ai_security_agent.tools.alive_check import filter_live_urls_async
from ai_security_agent.tools.api_structure import extract_json_keys, suggest_parameters_from_json
from ai_security_agent.tools.crawler import crawl_site, crawl_site_async, normalize_url_for_crawl
from ai_security_agent.tools.ct_logs import fetch_subdomains_from_ct, fetch_subdomains_from_ct_async
from ai_security_agent.tools.endpoint_fuzzer import fuzz_endpoints_async
from ai_security_agent.tools.http_client import (
    fetch_url,
    fetch_url_async,
    request_with_headers,
    request_with_headers_async,
)
from ai_security_agent.tools.js_parser import extract_api_calls_from_js
from ai_security_agent.tools.parameter_fuzzer import fuzz_parameters_async
from ai_security_agent.tools.subdomain_discovery import discover_subdomains_async, get_registered_domain

__all__ = [
    "crawl_site",
    "crawl_site_async",
    "normalize_url_for_crawl",
    "fetch_subdomains_from_ct",
    "fetch_subdomains_from_ct_async",
    "discover_subdomains_async",
    "get_registered_domain",
    "filter_live_urls_async",
    "fuzz_endpoints_async",
    "fuzz_parameters_async",
    "extract_json_keys",
    "suggest_parameters_from_json",
    "fetch_url",
    "fetch_url_async",
    "request_with_headers",
    "request_with_headers_async",
    "extract_api_calls_from_js",
]
