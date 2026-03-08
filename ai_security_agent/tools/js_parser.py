"""Extract API-like URLs from JavaScript (fetch, axios, URL strings)."""

import re
from urllib.parse import urljoin, urlparse

from ai_security_agent.utils.logger import get_logger

logger = get_logger(__name__)

# Patterns for API-like paths in JS (conservative)
API_PATH_PATTERNS = [
    re.compile(r"['\"]/(api|v1|v2|graphql|rest)/[^'\"]*['\"]", re.I),
    re.compile(r"['\"]/(user|users|order|orders|admin|auth)/[^'\"]*['\"]", re.I),
    re.compile(r"`/(api|v1|user|order)/[^`]*`"),
    re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'axios\.(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'\.get\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'["\'](https?://[^"\']+/api/[^"\']+)["\']', re.I),
]
# Path segments that look like IDs (numeric or UUID-like)
ID_LIKE = re.compile(r"/(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", re.I)


def _normalize_path_to_pattern(path: str) -> str:
    """Replace ID-like segments with {id} for pattern."""
    return ID_LIKE.sub("/{id}", path)


def extract_api_calls_from_js(js_content: str, base_url: str = "") -> list[tuple[str, str]]:
    """
    Parse JS content and return list of (url_or_path, method).
    URLs are absolute when base_url is provided; otherwise paths may be relative.
    """
    found: list[tuple[str, str]] = []
    seen: set[str] = set()

    for pattern in API_PATH_PATTERNS:
        for m in pattern.finditer(js_content):
            if m.lastindex and m.lastindex >= 1:
                url_or_path = (m.group(2) if m.lastindex >= 2 else m.group(1)).strip()
            else:
                url_or_path = m.group(0)
                for sep in ["'", '"', "`"]:
                    if sep in url_or_path:
                        parts = url_or_path.split(sep)
                        if len(parts) >= 2:
                            url_or_path = parts[1]
                            break
            if not url_or_path or url_or_path in seen:
                continue
            seen.add(url_or_path)
            method = "GET"
            if "post" in pattern.pattern.lower():
                method = "POST"
            elif "put" in pattern.pattern.lower():
                method = "PUT"
            elif "patch" in pattern.pattern.lower():
                method = "PATCH"
            elif "delete" in pattern.pattern.lower():
                method = "DELETE"
            if base_url and not url_or_path.startswith("http"):
                url_or_path = urljoin(base_url, url_or_path)
            found.append((url_or_path, method))

    # Also extract paths that look like /api/... or /v1/...
    for m in re.finditer(r"['\"]?(/(?:api|v1|v2|user|order|admin|auth)[^'\"]*)['\"]?", js_content):
        path = m.group(1).strip() if m.lastindex else m.group(0).strip()
        path = path.strip("'\"").split("?")[0].split(",")[0].strip()
        if path and len(path) > 3 and path not in seen:
            seen.add(path)
            if base_url:
                path = urljoin(base_url, path)
            found.append((path, "GET"))

    logger.debug("Extracted %d API-like URLs from JS (base=%s)", len(found), base_url or "none")
    return found


def get_path_pattern(path: str) -> str:
    """Return a normalized path pattern with {id} for ID-like segments."""
    parsed = urlparse(path) if path.startswith("http") else None
    p = parsed.path if parsed else path
    if "?" in p:
        p = p.split("?")[0]
    return _normalize_path_to_pattern(p)
