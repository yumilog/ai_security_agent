"""Extract API endpoints from JavaScript content (strings, fetch, axios)."""

import re
from urllib.parse import urljoin, urlparse

from ai_security_agent.utils.logger import get_logger

logger = get_logger(__name__)

# Path prefixes to detect (requirements: /api/*, /v1/*, /v2/*, /user/*, /admin/*, /internal/*)
JS_ENDPOINT_PREFIXES = ("api", "v1", "v2", "user", "admin", "internal")
JS_ENDPOINT_PREFIXES_EXTRA = ("v3", "graphql", "rest", "users", "orders", "auth")

# Regex: extract path inside single/double/template quotes (path starts with / and one of the prefixes)
# Matches: "/api/...", '/v1/...', "/user/123", `/api/order`, etc.
_PATH_IN_STRING = re.compile(
    r"['\"`](/("
    + "|".join(re.escape(p) for p in JS_ENDPOINT_PREFIXES + JS_ENDPOINT_PREFIXES_EXTRA)
    + r")/[^'\"`\s]*?)['\"`]",
    re.I,
)
# Regex: full URL in string (https?://.../api/...)
_FULL_URL = re.compile(
    r"['\"`](https?://[^'\"`\s]+/(?:"
    + "|".join(re.escape(p) for p in JS_ENDPOINT_PREFIXES + JS_ENDPOINT_PREFIXES_EXTRA)
    + r")/[^'\"`\s]*)['\"`]",
    re.I,
)
# fetch("...") or fetch('...')
_FETCH_URL = re.compile(r"fetch\s*\(\s*['\"`]([^'\"`]+)['\"`]", re.I)
# axios.get("...") / axios.post("...") etc.
_AXIOS_CALL = re.compile(
    r"axios\.(get|post|put|patch|delete)\s*\(\s*['\"`]([^'\"`]+)['\"`]",
    re.I,
)
# .get("...") / .post("...") (e.g. $http.get)
_HTTP_METHOD = re.compile(
    r"\.(get|post|put|patch|delete)\s*\(\s*['\"`]([^'\"`]+)['\"`]",
    re.I,
)
# Path segments that look like IDs (for pattern normalization)
ID_LIKE = re.compile(r"/(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", re.I)


def _normalize_path_to_pattern(path: str) -> str:
    """Replace ID-like segments with {id}."""
    return ID_LIKE.sub("/{id}", path)


def _is_allowed_path(path: str) -> bool:
    """True if path starts with one of the configured API prefixes."""
    path = path.strip().split("?")[0]
    if not path.startswith("/"):
        return False
    segment = path.lstrip("/").split("/")[0].lower()
    return segment in (p.lower() for p in JS_ENDPOINT_PREFIXES + JS_ENDPOINT_PREFIXES_EXTRA)


def _extract_from_strings(js_content: str) -> list[str]:
    """Extract endpoint paths/URLs from string literals using regex."""
    found: list[str] = []
    seen: set[str] = set()

    for pattern in (_PATH_IN_STRING, _FULL_URL):
        for m in pattern.finditer(js_content):
            path_or_url = m.group(1).strip()
            if not path_or_url or path_or_url in seen:
                continue
            if path_or_url.startswith("http"):
                parsed = urlparse(path_or_url)
                path_or_url = parsed.path or "/"
            else:
                path_or_url = path_or_url.split("?")[0]
            if _is_allowed_path(path_or_url):
                seen.add(path_or_url)
                found.append(path_or_url)

    return found


def _extract_from_fetch_axios(js_content: str) -> list[tuple[str, str]]:
    """Extract (url_or_path, method) from fetch and axios calls."""
    found: list[tuple[str, str]] = []
    seen: set[str] = set()

    for pattern, default_method in [
        (_FETCH_URL, "GET"),
        (_AXIOS_CALL, None),  # method from group 1
        (_HTTP_METHOD, None),
    ]:
        for m in pattern.finditer(js_content):
            if default_method:
                url_or_path = m.group(1).strip()
                method = default_method
            else:
                method = (m.group(1) or "get").upper()
                url_or_path = m.group(2).strip()
            url_or_path = url_or_path.split("?")[0]
            if not url_or_path or url_or_path in seen:
                continue
            if url_or_path.startswith("http"):
                parsed = urlparse(url_or_path)
                path = parsed.path or "/"
            else:
                path = url_or_path if url_or_path.startswith("/") else "/" + url_or_path
            if _is_allowed_path(path):
                seen.add(url_or_path)
                found.append((url_or_path, method))

    return found


def _normalize_key(url_or_path: str, base_url: str) -> str:
    """Normalize to absolute URL for dedup when base_url is set."""
    if base_url and not url_or_path.startswith("http"):
        return urljoin(base_url, url_or_path)
    return url_or_path.rstrip("/") or url_or_path


def extract_api_calls_from_js(js_content: str, base_url: str = "") -> list[tuple[str, str]]:
    """
    Parse JavaScript content and return list of (url_or_path, method).
    Detects /api/*, /v1/*, /v2/*, /user/*, /admin/*, /internal/* (and related) via regex.
    Deduplicates by final URL. Uses base_url to build absolute URLs when given.
    """
    found: list[tuple[str, str]] = []
    seen: set[str] = set()

    # From string literals (path-only)
    for path in _extract_from_strings(js_content):
        url = _normalize_key(path, base_url)
        if url in seen:
            continue
        seen.add(url)
        found.append((url, "GET"))

    # From fetch/axios (path or URL + method)
    for url_or_path, method in _extract_from_fetch_axios(js_content):
        url = _normalize_key(url_or_path, base_url)
        if url in seen:
            continue
        seen.add(url)
        found.append((url, method))

    logger.debug("Extracted %d API-like URLs from JS (base=%s)", len(found), base_url or "none")
    return found


def get_path_pattern(path: str) -> str:
    """Return a normalized path pattern with {id} for ID-like segments."""
    parsed = urlparse(path) if path.startswith("http") else None
    p = parsed.path if parsed else path
    if "?" in p:
        p = p.split("?")[0]
    return _normalize_path_to_pattern(p)
