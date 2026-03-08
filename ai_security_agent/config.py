"""Configuration for the AI Security Agent."""

import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv()

# Target & scope
DEFAULT_USER_AGENT = "AISecurityAgent/1.0 (Educational; Authorized Testing Only)"
MAX_CRAWL_DEPTH = 2
MAX_PAGES_PER_DOMAIN = 50
REQUEST_TIMEOUT_SECONDS = 15

# LLM (optional)
OPENAI_API_KEY: str | None = os.getenv("OPENAI_API_KEY")
ANTHROPIC_API_KEY: str | None = os.getenv("ANTHROPIC_API_KEY")
LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "openai").lower()
LLM_MODEL_OPENAI: str = os.getenv("LLM_MODEL_OPENAI", "gpt-4o-mini")
LLM_MODEL_ANTHROPIC: str = os.getenv("LLM_MODEL_ANTHROPIC", "claude-3-haiku-20240307")

# Output
REPORT_DIR: Path = Path(os.getenv("REPORT_DIR", "reports"))
REPORT_DIR.mkdir(parents=True, exist_ok=True)

# Safe testing limits
MAX_ENDPOINTS_TO_TEST = 20
MAX_VARIATIONS_PER_ENDPOINT = 5
MAX_QUERY_PARAM_VARIATIONS = 5

# Query parameter mutation: try these values for ID-like params (e.g. ?id=1, ?id=124)
QUERY_PARAM_MUTATION_VALUES = [1, 2, 124, 125, 126]

# Parameter discovery / parameter fuzzing: try these param names on endpoints (e.g. /api/order?user_id=1).
# Many IDORs are found by appending common param names; used in vuln_test_agent.
ID_PARAM_WORDLIST = [
    "user_id",
    "account_id",
    "uid",
    "profile_id",
    "owner_id",
    "customer_id",
    "id",
    "order_id",
    "document_id",
    "file_id",
]

# Response similarity: treat as "same structure" if length diff within this ratio (0.15 = 15%)
RESPONSE_SIMILARITY_TOLERANCE_RATIO = 0.15
# Min number of responses with similar length to flag as IDOR candidate
RESPONSE_SIMILARITY_MIN_COUNT = 2

# Async concurrency (limit concurrent requests per phase)
CRAWL_CONCURRENCY = 10
FETCH_JS_CONCURRENCY = 15
VULN_TEST_CONCURRENCY = 10

# Certificate Transparency (crt.sh) for subdomain discovery
CT_LOOKUP_ENABLED = os.getenv("CT_LOOKUP_ENABLED", "true").lower() in ("true", "1", "yes")
CT_CRTSH_TIMEOUT = float(os.getenv("CT_CRTSH_TIMEOUT", "30"))
CT_MAX_SUBDOMAINS = int(os.getenv("CT_MAX_SUBDOMAINS", "100"))  # cap seeds to avoid huge crawl

# --- Auth & session (from config.yaml or env) ---
# Default auth: applied to all requests when no profile specified
AUTH_COOKIES: dict[str, str] = {}
AUTH_JWT: str | None = None
AUTH_AUTHORIZATION_HEADER: str | None = None  # e.g. "Bearer xxx" or custom header value

# User-switching: list of named auth profiles (Account A, B, ...) for broken access control testing
AuthProfile = dict[str, Any]  # { "name": str, "cookie"?: dict, "jwt"?: str, "authorization"?: str }
AUTH_PROFILES: list[AuthProfile] = []

# Rate limit: max requests per second (0 = no limit)
RATE_LIMIT_REQ_PER_SEC: float = 0.0

# Scope: allowed domains (empty = use target origin only)
SCOPE_DOMAINS: list[str] = []

# Loaded config path (set after load_config_yaml)
CONFIG_PATH: Path | None = None


def _parse_auth_from_dict(auth: dict[str, Any]) -> tuple[dict[str, str], str | None, str | None]:
    """Extract (cookies, jwt, authorization) from auth dict."""
    cookies: dict[str, str] = {}
    if "cookie" in auth and isinstance(auth["cookie"], dict):
        cookies = {k: str(v) for k, v in auth["cookie"].items()}
    jwt_val = auth.get("jwt") and str(auth["jwt"]).strip() or None
    auth_header = auth.get("authorization") and str(auth["authorization"]).strip() or None
    return cookies, jwt_val, auth_header


def load_config_yaml(path: str | Path | None = None) -> dict[str, Any]:
    """
    Load config from YAML file. Merges into module-level AUTH_*, RATE_LIMIT, SCOPE.
    Returns the raw loaded dict. Call early (e.g. from main) so all agents use it.
    """
    global AUTH_COOKIES, AUTH_JWT, AUTH_AUTHORIZATION_HEADER
    global AUTH_PROFILES, RATE_LIMIT_REQ_PER_SEC, SCOPE_DOMAINS, CONFIG_PATH

    path = path or os.getenv("CONFIG_PATH") or Path.cwd() / "config.yaml"
    path = Path(path)
    if not path.is_file():
        return {}

    try:
        import yaml
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        return {}

    CONFIG_PATH = path

    if "auth" in data and isinstance(data["auth"], dict):
        auth = data["auth"]
        cookies, jwt_val, auth_header = _parse_auth_from_dict(auth)
        AUTH_COOKIES = cookies
        AUTH_JWT = jwt_val
        AUTH_AUTHORIZATION_HEADER = auth_header

        if "user_switching" in auth and isinstance(auth["user_switching"], list):
            AUTH_PROFILES = []
            for p in auth["user_switching"]:
                if isinstance(p, dict) and p.get("name"):
                    cookies_p, jwt_p, auth_p = _parse_auth_from_dict(p)
                    AUTH_PROFILES.append({
                        "name": str(p["name"]),
                        "cookie": cookies_p,
                        "jwt": jwt_p,
                        "authorization": auth_p,
                    })

    if "rate_limit" in data:
        try:
            RATE_LIMIT_REQ_PER_SEC = float(data["rate_limit"])
        except (TypeError, ValueError):
            pass

    if "scope" in data and isinstance(data["scope"], list):
        SCOPE_DOMAINS = [str(s).strip() for s in data["scope"] if s]

    return data


def get_http_client_options(profile: AuthProfile | None = None) -> dict[str, Any]:
    """
    Return headers and cookies for httpx client. All agents use this so auth is applied to every request.
    If profile is None, use default auth (AUTH_COOKIES, AUTH_JWT, AUTH_AUTHORIZATION_HEADER).
    If profile is given (e.g. for user switching), use that profile's cookie/jwt/authorization.
    """
    headers: dict[str, str] = {
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "text/html,application/json,application/xhtml+xml,*/*;q=0.9",
        "Accept-Language": "en-US,en;q=0.9",
    }
    cookies: dict[str, str] = {}

    if profile is None:
        cookies = dict(AUTH_COOKIES)
        if AUTH_JWT:
            headers["Authorization"] = f"Bearer {AUTH_JWT}"
        elif AUTH_AUTHORIZATION_HEADER:
            headers["Authorization"] = AUTH_AUTHORIZATION_HEADER
    else:
        cookies = dict(profile.get("cookie") or {})
        if profile.get("jwt"):
            headers["Authorization"] = f"Bearer {profile['jwt']}"
        elif profile.get("authorization"):
            headers["Authorization"] = profile["authorization"]

    if cookies:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

    return {"headers": headers, "cookies": cookies}
