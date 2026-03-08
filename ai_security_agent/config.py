"""Configuration for the AI Security Agent."""

import os
from pathlib import Path

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

# Parameter wordlist: append to endpoints for IDOR testing (e.g. /api/order?user_id=1)
ID_PARAM_WORDLIST = [
    "user_id",
    "account_id",
    "uid",
    "profile_id",
    "owner_id",
    "customer_id",
    "id",
]

# Response similarity: treat as "same structure" if length diff within this ratio (0.15 = 15%)
RESPONSE_SIMILARITY_TOLERANCE_RATIO = 0.15
# Min number of responses with similar length to flag as IDOR candidate
RESPONSE_SIMILARITY_MIN_COUNT = 2

# Async concurrency (limit concurrent requests per phase)
CRAWL_CONCURRENCY = 10
FETCH_JS_CONCURRENCY = 15
VULN_TEST_CONCURRENCY = 10
