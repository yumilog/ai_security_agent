"""API structure detection: extract field names from JSON responses for parameter fuzzing."""

import json
import re
from typing import Any

from ai_security_agent.utils.logger import get_logger

logger = get_logger(__name__)

# Common param names to add when we see similar keys (e.g. "id" -> try user_id, account_id)
KEY_TO_PARAMS: dict[str, list[str]] = {
    "id": ["user_id", "account_id", "owner_id", "customer_id", "profile_id"],
    "user": ["user_id", "uid"],
    "email": ["email", "user_id"],
}


def extract_json_keys(body: str) -> list[str]:
    """
    Parse JSON body and return a flat list of field names (keys).
    Nested keys are returned as top-level only for param fuzzing.
    """
    keys: set[str] = set()
    body = (body or "").strip()
    if not body or not body.startswith("{"):
        return []

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        # Try to extract key-like strings with regex
        for m in re.finditer(r'"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:', body):
            keys.add(m.group(1))
        return sorted(keys)

    def _collect(obj: Any, prefix: str = "") -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(k, str) and k.isidentifier():
                    keys.add(k)
                _collect(v, f"{prefix}.{k}" if prefix else k)
        elif isinstance(obj, list) and obj:
            _collect(obj[0], prefix)

    _collect(data)
    return sorted(keys)


def suggest_parameters_from_json(body: str) -> list[str]:
    """
    Extract JSON keys and suggest parameter names for fuzzing.
    Returns deduplicated list: extracted keys + common variants (e.g. id -> user_id, account_id).
    """
    keys = extract_json_keys(body)
    out: set[str] = set(keys)
    for k in keys:
        out.add(k)
        for variant in KEY_TO_PARAMS.get(k, []):
            out.add(variant)
    # Add common ID-like params if we saw any id-like key
    if any("id" in k.lower() or k.lower() == "id" for k in keys):
        out.update(["user_id", "account_id", "owner_id", "customer_id", "id"])
    return sorted(out)
