"""LLM client for analyzing request/response pairs (OpenAI or Anthropic)."""

import json
from typing import Any

from ai_security_agent.config import (
    ANTHROPIC_API_KEY,
    LLM_MODEL_ANTHROPIC,
    LLM_MODEL_OPENAI,
    LLM_PROVIDER,
    OPENAI_API_KEY,
)
from ai_security_agent.models.scan_result import VulnCandidate
from ai_security_agent.utils.logger import get_logger

logger = get_logger(__name__)

SYSTEM_PROMPT = """You are a security analyst assistant. You analyze HTTP request/response pairs from authorized security testing (educational or bug bounty in scope).

For each pair, evaluate ONLY for:
1. Potential IDOR (Insecure Direct Object Reference) - e.g. access to other users' resources by changing IDs
2. Access control weaknesses - e.g. missing auth, privilege escalation
3. Sensitive data exposure - e.g. PII, tokens, internal details in response

Respond with a JSON object only, no markdown:
{
  "has_concern": true/false,
  "candidates": [
    {
      "type": "idor" | "access_control" | "sensitive_data",
      "severity": "low" | "medium" | "high",
      "description": "brief description",
      "evidence": "relevant quote or detail"
    }
  ]
}
If no concerns, use "has_concern": false and "candidates": []."""


def _build_user_prompt(method: str, url: str, status: int, req_headers: dict[str, str], resp_headers: dict[str, str], body_preview: str) -> str:
    return f"""Request: {method} {url}
Response status: {status}
Request headers (relevant): {json.dumps(req_headers, indent=2)[:1500]}
Response headers (relevant): {json.dumps(resp_headers, indent=2)[:1500]}
Response body (preview): {body_preview[:2000]}

Analyze and return the JSON only."""


def _parse_llm_response(text: str, endpoint_url: str, method: str) -> list[VulnCandidate]:
    """Parse LLM JSON response into VulnCandidate list."""
    candidates: list[VulnCandidate] = []
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
    try:
        data = json.loads(text)
        for c in data.get("candidates", []):
            candidates.append(
                VulnCandidate(
                    type=c.get("type", "unknown"),
                    severity=c.get("severity", "low"),
                    endpoint_url=endpoint_url,
                    method=method,
                    description=c.get("description", ""),
                    evidence=c.get("evidence", ""),
                )
            )
    except json.JSONDecodeError as e:
        logger.warning("LLM response not valid JSON: %s", e)
    return candidates


def analyze_with_llm(
    method: str,
    url: str,
    status_code: int,
    request_headers: dict[str, str],
    response_headers: dict[str, str],
    response_body_preview: str,
) -> list[VulnCandidate]:
    """
    Send request/response summary to LLM and return structured vuln candidates.
    Returns empty list if LLM is not configured or on error.
    """
    if LLM_PROVIDER == "openai" and OPENAI_API_KEY:
        return _call_openai(
            method, url, status_code,
            request_headers, response_headers, response_body_preview,
        )
    if LLM_PROVIDER == "anthropic" and ANTHROPIC_API_KEY:
        return _call_anthropic(
            method, url, status_code,
            request_headers, response_headers, response_body_preview,
        )
    logger.debug("LLM not configured (provider=%s), skipping analysis", LLM_PROVIDER)
    return []


def _call_openai(
    method: str,
    url: str,
    status_code: int,
    req_h: dict[str, str],
    resp_h: dict[str, str],
    body_preview: str,
) -> list[VulnCandidate]:
    try:
        from openai import OpenAI
        client = OpenAI(api_key=OPENAI_API_KEY)
        user = _build_user_prompt(method, url, status_code, req_h, resp_h, body_preview)
        resp = client.chat.completions.create(
            model=LLM_MODEL_OPENAI,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user},
            ],
            temperature=0.2,
        )
        content = (resp.choices[0].message.content or "").strip()
        return _parse_llm_response(content, url, method)
    except Exception as e:
        logger.warning("OpenAI analysis failed: %s", e)
        return []


def _call_anthropic(
    method: str,
    url: str,
    status_code: int,
    req_h: dict[str, str],
    resp_h: dict[str, str],
    body_preview: str,
) -> list[VulnCandidate]:
    try:
        from anthropic import Anthropic
        client = Anthropic(api_key=ANTHROPIC_API_KEY)
        user = _build_user_prompt(method, url, status_code, req_h, resp_h, body_preview)
        resp = client.messages.create(
            model=LLM_MODEL_ANTHROPIC,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user}],
        )
        content = (resp.content[0].text if resp.content else "").strip()
        return _parse_llm_response(content, url, method)
    except Exception as e:
        logger.warning("Anthropic analysis failed: %s", e)
        return []
