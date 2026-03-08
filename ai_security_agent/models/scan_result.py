"""Scan and vulnerability result models."""

from typing import Any

from pydantic import BaseModel, Field


class SuspiciousResponse(BaseModel):
    """A response that may warrant further review."""

    url: str
    method: str
    status_code: int
    reason: str = Field(description="Why this response was flagged")
    request_headers: dict[str, str] = Field(default_factory=dict)
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body_preview: str = Field(default="", max_length=2000)


class VulnCandidate(BaseModel):
    """LLM or rule-based vulnerability candidate."""

    type: str = Field(description="e.g. idor, access_control, sensitive_data")
    severity: str = Field(description="e.g. low, medium, high")
    endpoint_url: str
    method: str
    description: str
    evidence: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Aggregated result of a security scan."""

    target_base_url: str
    discovered_urls: list[str] = Field(default_factory=list)
    endpoints: list[dict[str, Any]] = Field(default_factory=list)
    suspicious_responses: list[SuspiciousResponse] = Field(default_factory=list)
    vuln_candidates: list[VulnCandidate] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)
