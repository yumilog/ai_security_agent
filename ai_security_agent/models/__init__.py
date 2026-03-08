"""Data models for the security agent."""

from ai_security_agent.models.endpoint import Endpoint, EndpointMethod
from ai_security_agent.models.scan_result import (
    ScanResult,
    SuspiciousResponse,
    VulnCandidate,
)

__all__ = [
    "Endpoint",
    "EndpointMethod",
    "ScanResult",
    "SuspiciousResponse",
    "VulnCandidate",
]
