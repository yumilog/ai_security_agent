"""Report agent: build ScanResult and generate report file."""

from pathlib import Path

from ai_security_agent.models.endpoint import Endpoint
from ai_security_agent.models.scan_result import (
    ScanResult,
    SuspiciousResponse,
    VulnCandidate,
)
from ai_security_agent.reports.report_generator import generate_markdown_report
from ai_security_agent.utils.logger import get_logger

logger = get_logger(__name__)


def build_scan_result(
    target_base_url: str,
    discovered_urls: list[str],
    endpoints: list[Endpoint],
    suspicious_responses: list[SuspiciousResponse],
    vuln_candidates: list[VulnCandidate],
    meta: dict | None = None,
) -> ScanResult:
    """Assemble full scan result for reporting."""
    endpoint_dicts = [
        {
            "url": ep.url,
            "method": ep.method.value,
            "source": ep.source,
            "path_pattern": ep.path_pattern,
        }
        for ep in endpoints
    ]
    return ScanResult(
        target_base_url=target_base_url,
        discovered_urls=discovered_urls,
        endpoints=endpoint_dicts,
        suspicious_responses=suspicious_responses,
        vuln_candidates=vuln_candidates,
        meta=meta or {},
    )


def run_report_agent(
    result: ScanResult,
    output_path: Path | None = None,
) -> Path:
    """Generate markdown report from ScanResult. Returns path to file."""
    logger.info("Generating report for %s", result.target_base_url)
    return generate_markdown_report(result, output_path)
