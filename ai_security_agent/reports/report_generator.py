"""Generate structured security scan report (Markdown)."""

from pathlib import Path

from ai_security_agent.config import REPORT_DIR
from ai_security_agent.models.scan_result import ScanResult
from ai_security_agent.utils.logger import get_logger

logger = get_logger(__name__)


def generate_markdown_report(result: ScanResult, output_path: Path | None = None) -> Path:
    """
    Write a scan_report.md from ScanResult. Returns path to written file.
    """
    output_path = output_path or REPORT_DIR / "scan_report.md"
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    sections: list[str] = []

    # Header
    sections.append("# Security Scan Report\n")
    sections.append(f"**Target:** {result.target_base_url}\n")

    # Discovered URLs
    sections.append("## Discovered URLs\n")
    if result.discovered_urls:
        for u in result.discovered_urls[:100]:
            sections.append(f"- {u}\n")
        if len(result.discovered_urls) > 100:
            sections.append(f"- ... and {len(result.discovered_urls) - 100} more\n")
    else:
        sections.append("- (none)\n")

    # Endpoints
    sections.append("## Endpoints Discovered\n")
    if result.endpoints:
        for ep in result.endpoints:
            method = ep.get("method", "GET")
            url = ep.get("url", "")
            pattern = ep.get("path_pattern", "")
            source = ep.get("source", "")
            sections.append(f"- **{method}** `{url}`")
            if pattern:
                sections.append(f"  (pattern: `{pattern}`)")
            sections.append(f"  _source: {source}_\n")
    else:
        sections.append("- (none)\n")

    # Suspicious responses
    sections.append("## Suspicious Responses\n")
    if result.suspicious_responses:
        for s in result.suspicious_responses:
            sections.append(f"- **{s.method}** {s.url} → {s.status_code}")
            sections.append(f"  - Reason: {s.reason}\n")
    else:
        sections.append("- (none)\n")

    # Vulnerability candidates
    sections.append("## Possible Vulnerability Candidates\n")
    if result.vuln_candidates:
        for v in result.vuln_candidates:
            sections.append(f"- **[{v.severity.upper()}]** {v.type}")
            sections.append(f"  - Endpoint: {v.method} {v.endpoint_url}")
            sections.append(f"  - {v.description}")
            if v.evidence:
                sections.append(f"  - Evidence: {v.evidence[:500]}\n")
    else:
        sections.append("- (none)\n")

    # Meta
    if result.meta:
        sections.append("## Scan Meta\n")
        for k, v in result.meta.items():
            sections.append(f"- **{k}:** {v}\n")

    content = "".join(sections)
    output_path.write_text(content, encoding="utf-8")
    logger.info("Report written to %s", output_path)
    return output_path
