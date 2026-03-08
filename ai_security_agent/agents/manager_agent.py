"""Manager agent: orchestrate Recon -> Endpoint -> VulnTest -> Report (async)."""

from pathlib import Path
from urllib.parse import urlparse

from ai_security_agent.agents.endpoint_agent import run_endpoint_discovery
from ai_security_agent.agents.recon_agent import fetch_all_js_async, run_recon_async
from ai_security_agent.agents.report_agent import build_scan_result, run_report_agent
from ai_security_agent.agents.vuln_test_agent import run_vuln_tests_async
from ai_security_agent.config import MAX_ENDPOINTS_TO_TEST
from ai_security_agent.models.scan_result import ScanResult
from ai_security_agent.utils.logger import get_logger

logger = get_logger(__name__)


async def run_scan_async(
    target_url: str,
    use_llm: bool = True,
    report_path: str | None = None,
) -> ScanResult:
    """
    Execute full pipeline asynchronously:
    ReconAgent -> EndpointAgent -> VulnTestAgent -> ReportAgent.
    Returns the final ScanResult.
    """
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    if not base_url.startswith("http"):
        base_url = "https://" + base_url

    # 1. Recon (async crawl)
    page_urls, js_urls = await run_recon_async(target_url)
    discovered_urls = list(page_urls)
    js_contents = await fetch_all_js_async(js_urls)

    # 2. Endpoint discovery (CPU-bound, sync is fine)
    endpoints = run_endpoint_discovery(page_urls, js_contents, base_url)

    # 3. Vuln tests (async concurrent requests + optional LLM)
    suspicious, vuln_candidates = await run_vuln_tests_async(
        endpoints,
        target_base_url=base_url,
        max_endpoints=MAX_ENDPOINTS_TO_TEST,
        use_llm=use_llm,
    )

    # 4. Build result and report (sync I/O)
    result = build_scan_result(
        target_base_url=base_url,
        discovered_urls=discovered_urls,
        endpoints=endpoints,
        suspicious_responses=suspicious,
        vuln_candidates=vuln_candidates,
        meta={
            "pages_crawled": len(page_urls),
            "js_files_analyzed": len(js_contents),
            "endpoints_found": len(endpoints),
        },
    )
    out = run_report_agent(result, Path(report_path) if report_path else None)
    result.meta["report_path"] = str(out)
    logger.info("Scan complete. Report: %s", out)
    return result


def run_scan(
    target_url: str,
    use_llm: bool = True,
    report_path: str | None = None,
) -> ScanResult:
    """Sync wrapper: runs run_scan_async via asyncio.run."""
    import asyncio
    return asyncio.run(run_scan_async(target_url, use_llm, report_path))
