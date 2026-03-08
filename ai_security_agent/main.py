#!/usr/bin/env python3
"""
CLI entry point for the AI Security Agent (async pipeline).

Run from repo root:
    python -m ai_security_agent.main --target https://example.com
Or:
    python main.py --target https://example.com
"""

import argparse
import asyncio
import sys
from pathlib import Path

from ai_security_agent.agents.manager_agent import run_scan_async
from ai_security_agent.utils.logger import get_logger

logger = get_logger(__name__)


async def main_async() -> int:
    parser = argparse.ArgumentParser(
        description="AI-assisted web security testing agent (educational / authorized use only).",
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target URL to scan (e.g. https://example.com)",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM analysis of responses",
    )
    parser.add_argument(
        "--report",
        default=None,
        help="Output path for scan report (default: reports/scan_report.md)",
    )
    args = parser.parse_args()

    target = args.target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    logger.info("Starting scan for target: %s", target)
    try:
        result = await run_scan_async(
            target_url=target,
            use_llm=not args.no_llm,
            report_path=args.report,
        )
        logger.info(
            "Scan finished. Endpoints: %d, Suspicious: %d, Candidates: %d",
            len(result.endpoints),
            len(result.suspicious_responses),
            len(result.vuln_candidates),
        )
        if result.meta.get("report_path"):
            print(f"Report saved to: {result.meta['report_path']}")
        return 0
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        return 130
    except Exception as e:
        logger.exception("Scan failed: %s", e)
        return 1


def main() -> int:
    return asyncio.run(main_async())


if __name__ == "__main__":
    sys.exit(main())
