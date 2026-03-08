# AI Security Agent

Minimal **AI-assisted web security testing agent** for educational use and authorized testing (e.g. local test apps or in-scope bug bounty programs). It does **not** perform aggressive or illegal scanning; it demonstrates safe automated analysis and candidate vulnerability detection.

## Features

- **Async pipeline**: Crawling and HTTP tests use `asyncio` + `httpx.AsyncClient` for concurrent requests and faster scans.
- **Recon**: Crawl target site (concurrent per depth level), collect links and JavaScript URLs (JS fetched in parallel).
- **Endpoint discovery**: Detect API-like paths (`/api/*`, `/v1/*`, `/user/{id}`) from URLs and JS.
- **Safe vuln tests**: Numeric ID variation, concurrent request testing; store responses for analysis.
- **LLM analysis** (optional): Send request/response pairs to an LLM for IDOR, access control, sensitive data evaluation.
- **Report**: Generate `scan_report.md` with target, endpoints, suspicious responses, and vulnerability candidates.

Concurrency limits (in `config.py`): `CRAWL_CONCURRENCY`, `FETCH_JS_CONCURRENCY`, `VULN_TEST_CONCURRENCY`.

## Requirements

- Python 3.11+
- See `requirements.txt` for dependencies

## Installation

```bash
cd /path/to/ai-security-agent
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env and add OPENAI_API_KEY or ANTHROPIC_API_KEY if you want LLM analysis
```

## Usage

```bash
# From repo root
python main.py --target https://example.com
```

Options:

- `--target URL` (required): Base URL to scan
- `--no-llm`: Disable LLM analysis (crawl + endpoint + safe tests only)
- `--report PATH`: Custom report path (default: `reports/scan_report.md`)

Example run:

```bash
python main.py --target https://httpbin.org --no-llm
```

Output: crawl and endpoint discovery run; report is written to `reports/scan_report.md`.

## Project structure

```
ai_security_agent/
  main.py              # CLI entry (or use root main.py)
  config.py            # Settings, env vars
  agents/
    manager_agent.py   # Orchestrator
    recon_agent.py     # Crawl, collect links/JS
    endpoint_agent.py  # Discover API endpoints
    vuln_test_agent.py # Safe mutations, LLM analysis
    report_agent.py    # Build result, generate report
  tools/
    crawler.py         # Same-origin crawler
    http_client.py     # HTTP with safe defaults
    js_parser.py       # Extract API calls from JS
  llm/
    llm_client.py      # OpenAI / Anthropic analysis
  models/
    endpoint.py        # Endpoint model
    scan_result.py     # ScanResult, VulnCandidate, etc.
  reports/
    report_generator.py
  utils/
    logger.py
```

## Extending the system

- **New recon sources**: Add functions in `recon_agent` that return URLs; feed them into `run_endpoint_discovery`.
- **New endpoint patterns**: Extend `API_PATH_RE` and patterns in `tools/js_parser.py`; add logic in `endpoint_agent`.
- **New test types**: In `vuln_test_agent`, add mutation strategies (e.g. query param fuzzing) and append to `suspicious` / LLM input.
- **New LLM providers**: In `llm/llm_client.py`, add a branch in `analyze_with_llm` and a `_call_*` helper.
- **Report format**: Add a new writer in `reports/` (e.g. JSON, HTML) and call it from `report_agent`.

## Disclaimer

Use only on systems you are authorized to test. The authors are not responsible for misuse. This tool is for education and authorized security assessment only.
