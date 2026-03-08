# AI Security Agent

Minimal **AI-assisted web security testing agent** for educational use and authorized testing (e.g. local test apps or in-scope bug bounty programs). It does **not** perform aggressive or illegal scanning; it demonstrates safe automated analysis and candidate vulnerability detection.

## Features

- **Async pipeline**: Crawling and HTTP tests use `asyncio` + `httpx.AsyncClient` for concurrent requests and faster scans.
- **Recon**: Crawl target site (concurrent per depth level), collect links and JavaScript URLs (JS fetched in parallel).
- **Endpoint discovery**: Detect API-like paths (`/api/*`, `/v1/*`, `/user/{id}`) from crawled URLs and from JavaScript (see below).
- **Safe vuln tests**: Path ID variation, query param mutation, parameter fuzzing, response similarity, user switching; store responses for analysis.
- **LLM analysis** (optional): Send request/response pairs to an LLM for IDOR, access control, sensitive data evaluation.
- **Report**: Generate `scan_report.md` with target, endpoints, suspicious responses, and vulnerability candidates.

Concurrency limits (in `config.py`): `CRAWL_CONCURRENCY`, `FETCH_JS_CONCURRENCY`, `VULN_TEST_CONCURRENCY`.

### Crawler & scope

- **URL normalization + dedup**: URLs are normalized by **path + query parameter names** (values ignored). e.g. `/product?id=1`, `/product?id=2`, `/product?id=3` are treated as one pattern and only one representative URL is crawled, avoiding explosion to thousands of URLs.
- **eTLD+1 scope** (via `tldextract`): Only URLs whose **registrable domain** matches the target are allowed. Subdomains of the target are included; other domains are blocked.
  - **Allowed** (target `https://example.com`): `example.com`, `api.example.com`, `cdn.example.com`, `mobile.example.com`, `admin.example.com`
  - **Blocked**: `evil-example.com`, `google.com`
- **Certificate Transparency (CT) logs**: Before crawling, the recon agent can query **crt.sh** for certificates issued for the target’s registrable domain and collect subdomain names from the logs. Those subdomains are added as **extra seed URLs** so they are included in the crawl (subject to eTLD+1 scope and the usual limits). Disable with `CT_LOOKUP_ENABLED=false`. Options: `CT_CRTSH_TIMEOUT`, `CT_MAX_SUBDOMAINS` (default 100).

### JavaScript endpoint discovery

- During crawl, all `<script src="...">` URLs are collected and each JavaScript file is **downloaded asynchronously** (concurrency limited by `FETCH_JS_CONCURRENCY`).
- JS content is parsed with **regex** to extract API-like paths from strings and from `fetch` / `axios` calls.
- **Detected patterns**: `/api/*`, `/v1/*`, `/v2/*`, `/user/*`, `/admin/*`, `/internal/*` (and `/v3`, `/graphql`, `/rest`, `/auth`, etc.).
- Endpoints are **deduplicated** by URL and passed to the endpoint agent so `vuln_test_agent` can test them.

### Vulnerability tests

- **Path ID variation**: e.g. `/api/user/123` → test 124, 125, … (safe numeric mutation).
- **Query parameter mutation**: e.g. `/api/user?id=123` → test `?id=124`, `?id=125`, `?id=1` (common IDOR vector).
- **Parameter discovery / parameter fuzzing**: Append common param names to endpoints (e.g. `/api/order` → `?user_id=1`, `?account_id=1`, `?customer_id=1`). Wordlist in `config.ID_PARAM_WORDLIST`.
- **Response similarity**: If multiple IDs return responses with similar body length (same structure, different data), flag as **IDOR candidate**.
- **User switching**: If `config.yaml` defines two auth profiles under `auth.user_switching`, the same URL is requested as Account A and Account B; different status or body length is reported as **broken access control** candidate.

### Session / auth

- Optional `config.yaml` to attach **cookie**, **JWT**, or **Authorization** header to every request. All agents use the same HTTP client, so auth is applied automatically. **User switching** (two auth profiles) is described under Vulnerability tests above.

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

- `--target URL`: Base URL to scan (required unless set in `--config`)
- `--config PATH`: Path to `config.yaml` (auth, rate_limit, scope, optional target)
- `--no-llm`: Disable LLM analysis (crawl + endpoint + safe tests only)
- `--report PATH`: Custom report path (default: `reports/scan_report.md`)

### config.yaml (optional)

Copy `config.yaml.example` to `config.yaml` and set:

- **target**: Default scan target
- **auth.cookie**: `{ name: value }` — sent on every request
- **auth.jwt**: Token string → sent as `Authorization: Bearer <token>`
- **auth.authorization**: Raw header value
- **auth.user_switching**: List of `{ name, cookie? }` (two accounts) for broken access control testing
- **rate_limit**: Max requests per second (e.g. `5`)
- **scope**: Allowed domains

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
    crawler.py         # Crawler (eTLD+1 scope, URL normalization dedup, extra_seed_urls)
    ct_logs.py         # Certificate Transparency (crt.sh) subdomain lookup
    http_client.py     # HTTP client (auth from config)
    js_parser.py       # Extract API endpoints from JS (regex)
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
