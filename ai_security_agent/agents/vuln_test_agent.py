"""Vulnerability test agent: safe parameter mutation and response collection (async)."""

import asyncio
import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from ai_security_agent.config import (
    AUTH_PROFILES,
    get_http_client_options,
    ID_PARAM_WORDLIST,
    MAX_VARIATIONS_PER_ENDPOINT,
    MAX_QUERY_PARAM_VARIATIONS,
    QUERY_PARAM_MUTATION_VALUES,
    REQUEST_TIMEOUT_SECONDS,
    RESPONSE_SIMILARITY_MIN_COUNT,
    RESPONSE_SIMILARITY_TOLERANCE_RATIO,
    VULN_TEST_CONCURRENCY,
)
from ai_security_agent.llm.llm_client import analyze_with_llm
from ai_security_agent.models.endpoint import Endpoint, EndpointMethod
from ai_security_agent.models.scan_result import SuspiciousResponse, VulnCandidate
from ai_security_agent.tools.http_client import request_with_headers_async
from ai_security_agent.utils.logger import get_logger

logger = get_logger(__name__)

INTERESTING_STATUS = {200, 201, 403, 404}
BODY_PREVIEW_LEN = 1500


def _generate_id_variations(original_url: str, limit: int = MAX_VARIATIONS_PER_ENDPOINT) -> list[str]:
    """Generate safe numeric ID variations for URLs like /api/user/123."""
    variations: list[str] = []
    parts = urlparse(original_url)
    path = parts.path
    numbers = re.findall(r"\d+", path)
    if not numbers:
        return [original_url]
    first_num = numbers[0]
    for i in range(limit):
        new_num = int(first_num) + i if first_num.isdigit() else 123 + i
        new_path = path.replace(first_num, str(new_num), 1)
        new_url = f"{parts.scheme}://{parts.netloc}{new_path}"
        if parts.query:
            new_url += "?" + parts.query
        variations.append(new_url)
    return variations


def _generate_query_param_mutations(original_url: str) -> list[str]:
    """
    Mutate numeric query parameters (e.g. ?id=123 -> ?id=124, ?id=125, ?id=1).
    Common IDOR vector in bug bounties.
    """
    result: list[str] = []
    parsed = urlparse(original_url)
    if not parsed.query:
        return result
    try:
        params = parse_qs(parsed.query, keep_blank_values=True)
    except Exception:
        return result
    for key, values in list(params.items()):
        if not values:
            continue
        val = values[0]
        if not val or not str(val).strip().isdigit():
            continue
        for mut_val in QUERY_PARAM_MUTATION_VALUES[:MAX_QUERY_PARAM_VARIATIONS]:
            mut_str = str(mut_val)
            if mut_str == val:
                continue
            new_params = params.copy()
            new_params[key] = [mut_str]
            new_query = urlencode(new_params, doseq=True)
            new_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment,
            ))
            result.append(new_url)
    return result


def _generate_wordlist_param_urls(original_url: str) -> list[str]:
    """
    Append parameter wordlist to endpoint (e.g. /api/order -> ?user_id=1, ?account_id=1).
    """
    result: list[str] = []
    parsed = urlparse(original_url)
    base_path = parsed.path or "/"
    existing = parse_qs(parsed.query, keep_blank_values=True) if parsed.query else {}
    for param in ID_PARAM_WORDLIST:
        if param in existing:
            continue
        new_params = {**existing, param: ["1"]}
        new_query = urlencode(new_params, doseq=True)
        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            base_path,
            parsed.params,
            new_query,
            parsed.fragment,
        ))
        result.append(new_url)
    return result


def _endpoint_pattern_for_similarity(url: str) -> str:
    """
    Normalize URL to a pattern for grouping (path + param names; values replaced).
    E.g. /api/user?id=123 and /api/user?id=124 -> same pattern.
    """
    parsed = urlparse(url)
    path = parsed.path or "/"
    if not parsed.query:
        return path
    try:
        params = parse_qs(parsed.query, keep_blank_values=True)
    except Exception:
        return path
    keys = sorted(params.keys())
    if not keys:
        return path
    return path + "?" + "&".join(f"{k}=*" for k in keys)


def _detect_response_similarity(
    results: list[tuple[str, str, int, dict, dict, str]],
) -> list[VulnCandidate]:
    """
    Group responses by endpoint pattern; if multiple 200 responses have similar
    body length (same structure, different data), flag as IDOR candidate.
    """
    candidates: list[VulnCandidate] = []
    by_pattern: dict[str, list[tuple[str, str, int, int]]] = {}
    for url, method, status, _req_h, _resp_h, body in results:
        if status != 200:
            continue
        pattern = _endpoint_pattern_for_similarity(url)
        length = len(body)
        by_pattern.setdefault(pattern, []).append((url, method, status, length))

    for pattern, entries in by_pattern.items():
        if len(entries) < RESPONSE_SIMILARITY_MIN_COUNT:
            continue
        lengths = [e[3] for e in entries]
        min_len = min(lengths)
        max_len = max(lengths)
        if min_len == 0:
            continue
        ratio = (max_len - min_len) / min_len
        if ratio <= RESPONSE_SIMILARITY_TOLERANCE_RATIO:
            urls = [e[0] for e in entries]
            length_str = ", ".join(f"len={e[3]}" for e in entries)
            candidates.append(
                VulnCandidate(
                    type="idor",
                    severity="medium",
                    endpoint_url=urls[0],
                    method=entries[0][1],
                    description="Response similarity: same structure, different data (IDOR candidate). "
                    "Multiple IDs returned similar response length.",
                    evidence=f"Pattern: {pattern}. Response lengths: {length_str}",
                    extra={"pattern": pattern, "urls": urls, "lengths": lengths},
                )
            )
            logger.info("Response similarity IDOR candidate: %s (lengths %s)", pattern, lengths)
    return candidates


async def _collect_response_async(
    client: httpx.AsyncClient,
    url: str,
    method: str,
    profile: dict | None = None,
) -> tuple[int, dict[str, str], dict[str, str], str]:
    """Perform async request; return (status, req_headers, resp_headers, body_preview). Optionally use auth profile."""
    try:
        resp, req_headers = await request_with_headers_async(client, url, method, profile=profile)
        resp_headers = dict(resp.headers)
        body = resp.text[:BODY_PREVIEW_LEN] if resp.text else ""
        return resp.status_code, req_headers, resp_headers, body
    except Exception as e:
        logger.warning("Request failed %s %s: %s", method, url, e)
        return 0, {}, {}, str(e)


async def _run_user_switching_async(
    client: httpx.AsyncClient,
    tasks: list[tuple[str, str]],
) -> list[VulnCandidate]:
    """
    Request same URL with Account A and Account B; if response differs (status or body length),
    flag as broken access control candidate.
    """
    if len(AUTH_PROFILES) < 2:
        return []
    profile_a, profile_b = AUTH_PROFILES[0], AUTH_PROFILES[1]
    name_a = profile_a.get("name", "A")
    name_b = profile_b.get("name", "B")
    candidates: list[VulnCandidate] = []
    # Length diff ratio to consider "different" (e.g. 0.2 = 20%)
    length_diff_ratio = 0.2

    for url, method in tasks:
        try:
            status_a, _, _, body_a = await _collect_response_async(client, url, method, profile=profile_a)
            status_b, _, _, body_b = await _collect_response_async(client, url, method, profile=profile_b)
        except Exception as e:
            logger.debug("User switching request failed %s: %s", url, e)
            continue
        len_a, len_b = len(body_a), len(body_b)
        status_diff = status_a != status_b
        if len_a and len_b:
            length_ratio = abs(len_a - len_b) / max(len_a, len_b)
            length_diff = length_ratio > length_diff_ratio
        else:
            length_diff = len_a != len_b
        if status_diff or length_diff:
            evidence = f"{name_a}: {status_a} (len={len_a}); {name_b}: {status_b} (len={len_b})"
            candidates.append(
                VulnCandidate(
                    type="broken_access_control",
                    severity="high",
                    endpoint_url=url,
                    method=method,
                    description="User switching: different response for same URL (Account A vs B). Possible broken access control.",
                    evidence=evidence,
                    extra={"profile_a": name_a, "profile_b": name_b, "status_a": status_a, "status_b": status_b},
                )
            )
    return candidates


def _collect_response(url: str, method: str) -> tuple[int, dict[str, str], dict[str, str], str]:
    """Sync fallback for single request (backward compat)."""
    from ai_security_agent.tools.http_client import request_with_headers
    try:
        resp, req_headers = request_with_headers(url, method)
        resp_headers = dict(resp.headers)
        body = resp.text[:BODY_PREVIEW_LEN] if resp.text else ""
        return resp.status_code, req_headers, resp_headers, body
    except Exception as e:
        logger.warning("Request failed %s %s: %s", method, url, e)
        return 0, {}, {}, str(e)


async def run_vuln_tests_async(
    endpoints: list[Endpoint],
    target_base_url: str,
    max_endpoints: int = 20,
    use_llm: bool = True,
    concurrency: int = VULN_TEST_CONCURRENCY,
) -> tuple[list[SuspiciousResponse], list[VulnCandidate]]:
    """
    Run safe mutation tests: path ID, query param mutation, param wordlist;
    then response similarity detection. Returns (suspicious_responses, vuln_candidates).
    """
    suspicious: list[SuspiciousResponse] = []
    vuln_candidates: list[VulnCandidate] = []
    seen_urls: set[str] = set()
    semaphore = asyncio.Semaphore(concurrency)

    tasks: list[tuple[str, str]] = []
    for ep in endpoints[:max_endpoints]:
        url = ep.url
        method = ep.method.value
        if url in seen_urls:
            continue
        seen_urls.add(url)
        tasks.append((url, method))

        # 1) Path ID variations (e.g. /api/user/123 -> 124, 125)
        if re.search(r"/\d+", urlparse(url).path):
            for var_url in _generate_id_variations(url)[1:]:
                if var_url not in seen_urls:
                    seen_urls.add(var_url)
                    tasks.append((var_url, method))

        # 2) Query parameter mutation (e.g. ?id=123 -> ?id=124, ?id=1)
        for mut_url in _generate_query_param_mutations(url):
            if mut_url not in seen_urls:
                seen_urls.add(mut_url)
                tasks.append((mut_url, method))

        # 3) Parameter wordlist (e.g. /api/order -> ?user_id=1, ?account_id=1)
        for wordlist_url in _generate_wordlist_param_urls(url):
            if wordlist_url not in seen_urls:
                seen_urls.add(wordlist_url)
                tasks.append((wordlist_url, method))

    async def do_one(
        client: httpx.AsyncClient,
        url: str,
        method: str,
    ) -> tuple[str, str, int, dict, dict, str]:
        async with semaphore:
            status, req_h, resp_h, body = await _collect_response_async(client, url, method)
        return (url, method, status, req_h, resp_h, body)

    opts = get_http_client_options(None)
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=REQUEST_TIMEOUT_SECONDS,
        headers=opts["headers"],
        cookies=opts.get("cookies"),
    ) as client:
        results = await asyncio.gather(
            *[do_one(client, u, m) for u, m in tasks],
            return_exceptions=True,
        )

    valid_results: list[tuple[str, str, int, dict, dict, str]] = []
    for r in results:
        if isinstance(r, Exception):
            logger.warning("Vuln test task failed: %s", r)
            continue
        url, method, status, req_h, resp_h, body = r
        valid_results.append((url, method, status, req_h, resp_h, body))
        if status in INTERESTING_STATUS:
            reason = f"Status {status} on API-like endpoint"
            suspicious.append(
                SuspiciousResponse(
                    url=url,
                    method=method,
                    status_code=status,
                    reason=reason,
                    request_headers=req_h,
                    response_headers=resp_h,
                    response_body_preview=body[:2000],
                )
            )
            if use_llm:
                for v in analyze_with_llm(method, url, status, req_h, resp_h, body):
                    vuln_candidates.append(v)

    # 4) Response similarity: same structure, different data -> IDOR candidate
    similarity_candidates = _detect_response_similarity(valid_results)
    vuln_candidates.extend(similarity_candidates)

    # 5) User switching: A vs B same URL -> different response = broken access control candidate
    switch_candidates: list[VulnCandidate] = []
    if len(AUTH_PROFILES) >= 2:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=REQUEST_TIMEOUT_SECONDS,
            headers=get_http_client_options(None)["headers"],
            cookies=get_http_client_options(None).get("cookies"),
        ) as switch_client:
            switch_candidates = await _run_user_switching_async(
                switch_client,
                [(ep.url, ep.method.value) for ep in endpoints[:max_endpoints]],
            )
        vuln_candidates.extend(switch_candidates)
        logger.info("User switching: %d broken access control candidates", len(switch_candidates))

    logger.info(
        "Vuln tests done: %d suspicious, %d LLM candidates, %d similarity IDOR, %d user-switch candidates",
        len(suspicious),
        len(vuln_candidates) - len(similarity_candidates) - len(switch_candidates),
        len(similarity_candidates),
        len(switch_candidates),
    )
    return suspicious, vuln_candidates


def run_vuln_tests(
    endpoints: list[Endpoint],
    target_base_url: str,
    max_endpoints: int = 20,
    use_llm: bool = True,
) -> tuple[list[SuspiciousResponse], list[VulnCandidate]]:
    """Sync wrapper around run_vuln_tests_async."""
    return asyncio.run(run_vuln_tests_async(endpoints, target_base_url, max_endpoints, use_llm))
