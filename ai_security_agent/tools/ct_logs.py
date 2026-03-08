"""Certificate Transparency (CT) log lookup for subdomain discovery."""

import re
from urllib.parse import urlparse

import httpx
import tldextract

from ai_security_agent.config import CT_CRTSH_TIMEOUT, CT_LOOKUP_ENABLED, CT_MAX_SUBDOMAINS
from ai_security_agent.utils.logger import get_logger

logger = get_logger(__name__)

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


def _get_registered_domain(domain_or_url: str) -> str:
    """Return eTLD+1 for domain or URL."""
    if not domain_or_url:
        return ""
    s = domain_or_url.strip()
    if s.startswith(("http://", "https://")):
        s = urlparse(s).netloc
    ext = tldextract.extract(s)
    rd = getattr(ext, "top_domain_under_public_suffix", None) or getattr(
        ext, "registered_domain", None
    )
    if rd:
        return rd.lower()
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return s.lower()


def _is_valid_hostname(name: str) -> bool:
    """Reject wildcards and obviously invalid names."""
    if not name or len(name) > 253:
        return False
    if name.startswith("*."):
        name = name[2:]
    if "*" in name or " " in name:
        return False
    return bool(re.match(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", name, re.I))


def fetch_subdomains_from_ct(registered_domain: str) -> list[str]:
    """
    Query crt.sh for certificates mentioning the given (registrable) domain.
    Returns a deduplicated list of hostnames (subdomains + root) that belong to that domain.
    """
    if not CT_LOOKUP_ENABLED or not registered_domain:
        return []
    domain = registered_domain.strip().lower()
    url = CRTSH_URL.format(domain=domain)
    try:
        with httpx.Client(timeout=CT_CRTSH_TIMEOUT) as client:
            resp = client.get(url)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        logger.warning("CT log lookup failed for %s: %s", domain, e)
        return []

    seen: set[str] = set()
    out: list[str] = []

    for entry in data if isinstance(data, list) else []:
        if not isinstance(entry, dict):
            continue
        name_value = entry.get("name_value") or ""
        for part in name_value.replace(",", "\n").split():
            name = part.strip().lower()
            if not name or not _is_valid_hostname(name):
                continue
            if name.startswith("*."):
                name = name[2:]
            if name in seen:
                continue
            if name != domain and not name.endswith("." + domain):
                continue
            seen.add(name)
            out.append(name)

    out = sorted(out)
    if len(out) > CT_MAX_SUBDOMAINS:
        out = out[: CT_MAX_SUBDOMAINS]
        logger.info("CT logs: found subdomains for %s (capped at %d)", domain, CT_MAX_SUBDOMAINS)
    else:
        logger.info("CT logs: found %d subdomains for %s", len(out), domain)
    return out


async def fetch_subdomains_from_ct_async(registered_domain: str) -> list[str]:
    """Async wrapper: run fetch_subdomains_from_ct in executor to avoid blocking."""
    import asyncio
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, fetch_subdomains_from_ct, registered_domain)
