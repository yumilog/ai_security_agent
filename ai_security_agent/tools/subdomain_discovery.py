"""Subdomain discovery: CT logs + DNS brute wordlist, filtered by eTLD+1 scope."""

from urllib.parse import urlparse

import tldextract

from ai_security_agent.tools.ct_logs import fetch_subdomains_from_ct_async
from ai_security_agent.utils.logger import get_logger

logger = get_logger(__name__)

# Common subdomain prefixes for brute (no actual DNS; combined with alive check later)
SUBDOMAIN_WORDLIST = [
    "www",
    "api",
    "cdn",
    "mail",
    "admin",
    "staging",
    "dev",
    "test",
    "mobile",
    "app",
    "secure",
    "portal",
    "internal",
    "vpn",
    "ftp",
    "git",
    "graphql",
    "rest",
    "v1",
    "v2",
]


def get_registered_domain(url_or_domain: str) -> str:
    """Return eTLD+1 for URL or domain."""
    s = (url_or_domain or "").strip()
    if not s:
        return ""
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


def _subdomains_from_wordlist(registered_domain: str) -> list[str]:
    """Generate subdomain hostnames from wordlist (e.g. api.example.com)."""
    if not registered_domain:
        return []
    domain = registered_domain.strip().lower()
    seen = {domain}
    out = [domain]
    for sub in SUBDOMAIN_WORDLIST:
        sub = sub.strip()
        if not sub:
            continue
        host = f"{sub}.{domain}"
        if host not in seen:
            seen.add(host)
            out.append(host)
    return out


async def discover_subdomains_async(
    target_url: str,
    use_ct: bool = True,
    use_wordlist: bool = True,
) -> list[str]:
    """
    Discover subdomains for the target's registrable domain.
    Uses Certificate Transparency (crt.sh) and/or a DNS brute wordlist.
    Returns a deduplicated list of hostnames (same eTLD+1). Filter by scope is implicit.
    """
    registered_domain = get_registered_domain(target_url)
    if not registered_domain:
        logger.warning("Could not get registered domain for %s", target_url)
        return []

    seen: set[str] = set()
    out: list[str] = []

    if use_ct:
        ct_hosts = await fetch_subdomains_from_ct_async(registered_domain)
        for h in ct_hosts:
            if get_registered_domain(h) == registered_domain and h not in seen:
                seen.add(h)
                out.append(h)

    if use_wordlist:
        for h in _subdomains_from_wordlist(registered_domain):
            if h not in seen:
                seen.add(h)
                out.append(h)

    result = sorted(set(out))
    logger.info("Subdomain discovery: %d hosts for %s (CT=%s, wordlist=%s)",
                len(result), registered_domain, use_ct, use_wordlist)
    return result
