"""Safety guards, enforced in code and covered by tests.

1. Passive only — outbound HTTP GET is permitted solely to allow-listed public data services
   (indexes, feeds, registries, resolvers). Nothing is ever sent to a monitored organisation's hosts.
2. Metadata only for dark-web / breach / infostealer data — credential values and dump contents are
   rejected or redacted before storage.
"""
import re
from urllib.parse import urlparse

# Suffix match: "sec.gov" allows www.sec.gov, efts.sec.gov, data.sec.gov …
ALLOWED_SUFFIXES = {
    # registries & identity
    "sec.gov", "gleif.org", "wikidata.org", "githubusercontent.com", "github.com",
    # vulnerabilities & exploitation
    "cisa.gov", "first.org", "nist.gov", "osv.dev", "empiricalsecurity.com", "cyentia.com", "exploit-db.com",
    "gitlab.com", "msrc.microsoft.com",
    # exposure / infrastructure indexes (passive)
    "internetdb.shodan.io", "crt.sh", "certspotter.com", "ripe.net", "dns.google", "cloudflare-dns.com",
    "amazonaws.com", "gstatic.com", "cloudflare.com", "oracle.com", "fastly.com", "digitalocean.com",
    "download.microsoft.com", "microsoft.com",
    "greynoise.io", "alienvault.com",
    # compromised-host / abuse feeds
    "abuse.ch", "emergingthreats.net", "cinsscore.com", "spamhaus.org", "torproject.org", "openphish.com",
    "blocklist.de", "iplists.firehol.org",
    # dark-web trackers (third-party, metadata)
    "ransomware.live", "ransomlook.io", "hudsonrock.com", "haveibeenpwned.com", "witha.name",
    # chatter
    "algolia.com", "reddit.com", "infosec.exchange", "mastodon.social", "bsky.app", "ycombinator.com",
    # threat intel, research, government, news RSS
    "mitre.org", "attack.mitre.org", "incidentdatabase.ai", "airisk.mit.edu", "docs.google.com",
    "oecd.ai", "sans.edu",
}

_extra_allowed: set[str] = set()


def allow_host(host: str) -> None:
    """Register a feed host from the source registry (RSS publishers). Called at startup only."""
    if host:
        _extra_allowed.add(host.lower().lstrip("."))


class PassiveGuardError(PermissionError):
    pass


def host_allowed(host: str) -> bool:
    host = host.lower().split(":")[0]
    for s in ALLOWED_SUFFIXES | _extra_allowed:
        if host == s or host.endswith("." + s):
            return True
    return False


def check_url(url: str) -> str:
    p = urlparse(url)
    if p.scheme not in ("https", "http"):
        raise PassiveGuardError(f"scheme not allowed: {p.scheme}")
    if not host_allowed(p.netloc):
        raise PassiveGuardError(f"host not on passive allow-list: {p.netloc}")
    return url


# --- credential / PII redaction ---------------------------------------------------------------
_CRED = [
    re.compile(r"(?i)\b(password|passwd|pwd|pass)\s*[:=]\s*\S+"),
    re.compile(r"(?i)\bbearer\s+[a-z0-9_\-\.=]{12,}"),
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\s*[:|;]\s*\S+"),  # email:password combos
    re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),                                      # AWS access keys
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),                                   # GitHub tokens
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),                                          # API secret keys
]
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SENSITIVE_KEYS = {"password", "pass", "pwd", "secret", "token", "credentials", "cookie", "cookies", "hash"}


def has_credentials(text: str) -> bool:
    return any(p.search(text or "") for p in _CRED)


def redact(text: str | None, emails: bool = True) -> str:
    if not text:
        return ""
    for p in _CRED:
        text = p.sub("[redacted]", text)
    if emails:
        text = _EMAIL.sub("[email]", text)
    return text


def clean(obj):
    """Recursively redact a payload; drops sensitive keys entirely."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, list):
        return [clean(v) for v in obj]
    if isinstance(obj, dict):
        return {k: clean(v) for k, v in obj.items() if str(k).lower() not in _SENSITIVE_KEYS}
    return obj
