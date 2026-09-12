"""Confidence on every finding — how strong the evidence behind the rule is (reconciled with production v2.1 "Prevent").

confirmed   : an observed record — DNS / RDAP / certificate, a CVE on an owned host, a domain/CIK/LEI match, an SEC filing.
likely      : an exact-name or domain match on a third-party dataset, a product seen without its version, a DNS-evidenced provider.
unconfirmed : text mentions, products inferred from hostnames, forum claims.

Unconfirmed evidence never produces Critical: it is capped at High, and the cap is recorded on the finding.
"""

CONFIRMED = ("HYG-", "DOM-", "CRT-EXPIRY", "BGP-", "SURF-RISKY-PORT", "SURF-TAKEOVER", "SURF-LARGE", "VUL-KEV-EXPOSED", "VUL-EXPOSED",
             "VUL-EPSS-SURGE", "CMP-", "DISC-", "DNS-", "IOC-OWN-", "AI-SERVICE-DNS", "AI-EXPOSED-SERVICE", "AI-KEV-EXPOSED", "NRD-",
             "LOOK-", "PHISH-", "WEB-CLICKFIX", "WEB-MALWARE", "DW-DDOS", "TP-CONCENTRATION")
UNCONFIRMED = ("SURF-EDGE", "AI-KEV-PRODUCT", "AI-EXPOSED-PORT", "AI-INCIDENT", "DW-FORUM", "DW-ACCESS", "INC-NAMED", "THR-", "TP-NAMED-CUSTOMER")
DEFINITIONS = {
    "confirmed": "Observed directly: a DNS, RDAP or certificate record, a CVE reported on an owned host, a domain / CIK / LEI match, or an SEC filing.",
    "likely": "Matched by exact name or domain in a third-party dataset, a product seen without its version, or a provider evidenced in DNS.",
    "unconfirmed": "A text mention, a product inferred from a hostname, or a forum claim. Never rated above High.",
}


def confidence(rule_id: str) -> str:
    # order matters: SURF-EDGE-KEV is hostname-inferred (unconfirmed) even though other SURF- rules are observed
    if rule_id.startswith(UNCONFIRMED):
        return "unconfirmed"
    if rule_id.startswith(CONFIRMED):
        return "confirmed"
    return "likely"


def apply(f: dict) -> dict:
    """Set f['confidence'] and cap unconfirmed Critical at High (noted in data.capped_from)."""
    f["confidence"] = confidence(f["rule_id"])
    if f["confidence"] == "unconfirmed" and f.get("severity") == "critical":
        f["severity"] = "high"
        f["data"] = {**(f.get("data") or {}), "capped_from": "critical"}
    return f
