"""Explainable rating. No scores, no weights — four levels, each assigned by a named, readable rule.

Every finding, vulnerability and incident carries (severity, rule_id). The UI shows the rule text next to
the level so an analyst can always answer "why is this Critical?" in one sentence.
"""
LEVELS = ["critical", "high", "medium", "low"]
RANK = {lvl: i for i, lvl in enumerate(LEVELS)}

# rule_id: (level, applies_to, plain-English condition)
RULES: dict[str, tuple[str, str, str]] = {
    # --- organisation findings -----------------------------------------------------------------
    "DW-LEAK-30":   ("critical", "organisation", "Named on a ransomware / extortion leak site in the last 30 days."),
    "DW-LEAK-180":  ("high",     "organisation", "Named on a ransomware / extortion leak site 31–180 days ago."),
    "DW-LEAK-OLD":  ("medium",   "organisation", "Named on a ransomware / extortion leak site more than 180 days ago."),
    "DW-ACCESS-14": ("critical", "organisation", "A dark-web forum/market post in the last 14 days offers initial access (VPN, RDP, admin panel, shell) to this organisation (reported claim)."),
    "DW-FORUM-30":  ("high",     "organisation", "A dark-web forum/market post in the last 30 days claims this organisation's data or credentials are for sale or leaked (reported claim)."),
    "DW-FORUM-OLD": ("medium",   "organisation", "Named in a dark-web forum or market claim more than 30 days ago."),
    "DW-STEALER-30": ("high",    "organisation", "An employee device holding this organisation's corporate credentials was infected by an infostealer in the last 30 days (Hudson Rock, counts only)."),
    "DW-STEALER-EMP": ("medium", "organisation", "Employee devices with this organisation's credentials were infected by infostealers 31–180 days ago, or 1,000+ customer devices in the last 30 days."),
    "DW-STEALER-OLD": ("low",    "organisation", "Older or customer-only infostealer exposure below the Medium thresholds."),
    "DW-DDOS-7":    ("high",     "organisation", "A host of this organisation appears on a hacktivist DDoS target list (NoName057(16) DDoSia) in the last 7 days."),
    "DW-DDOS-30":   ("medium",   "organisation", "A host of this organisation appeared on a hacktivist DDoS target list 8–30 days ago."),
    "BR-PUBLIC-90": ("high",     "organisation", "A breach of this organisation's domain was added to the public breach catalogue (HIBP) in the last 90 days."),
    "BR-PUBLIC-12M": ("medium",  "organisation", "A breach of this organisation's domain was added to the public breach catalogue (HIBP) 3–12 months ago."),
    "BR-PUBLIC-OLD": ("low",     "organisation", "A historic (older than 12 months) breach of this organisation's domain is in the public breach catalogue."),
    "CMP-C2":       ("critical", "organisation", "An IP address inside this organisation's own network is listed as botnet command-and-control or malware distribution (abuse.ch)."),
    "CMP-ABUSE":    ("high",     "organisation", "An IP address inside this organisation's own network is on a compromised-host / attacker blocklist (Emerging Threats, CINS, Spamhaus, blocklist.de)."),
    "VUL-KEV-EXPOSED": ("critical", "organisation", "An internet-facing host of this organisation reports a CVE that CISA lists as actively exploited (KEV)."),
    "VUL-EXPOSED-HIGH": ("high", "organisation", "An internet-facing host reports a CVE with high exploit likelihood (EPSS ≥ 10%) or a public exploit."),
    "VUL-EXPOSED":  ("medium",   "organisation", "An internet-facing host reports known CVEs (indexed by Shodan InternetDB)."),
    "SURF-RISKY-PORT": ("high",  "organisation", "Remote-administration or database service exposed to the internet (e.g. RDP, SMB, Telnet, VNC, MySQL, MSSQL, PostgreSQL, MongoDB, Redis, Elasticsearch, Docker API)."),
    "SURF-EDGE-KEV": ("high",    "organisation", "Public hostnames indicate an edge/remote-access product that itself had a CISA KEV addition in the last 30 days."),
    "SURF-EDGE":    ("low",      "organisation", "Public hostnames indicate an edge / remote-access product (VPN, gateway, webmail) — inventory only."),
    "SURF-LARGE":   ("low",      "organisation", "Large certificate-transparency footprint (many distinct public hostnames) — inventory only."),
    "HYG-DMARC-NONE": ("medium", "organisation", "Email domain has no DMARC record, or DMARC policy is p=none (spoofing not blocked)."),
    "HYG-SPF-MISSING": ("medium", "organisation", "Email domain publishes no SPF record."),
    "HYG-SPF-SOFT": ("low",      "organisation", "SPF ends in ~all / ?all (soft fail) rather than -all."),
    "HYG-DNSSEC":   ("low",      "organisation", "Domain is not DNSSEC-signed."),
    "HYG-MTASTS":   ("low",      "organisation", "No MTA-STS policy (inbound mail TLS not enforced)."),
    "HYG-CAA":      ("low",      "organisation", "No CAA record (any certificate authority may issue for the domain)."),
    "HYG-SPF-LOOKUPS": ("medium", "organisation", "SPF record needs more than the 10 DNS lookups RFC 7208 allows — receivers return permerror, so SPF silently stops protecting the domain."),
    "HYG-DKIM-NONE": ("medium",  "organisation", "No DKIM key published on any common selector, so receivers cannot verify that mail was signed by this domain."),
    "HYG-TLSRPT":   ("low",      "organisation", "No TLS-RPT record, so failed inbound mail encryption is never reported back — inventory only."),
    "HYG-NS-SINGLE": ("low",     "organisation", "Every authoritative nameserver is with a single provider (no DNS redundancy) — inventory only."),
    # --- domain lifecycle (RDAP) ---------------------------------------------------------------
    "DOM-LOCK":     ("high",     "organisation", "The primary domain carries no registrar transfer lock (clientTransferProhibited), so an unauthorised transfer could move its email and web traffic (RDAP)."),
    "DOM-EXPIRY-30": ("critical", "organisation", "The primary domain expires within 30 days; if it lapses, email and web stop and the name can be re-registered by anyone (RDAP)."),
    "DOM-EXPIRY-90": ("medium",  "organisation", "The primary domain expires within 90 days (RDAP)."),
    # --- certificates (Certificate Transparency) -----------------------------------------------
    "CRT-CAA-VIOLATION": ("medium", "organisation", "A certificate issued after the current CAA policy was observed names a certificate authority the policy does not authorise (possible mis-issuance or unsanctioned IT)."),
    "CRT-EXPIRY-14": ("medium",  "organisation", "A certificate covering a live public hostname expires within 14 days (certificate transparency logs)."),
    # --- routing integrity (RPKI) --------------------------------------------------------------
    "BGP-RPKI-INVALID": ("high", "organisation", "An IP prefix registered to this organisation is announced by an origin its own ROA does not authorise (RPKI invalid — possible hijack or stale ROA)."),
    "BGP-RPKI-NONE": ("medium",  "organisation", "An IP prefix registered to this organisation has no Route Origin Authorisation, so networks filtering on RPKI cannot tell a hijack from a legitimate announcement."),
    # --- lookalike domains (passive DNS + certificate transparency) ----------------------------
    "LOOK-MX":      ("high",     "organisation", "A lookalike of this organisation's domain is registered and accepts mail (MX record), the usual preparation for invoice fraud and credential phishing."),
    "LOOK-LIVE":    ("medium",   "organisation", "A lookalike of this organisation's domain is registered and resolves to a live address (public DNS)."),
    "DISC-8K-90":   ("critical", "organisation", "Filed an SEC 8-K Item 1.05 (material cybersecurity incident) in the last 90 days."),
    "DISC-8K-OLD":  ("high",     "organisation", "Filed an SEC 8-K Item 1.05 (material cybersecurity incident) more than 90 days ago."),
    "INC-NAMED-30": ("high",     "organisation", "Named as the victim in cyber-incident reporting by two or more independent publishers in the last 30 days."),
    "INC-NAMED-1":  ("medium",   "organisation", "Named as the victim in cyber-incident reporting by one publisher in the last 30 days."),
    "TP-VENDOR-INC": ("high",    "organisation", "A third-party provider this organisation uses (evidenced in its public DNS) is involved in an active incident (last 30 days)."),
    "TP-CONCENTRATION": ("low",  "organisation", "Depends on a provider shared by many monitored organisations (concentration risk) — inventory only."),
    "THR-SECTOR":   ("low",      "organisation", "Threat context: ransomware groups listed 10+ victims in this organisation's sector and country in the last 30 days."),
    "DISC-801":     ("medium",   "organisation", "Filed an SEC 8-K Item 8.01 mentioning a cybersecurity incident in the last 12 months."),
    "SURF-TAKEOVER": ("high",    "organisation", "A public hostname's CNAME points to a cloud resource that no longer resolves (possible subdomain takeover)."),
    "DW-LEAK-SUB":  ("high",     "organisation", "A subsidiary (per GLEIF) was named on a ransomware / extortion leak site in the last 90 days."),
    "AI-INCIDENT":  ("medium",   "organisation", "Named as deployer or developer in an AI Incident Database report in the last 12 months."),
    "AI-SERVICE-DNS": ("low",    "organisation", "Uses generative-AI services, evidenced by the provider's domain-verification record in public DNS — inventory only."),
    "AI-PROVIDER-INC": ("medium", "organisation", "A generative-AI provider this organisation uses (public DNS evidence) had an AI-system incident, an AI Incident Database report or a major service incident in the last 30 days."),
    "AI-EXPOSED-SERVICE": ("high", "organisation", "An internet-facing host of this organisation exposes a self-hosted AI or machine-learning service, identified by port and product. These are frequently deployed with no authentication. Only the hostnames the passive scan resolves are covered."),
    "AI-EXPOSED-PORT": ("medium", "organisation", "An internet-facing host exposes a port commonly used by a self-hosted AI or machine-learning service, without product confirmation — the port alone is not proof."),
    "AI-HOST":      ("low",      "organisation", "Public hostnames or CNAMEs indicate a self-hosted or managed AI platform — inventory only."),
    # --- vulnerabilities ---------------------------------------------------------------------
    "V-KEV-RANSOM": ("critical", "vulnerability", "In CISA KEV and known to be used in ransomware campaigns."),
    "V-KEV-NEW":    ("critical", "vulnerability", "Added to CISA KEV in the last 30 days (fresh, active exploitation)."),
    "V-KEV-TOOLED": ("critical", "vulnerability", "In CISA KEV, EPSS ≥ 90% and a public exploit module exists (Metasploit / Nuclei)."),
    "V-KEV":        ("high",     "vulnerability", "In CISA KEV (confirmed exploited in the wild)."),
    "V-EPSS-HIGH":  ("high",     "vulnerability", "Not in KEV, but EPSS exploit probability ≥ 50%."),
    "V-CVSS-EXPLOIT": ("high",   "vulnerability", "CVSS ≥ 9.0 and a public exploit exists (Metasploit / ExploitDB / Nuclei)."),
    "V-EPSS-MED":   ("medium",   "vulnerability", "EPSS exploit probability 10–50%, or a public exploit exists."),
    "V-OTHER":      ("low",      "vulnerability", "No exploitation evidence, no public exploit and EPSS < 10%."),
    # --- incidents ---------------------------------------------------------------------------
    "I-WATCH-VICTIM": ("critical", "incident", "A monitored organisation is the named victim."),
    "I-SUPPLY-WATCH": ("critical", "incident", "Supply-chain / provider incident and one or more monitored organisations depend on the affected provider."),
    "I-KEV-MASS":   ("critical", "incident", "Active exploitation of a product listed in CISA KEV in the last 14 days, reported by 3+ independent publishers."),
    "I-MULTI":      ("high",     "incident", "Reported by two or more independent publishers."),
    "I-LEAK":       ("high",     "incident", "Ransomware / extortion leak-site listing (claim by the group, not yet confirmed by the victim)."),
    "I-SINGLE":     ("medium",   "incident", "Single-source report."),
    "I-INFO":       ("low",      "incident", "Informational — outage or advisory without confirmed compromise."),
}

RISKY_PORTS = {21: "FTP", 23: "Telnet", 445: "SMB", 139: "NetBIOS", 3389: "RDP", 5900: "VNC", 5901: "VNC",
               1433: "MSSQL", 1521: "Oracle DB", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
               6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 2375: "Docker API",
               5985: "WinRM", 5986: "WinRM", 161: "SNMP", 623: "IPMI", 9000: "Admin panel", 10250: "Kubelet"}


# How strongly the evidence supports a finding. This is not a probability and it never
# changes the rule that fired — it says what kind of evidence stands behind it.
#
#   confirmed   — an observed record: a DNS, RDAP or certificate lookup, a CVE on a host we
#                 resolved, an SEC filing, a domain / CIK / LEI match.
#   likely      — a strong but indirect join: an exact name match, a product CPE without its
#                 version, a breach whose domain matches, a CAA mismatch.
#   unconfirmed — an inference or someone else's claim: a text mention, a product guessed from
#                 a hostname, a forum post.
CONFIDENCE = ("confirmed", "likely", "unconfirmed")
DEFAULT_CONFIDENCE = "likely"
RULE_CONFIDENCE = {
    # observed records
    **{r: "confirmed" for r in (
        "HYG-DMARC-NONE", "HYG-SPF-MISSING", "HYG-SPF-SOFT", "HYG-SPF-LOOKUPS", "HYG-DKIM-NONE",
        "HYG-DNSSEC", "HYG-MTASTS", "HYG-TLSRPT", "HYG-CAA", "HYG-NS-SINGLE",
        "DOM-LOCK", "DOM-EXPIRY-30", "DOM-EXPIRY-90", "CRT-EXPIRY-14",
        "BGP-RPKI-INVALID", "BGP-RPKI-NONE", "LOOK-MX", "LOOK-LIVE",
        "SURF-TAKEOVER", "SURF-RISKY-PORT", "VUL-KEV-EXPOSED", "VUL-EXPOSED-HIGH", "VUL-EXPOSED",
        "CMP-C2", "CMP-ABUSE", "DISC-8K-90", "DISC-8K-OLD", "DISC-801", "AI-SERVICE-DNS",
        "AI-EXPOSED-SERVICE", "SURF-LARGE")},
    # strong but indirect
    **{r: "likely" for r in (
        "CRT-CAA-VIOLATION", "BR-PUBLIC-90", "BR-PUBLIC-12M", "BR-PUBLIC-OLD",
        "DW-STEALER-30", "DW-STEALER-EMP", "DW-STEALER-OLD", "DW-DDOS-7", "DW-DDOS-30",
        "DW-LEAK-30", "DW-LEAK-180", "DW-LEAK-OLD", "DW-LEAK-SUB", "TP-VENDOR-INC",
        "AI-PROVIDER-INC", "AI-HOST", "AI-INCIDENT")},
    # inference, or someone else's claim
    **{r: "unconfirmed" for r in (
        "DW-ACCESS-14", "DW-FORUM-30", "DW-FORUM-OLD", "INC-NAMED-30", "INC-NAMED-1",
        "SURF-EDGE", "SURF-EDGE-KEV", "AI-EXPOSED-PORT", "THR-SECTOR", "TP-CONCENTRATION")},
}


def confidence_for(rule_id: str) -> str:
    return RULE_CONFIDENCE.get(rule_id, DEFAULT_CONFIDENCE)


def cap_for_confidence(severity: str, confidence: str) -> str:
    """Evidence that is only inferred or claimed never reads as Critical.

    A hostname that looks like a VPN, or a forum post claiming access, may well be right —
    but it is not the same standing as a record we resolved, and presenting it at the top
    level costs the reader trust in every Critical on the page.
    """
    return "high" if confidence == "unconfirmed" and severity == "critical" else severity


def rule(rule_id: str) -> tuple[str, str]:
    """-> (severity, reason text)"""
    lvl, _, text = RULES[rule_id]
    return lvl, text


def worst(levels) -> str | None:
    levels = [l for l in levels if l in RANK]
    return min(levels, key=RANK.get) if levels else None


def vuln_rule(in_kev: bool, ransomware: bool, epss: float | None, cvss: float | None,
              kev_age_days: int | None = None, tooled: bool = False, public_exploit: bool = False) -> str:
    """Calibrated on the live catalogue: ~40% of KEV lands Critical (vs 64% with a looser rule)."""
    e = epss or 0.0
    if in_kev and ransomware:
        return "V-KEV-RANSOM"
    if in_kev and kev_age_days is not None and kev_age_days <= 30:
        return "V-KEV-NEW"
    if in_kev and e >= 0.9 and tooled:
        return "V-KEV-TOOLED"
    if in_kev:
        return "V-KEV"
    if e >= 0.5:
        return "V-EPSS-HIGH"
    if (cvss or 0) >= 9.0 and public_exploit:
        return "V-CVSS-EXPLOIT"
    if e >= 0.1 or public_exploit:
        return "V-EPSS-MED"
    return "V-OTHER"


def catalogue() -> list[dict]:
    return [{"id": k, "level": v[0], "applies_to": v[1], "rule": v[2]} for k, v in RULES.items()]
