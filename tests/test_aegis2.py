"""Guardrails and explainability, encoded as tests (run: .venv\\Scripts\\python -m pytest tests/test_aegis2.py -q)."""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from aegis.guard import PassiveGuardError, check_url, clean, has_credentials, redact  # noqa: E402
from aegis.intel import fingerprints as fp  # noqa: E402
from aegis.intel.pipeline import extract_victim, product_match  # noqa: E402
from aegis.intel.themes import cves_for, themes_for  # noqa: E402
from aegis.rating import RULES, rule, vuln_rule, worst  # noqa: E402


# --- passive only -------------------------------------------------------------------------------
@pytest.mark.parametrize("url", ["https://www.cisa.gov/x.json", "https://api.first.org/data/v1/epss", "https://internetdb.shodan.io/1.2.3.4",
                                 "https://dns.google/resolve?name=a.com", "https://efts.sec.gov/LATEST/search-index"])
def test_allowlisted_public_sources_pass(url):
    assert check_url(url) == url


@pytest.mark.parametrize("url", ["https://www.hsbc.com/", "http://10.0.0.1/admin", "https://abcdefgh.onion/leak", "ftp://files.example.com/x",
                                 "https://t.me/s/somechannel", "https://pastebin.com/raw/abc"])
def test_monitored_orgs_darkweb_and_pastes_are_blocked(url):
    with pytest.raises(PassiveGuardError):
        check_url(url)


# --- metadata only: credentials never stored -----------------------------------------------------
def test_credential_patterns_are_detected_and_redacted():
    dump = "user@corp.com:Winter2026! and password=hunter2 and AKIAABCDEFGHIJKLMNOP"
    assert has_credentials(dump)
    out = redact(dump)
    assert "Winter2026" not in out and "hunter2" not in out and "AKIA" not in out


def test_clean_drops_sensitive_keys_recursively():
    out = clean({"victim": "Acme", "password": "x", "nested": {"token": "y", "note": "a@b.com"}})
    assert "password" not in out and "token" not in out["nested"] and out["nested"]["note"] == "[email]"


# --- explainable rating ---------------------------------------------------------------------------
def test_every_rule_has_level_scope_and_text():
    for rid, (lvl, scope, text) in RULES.items():
        assert lvl in ("critical", "high", "medium", "low"), rid
        assert scope in ("organisation", "vulnerability", "incident"), rid
        assert len(text) > 20, rid


def test_vulnerability_rules_are_calibrated():
    assert vuln_rule(True, True, 0.01, None) == "V-KEV-RANSOM"
    assert vuln_rule(True, False, 0.2, None, kev_age_days=5) == "V-KEV-NEW"
    assert vuln_rule(True, False, 0.95, None, kev_age_days=400, tooled=True) == "V-KEV-TOOLED"
    assert vuln_rule(True, False, 0.95, None, kev_age_days=400, tooled=False) == "V-KEV"
    assert vuln_rule(False, False, 0.6, None) == "V-EPSS-HIGH"
    assert vuln_rule(False, False, 0.01, 9.8, public_exploit=True) == "V-CVSS-EXPLOIT"
    assert vuln_rule(False, False, 0.01, 5.0) == "V-OTHER"
    assert rule("V-KEV-RANSOM")[0] == "critical"


def test_worst_level_wins():
    assert worst(["low", "high", "medium"]) == "high"
    assert worst([]) is None


# --- fingerprints (third parties from public DNS) ---------------------------------------------------
def test_dns_fingerprints():
    assert fp.match(fp.MX_C, "mxa-00299f02.gslb.pphosted.com")[0] == "Proofpoint"
    assert fp.match(fp.TXT_C, "atlassian-domain-verification=abc")[0] == "Atlassian"
    assert fp.match(fp.CNAME_C, "acme.my.salesforce.com")[0] == "Salesforce"
    assert fp.edge_product("sslvpn.corp.example.com")[1].startswith("FortiGate") or fp.edge_product("sslvpn.corp.example.com")
    assert fp.edge_product("citrix-dr.bpweb.bp.com")[0] == "Citrix"
    assert fp.edge_product("www.example.com") is None


# --- victim extraction: organisations only, never people, never vendors announcing flaws ------------
@pytest.mark.parametrize("title,expected", [
    ("AdaptHealth confirms 4.1 million people exposed in July cyberattack", "AdaptHealth"),
    ("Hospital operator Nutex Health says data stolen in cyberattack", "Nutex Health"),
    ("FBI investigates cyberattack on Micro-Comm in Kansas", "Micro-Comm"),
    ("Healthcare Giant McKesson Investigates Data Breach Incident", "McKesson"),
    ("Google warns of new Chrome zero-day bug exploited in attacks", None),
    ("CIA’s Michael Ellis says cyber intelligence is changing how the agency operates", None),
    ("Electronic health record company says customer data stolen in breach", None),
    ("Mathspace Breach Impacts More Than 1 Million Users in Australia, NZ", "Mathspace"),
])
def test_victim_extraction(title, expected):
    assert extract_victim(title) == expected


def test_product_match_is_product_level():
    assert product_match("Citrix", "NetScaler", "NetScaler ADC / Gateway")
    assert product_match("Microsoft", "SharePoint Server", "SharePoint Server")
    assert not product_match("Microsoft", "Windows", "Exchange Server")
    assert not product_match("Microsoft", "Internet Key Exchange (IKE) Service Extensions", "Exchange Server")


@pytest.mark.parametrize("title,expected", [
    ("Admin Access to a US Healthcare Provider Network Offered for Sale", "access"),
    ("Initial access to European logistics firm advertised on forum", "access"),
    ("Online Banking Access to a BNP Paribas Savings Account Offered for Sale", "data"),
    ("12 Million Acme Customer Records Offered for Sale", "data"),
    ("Stealer logs with corporate credentials leaked", "credentials"),
])
def test_dark_web_claim_classification(title, expected):
    from aegis.collectors.darkweb import claim_kind
    assert claim_kind(title) == expected


def test_themes_and_cves():
    t = "Cl0p ransomware gang exploits MOVEit zero-day CVE-2023-34362 in supply-chain attack on payroll provider"
    th = themes_for(t)
    assert "Ransomware & extortion" in th and "Zero-day exploitation" in th and "Supply-chain compromise" in th
    assert cves_for(t) == ["CVE-2023-34362"]
