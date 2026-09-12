"""v2.2 — AI-era threats: indicator extraction, brand-impersonation matching, AI stack rules, DNS drift, themes.
Fixtures are named *_fixture; nothing here is written to the database."""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from aegis.guard import check_url  # noqa: E402
from aegis.intel import ai as aimod  # noqa: E402
from aegis.intel import fingerprints as fp  # noqa: E402
from aegis.intel.atlas import atlas_for  # noqa: E402
from aegis.intel.iocs import BrandIndex, extract, refang  # noqa: E402
from aegis.intel.pipeline import RULE_CAT, dns_drift, rule_cat  # noqa: E402
from aegis.intel.themes import themes_for  # noqa: E402
from aegis.rating import RULES  # noqa: E402

orgs_fixture = [
    {"id": "us-msft", "name": "Microsoft", "domain": "microsoft.com", "domains": ["microsoft.com"]},
    {"id": "us-amzn", "name": "Amazon", "domain": "amazon.com", "domains": ["amazon.com"]},
    {"id": "us-dal", "name": "Delta Air Lines", "domain": "delta.com", "domains": ["delta.com"]},
    {"id": "gb-tsco", "name": "Tesco", "domain": "tesco.com", "domains": ["tesco.com"]},
    {"id": "us-wmb", "name": "Williams Companies", "domain": "williams.com", "domains": ["williams.com"]},
    {"id": "us-dri", "name": "Darden Restaurants", "domain": "darden.com", "domains": ["darden.com"]},
    {"id": "us-coin", "name": "Coinbase", "domain": "coinbase.com", "domains": ["coinbase.com"]},
    {"id": "us-goog", "name": "Alphabet Inc.", "domain": "abc.xyz", "domains": ["abc.xyz"]},
    {"id": "us-anet", "name": "Arista Networks", "domain": "arista.com", "domains": ["arista.com"]},
    {"id": "us-nke", "name": "Nike, Inc.", "domain": "nike.com", "domains": ["nike.com"]},
]


@pytest.fixture(scope="module")
def bi():
    return BrandIndex(orgs_fixture)


# --- indicators --------------------------------------------------------------------------------------
def test_refang_and_extract_defanged_only():
    text = ("Infrastructure: ms365-live[.]com, teams[.]ms365-live[.]com and hxxps://owa-ms365[.]com/login; C2 104.145.210[.]184. "
            "See also microsoft.com for guidance and the file msedgeupdate.exe and learnings.md. SHA256 "
            "a3f5c1d2e4b6a7980f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778")
    assert "ms365-live.com" in refang("ms365-live[.]com")
    iocs = extract(text, defanged_only=True, publisher_host="www.anthropic.com")
    vals = {i["value"] for i in iocs}
    assert {"ms365-live.com", "teams.ms365-live.com", "104.145.210.184"} <= vals
    assert "microsoft.com" not in vals                      # plain reference, not defanged
    assert not any(v.endswith((".exe", ".md")) for v in vals)  # file names are not domains
    assert any(i["type"] == "sha256" for i in iocs)


def test_json_escapes_do_not_glue_onto_domains():
    vals = {i["value"] for i in extract(r"list:\nteams[.]ms365-live[.]com\n", defanged_only=True)}
    assert "teams.ms365-live.com" in vals and not any(v.startswith("nteams") for v in vals)


def test_ipv6_is_not_truncated():
    vals = {i["value"] for i in extract("C2 2001:ac8:27:89::a02d observed")}
    assert "2001:ac8:27:89::a02d" in vals


# --- brand impersonation ------------------------------------------------------------------------------
@pytest.mark.parametrize("domain,org", [
    ("ms365-live.com", "us-msft"), ("owa-ms365.com", "us-msft"), ("m365-secure-login.com", "us-msft"),
    ("microsoftteamsbooking.com", "us-msft"), ("micros0ft-login.com", "us-msft"),
    ("aws-us-east-3.com", "us-amzn"), ("delta-login.com", "us-dal"), ("stat-coinbase.com", "us-coin"),
    ("account-googlee.icu", "us-goog"), ("dardengiftcardaccess.com", "us-dri"),
    ("helpdesk-nike.com", "us-nke"),              # MISP OSINT help-desk impersonation set
    ("login.outlooksstoragefile.digital", "us-msft"),
])
def test_brand_matches(bi, domain, org):
    m = bi.match(domain)
    assert m and m["org_id"] == org, (domain, m)


@pytest.mark.parametrize("domain", [
    "deltaclient.xyz",          # Anthropic report IOC — "delta" is a dictionary word without a lure: not Delta Air Lines
    "yesilyurtescort.site",     # "tesco" inside "escort"
    "williamsfamilyreunion828.com", "williamsnotaryservice.com", "googleyzq1.com",
    "microsoft.com", "login.microsoft.com",  # the brand's own domains never match
    "mslogin.vercel.app",       # free-hosting platforms are excluded
    "mail.thesugarista.com",    # a word ending in a brand is not the brand
    "vpn.delt4.de",             # digit swaps only count for strong brands
])
def test_brand_non_matches(bi, domain):
    assert bi.match(domain) is None, (domain, bi.match(domain))


# --- AI stack ---------------------------------------------------------------------------------------------
def test_ai_product_recognition():
    assert aimod.product_from_cpe("cpe:/a:langflow:langflow:1.2") == "Langflow"
    assert aimod.product_from_cpe("cpe:/a:anyscale:ray") == "Ray"
    assert aimod.kev_product("Ray-Project", "Ray") == "Ray"
    assert aimod.kev_product("DrayTek", "Vigor Routers") is None and aimod.kev_product("Array Networks", "ArrayOS AG") is None
    assert aimod.kev_product("BerriAI", "LiteLLM") == "LiteLLM"


def test_ai_port_rules():
    assert aimod.assess_host([11434], [], [])["evidence"] == "port"
    assert aimod.assess_host([8888, 5000], [], []) is None          # ambiguous ports need product evidence
    assert aimod.assess_host([8888], ["cpe:/a:jupyter:notebook"], [])["evidence"] == "cpe"


def test_edge_receiver_false_positive_fixed():
    assert fp.edge_product("github-receiver.micron.com") is None
    assert fp.edge_product("citrix-receiver.example.com")[0] == "Citrix"
    assert fp.edge_product("sslvpn.example.com") is not None
    assert fp.edge_product("langflow.corp.example.com")[0] == "Langflow"


# --- DNS drift ----------------------------------------------------------------------------------------------
def snap_fixture(ns, mx=("mx1.mail.protection.outlook.com",), dnssec=1, caa=("0 issue \"digicert.com\"",)):
    return {"ns": list(ns), "mx": list(mx), "dnssec": dnssec, "caa": list(caa)}


def test_dns_drift_requires_persistence_and_novelty():
    old = [snap_fixture(["ns1.corp-dns.com", "ns2.corp-dns.com"]) for _ in range(3)]
    new = snap_fixture(["ns1.evil-dns.net", "ns2.evil-dns.net"], dnssec=0)
    rids = {r[0] for r in dns_drift([new, new] + old)}
    assert "DNS-NS-REPLACED" in rids and "DNS-DNSSEC-LOST" in rids
    assert dns_drift([new] + old) == [] or "DNS-NS-REPLACED" not in {r[0] for r in dns_drift([new] + old)}  # one scan is not enough
    assert dns_drift(old[:2]) == []                                         # needs history
    same_provider = snap_fixture(["ns3.corp-dns.com", "ns4.corp-dns.com"])
    assert "DNS-NS-REPLACED" not in {r[0] for r in dns_drift([same_provider, same_provider] + old)}


# --- themes & ATLAS ---------------------------------------------------------------------------------------
def test_influence_operations_are_not_law_enforcement():
    t = themes_for("Disrupting a covert influence operation from Russia")
    assert "Influence operations & FIMI" in t and "Law enforcement & takedowns" not in t
    assert "Law enforcement & takedowns" not in themes_for("Russian Influence Operation Targets Voters")
    assert "Law enforcement & takedowns" in themes_for("Europol's Operation Endgame dismantles botnets")


def test_new_ai_era_themes():
    assert "Autonomous / agentic intrusion" in themes_for("AI-orchestrated intrusion hit 30 organisations")
    assert "Device-code & token theft" in themes_for("Device code phishing steals Microsoft 365 tokens")
    assert "AI supply chain & key theft" in themes_for("Attackers exploit LiteLLM to steal API keys")
    assert "DNS hijacking" in themes_for("Midnight Blizzard uses DNS hijacking on hotel Wi-Fi")


def test_atlas_tagging():
    ids = {t["id"] for t in atlas_for("Indirect prompt injection in a coding agent leaks API keys")}
    assert "AML.T0051" in ids


# --- explainable rules ----------------------------------------------------------------------------------
V22_CATEGORY = {"AI-KEV-EXPOSED": "ai", "AI-EXPOSED-PORT": "ai", "IOC-BRAND-LIVE": "impersonation", "IOC-BRAND": "impersonation",
                "NRD-PHISH": "impersonation", "PHISH-TARGET": "impersonation", "IOC-OWN-DOMAIN": "compromise", "IOC-OWN-IP": "compromise",
                "WEB-CLICKFIX": "compromise", "WEB-MALWARE": "compromise", "WEB-CMS-KEV": "vulns", "DNS-NS-REPLACED": "hygiene",
                "DNS-CAA-REMOVED": "hygiene", "TP-NAMED-CUSTOMER": "software"}


def test_v22_rules_exist_and_map_to_categories():
    for rid, cat in V22_CATEGORY.items():
        assert rid in RULES, rid
        assert rule_cat(rid) == cat, (rid, rule_cat(rid))


def test_only_surf_large_falls_back_to_footprint():
    fallback = [r for r, (_, scope, _) in RULES.items() if scope == "organisation" and rule_cat(r) == "footprint"]
    assert fallback == ["SURF-LARGE"], fallback
    assert RULE_CAT["CRT-"] == "hygiene" and RULE_CAT["LOOK-"] == "impersonation" and RULE_CAT["BGP-"] == "exposure"


# --- provider catalogue ------------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def cat():
    from aegis.intel.providers import CATALOGUE, Catalogue
    rows = [{"name": p["name"], "category": p["category"], "aliases": p.get("aliases") or [],
             "patterns": {k: p.get(k) or [] for k in ("cname", "txt", "spf", "mx", "ns")}, "observable": 0 if p.get("observable") is False else 1,
             "source": "catalogue"} for p in CATALOGUE]
    return Catalogue(rows)


@pytest.mark.parametrize("kind,value,name", [
    ("cname", "acme-prod.cloud.databricks.com", "Databricks"), ("cname", "adb-123.4.azuredatabricks.net", "Databricks"),
    ("cname", "xy12345.eu-west-1.privatelink.snowflakecomputing.com", "Snowflake"), ("cname", "login.us.auth0.com", "Auth0"),
    ("spf", "_spf.vali.email", "Valimail"), ("cname", "investors.q4web.com", "Q4 Inc"), ("ns", "ns1.foundationdns.com", "Cloudflare"),
    ("txt", "okta-verification=abc", "Okta"), ("cname", "www.company.com.t.en25.com", "Oracle Eloqua"),
])
def test_catalogue_dns_patterns(cat, kind, value, name):
    assert cat.match(kind, value)[0] == name


def test_catalogue_names_and_aliases(cat):
    assert cat.canonical("Snowflake Data Cloud") == "Snowflake" and cat.canonical("SendGrid (Twilio)") == "Twilio"
    assert "Snowflake" in cat.mentioned("Wiz agent gets into Snowflake's internal Jira") and cat.mentioned("A snowflake-shaped cake") == []
    assert cat.observable("Blue Yonder") is False and cat.observable("Databricks") is True


# --- speed & spread ------------------------------------------------------------------------------------------
def test_time_to_exploit_and_bins():
    from aegis.intel.velocity import exploit_stats, kev_lag, lag_bin
    assert kev_lag("2026-09-01", "2026-09-04") == 3 and kev_lag("2026-09-05", "2026-09-04") == -1 and kev_lag("n/a", "2026-09-04") is None
    assert lag_bin(-1).startswith("Zero-day") and lag_bin(5) == "1–7 days" and lag_bin(400) == "Over a year"
    rows_fixture = [{"cve": f"CVE-2026-{i}", "vendor": "Acme", "published": "2026-08-01", "kev_added": f"2026-08-{d:02d}"} for i, d in enumerate([1, 3, 10, 20])]
    st = exploit_stats(rows_fixture)
    assert st["n"] == 4 and st["zero_day"] == 1 and st["within_7d"] == 2 and st["vendors"][0]["vendor"] == "Acme"


def test_spread_curve():
    from aegis.intel.velocity import spread
    src_fixture = [{"publisher": "A", "published": "2026-09-01T00:00:00Z"}, {"publisher": "B", "published": "2026-09-01T10:00:00Z"},
                   {"publisher": "A", "published": "2026-09-01T12:00:00Z"}, {"publisher": "C", "published": "2026-09-02T02:00:00Z"},
                   {"publisher": "D", "published": "2026-09-09T00:00:00Z"}]
    sp = spread(src_fixture)
    assert sp["publishers"] == 4 and sp["publishers_72h"] == 3 and sp["hours_to_3"] == 26.0 and sp["spreading"]
    assert not spread(src_fixture[:2])["spreading"]


def test_epss_surge():
    from aegis.intel.velocity import epss_surge
    assert epss_surge(0.45, 0.2) and epss_surge(0.12, 0.03) and not epss_surge(0.05, 0.02) and not epss_surge(0.5, 0.45) and not epss_surge(0.3, None)


def test_deadline_rules():
    from datetime import date, timedelta
    from aegis.intel.velocity import deadline
    today = date.today().isoformat()
    kev_fixture = {"CVE-FAST": {"kev_added": "2024-01-10", "lag": 2, "kev_due": "2024-01-31"},
                   "CVE-SLOW": {"kev_added": "2023-01-10", "lag": 400, "kev_due": "2023-01-31"},
                   "CVE-FRESH": {"kev_added": (date.today() - timedelta(days=40)).isoformat(), "lag": 90, "kev_due": (date.today() + timedelta(days=3)).isoformat()}}
    fs = f"{today}T00:00:00Z"
    assert deadline("VUL-KEV-EXPOSED", "critical", fs, ["CVE-FAST"], kev_fixture)[1] == "DL-72H"
    assert deadline("VUL-KEV-EXPOSED", "critical", fs, ["CVE-SLOW"], kev_fixture)[1] == "DL-7D"
    assert deadline("VUL-KEV-EXPOSED", "critical", fs, ["CVE-FRESH"], kev_fixture)[1] == "DL-CISA"
    assert deadline("NRD-LIVE", "high", fs, [], kev_fixture)[1] == "DL-72H"
    assert deadline("HYG-DMARC-NONE", "medium", fs, [], kev_fixture)[1] == "DL-90D"
    assert deadline("HYG-CAA", "low", fs, [], kev_fixture) == (None, None)
    assert deadline("SURF-EDGE-KEV", "high", fs, [], kev_fixture)[1] == "DL-7D-EXPLOITED"   # name-based: verify within a week, not 72h
    assert deadline("DISC-8K-OLD", "high", fs, [], kev_fixture) == (None, None)            # a past disclosure is context, not an action


@pytest.mark.parametrize("domain,theme", [
    ("helpdesk-nike.com", "Help desk & IT support"), ("ms365-live.com", "Microsoft 365 & collaboration"),
    ("signin-sso.id-sage.pro", "Login & account security"), ("dardengiftcardaccess.com", "Payments, rewards & gift cards"),
    ("aws-us-east-3.com", "Cloud & API infrastructure"), ("northerntrust.info", "Brand name only"),
])
def test_lure_themes(domain, theme):
    from aegis.intel.iocs import lure_theme
    assert lure_theme(domain) == theme


@pytest.mark.parametrize("url", ["https://www.anthropic.com/threat-intelligence", "https://www.circl.lu/doc/misp/feed-osint/manifest.json",
                                 "https://www.whoisds.com/whois-database/newly-registered-domains/x/nrd", "https://api.osv.dev/v1/query",
                                 "https://status.claude.com/api/v2/incidents.json", "https://threatfox.abuse.ch/export/json/recent/"])
def test_new_sources_are_allowlisted(url):
    assert check_url(url) == url
