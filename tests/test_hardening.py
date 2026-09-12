"""Domain, certificate & routing hardening rules (BGP-RPKI-*, CRT-*, DOM-*, HYG-DKIM-NONE, HYG-NS-SINGLE, HYG-SPF-LOOKUPS,
HYG-TLSRPT, LOOK-*). Pure functions only; fixtures are named *_fixture and nothing here touches the network or database."""
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from aegis.guard import check_url  # noqa: E402
from aegis.intel import hardening as hd  # noqa: E402
from aegis.intel.pipeline import rule_cat  # noqa: E402
from aegis.intel.velocity import deadline  # noqa: E402
from aegis.rating import RULES  # noqa: E402

UTC = timezone.utc
NOW = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)

# --- SPF --------------------------------------------------------------------------------------------------
spf_zone_fixture = {
    "big.example": ["v=spf1 include:a.example include:b.example include:c.example mx a -all"],
    "a.example": ["v=spf1 include:a1.example include:a2.example ip4:192.0.2.0/24 ~all"],
    "a1.example": ["v=spf1 a mx ptr ~all"],
    "a2.example": ["v=spf1 exists:%{i}.x.example ~all"],
    "b.example": ["v=spf1 include:b1.example include:b2.example -all"],
    "b1.example": ["v=spf1 mx -all"],
    "b2.example": ["v=spf1 a -all"],
    "c.example": ["v=spf1 redirect=c1.example"],
    "c1.example": ["v=spf1 include:b1.example -all"],
    "loop.example": ["v=spf1 include:loop2.example -all"],
    "loop2.example": ["v=spf1 include:loop.example include:loop2.example -all"],
    "small.example": ["v=spf1 include:_spf.mail.example ~all"],
    "_spf.mail.example": ["v=spf1 include:nb1.mail.example include:nb2.mail.example ~all"],
    "nb1.mail.example": ["v=spf1 ip4:198.51.100.0/24 ~all"],
    "nb2.mail.example": ["v=spf1 ip4:203.0.113.0/24 ~all"],
}


def resolver_fixture(name):
    if name not in spf_zone_fixture:
        raise LookupError(name)
    return spf_zone_fixture[name]


def test_spf_count_over_ten_fires():
    tr = {}
    n = hd.spf_lookup_count(spf_zone_fixture["big.example"][0], resolver_fixture, domain="big.example", trace=tr)
    assert n == 17 and n > hd.SPF_LIMIT
    assert "b1.example" in tr["loops"]                       # included twice: counted, walked once
    h = {"domain": "big.example", "checked": "2026-09-11T00:00:00Z",
         "dns": {"spf": spf_zone_fixture["big.example"][0], "spf_lookups": n, "spf_trace": tr, "mx": ["mx.big.example"], "ns": []}}
    assert [f["rule_id"] for f in hd.hardening_findings({"id": "x", "domain": "big.example"}, h, NOW)] == ["HYG-SPF-LOOKUPS"]


def test_spf_small_and_loops_terminate():
    assert hd.spf_lookup_count(spf_zone_fixture["small.example"][0], resolver_fixture, domain="small.example") == 3
    tr = {}
    assert hd.spf_lookup_count(spf_zone_fixture["loop.example"][0], resolver_fixture, domain="loop.example", trace=tr) == 3
    assert set(tr["loops"]) == {"loop.example", "loop2.example"}
    # an unresolvable include is counted but not walked; redirect is ignored when "all" is present
    assert hd.spf_lookup_count("v=spf1 include:gone.example redirect=b.example -all", resolver_fixture) == 1


# --- DKIM / TLS-RPT ---------------------------------------------------------------------------------------
def test_dkim_none_vs_present():
    none_fixture = {s: [] for s in hd.DKIM_SELECTORS}
    assert hd.dkim_present(none_fixture) is False
    assert hd.dkim_present({**none_fixture, "selector1": ["v=DKIM1; k=rsa; p=MIIBIjANBgkqh"]}) is True
    assert hd.dkim_present({**none_fixture, "google": ["k=rsa; p=MIIBIjANBgkqh"]}) is True
    assert hd.dkim_present({**none_fixture, "s1": ["v=spf1 -all"]}) is False       # a wildcard TXT is not a key
    assert hd.dkim_present({**none_fixture, "k1": None}) is None                     # a failed lookup: not evaluable
    assert 14 <= len(hd.DKIM_SELECTORS) <= 18 and "protonmail" in hd.DKIM_SELECTORS


def test_tlsrpt():
    assert hd.tlsrpt_present(["v=TLSRPTv1; rua=mailto:tlsrpt@example.com"])
    assert not hd.tlsrpt_present([]) and not hd.tlsrpt_present(["v=spf1 -all"])


# --- nameservers ------------------------------------------------------------------------------------------
def test_ns_single_provider_grouping():
    aws_fixture = ["ns-1.awsdns-01.com", "ns-2.awsdns-22.net", "ns-3.awsdns-33.org", "ns-4.awsdns-44.co.uk"]
    assert hd.ns_single_provider(aws_fixture) is True and hd.ns_providers(aws_fixture) == ["AWS Route 53"]
    assert hd.ns_single_provider(["ns1-01.azure-dns.com", "ns2-01.azure-dns.net", "ns3-01.azure-dns.org", "ns4-01.azure-dns.info"]) is True
    assert hd.ns_single_provider(["ns1-01.azure-dns.com", "a1-64.akam.net"]) is False
    assert hd.ns_single_provider(["dns1.p01.nsone.net", "pdns1.ultradns.net"]) is False
    assert hd.ns_single_provider(["ns1.micron.com", "ns2.micron.com"]) is True       # self-hosted: one provider
    assert hd.ns_single_provider([]) is None


# --- RDAP --------------------------------------------------------------------------------------------------
rdap_fixture = {  # shape of rdap.verisign.com (micron.com, Sept 2026)
    "status": ["client transfer prohibited", "server delete prohibited", "server transfer prohibited", "server update prohibited"],
    "events": [{"eventAction": "registration", "eventDate": "1994-12-02T05:00:00Z"},
               {"eventAction": "expiration", "eventDate": "2027-12-01T05:00:00Z"},
               {"eventAction": "last update of RDAP database", "eventDate": "2026-09-11T12:22:44Z"}]}


def test_rdap_expiry_and_lock_parsing():
    st = hd.rdap_domain_status(rdap_fixture)
    assert st["expires"] == "2027-12-01T05:00:00Z" and st["locked"] is True
    assert hd.rdap_domain_status({"status": ["clientTransferProhibited"]})["locked"] is True
    assert hd.rdap_domain_status({"status": ["active"], "events": []}) == {"expires": None, "locked": False, "status": ["active"]}
    assert hd.rdap_domain_status({})["locked"] is None


@pytest.mark.parametrize("days,rid", [(20, "DOM-EXPIRY-30"), (60, "DOM-EXPIRY-90"), (200, None)])
def test_domain_expiry_findings(days, rid):
    h = {"domain": "example.com", "rdap": {"checked": "2026-09-11T00:00:00Z", "url": "https://rdap.verisign.com/com/v1/domain/example.com",
                                           "expires": (NOW + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ"), "locked": True, "status": []}}
    got = [f["rule_id"] for f in hd.hardening_findings({"id": "x", "domain": "example.com"}, h, NOW)]
    assert got == ([rid] if rid else [])


def test_domain_lock_only_where_registry_publishes_it():
    rd = {"checked": "2026-09-11T00:00:00Z", "url": "https://rdap.denic.de/domain/example.de", "expires": None, "locked": False, "status": ["active"]}
    assert hd.hardening_findings({"id": "x", "domain": "example.de"}, {"domain": "example.de", "rdap": rd}, NOW) == []
    f = hd.hardening_findings({"id": "x", "domain": "example.com"}, {"domain": "example.com", "rdap": {**rd, "url": "https://rdap.verisign.com/com/v1/domain/example.com"}}, NOW)
    assert [x["rule_id"] for x in f] == ["DOM-LOCK"] and f[0]["evidence_url"].startswith("https://rdap.verisign.com/")


# --- RPKI --------------------------------------------------------------------------------------------------
def test_rpki_findings():
    res_fixture = [{"prefix": "146.143.0.0/16", "asn": "3486", "status": "unknown", "roas": []},
                   {"prefix": "193.0.0.0/21", "asn": "3333", "status": "valid", "roas": [{"origin": "3333", "prefix": "193.0.0.0/21", "max_length": 21}]},
                   {"prefix": "198.51.100.0/24", "asn": "64500", "status": "invalid_asn", "roas": [{"origin": "64501", "prefix": "198.51.100.0/24", "max_length": 24}]}]
    r = hd.rpki_findings(res_fixture)
    assert [x["prefix"] for x in r["invalid"]] == ["198.51.100.0/24"] and [x["prefix"] for x in r["none"]] == ["146.143.0.0/16"]
    f = hd.hardening_findings({"id": "x", "domain": "example.com"}, {"domain": "example.com", "rpki": {"checked": "t", "results": res_fixture}}, NOW)
    assert {x["rule_id"] for x in f} == {"BGP-RPKI-INVALID", "BGP-RPKI-NONE"}
    assert all(x["evidence_url"].startswith("https://stat.ripe.net/data/rpki-validation/") for x in f)


# --- CAA (RFC 8659) --------------------------------------------------------------------------------------------
def test_caa_no_record_anywhere_is_no_restriction():
    # production false positive 1: apps.micron.cn — micron.cn publishes no CAA; micron.com's policy does not apply
    cert_fixture = {"id": 1, "names": ["apps.micron.cn"], "issuer": "C=US, O=Let's Encrypt, CN=R11", "not_before": "2026-08-01T00:00:00"}
    caa_fixture = {"micron.com": ['0 issue "digicert.com"'], "micron.cn": [], "apps.micron.cn": []}
    r = hd.caa_evaluate(cert_fixture, caa_fixture, {"micron.com": "2026-01-01T00:00:00Z"})
    assert r["status"] == "unrestricted"
    assert hd.caa_evaluate(cert_fixture, {"micron.com": ['0 issue "digicert.com"']}, {})["status"] == "not_evaluable"


def test_caa_digicert_brand_is_authorised():
    # production false positive 2: my.uptale.micron.com issued by GeoTrust (a DigiCert brand); micron.com CAA lists digicert.com
    cert_fixture = {"id": 2, "names": ["my.uptale.micron.com"], "not_before": "2026-08-01T00:00:00",
                    "issuer": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=GeoTrust TLS RSA CA G1"}
    caa_fixture = {"my.uptale.micron.com": [], "uptale.micron.com": [],
                   "micron.com": ['0 issue "digicert.com"', '0 issue "letsencrypt.org', '0 iodef "mailto:webmaster@micron.com"']}
    r = hd.caa_evaluate(cert_fixture, caa_fixture, {"micron.com": "2026-01-01T00:00:00Z"})
    assert r["status"] == "authorised" and r["domain"] == "micron.com"


def test_caa_violation_fires_only_after_policy_was_observed():
    cert_fixture = {"id": 12345, "names": ["shop.example.com"], "issuer": "C=US, O=Let's Encrypt, CN=R11", "not_before": "2026-06-01T00:00:00"}
    caa_fixture = {"shop.example.com": [], "example.com": ['0 issue "digicert.com"', '0 issuewild "digicert.com"']}
    assert hd.caa_evaluate(cert_fixture, caa_fixture, {"example.com": "2026-01-01T00:00:00Z"})["status"] == "violation"
    assert hd.caa_evaluate(cert_fixture, caa_fixture, {"example.com": "2026-07-01T00:00:00Z"})["status"] == "not_evaluable"
    unknown = {**cert_fixture, "issuer": "C=US, O=Microsoft Corporation, CN=Microsoft Azure RSA TLS Issuing CA 03"}
    assert hd.caa_evaluate(unknown, caa_fixture, {"example.com": "2026-01-01T00:00:00Z"})["status"] == "not_evaluable"
    h = {"domain": "example.com", "certs": {"checked": "t", "recent": [cert_fixture]}, "caa_by_domain": caa_fixture,
         "caa_first_seen": {"example.com": "2026-01-01T00:00:00Z"}}
    f = hd.hardening_findings({"id": "x", "domain": "example.com"}, h, NOW)
    assert [x["rule_id"] for x in f] == ["CRT-CAA-VIOLATION"] and f[0]["evidence_url"] == "https://crt.sh/?id=12345"


def test_caa_wildcard_uses_issuewild_and_generic_encoding():
    cert_fixture = {"id": 3, "names": ["*.example.com"], "issuer": "C=US, O=Let's Encrypt, CN=R11", "not_before": "2026-06-01T00:00:00"}
    caa_fixture = {"example.com": ['0 issue "letsencrypt.org"', '0 issuewild ";"']}
    assert hd.caa_evaluate(cert_fixture, caa_fixture, {"example.com": "2026-01-01T00:00:00Z"})["status"] == "violation"
    raw = "\\# 19 00 05 69 73 73 75 65 6c 65 74 73 65 6e 63 72 79 70 74 2e 6f 72 67"  # 0 issue "letsencrypt.org"
    assert hd.caa_parse([raw]) == [(0, "issue", "letsencrypt.org")]


# --- certificate expiry ---------------------------------------------------------------------------------------
def test_ct_expiring_ignores_renewed_and_apex():
    certs_fixture = [
        {"id": 1, "issuer": "LE", "not_before": "2026-06-20T00:00:00", "not_after": "2026-09-18T00:00:00", "names": ["old.example.com", "renewed.example.com", "example.com"]},
        {"id": 2, "issuer": "LE", "not_before": "2026-09-01T00:00:00", "not_after": "2026-11-30T00:00:00", "names": ["renewed.example.com"]},
        {"id": 3, "issuer": "LE", "not_before": "2026-06-20T00:00:00", "not_after": "2026-09-20T00:00:00", "names": ["*.api.example.com"]},
    ]
    exp = hd.ct_expiring(certs_fixture, hosts=["v1.api.example.com"], now=NOW)
    assert set(exp) == {"old.example.com", "v1.api.example.com"}
    h = {"domain": "example.com", "certs": {"checked": "t", "expiring_live": {"old.example.com": exp["old.example.com"]}}}
    f = hd.hardening_findings({"id": "x", "domain": "example.com"}, h, NOW)
    assert [x["rule_id"] for x in f] == ["CRT-EXPIRY-14"] and f[0]["evidence_url"] == "https://crt.sh/?id=1"


# --- lookalikes ----------------------------------------------------------------------------------------------
def test_permutations_exclude_own_domain():
    p = hd.lookalike_permutations("micron.com", "US", exclude=["micron.net"])
    assert "micron.com" not in p and "micron.net" not in p and len(p) <= 60
    assert {"micr0n.com", "micon.com", "micorn.com", "micron.org", "micron.us", "mi-cron.com"} <= set(p)
    assert "tesco.co.uk" not in hd.lookalike_permutations("tesco.co.uk", "GB") and "tesco.com" in hd.lookalike_permutations("tesco.co.uk", "GB")
    assert hd.lookalike_permutations("3m.com") == []                                  # too short to permute meaningfully


def test_lookalike_findings_and_defensive():
    hits_fixture = [{"domain": "micr0n.com", "a": ["203.0.113.9"], "mx": ["mx.evil.example"], "ns": ["ns1.evil.example"]},
                    {"domain": "micon.com", "a": ["198.51.100.7"], "mx": [], "ns": ["ns1.parking.example"]},
                    {"domain": "micron.org", "a": ["198.51.100.8"], "mx": [], "ns": ["ns1.markmonitor.com"]}]
    for x in hits_fixture:
        x["defensive"] = hd.lookalike_defensive(x, "micron.com", ["ns1.micron.com"], ["mx.micron.com"])
    assert [x["defensive"] for x in hits_fixture] == [False, False, True]
    f = hd.hardening_findings({"id": "x", "domain": "micron.com"}, {"domain": "micron.com", "lookalikes": {"checked": "t", "hits": hits_fixture}}, NOW)
    assert {x["rule_id"]: x["data"]["domains"] for x in f} == {"LOOK-MX": ["micr0n.com"], "LOOK-LIVE": ["micon.com"]}


# --- rules ---------------------------------------------------------------------------------------------------
HARDENING_RULES = {"BGP-RPKI-INVALID": ("high", "exposure"), "BGP-RPKI-NONE": ("medium", "exposure"),
                   "CRT-CAA-VIOLATION": ("medium", "hygiene"), "CRT-EXPIRY-14": ("medium", "hygiene"),
                   "DOM-EXPIRY-30": ("critical", "hygiene"), "DOM-EXPIRY-90": ("medium", "hygiene"), "DOM-LOCK": ("high", "hygiene"),
                   "HYG-DKIM-NONE": ("medium", "hygiene"), "HYG-NS-SINGLE": ("low", "hygiene"), "HYG-SPF-LOOKUPS": ("medium", "hygiene"),
                   "HYG-TLSRPT": ("low", "hygiene"), "LOOK-LIVE": ("medium", "impersonation"), "LOOK-MX": ("high", "impersonation")}


def test_rules_exist_with_levels_and_categories():
    for rid, (lvl, cat) in HARDENING_RULES.items():
        assert rid in RULES, rid
        assert RULES[rid][0] == lvl and RULES[rid][1] == "organisation", rid
        assert rule_cat(rid) == cat, (rid, rule_cat(rid))
    assert RULES["DOM-LOCK"][2] == ("The primary domain carries no registrar transfer lock (clientTransferProhibited), so an unauthorised "
                                    "transfer could move its email and web traffic (RDAP).")


def test_low_rules_are_inventory_without_deadline():
    for rid in ("HYG-NS-SINGLE", "HYG-TLSRPT"):
        assert deadline(rid, RULES[rid][0], "2026-09-11T00:00:00Z", [], {}) == (None, None)


def test_full_org_findings_link_evidence():
    h = {"domain": "example.com", "checked": "2026-09-11T00:00:00Z",
         "dns": {"checked": "t", "dkim_present": False, "tlsrpt": False, "ns": ["ns-1.awsdns-01.com", "ns-2.awsdns-02.net"],
                 "mx": ["mx.example.com"], "null_mx": False, "spf": "v=spf1 include:x.example -all", "spf_lookups": 2}}
    f = hd.hardening_findings({"id": "x", "domain": "example.com"}, h, NOW)
    assert {x["rule_id"] for x in f} == {"HYG-DKIM-NONE", "HYG-NS-SINGLE", "HYG-TLSRPT"}
    assert all(x["evidence_url"].startswith("https://dns.google/resolve?name=") and x["category"] == "hygiene" for x in f)
    # a domain that sends and receives no mail gets no DKIM / TLS-RPT finding
    h["dns"].update({"mx": [], "spf": "v=spf1 -all"})
    assert {x["rule_id"] for x in hd.hardening_findings({"id": "x", "domain": "example.com"}, h, NOW)} == {"HYG-NS-SINGLE"}
    # a failed check stores its error and yields nothing
    assert hd.hardening_findings({"id": "x", "domain": "example.com"}, {"domain": "example.com", "dns": {"error": "DoH down"}}, NOW) == []


@pytest.mark.parametrize("url", ["https://data.iana.org/rdap/dns.json", "https://rdap.verisign.com/com/v1/domain/micron.com",
                                 "https://rdap.nominet.uk/uk/domain/abf.co.uk", "https://rdap.denic.de/domain/commerzbank.de",
                                 "https://stat.ripe.net/data/rpki-validation/data.json"])
def test_hardening_hosts_allowlisted(url):
    assert check_url(url) == url
