"""Guardrails and explainability, encoded as tests (run: .venv\\Scripts\\python -m pytest tests/test_aegis2.py -q)."""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from aegis import actions as act  # noqa: E402
from aegis import playbooks  # noqa: E402
from aegis.guard import PassiveGuardError, check_url, clean, has_credentials, redact  # noqa: E402
from aegis.intel import fingerprints as fp  # noqa: E402
from aegis.intel import prevent  # noqa: E402
from aegis.intel.pipeline import extract_victim, product_match, rule_cat  # noqa: E402
from aegis.intel.themes import cves_for, themes_for  # noqa: E402
from aegis.rating import CONFIDENCE, RULE_CONFIDENCE, RULES, cap_for_confidence, confidence_for, rule, vuln_rule, worst  # noqa: E402


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


# --- preventive checks: domain lifecycle, routing, certificates, lookalikes -----------------------
def test_rdap_summary_reads_the_wire_format_not_the_epp_codes():
    # RDAP normalises EPP status to lower-case words; the camel-case form never appears on the wire.
    js = {"status": ["client transfer prohibited", "server delete prohibited"],
          "events": [{"eventAction": "registration", "eventDate": "1988-05-27T04:00:00Z"},
                     {"eventAction": "expiration", "eventDate": "2027-05-26T04:00:00Z"}],
          "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                                        ["fn", {}, "text", "CSC Corporate Domains, Inc."]]]}]}
    s = prevent.rdap_summary(js)
    assert s["locked"] is True
    assert s["expires"].startswith("2027-05-26")
    assert s["registrar"] == "CSC Corporate Domains, Inc."


def test_rdap_summary_flags_a_domain_with_no_transfer_lock():
    s = prevent.rdap_summary({"status": ["active"], "events": [{"eventAction": "expiration", "eventDate": "2027-01-01T00:00:00Z"}]})
    assert s["locked"] is False


@pytest.mark.parametrize("js", [None, {}, {"status": []}, "not a dict"])
def test_rdap_summary_returns_none_when_unusable(js):
    assert prevent.rdap_summary(js) is None


@pytest.mark.parametrize("days,expected", [(-3, "DOM-EXPIRY-30"), (0, "DOM-EXPIRY-30"), (30, "DOM-EXPIRY-30"),
                                           (31, "DOM-EXPIRY-90"), (90, "DOM-EXPIRY-90"), (91, None), (400, None), (None, None)])
def test_domain_expiry_buckets_at_the_boundaries(days, expected):
    assert prevent.expiry_rule(days) == expected


@pytest.mark.parametrize("state,expected", [("invalid", "BGP-RPKI-INVALID"), ("unknown", "BGP-RPKI-NONE"),
                                            ("valid", None), ("VALID", None), (None, None), ("", None)])
def test_rpki_state_maps_to_a_rule(state, expected):
    assert prevent.rpki_rule(state) == expected


def test_caa_allowed_parses_an_issue_policy():
    assert prevent.caa_allowed(['0 issue "letsencrypt.org"', '0 issuewild "digicert.com"']) == {"letsencrypt.org", "digicert.com"}
    assert prevent.caa_allowed(['0 iodef "mailto:security@example.com"']) is None   # no issue clause
    assert prevent.caa_allowed([]) is None
    assert prevent.caa_allowed(['0 issue ";"']) == set()                            # issuance denied outright


def test_caa_violation_only_fires_on_a_known_ca_outside_a_real_policy():
    allowed = {"letsencrypt.org"}
    assert prevent.caa_violation("C=US, O=DigiCert Inc, CN=DigiCert TLS RSA", allowed) is True
    assert prevent.caa_violation("C=US, O=Let's Encrypt, CN=R11", allowed) is False
    # no CAA record published -> HYG-CAA's business, never a violation
    assert prevent.caa_violation("C=US, O=DigiCert Inc", None) is False
    # an issuer this build does not recognise must stay quiet rather than guess
    assert prevent.caa_violation("C=XX, O=Some Regional CA Ltd", allowed) is False


def test_lookalikes_are_plausible_and_exclude_the_original():
    out = prevent.lookalikes("example.com")
    assert "example.com" not in out
    assert len(out) == len(set(out))
    assert "exmple.com" in out          # omission
    assert "exapmle.com" in out         # transposition
    assert "example.net" in out         # TLD swap
    assert all("." in c for c in out)


@pytest.mark.parametrize("domain", ["", "x", "nodot", "a.com", "."])
def test_lookalikes_declines_domains_too_short_to_be_useful(domain):
    assert prevent.lookalikes(domain) == []


@pytest.mark.parametrize("mx,resolves,expected", [(True, True, "LOOK-MX"), (True, False, "LOOK-MX"),
                                                  (False, True, "LOOK-LIVE"), (False, False, None)])
def test_lookalike_rule_puts_mail_first(mx, resolves, expected):
    assert prevent.lookalike_rule(mx, resolves) == expected


def test_spf_lookup_excess_uses_the_rfc_limit():
    assert prevent.SPF_LOOKUP_LIMIT == 10
    assert prevent.spf_lookup_excess({"lookups": 11}) is True
    assert prevent.spf_lookup_excess({"lookups": 10}) is False
    assert prevent.spf_lookup_excess({"lookups": 0}) is False
    assert prevent.spf_lookup_excess(None) is False


def test_nameserver_concentration_needs_at_least_two_servers():
    assert prevent.ns_single_provider(["a.ns.example.net", "b.ns.example.net"]) is True
    assert prevent.ns_single_provider(["a.ns.example.net", "b.ns.other.org"]) is False
    assert prevent.ns_single_provider(["only.ns.example.net"]) is False   # one NS is not "concentration"
    assert prevent.ns_single_provider([]) is False


def test_new_prevent_rules_are_registered_and_levelled():
    expected = {"HYG-SPF-LOOKUPS": "medium", "HYG-DKIM-NONE": "medium", "HYG-TLSRPT": "low", "HYG-NS-SINGLE": "low",
                "DOM-LOCK": "high", "DOM-EXPIRY-30": "critical", "DOM-EXPIRY-90": "medium",
                "CRT-CAA-VIOLATION": "high", "CRT-EXPIRY-14": "medium",
                "BGP-RPKI-INVALID": "high", "BGP-RPKI-NONE": "medium", "LOOK-MX": "high", "LOOK-LIVE": "medium"}
    for rid, lvl in expected.items():
        assert rid in RULES, rid
        assert rule(rid)[0] == lvl, rid


def test_new_rule_families_are_routed_to_a_category():
    # rule_cat falls back to "footprint" silently, so assert the intended destination
    assert rule_cat("DOM-LOCK") == "hygiene"
    assert rule_cat("LOOK-MX") == "hygiene"
    assert rule_cat("BGP-RPKI-INVALID") == "footprint"
    assert rule_cat("CRT-EXPIRY-14") == "footprint"


def test_rdap_hosts_are_not_trusted_until_iana_registers_them():
    with pytest.raises(PassiveGuardError):
        check_url("https://rdap.example-registry.invalid/domain/x.com")
    assert check_url("https://data.iana.org/rdap/dns.json")


# --- v2.0.1: CAA false positives, edge fingerprints, category mapping -----------------------------
# Both cases below were live High findings on production against Micron.
MICRON_CAA_fixture = ['0 issuewild "www.digicert.com', '0 issue "www.digicert.com', '0 issue "letsencrypt.org',
                      '0 issue "pki.goog', '0 iodef "mailto:webmaster@micron.com', '0 issue "amazon.com']


def test_caa_ignores_a_certificate_for_a_different_registrable_domain():
    # crt.sh returns a certificate when ANY of its names match, so a micron.com query also
    # returns micron.cn certificates. That domain has its own (absent) policy.
    assert prevent.covered_by("apps.micron.cn", "micron.com") is False
    assert prevent.covered_by("my.uptale.micron.com", "micron.com") is True
    assert prevent.covered_by("micron.com", "micron.com") is True
    assert prevent.covered_by("*.micron.com", "micron.com") is True
    assert prevent.covered_by("notmicron.com", "micron.com") is False


def test_digicert_brands_resolve_to_the_digicert_caa_identifiers():
    allowed = prevent.caa_allowed(MICRON_CAA_fixture)
    assert "www.digicert.com" in allowed
    # the exact two issuers that produced the false findings
    for issuer in ["C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
                   "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=GeoTrust TLS RSA CA G1"]:
        assert prevent.caa_violation(issuer, allowed, "2026-01-01", "2025-01-01") is False, issuer


def test_caa_needs_the_certificate_to_postdate_the_observed_policy():
    allowed = {"letsencrypt.org"}
    unauthorised = "C=US, O=DigiCert Inc, CN=DigiCert Global G2"
    # issued after the policy was first observed -> evaluable, and it is a violation
    assert prevent.caa_violation(unauthorised, allowed, "2026-06-01", "2026-01-01") is True
    # issued before the policy existed -> proves nothing, so no finding
    assert prevent.caa_violation(unauthorised, allowed, "2024-06-01", "2026-01-01") is False
    # missing either timestamp -> not evaluable
    assert prevent.caa_violation(unauthorised, allowed, None, "2026-01-01") is False
    assert prevent.caa_violation(unauthorised, allowed, "2026-06-01", None) is False


def test_caa_key_changes_only_when_the_policy_changes():
    a = prevent.caa_key(['0 issue "letsencrypt.org', '0 issue "amazon.com'])
    b = prevent.caa_key(['0 issue "amazon.com', '0 issue "letsencrypt.org'])   # same set, different order
    c = prevent.caa_key(['0 issue "letsencrypt.org'])
    assert a == b and a != c
    assert prevent.caa_key(None) == ""


@pytest.mark.parametrize("host,expected", [
    ("github-receiver.micron.com", None),              # the false positive being fixed
    ("citrix-receiver.example.com", "Citrix"),
    ("netscaler.example.com", "Citrix"),
    ("ics.example.com", None),                         # industrial control systems, not Ivanti
    ("mdm.example.com", None),                         # any vendor's MDM
    ("rds.example.com", None),                         # also AWS RDS
    ("connect-secure.example.com", "Ivanti"),
])
def test_edge_patterns_name_a_product_or_stay_silent(host, expected):
    hit = fp.edge_product(host)
    assert (hit[0] if hit else None) == expected, host


def test_generic_remote_access_hostnames_have_no_vendor():
    # they may still be inventory, but a vendor-less entry can never raise a -KEV rule
    hit = fp.edge_product("sslvpn.example.com")
    assert hit is not None and hit[0] is None


def test_newer_rules_are_categorised_deliberately():
    expected = {"CRT-CAA-VIOLATION": "hygiene", "CRT-EXPIRY-14": "hygiene",
                "DOM-LOCK": "hygiene", "DOM-EXPIRY-30": "hygiene", "DOM-EXPIRY-90": "hygiene",
                "HYG-DKIM-NONE": "hygiene", "HYG-SPF-LOOKUPS": "hygiene", "HYG-TLSRPT": "hygiene",
                "HYG-NS-SINGLE": "hygiene", "BGP-RPKI-INVALID": "exposure", "BGP-RPKI-NONE": "exposure",
                "LOOK-MX": "chatter", "LOOK-LIVE": "chatter"}
    for rid, cat in expected.items():
        assert rule_cat(rid) == cat, rid


def test_only_surf_large_falls_through_to_footprint():
    fell_back = [r for r, v in RULES.items() if v[1] == "organisation" and rule_cat(r) == "footprint"]
    assert fell_back == ["SURF-LARGE"], fell_back


def test_caa_violation_is_medium_not_high():
    assert rule("CRT-CAA-VIOLATION")[0] == "medium"


# --- v2.1 B1: confidence ---------------------------------------------------------------------
def test_every_organisation_rule_declares_a_confidence():
    for rid, (_, scope, _) in RULES.items():
        if scope == "organisation":
            assert rid in RULE_CONFIDENCE, rid
            assert RULE_CONFIDENCE[rid] in CONFIDENCE, rid


def test_confidence_buckets_do_not_overlap_or_invent_rules():
    for rid in RULE_CONFIDENCE:
        assert rid in RULES, rid


@pytest.mark.parametrize("severity,confidence,expected", [
    ("critical", "unconfirmed", "high"),      # the cap
    ("critical", "likely", "critical"),
    ("critical", "confirmed", "critical"),
    ("high", "unconfirmed", "high"),          # nothing below Critical moves
    ("medium", "unconfirmed", "medium"),
    ("low", "unconfirmed", "low"),
])
def test_unconfirmed_evidence_is_capped_at_high(severity, confidence, expected):
    assert cap_for_confidence(severity, confidence) == expected


def test_a_forum_claim_of_access_is_not_presented_as_critical():
    # DW-ACCESS-14 is declared Critical but rests on a broker's claim, so it reads as High
    assert rule("DW-ACCESS-14")[0] == "critical"
    assert confidence_for("DW-ACCESS-14") == "unconfirmed"
    assert cap_for_confidence(*(rule("DW-ACCESS-14")[0], confidence_for("DW-ACCESS-14"))) == "high"


def test_observed_records_are_confirmed_and_inferences_are_not():
    for rid in ("HYG-DMARC-NONE", "DOM-LOCK", "BGP-RPKI-INVALID", "AI-SERVICE-DNS", "VUL-KEV-EXPOSED"):
        assert confidence_for(rid) == "confirmed", rid
    for rid in ("SURF-EDGE", "AI-EXPOSED-PORT", "DW-FORUM-30", "THR-SECTOR"):
        assert confidence_for(rid) == "unconfirmed", rid
    # a CAA mismatch is a strong join, not an observation of mis-issuance
    assert confidence_for("CRT-CAA-VIOLATION") == "likely"


def test_link_types_all_declare_a_confidence():
    from aegis.intel.pipeline import LINK_CONFIDENCE
    for lt in pipeline_link_types():
        assert lt in LINK_CONFIDENCE, lt
    assert LINK_CONFIDENCE["TARGETING"] == "unconfirmed"   # same sector and country is an inference
    assert LINK_CONFIDENCE["GROUP"] == "confirmed"         # a GLEIF corporate-group record


def pipeline_link_types():
    from aegis.intel.pipeline import LINK_TYPES
    return list(LINK_TYPES)


# --- v2.1 B3: the action lifecycle -------------------------------------------------------------
def test_low_findings_are_inventory_not_actions():
    assert act.actionable("critical") and act.actionable("high") and act.actionable("medium")
    assert not act.actionable("low")
    assert act.sla_days("low") is None


def test_due_dates_follow_the_level():
    assert act.sla_days("critical") == 7 and act.sla_days("high") == 30 and act.sla_days("medium") == 90
    due = act.due_date("critical", "2026-01-01T00:00:00Z")
    assert due.startswith("2026-01-08")
    assert act.due_date("low", "2026-01-01T00:00:00Z") is None


def test_sla_is_overridable_per_deployment(monkeypatch):
    monkeypatch.setenv("AEGIS_SLA_CRITICAL", "3")
    assert act.sla_days("critical") == 3
    monkeypatch.setenv("AEGIS_SLA_CRITICAL", "nonsense")
    assert act.sla_days("critical") == 7          # falls back rather than crashing


@pytest.mark.parametrize("current,nxt,allowed", [
    ("new", "acknowledged", True), ("new", "in_progress", True), ("acknowledged", "in_progress", True),
    ("in_progress", "resolved", True), ("new", "false_positive", True), ("new", "accepted_risk", True),
    ("resolved", "new", True),                     # reopening is allowed
    ("false_positive", "in_progress", False),      # withdraw it first
    ("resolved", "acknowledged", False),
    ("new", "new", False),
])
def test_allowed_transitions(current, nxt, allowed):
    assert act.can_transition(current, nxt) is allowed


def test_suppressing_a_finding_requires_a_reason():
    assert act.validate("new", "false_positive") == "false_positive needs a reason."
    assert act.validate("new", "false_positive", reason="Not our host") is None
    assert act.validate("new", "accepted_risk", reason="Compensating control") == "accepted_risk needs an expiry date."
    assert act.validate("new", "accepted_risk", reason="Compensating control", expires="2027-01-01") is None
    assert act.validate("new", "nonsense") == "'nonsense' is not a status."


def test_accepted_risk_expires_but_false_positive_does_not():
    today = "2026-06-01"
    assert act.suppressed("false_positive", None, today) is True
    assert act.suppressed("accepted_risk", "2026-12-01", today) is True     # still accepted
    assert act.suppressed("accepted_risk", "2026-01-01", today) is False    # lapsed, so it returns
    assert act.suppressed("accepted_risk", None, today) is False
    assert act.suppressed(None, None, today) is False


def test_only_an_open_action_can_be_overdue():
    past, now = "2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z"
    assert act.overdue(past, "new", now) is True
    assert act.overdue(past, "in_progress", now) is True
    assert act.overdue(past, "resolved", now) is False        # closed late is history, not a task
    assert act.overdue(None, "new", now) is False


def test_history_entries_are_attributed_even_when_nobody_signs_in():
    e = act.entry("in_progress", "  ", "2026-01-01T00:00:00Z")
    assert e["by"] == "unattributed" and e["status"] == "in_progress"
    e2 = act.entry("accepted_risk", "N. Kukreja", "2026-01-01T00:00:00Z", reason="Mitigated at the edge")
    assert e2["by"] == "N. Kukreja" and e2["reason"] == "Mitigated at the edge"


def test_every_actionable_rule_has_a_playbook_owner():
    # an action with no owner role cannot be routed to anyone
    missing = [r for r, (lvl, scope, _) in RULES.items()
               if scope == "organisation" and act.actionable(lvl) and r not in playbooks.PLAYBOOKS]
    assert missing == [], missing
