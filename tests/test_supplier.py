"""Supplier intelligence: fourth parties from a provider's own DNS, legal-name normalisation, entity-only screening, summary."""
import pytest

from aegis.intel import supplier as S
from aegis.intel.providers import CATALOGUE, KINDS, Catalogue


@pytest.fixture()
def catalogue_fixture():
    rows = [{"name": p["name"], "category": p["category"], "aliases": p.get("aliases") or [],
             "patterns": {k: p.get(k) or [] for k in KINDS}, "observable": 1} for p in CATALOGUE]
    return Catalogue(rows)


@pytest.fixture()
def snowflake_dns_fixture():
    # Snowflake-like: mail on Google, DNS on Route 53, its own verification record, an SPF chain one level deep
    return {"domain": "snowflake.com",
            "mx": ["aspmx.l.google.com", "alt1.aspmx.l.google.com"],
            "ns": ["ns-1234.awsdns-26.org", "ns-567.awsdns-07.net"],
            "txt": ["snowflake-verification=abc123", "atlassian-domain-verification=xyz", "v=spf1 include:_spf.snowflake.com ~all"],
            "spf": ["_spf.snowflake.com"],
            "spf_nested": {"_spf.snowflake.com": ["_spf.google.com", "sendgrid.net"]},
            "sources": {"mx": "https://dns.google/resolve?name=snowflake.com&type=MX",
                        "ns": "https://dns.google/resolve?name=snowflake.com&type=NS",
                        "txt": "https://dns.google/resolve?name=snowflake.com&type=TXT"}}


@pytest.fixture()
def entity_rows_fixture():
    return [
        {"name": "ACME WIDGETS LTD", "aliases": [], "type": "Entity", "list": "US Consolidated Screening List",
         "source": "Entity List (EL) - Bureau of Industry and Security", "programme": "EAR", "id": "1", "url": "https://example.gov/1"},
        {"name": "Globex Trading House", "aliases": ["GLOBEX CORPORATION"], "type": "Entity", "list": "UK Sanctions List",
         "source": "UK FCDO", "programme": "Russia", "id": "RUS0001", "url": "https://example.gov/uk"},
        {"name": "Initech Holdings", "aliases": [], "type": "Individual", "list": "US Consolidated Screening List",
         "source": "SDN", "programme": "X", "id": "3", "url": "https://example.gov/3"},
        {"name": "Hooli", "aliases": ["Hooli Inc"], "type": "Vessel", "list": "US Consolidated Screening List",
         "source": "SDN", "programme": "X", "id": "4", "url": "https://example.gov/4"},
        {"name": "Acme Widgets International", "aliases": [], "type": "Entity", "list": "US Consolidated Screening List",
         "source": "SDN", "programme": "X", "id": "5", "url": "https://example.gov/5"},
    ]


@pytest.fixture()
def intel_fixture():
    return {
        "Snowflake": {"domain": "snowflake.com", "fourth_parties": [{"provider": "AWS", "category": "Cloud platform", "evidence": "NS x"},
                                                                     {"provider": "Google Workspace", "category": "Email & collaboration", "evidence": "MX y"}],
                      "country": "US", "parent": None, "sanctions": [], "sbd_pledge": True},
        "Okta": {"domain": "okta.com", "fourth_parties": [{"provider": "Amazon Web Services", "category": "Cloud platform", "evidence": "NS z"}],
                 "country": "US", "parent": None, "sanctions": None, "sbd_pledge": True},
        "GitHub": {"domain": "github.com", "fourth_parties": [], "country": "US",
                   "parent": {"name": "MICROSOFT CORPORATION", "country": "US", "lei": "INR2EJN1ERAN0W5ZP974"}, "sanctions": [], "sbd_pledge": True},
    }


@pytest.fixture()
def deps_fixture():
    return [
        {"org_id": "o1", "vendor": "Snowflake", "category": "Data platform"},
        {"org_id": "o2", "vendor": "Snowflake", "category": "Data platform"},
        {"org_id": "o2", "vendor": "AWS", "category": "Cloud platform"},
        ("o3", "Okta", "Identity & access"),
        ("o4", "AWS", "Cloud platform"),
        ("o5", "Amazon Web Services", "Cloud platform"),  # alias -> canonical AWS
        ("o3", "Okta Inc", "Identity & access"),           # alias of the same provider — counted once
    ]


def test_provider_domains_use_catalogue_names():
    names = {p["name"] for p in CATALOGUE}
    assert len(S.PROVIDER_DOMAINS) >= 60
    assert set(S.PROVIDER_DOMAINS) <= names
    assert set(S.PROVIDER_LEGAL) <= set(S.PROVIDER_DOMAINS)
    assert S.PROVIDER_DOMAINS["Snowflake"] == "snowflake.com" and S.PROVIDER_DOMAINS["AWS"] == "amazon.com"


def test_fourth_parties_from_provider_dns(catalogue_fixture, snowflake_dns_fixture):
    fps = S.fourth_parties("Snowflake", snowflake_dns_fixture, catalogue_fixture)
    names = [f["provider"] for f in fps]
    assert "Google Workspace" in names and "AWS" in names
    assert "Snowflake" not in names                        # its own TXT record is not a fourth party
    assert "Atlassian" in names and "Twilio" in names      # TXT verification, nested SPF include (sendgrid.net)
    assert len(names) == len(set(names))                   # one entry per fourth party
    aws = next(f for f in fps if f["provider"] == "AWS")
    assert aws["evidence"].startswith("NS ") and aws["source"].endswith("type=NS") and aws["kind"] == "ns"
    assert next(f for f in fps if f["provider"] == "Atlassian")["kind"] == "txt"
    tw = next(f for f in fps if f["provider"] == "Twilio")
    assert "via include:_spf.snowflake.com" in tw["evidence"]


def test_fourth_parties_exclude_same_company(catalogue_fixture):
    dns = {"domain": "google.com", "mx": ["smtp.google.com"], "ns": ["ns1.google.com"],
           "txt": ["google-site-verification=abc", "docusign=123"], "spf": ["_spf.google.com"], "spf_nested": {}}
    names = [f["provider"] for f in S.fourth_parties("Google Cloud", dns, catalogue_fixture)]
    assert names == ["DocuSign"]                           # Google Workspace / "Google" are the same company
    dns = {"domain": "amazon.com", "mx": ["amazon-smtp.amazon.com"], "ns": ["ns-1.awsdns-01.com", "pdns1.ultradns.net"],
           "txt": ["amazonses:xyz"], "spf": ["amazonses.com"], "spf_nested": {}}
    names = [f["provider"] for f in S.fourth_parties("AWS", dns, catalogue_fixture)]
    assert names == ["Vercara UltraDNS"]


def test_norm_name_suffixes():
    assert S.norm_name("Snowflake Inc.") == "snowflake"
    assert S.norm_name("PayPal Holdings, Inc.") == "paypal"
    assert S.norm_name("Elastic N.V.") == "elastic"
    assert S.norm_name("Siemens AG") == "siemens"
    assert S.norm_name("SAP SE") == "sap"
    assert S.norm_name("The Rocket Science Group LLC") == "rocket science"
    assert S.norm_name("China Telecom Co., Ltd.") == "china telecom"
    assert S.norm_name("Microsoft Corporation") == S.norm_name("MICROSOFT CORP") == "microsoft"
    assert S.norm_name("Société Générale S.A.") == "societe generale"
    assert S.norm_name("Group") == "group"                 # never normalised to empty
    assert S.norm_name("Coca-Cola Company") == "coca cola"


def test_screen_exact_entities_only(entity_rows_fixture):
    hits = S.screen(["Acme Widgets, Inc.", "Globex Corporation", "Initech Holdings", "Hooli Inc", "Acme"], entity_rows_fixture)
    got = {(h["queried"], h["id"]) for h in hits}
    assert ("Acme Widgets, Inc.", "1") in got             # exact normalised primary name
    assert ("Globex Corporation", "RUS0001") in got       # exact alias
    assert not any(h["id"] in ("3", "4") for h in hits)   # Individual and Vessel rows are never matched
    assert not any(h["id"] == "5" for h in hits)          # "Acme Widgets International" — no fuzzy/partial matching
    assert len(hits) == 2
    assert all(h["url"] and h["list"] and "human" in h["review"] for h in hits)
    assert S.screen(["Snowflake Inc."], entity_rows_fixture) == []


def test_parse_lists_drop_individuals():
    csl = ("_id,source,entity_number,type,programs,name,title,addresses,alt_names,source_list_url,source_information_url\n"
           "1,SDN,1,Entity,RUSSIA,ACME WIDGETS LTD,,,Acme W; ACME,https://l,https://i\n"
           "2,SDN,2,Individual,RUSSIA,John Example,,,,https://l,https://i\n"
           "3,Entity List (EL) - Bureau of Industry and Security,3,,EAR,Beta Technologies Co.,,,,https://l,\n"
           "4,Denied Persons List (DPL) - Bureau of Industry and Security,4,,,KATSUTA KEISUKE,,,,https://l,\n"
           "5,SDN,5,Vessel,X,SEA STAR,,,,https://l,\n")
    rows, dropped = S.parse_csl(csl)
    assert [r["name"] for r in rows] == ["ACME WIDGETS LTD", "Beta Technologies Co."]
    assert rows[0]["aliases"] == ["Acme W", "ACME"] and rows[1]["type"] == "Entity (inferred)"
    assert dropped == {"Individual": 1, "untyped, no corporate marker": 1, "Vessel": 1}
    uk = ("Report Date: 10-Sep-2026\n"
          "Last Updated,Unique ID,Name 6,Name 1,Name 2,Name type,Regime Name,Designation Type,Sanctions Imposed\n"
          "01/01/2026,RUS1,GLOBEX TRADING HOUSE,,,Primary Name,Russia,Entity,Asset freeze\n"
          "01/01/2026,RUS1,GLOBEX CORPORATION,,,Alias,Russia,Entity,Asset freeze\n"
          "01/01/2026,RUS2,,Ivan,Example,Primary name,Russia,Individual,Asset freeze\n")
    rows, dropped = S.parse_uk(uk)
    assert len(rows) == 1 and rows[0]["name"] == "GLOBEX TRADING HOUSE" and rows[0]["aliases"] == ["GLOBEX CORPORATION"]
    assert dropped == {"Individual": 1} and "Ivan" not in repr(rows)


def test_parse_sbd():
    page = "<h4>3 Companies</h4><table><tbody><tr><td>Cloudflare</td><td>Amazon Web Services</td><td>Cloud&nbsp;</td></tr></tbody></table>"
    assert S.parse_sbd(page) == ["Cloudflare", "Amazon Web Services", "Cloud"]


def test_gleif_choose_confident_only():
    recs = [{"lei": "A", "name": "SLACK TECHNOLOGIES, INC.", "country": "US", "entity_status": "ACTIVE", "registration_status": "LAPSED"},
            {"lei": "B", "name": "SLACK TECHNOLOGIES INDIA LLP", "country": "IN", "entity_status": "ACTIVE", "registration_status": "ISSUED"}]
    assert S.gleif_choose("Slack Technologies, LLC", "US", recs)[0] == "A"
    two = [{"lei": "X", "name": "EXAMPLE INC", "country": "US", "entity_status": "ACTIVE", "registration_status": "ISSUED"},
           {"lei": "Y", "name": "Example, Inc.", "country": "US", "entity_status": "ACTIVE", "registration_status": "ISSUED"}]
    assert S.gleif_choose("Example Inc.", "US", two)[0] is None           # ambiguous -> no match
    assert S.gleif_choose("Example Inc.", "DE", two)[0] is None           # wrong country -> no match


def test_summary_indirect_dependents(intel_fixture, deps_fixture, catalogue_fixture):
    s = S.summary(intel_fixture, deps_fixture, catalogue_fixture)
    prov = {p["provider"]: p for p in s["providers"]}
    assert prov["Snowflake"]["dependents"] == 2 and prov["Okta"]["dependents"] == 1
    snow = {x["fourth_party"]: x for x in prov["Snowflake"]["second_order"]}
    assert snow["AWS"]["path"] == "via Snowflake → AWS"
    assert snow["AWS"]["orgs"] == 2 and snow["AWS"]["indirect_only"] == 1          # o2 also uses AWS directly
    assert snow["Google Workspace"]["indirect_only"] == 2
    assert prov["Okta"]["fourth_parties"][0]["provider"] == "AWS"                  # canonicalised
    conc = {c["fourth_party"]: c for c in s["concentration"]}
    aws = conc["AWS"]
    assert aws["direct"] == 3                   # o2, o4, o5 (alias)
    assert aws["indirect_only"] == 2            # o1 via Snowflake, o3 via Okta
    assert aws["total"] == 5
    assert [c["provider"] for c in aws["carried_by"]] == ["Snowflake", "Okta"]
    assert conc["Google Workspace"]["direct"] == 0 and conc["Google Workspace"]["indirect_only"] == 2
    assert prov["GitHub"]["ownership_country"] == "US" and prov["GitHub"]["parent"]["name"] == "MICROSOFT CORPORATION"
    assert prov["Okta"]["sanctions_flag"] is None and prov["Snowflake"]["sanctions_flag"] is False
    t = s["totals"]
    # o1, o3 reach AWS only indirectly; o2 uses AWS directly but reaches Google Workspace only via Snowflake
    assert t["providers"] == 3 and t["with_fourth_parties"] == 2 and t["orgs_reached_only_indirectly"] == 3
    assert t["orgs_with_dependencies"] == 5 and t["sbd_signers"] == 3 and t["with_parent"] == 1
