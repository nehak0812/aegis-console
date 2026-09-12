"""Supplier intelligence (Exiger-inspired, passive): what AEGIS's providers themselves rely on (fourth parties), who owns
them (GLEIF), whether a provider, its aliases or its ultimate parent appears on a government sanctions / export-control
ENTITY list, and whether it signed CISA's Secure by Design pledge.

Pure functions only; the collector `aegis/collectors/supplier_intel.py` does the fetching. Rules:
* Passive: fourth parties come from the provider's own public DNS (MX, NS, TXT, SPF includes) read through public
  DNS-over-HTTPS resolvers, never from the provider's website.
* No person-level data: sanctions rows whose type is not an entity are dropped at parse time and ignored by `screen`.
* No numeric scores: every output is a fact with evidence, or a count.
"""
import csv
import html as _html
import io
import re
import unicodedata
from collections import defaultdict

from aegis.intel import fingerprints as fp

# Canonical provider name (exactly as in providers.CATALOGUE) -> primary corporate domain. Products of one company share
# the company's domain (Microsoft 365 / Azure / Intune -> microsoft.com); such siblings are never each other's fourth party.
PROVIDER_DOMAINS: dict[str, str] = {
    # data & analytics
    "Snowflake": "snowflake.com", "Databricks": "databricks.com", "MongoDB Atlas": "mongodb.com", "Confluent": "confluent.io",
    "Elastic Cloud": "elastic.co", "Redis Cloud": "redis.io", "Cloudera": "cloudera.com", "Palantir": "palantir.com",
    "Teradata": "teradata.com", "Fivetran": "fivetran.com", "Segment": "segment.com", "Mixpanel": "mixpanel.com",
    "Amplitude": "amplitude.com", "Gainsight": "gainsight.com",
    # observability
    "Datadog": "datadoghq.com", "Splunk": "splunk.com", "New Relic": "newrelic.com", "Dynatrace": "dynatrace.com",
    "PagerDuty": "pagerduty.com", "Atlassian Statuspage": "atlassian.com", "Site24x7": "site24x7.com",
    # identity
    "Okta": "okta.com", "Auth0": "auth0.com", "Ping Identity": "pingidentity.com", "OneLogin": "onelogin.com",
    "ForgeRock": "forgerock.com", "CyberArk": "cyberark.com", "SailPoint": "sailpoint.com", "Cisco Duo": "duo.com",
    "1Password": "1password.com", "LastPass": "lastpass.com",
    # HR, finance & ERP
    "Workday": "workday.com", "ServiceNow": "servicenow.com", "SAP": "sap.com", "SAP Commerce Cloud": "sap.com",
    "Oracle Cloud": "oracle.com", "Oracle Eloqua": "oracle.com", "Oracle Health": "oracle.com", "Coupa": "coupa.com",
    "ADP": "adp.com", "UKG": "ukg.com", "Paychex": "paychex.com", "Workhuman": "workhuman.com", "Docebo": "docebo.com",
    "KnowBe4": "knowbe4.com", "Qualtrics": "qualtrics.com", "Cvent": "cvent.com", "Everbridge": "everbridge.com",
    "Yardi": "yardi.com",
    # CRM, marketing, messaging
    "Salesforce": "salesforce.com", "Salesforce Pardot": "salesforce.com", "MuleSoft": "mulesoft.com",
    "Salesloft": "salesloft.com", "HubSpot": "hubspot.com", "Zendesk": "zendesk.com", "Freshworks": "freshworks.com",
    "Intercom": "intercom.com", "Twilio": "twilio.com", "Mailchimp": "mailchimp.com", "Marketo": "marketo.com",
    "Constant Contact": "constantcontact.com", "Campaign Monitor": "campaignmonitor.com", "Valimail": "valimail.com",
    "Red Sift OnDMARC": "redsift.com", "Agari": "agari.com",
    # payments & commerce
    "Stripe": "stripe.com", "Adyen": "adyen.com", "PayPal": "paypal.com", "Shopify": "shopify.com",
    # developer & collaboration
    "Atlassian": "atlassian.com", "GitHub": "github.com", "GitLab": "gitlab.com", "JFrog": "jfrog.com",
    "Slack": "slack.com", "Zoom": "zoom.us", "Cisco Webex": "webex.com", "Box": "box.com", "Dropbox": "dropbox.com",
    "DocuSign": "docusign.com", "Adobe": "adobe.com", "Miro": "miro.com", "Notion": "notion.so",
    "Smartsheet": "smartsheet.com", "OneTrust": "onetrust.com",
    # web & IR hosting
    "Q4 Inc": "q4inc.com", "Optimizely": "optimizely.com", "WP Engine": "wpengine.com", "Squarespace": "squarespace.com",
    "Webflow": "webflow.com",
    # CDN, DNS, network & endpoint security
    "Cloudflare": "cloudflare.com", "Akamai": "akamai.com", "Fastly": "fastly.com", "Imperva": "imperva.com",
    "F5 Distributed Cloud": "f5.com", "Radware": "radware.com", "Zscaler": "zscaler.com", "Netskope": "netskope.com",
    "CrowdStrike": "crowdstrike.com", "SentinelOne": "sentinelone.com", "Palo Alto Prisma Access": "paloaltonetworks.com",
    "Vercara UltraDNS": "vercara.com", "MarkMonitor": "markmonitor.com", "Com Laude": "comlaude.com",
    # clouds & device management
    "AWS": "amazon.com", "Microsoft Azure": "microsoft.com", "Microsoft 365": "microsoft.com",
    "Microsoft Intune": "microsoft.com", "Google Cloud": "google.com", "Google Workspace": "google.com",
    "IBM Cloud": "ibm.com", "Jamf": "jamf.com",
    # file transfer & MSP / RMM
    "Progress MOVEit": "progress.com", "Fortra GoAnywhere": "fortra.com", "Kiteworks": "kiteworks.com",
    "Kaseya": "kaseya.com", "ConnectWise": "connectwise.com", "SolarWinds": "solarwinds.com", "N-able": "n-able.com",
    "NinjaOne": "ninjaone.com",
    # sector platforms
    "Change Healthcare": "changehealthcare.com", "CDK Global": "cdkglobal.com", "Blue Yonder": "blueyonder.com",
    "Epic Systems": "epic.com",
    # AI providers
    "OpenAI": "openai.com", "Anthropic": "anthropic.com",
}

# Legal entity for the GLEIF lookup, with its expected legal/HQ country (ISO 3166-1 alpha-2) used only to disambiguate.
# Only names we are sure of; providers without an entry are reported as "no legal name configured", never guessed.
_MS, _GOOG, _ORCL, _SAP, _CRM, _CSCO, _TEAM = (("Microsoft Corporation", "US"), ("Google LLC", "US"), ("Oracle Corporation", "US"),
                                                ("SAP SE", "DE"), ("Salesforce, Inc.", "US"), ("Cisco Systems, Inc.", "US"),
                                                ("Atlassian Corporation", "US"))
PROVIDER_LEGAL: dict[str, tuple[str, str]] = {
    "Snowflake": ("Snowflake Inc.", "US"), "Databricks": ("Databricks, Inc.", "US"), "MongoDB Atlas": ("MongoDB, Inc.", "US"),
    "Confluent": ("Confluent, Inc.", "US"), "Elastic Cloud": ("Elastic N.V.", "NL"), "Cloudera": ("Cloudera, Inc.", "US"),
    "Palantir": ("Palantir Technologies Inc.", "US"), "Teradata": ("Teradata Corporation", "US"),
    "Mixpanel": ("Mixpanel, Inc.", "US"), "Amplitude": ("Amplitude, Inc.", "US"), "Gainsight": ("Gainsight, Inc.", "US"),
    "Datadog": ("Datadog, Inc.", "US"), "Splunk": ("Splunk Inc.", "US"), "New Relic": ("New Relic, Inc.", "US"),
    "Dynatrace": ("Dynatrace, Inc.", "US"), "PagerDuty": ("PagerDuty, Inc.", "US"), "Atlassian Statuspage": _TEAM,
    "Okta": ("Okta, Inc.", "US"), "Auth0": ("Auth0, Inc.", "US"), "Ping Identity": ("Ping Identity Corporation", "US"),
    "CyberArk": ("CyberArk Software Ltd.", "IL"), "Cisco Duo": _CSCO, "1Password": ("AgileBits Inc.", "CA"),
    "Workday": ("Workday, Inc.", "US"), "ServiceNow": ("ServiceNow, Inc.", "US"), "SAP": _SAP, "SAP Commerce Cloud": _SAP,
    "Oracle Cloud": _ORCL, "Oracle Eloqua": _ORCL, "Oracle Health": _ORCL, "Coupa": ("Coupa Software Incorporated", "US"),
    "ADP": ("Automatic Data Processing, Inc.", "US"), "Paychex": ("Paychex, Inc.", "US"), "KnowBe4": ("KnowBe4, Inc.", "US"),
    "Everbridge": ("Everbridge, Inc.", "US"),
    "Salesforce": _CRM, "Salesforce Pardot": _CRM, "MuleSoft": ("MuleSoft, LLC", "US"), "Slack": ("Slack Technologies, LLC", "US"),
    "HubSpot": ("HubSpot, Inc.", "US"), "Zendesk": ("Zendesk, Inc.", "US"), "Freshworks": ("Freshworks Inc.", "US"),
    "Twilio": ("Twilio Inc.", "US"), "Mailchimp": ("The Rocket Science Group LLC", "US"), "Marketo": ("Marketo, Inc.", "US"),
    "Constant Contact": ("Constant Contact, Inc.", "US"),
    "Stripe": ("Stripe, Inc.", "US"), "Adyen": ("Adyen N.V.", "NL"), "PayPal": ("PayPal Holdings, Inc.", "US"),
    "Shopify": ("Shopify Inc.", "CA"),
    "Atlassian": _TEAM, "GitHub": ("GitHub, Inc.", "US"), "GitLab": ("GitLab Inc.", "US"), "JFrog": ("JFrog Ltd.", "IL"),
    "Zoom": ("Zoom Communications, Inc.", "US"), "Cisco Webex": _CSCO, "Box": ("Box, Inc.", "US"),
    "Dropbox": ("Dropbox, Inc.", "US"), "DocuSign": ("DocuSign, Inc.", "US"), "Adobe": ("Adobe Inc.", "US"),
    "Miro": ("RealtimeBoard, Inc.", "US"), "Notion": ("Notion Labs, Inc.", "US"), "Smartsheet": ("Smartsheet Inc.", "US"),
    "OneTrust": ("OneTrust LLC", "US"),
    "Q4 Inc": ("Q4 Inc.", "CA"), "Squarespace": ("Squarespace, Inc.", "US"), "Webflow": ("Webflow, Inc.", "US"),
    "Cloudflare": ("Cloudflare, Inc.", "US"), "Akamai": ("Akamai Technologies, Inc.", "US"), "Fastly": ("Fastly, Inc.", "US"),
    "Imperva": ("Imperva, Inc.", "US"), "F5 Distributed Cloud": ("F5, Inc.", "US"), "Radware": ("Radware Ltd.", "IL"),
    "Zscaler": ("Zscaler, Inc.", "US"), "Netskope": ("Netskope, Inc.", "US"), "CrowdStrike": ("CrowdStrike Holdings, Inc.", "US"),
    "SentinelOne": ("SentinelOne, Inc.", "US"), "Palo Alto Prisma Access": ("Palo Alto Networks, Inc.", "US"),
    "MarkMonitor": ("MarkMonitor Inc.", "US"),
    "AWS": ("Amazon Web Services, Inc.", "US"), "Microsoft Azure": _MS, "Microsoft 365": _MS, "Microsoft Intune": _MS,
    "Google Cloud": _GOOG, "Google Workspace": _GOOG, "IBM Cloud": ("International Business Machines Corporation", "US"),
    "Jamf": ("Jamf Holding Corp.", "US"),
    "Progress MOVEit": ("Progress Software Corporation", "US"), "Fortra GoAnywhere": ("Fortra, LLC", "US"),
    "ConnectWise": ("ConnectWise, LLC", "US"), "SolarWinds": ("SolarWinds Corporation", "US"), "N-able": ("N-able, Inc.", "US"),
    "Change Healthcare": ("Change Healthcare Inc.", "US"), "CDK Global": ("CDK Global, Inc.", "US"),
    "Blue Yonder": ("Blue Yonder Group, Inc.", "US"), "Epic Systems": ("Epic Systems Corporation", "US"),
    "Anthropic": ("Anthropic PBC", "US"),
}

# Corporate-group names used when matching published name lists (the CISA pledge lists "Cisco", not "Cisco Duo").
GROUP_NAMES: dict[str, list[str]] = {"Cisco Duo": ["Cisco"], "Cisco Webex": ["Cisco"]}

SCREEN_NOTE = ("Screening signal only: an exact normalised-name match against a government entity list. It is NOT a "
               "determination; a human must review the listed entry (address, programme, identifiers) before any action.")


# ------------------------------------------------------------------ names
_SUFFIXES = {"inc", "incorporated", "llc", "ltd", "plc", "corp", "corporation", "gmbh", "ag", "sa", "nv", "bv", "co",
             "company", "holdings", "holding", "group", "limited", "se", "pbc", "lp", "llp", "pty", "pte"}


def _flat(s: str | None) -> str:
    """Lower-case, accents removed, punctuation removed ("S.A." -> "sa", "Co.," -> "co"), whitespace collapsed."""
    s = unicodedata.normalize("NFKD", s or "").encode("ascii", "ignore").decode()
    s = s.lower().replace("&", " and ").replace(".", "").replace("'", "").replace("’", "")
    return " ".join(re.sub(r"[^a-z0-9]+", " ", s).split())


def norm_name(s: str | None) -> str:
    """Normalise a legal name for exact comparison: lower-case, punctuation stripped, a leading "the" and trailing legal-form
    suffixes (inc, llc, ltd, plc, corp, corporation, gmbh, ag, sa, nv, bv, co, company, holdings, group, limited, …) removed.
    "PayPal Holdings, Inc." -> "paypal"; "Elastic N.V." -> "elastic"; "The Rocket Science Group LLC" -> "rocket science"."""
    toks = _flat(s).split()
    if len(toks) > 1 and toks[0] == "the":
        toks = toks[1:]
    while len(toks) > 1 and toks[-1] in _SUFFIXES:
        toks.pop()
    return " ".join(toks)


# ------------------------------------------------------------------ fourth parties
def spf_includes(txts: list[str] | None) -> list[str]:
    """include: and redirect= targets of the SPF record among `txts`."""
    rec = next((t for t in txts or [] if t.lower().startswith("v=spf1")), None)
    if not rec:
        return []
    out = []
    for tok in rec.split():
        m = re.match(r"(?i)^[+~?-]?include:(\S+)$", tok) or re.match(r"(?i)^redirect=(\S+)$", tok)
        if m:
            out.append(m.group(1).lower().rstrip("."))
    return list(dict.fromkeys(out))


_GENERIC = {"cloud", "data", "email", "mail", "secure", "security", "services", "business", "the", "access", "global"}
_FP_TABLES = {"mx": fp.MX_C, "ns": fp.NS_C, "txt": fp.TXT_C, "spf": fp.SPF_C}


def _tok(s: str) -> str:
    t = _flat(s).split()
    return t[0] if t else ""


def fourth_parties(provider: str, dns_records: dict, catalogue, exclude=None, fingerprints: bool = True) -> list[dict]:
    """Providers that `provider` itself relies on, from its own public DNS — the same matching AEGIS applies to monitored
    organisations: the provider catalogue first (as pipeline.derive_dependencies), then the surface-scan fingerprint tables.

    dns_records: {"domain", "mx": [hosts], "ns": [hosts], "txt": [strings], "spf": [include domains],
                  "spf_nested": {include: [includes of that include]}, "sources": {"mx"|"ns"|"txt"|"spf:<include>": url}}
    Self-matches are excluded: the provider, its same-domain siblings (Microsoft 365 / Azure), names in `exclude`, and
    vendors of the same corporate group (e.g. "Amazon SES" or "AWS Route 53" for AWS on amazon.com, "Google" for google.com).
    Returns [{provider, category, evidence, source}] — one entry per fourth party, first evidence kept."""
    domain = (dns_records.get("domain") or PROVIDER_DOMAINS.get(provider) or "").lower()
    self_names = {provider} | set(exclude or ())
    if domain:
        self_names |= {p for p, d in PROVIDER_DOMAINS.items() if d == domain}
    self_toks = {t for n in self_names for t in _flat(n).split() if len(t) >= 3} | ({domain.split(".")[0]} if domain else set())
    self_toks -= _GENERIC
    sources = dns_records.get("sources") or {}
    out, seen = [], set()

    def add(kind, value, evidence, source):
        v = (value or "").lower().rstrip(".")
        if domain and (v == domain or v.endswith("." + domain)):  # the provider's own infrastructure
            return
        hit = catalogue.match(kind, value)
        if not hit and fingerprints and kind in _FP_TABLES:
            h = fp.match(_FP_TABLES[kind], value)
            if h:
                hit = (catalogue.canonical(h[0]) or h[0], h[1])
        if not hit:
            return
        name, cat = hit
        if name in self_names or _tok(name) in self_toks or name in seen:
            return
        seen.add(name)
        # kind: mx / ns / spf = infrastructure the provider runs on; txt = an account verified with that service (weaker signal)
        out.append({"provider": name, "category": cat, "kind": kind, "evidence": evidence[:200], "source": source})

    for m in dns_records.get("mx") or []:
        add("mx", m, f"MX {m}", sources.get("mx"))
    for n in dns_records.get("ns") or []:
        add("ns", n, f"NS {n}", sources.get("ns"))
    for t in dns_records.get("txt") or []:
        if not t.lower().startswith("v=spf1"):
            add("txt", t, f"TXT {t[:60]}…" if len(t) > 60 else f"TXT {t}", sources.get("txt"))
    for i in dns_records.get("spf") or []:
        add("spf", i, f"SPF include:{i}", sources.get("txt"))
    for parent, kids in (dns_records.get("spf_nested") or {}).items():
        for k in kids or []:
            add("spf", k, f"SPF include:{k} (via include:{parent})", sources.get(f"spf:{parent}"))
    return out


# ------------------------------------------------------------------ ownership (GLEIF)
def gleif_choose(legal_name: str, country: str | None, records: list[dict]) -> tuple[str | None, str]:
    """Pick one LEI only when the match is confident. records: [{lei, name, country, hq_country, entity_status,
    registration_status}]. Tier 1 = identical punctuation-free name, tier 2 = identical norm_name; within a tier the legal or
    HQ country must equal `country` and the entity must be ACTIVE. More than one survivor -> the single ISSUED one, else none."""
    flat, nn = _flat(legal_name), norm_name(legal_name)
    reason = "no exact legal-name match"
    for tier in ([r for r in records if _flat(r.get("name")) == flat], [r for r in records if norm_name(r.get("name")) == nn]):
        if not tier:
            continue
        if country:
            tier = [r for r in tier if country in (r.get("country"), r.get("hq_country"))]
        tier = [r for r in tier if (r.get("entity_status") or "ACTIVE") == "ACTIVE"]
        if len(tier) > 1:
            issued = [r for r in tier if r.get("registration_status") == "ISSUED"]
            tier = issued if len(issued) == 1 else tier
        if len(tier) == 1:
            return tier[0]["lei"], "single exact legal-name match"
        reason = "ambiguous: several LEIs share the name" if tier else "exact name found, but not an active entity in the expected country"
    return None, reason


# ------------------------------------------------------------------ sanctions / export-control lists (entities only)
_CORP_FORM = re.compile(
    r"\b(inc|incorporated|llc|ltd|limited|plc|corp|corporation|co|company|gmbh|ag|sa|nv|bv|jsc|pjsc|ojsc|cjsc|ooo|oao|zao|"
    r"llp|pte|pvt|srl|sarl|spa|kg|bhd|fze|fzco|fzc|group|holdings?|industr(?:y|ies|ial)|technolog(?:y|ies)|electronics?|"
    r"trading|enterprises?|international|systems?|solutions|institute|university|academy|laborator(?:y|ies)|research|"
    r"bureau|cent(?:er|re)|factory|bank|shipping|logistics|aviation|airlines?|engineering|manufacturing|import|export)\b", re.I)


def _csv_rows(text: str):
    csv.field_size_limit(2**31 - 1)
    return csv.reader(io.StringIO(text))


def parse_csl(text: str) -> tuple[list[dict], dict]:
    """US Consolidated Screening List CSV (data.trade.gov) -> ENTITY rows only.
    type == "Entity" is kept. Rows with an empty type (the BIS Entity List, DPL, ITAR debarred, UVL, ISN and MEU leave it
    blank and mix people with companies) are kept only when the name carries a corporate form or organisation word
    ("Ltd", "Co", "Institute", "Technologies" …), and marked type "Entity (inferred)". Individuals, vessels, aircraft and
    untyped rows without such a marker are dropped before anything is returned."""
    rd = _csv_rows(text.lstrip("﻿"))
    head = next(rd, [])
    ix = {h: i for i, h in enumerate(head)}
    need = {"type", "name", "source", "programs", "alt_names"}
    if not need <= set(ix):
        raise ValueError(f"CSL columns changed: missing {sorted(need - set(ix))}")
    g = lambda r, k: (r[ix[k]] if k in ix and ix[k] < len(r) else "").strip()  # noqa: E731
    out, dropped = [], defaultdict(int)
    for r in rd:
        typ, name = g(r, "type"), g(r, "name")
        if not name:
            continue
        if typ == "Entity":
            t = "Entity"
        elif not typ and _CORP_FORM.search(name.replace(".", "")):
            t = "Entity (inferred)"
        else:
            dropped[typ or "untyped, no corporate marker"] += 1
            continue
        out.append({"name": name, "aliases": [a.strip() for a in g(r, "alt_names").split(";") if a.strip()], "type": t,
                    "list": "US Consolidated Screening List", "source": g(r, "source"), "programme": g(r, "programs"),
                    "id": g(r, "_id") or g(r, "entity_number"),
                    "url": g(r, "source_information_url") or g(r, "source_list_url")})
    return out, dict(dropped)


def parse_uk(text: str, url: str = "https://sanctionslist.fcdo.gov.uk/docs/UK-Sanctions-List.csv") -> tuple[list[dict], dict]:
    """UK Sanctions List CSV (FCDO) -> ENTITY designations only, one row per Unique ID with its aliases.
    The file starts with a "Report Date:" line; entity names are in "Name 6". Individuals and ships are dropped."""
    rd = _csv_rows(text.lstrip("﻿"))
    head = None
    for r in rd:
        if r and r[0].strip() == "Last Updated":
            head = r
            break
    if not head:
        raise ValueError("UK sanctions list: header row not found")
    ix = {h.strip(): i for i, h in enumerate(head)}
    need = {"Unique ID", "Name 6", "Name type", "Designation Type", "Regime Name"}
    if not need <= set(ix):
        raise ValueError(f"UK sanctions list columns changed: missing {sorted(need - set(ix))}")
    g = lambda r, k: (r[ix[k]] if k in ix and ix[k] < len(r) else "").strip()  # noqa: E731
    ents: dict[str, dict] = {}
    dropped = defaultdict(set)
    for r in rd:
        uid, typ = g(r, "Unique ID"), g(r, "Designation Type")
        if not uid:
            continue
        if typ != "Entity":
            dropped[typ or "untyped"].add(uid)
            continue
        name = g(r, "Name 6") or " ".join(x for x in (g(r, f"Name {i}") for i in range(1, 6)) if x)
        if not name:
            continue
        e = ents.setdefault(uid, {"name": None, "aliases": [], "type": "Entity", "list": "UK Sanctions List",
                                  "source": "UK FCDO", "programme": g(r, "Regime Name"), "id": uid, "url": url,
                                  "sanctions_imposed": g(r, "Sanctions Imposed")})
        nt = g(r, "Name type").lower()
        if nt.startswith("primary name") and "variation" not in nt and not e["name"]:
            e["name"] = name
        elif name not in e["aliases"]:
            e["aliases"].append(name)
    out = []
    for e in ents.values():
        if not e["name"]:
            e["name"] = e["aliases"].pop(0)
        e["aliases"] = [a for a in e["aliases"] if a != e["name"]]
        out.append(e)
    return out, {k: len(v) for k, v in dropped.items()}


def _is_entity(row: dict) -> bool:
    return (row.get("type") or "").strip().lower().startswith("entity")


def screen(names, entity_rows: list[dict]) -> list[dict]:
    """Screen `names` against sanctions / export-control ENTITY rows. Conservative by design:
    * a match needs the normalised name (norm_name) of a queried name to EQUAL the normalised primary name or one exact
      alias of a listed entity — no fuzzy, partial or token matching;
    * rows whose type is not an entity (Individual, Vessel, Aircraft, blank) are ignored, so no person is ever matched;
    * queried names that normalise to fewer than 3 characters are skipped.
    The result is a SCREENING SIGNAL that needs human review (see SCREEN_NOTE), not a finding.
    Returns [{queried, key, matched, match, list, source, programme, id, url, review}]."""
    want: dict[str, str] = {}
    for n in names or []:
        k = norm_name(n)
        if len(k) >= 3:
            want.setdefault(k, n)
    out, seen = [], set()
    if not want:
        return out
    for r in entity_rows or []:
        if not _is_entity(r):
            continue
        for cand, how in [(r.get("name"), "primary name")] + [(a, "alias") for a in r.get("aliases") or []]:
            k = norm_name(cand)
            if k in want:
                key = (r.get("list"), r.get("id") or r.get("name"), k)
                if key not in seen:
                    seen.add(key)
                    out.append({"queried": want[k], "key": k, "matched": cand, "match": f"exact normalised {how}",
                                "list": r.get("list"), "source": r.get("source"), "programme": r.get("programme"),
                                "id": r.get("id"), "url": r.get("url"), "review": SCREEN_NOTE})
                break
    return out


# ------------------------------------------------------------------ CISA Secure by Design pledge
def parse_sbd(page: str) -> list[str]:
    """Signer names from the CISA 'Secure by Design Pledge Signers' page (a table of company names, one per cell)."""
    names = []
    for tbl in re.findall(r"<table[^>]*>(.*?)</table>", page or "", re.S | re.I):
        for cell in re.findall(r"<td[^>]*>(.*?)</td>", tbl, re.S | re.I):
            n = " ".join(_html.unescape(re.sub(r"<[^>]+>", " ", cell)).replace("\xa0", " ").split())
            if n and n not in names:
                names.append(n)
    return names


# ------------------------------------------------------------------ API summary
def summary(intel: dict, deps, catalogue=None) -> dict:
    """What the supplier-intelligence endpoint returns.
    intel: the `supplier_intel` kv value. deps: rows of (org_id, vendor, category) from `dependency` (dicts or tuples);
    vendor names are canonicalised with `catalogue` when given ("Amazon Web Services" -> "AWS").
    * providers: dependents (distinct orgs), fourth parties, and the second-order exposure each fourth party implies
      ("via Snowflake → AWS": the Snowflake dependents, and how many of them do not use AWS directly), ownership, sanctions
      flag (None = not screened), SbD pledge;
    * concentration: per fourth party, orgs depending on it directly, orgs reaching it ONLY indirectly through one of their
      providers, and which providers carry it;
    * totals. Counts only — no scores."""
    def canon(v):
        return ((catalogue.canonical(v) if catalogue else None) or v) if v else v

    orgs_of: dict[str, set] = defaultdict(set)
    cat_of: dict[str, str] = {}
    for d in deps or []:
        oid, vendor, category = (d.get("org_id"), d.get("vendor"), d.get("category")) if isinstance(d, dict) else (tuple(d) + (None, None))[:3]
        v = canon(vendor)
        if oid and v:
            orgs_of[v].add(oid)
            cat_of.setdefault(v, category)
    carriers: dict[str, set] = defaultdict(set)
    fp_cat: dict[str, str] = {}
    fp_kinds: dict[str, set] = defaultdict(set)
    providers = []
    for name in sorted(intel or {}):
        e = intel[name] or {}
        mine = orgs_of.get(name, set())
        second, fps = [], []
        for f in e.get("fourth_parties") or []:
            fname = canon(f.get("provider"))
            if not fname or fname == name:
                continue
            carriers[fname].add(name)
            fp_cat.setdefault(fname, f.get("category"))
            if f.get("kind"):
                fp_kinds[fname].add(f["kind"])
            fps.append({**f, "provider": fname})
            second.append({"fourth_party": fname, "path": f"via {name} → {fname}", "orgs": len(mine),
                           "indirect_only": len(mine - orgs_of.get(fname, set()))})
        parent = e.get("parent") or None
        sanc = e.get("sanctions")
        providers.append({
            "provider": name, "category": e.get("category") or cat_of.get(name), "domain": e.get("domain"),
            "dependents": len(mine), "fourth_parties": fps, "second_order": sorted(second, key=lambda s: -s["indirect_only"]),
            "legal_name": e.get("legal_name"), "lei": e.get("lei"), "country": e.get("country"),
            "parent": ({"name": parent.get("name"), "country": parent.get("country"), "lei": parent.get("lei")} if parent else None),
            "ownership_country": (parent or {}).get("country") or e.get("country"),
            "sanctions_flag": (bool(sanc) if sanc is not None else None), "sanctions": sanc or [],
            "sbd_pledge": e.get("sbd_pledge"), "checked": e.get("checked"), "sources": e.get("sources"),
        })
    concentration = []
    reached_indirect: set = set()
    for f, provs in carriers.items():
        direct = orgs_of.get(f, set())
        via = set().union(*(orgs_of.get(p, set()) for p in provs))
        only = via - direct
        reached_indirect |= only
        concentration.append({
            "fourth_party": f, "category": fp_cat.get(f) or cat_of.get(f), "direct": len(direct), "indirect_only": len(only),
            "total": len(direct | via),
            # record kinds behind the provider->fourth-party links: mx/ns/spf = infrastructure, txt = verified account only
            "evidence_kinds": sorted(fp_kinds.get(f, ())),
            "infrastructure": bool(fp_kinds.get(f, set()) & {"mx", "ns", "spf"}),
            "carried_by": sorted(({"provider": p, "dependents": len(orgs_of.get(p, set()))} for p in provs),
                                 key=lambda c: (-c["dependents"], c["provider"])),
        })
    concentration.sort(key=lambda c: (-c["total"], -c["indirect_only"], c["fourth_party"]))
    providers.sort(key=lambda p: (-p["dependents"], p["provider"]))
    all_orgs = set().union(*orgs_of.values()) if orgs_of else set()
    totals = {
        "providers": len(providers),
        "with_fourth_parties": sum(1 for p in providers if p["fourth_parties"]),
        "fourth_party_links": sum(len(p["fourth_parties"]) for p in providers),
        "distinct_fourth_parties": len(concentration),
        "with_lei": sum(1 for p in providers if p["lei"]),
        "with_parent": sum(1 for p in providers if p["parent"]),
        "sanctions_flagged": sum(1 for p in providers if p["sanctions_flag"]),
        "sanctions_screened": sum(1 for p in providers if p["sanctions_flag"] is not None),
        "sbd_signers": sum(1 for p in providers if p["sbd_pledge"]),
        "orgs_with_dependencies": len(all_orgs),
        "orgs_reached_only_indirectly": len(reached_indirect),
    }
    return {"providers": providers, "concentration": concentration, "totals": totals, "screening_note": SCREEN_NOTE}
