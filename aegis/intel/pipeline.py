"""The intelligence layer. Runs after collectors, fully deterministic and explainable:

1. enrich    — tag recent items with actors, vendors, victims and monitored organisations
2. incidents — cluster leak listings, filings, breaches, news and exploitation reports into incidents
3. impact    — link each incident to the organisations it could affect, with the reason and evidence
4. findings  — evaluate every rule in aegis.rating against each organisation's evidence
"""
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from aegis import db, playbooks
from aegis.actions import TERMINAL, actionable, due_date, entry, sla_days, suppressed
from aegis.intel.entities import matcher, norm, reg_domain
from aegis.intel import fingerprints as fp
from aegis.intel import prevent
from aegis.intel.themes import themes_for_ai
from aegis.rating import RANK, RISKY_PORTS, cap_for_confidence, confidence_for, rule, worst

UTC = timezone.utc


def ts(days: int = 0) -> str:
    return (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def days_since(s: str | None) -> float:
    if not s:
        return 1e9
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00").replace(" ", "T"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=UTC)
        return max(0.0, (datetime.now(UTC) - d).total_seconds() / 86400)
    except ValueError:
        return 1e9


def hid(*parts) -> str:
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:16]


# ============================================================== 1. enrichment
COMMON_WORDS = {"play", "hunters", "medusa", "rhysida", "fog", "lynx", "cicada", "nova", "safe", "embargo", "interlock", "kraken",
                "chaos", "apt", "everest", "money", "dragon", "hive", "bianlian", "trigona", "rook", "cloak", "sarcoma", "termite",
                "orca", "raworld", "helldown", "blackout", "pear", "morpheus", "arcus", "ransomhub", "spider", "bear", "panda",
                "target", "sphinx", "wolf", "tiger", "leopard", "kitten", "jackal", "leak", "data", "group", "team", "the",
                "anonymous", "killnet", "unknown", "stealer", "sector", "global", "secret", "insider", "direct"}
RW_CONTEXT = re.compile(r"ransomware|extortion|leak site|gang|claimed|claims|threat actor|operation", re.I)
VICTIM_PATTERNS = [  # "attack on X" first, so "FBI investigates cyberattack on Micro-Comm" names Micro-Comm, not the FBI
    re.compile(r"(?:ransomware|cyber-?attack|cyber ?incident|data breach|breach|hack|attack|leak)\s+(?:on|at|of|hits|against|targeting|disrupts)\s+(?P<v>[A-Z][\w&.'’\- ]{2,60}?)(?=[,:;.]|\s+(?:exposes|leaves|disrupts|affects|impacts|compromises|leads|forces|after|in|as)\b|$)", re.I),
    re.compile(r"^(?P<v>[A-Z][\w&.,'’\- ]{2,60}?)\s+(?:confirms|discloses|says|reports|notifies|investigating|investigates|warns|suffers|hit by|hit with|targeted by|struck by|reveals)\b.*\b(?:breach|cyberattack|cyber attack|attack|incident|ransomware|hack(?:ed|ers)?|outage|leak|intrusion|stolen|stole)\b", re.I),
    re.compile(r"^(?P<v>[A-Z][\w&.'’\- ]{2,50}?)\s+(?:data breach|cyberattack|cyber attack|ransomware attack|hack|breach)\b", re.I),
]
BAD_VICTIMS = re.compile(r"^(the|a|an|new|how|why|what|this|these|us|uk|eu|hackers?|cybercriminals?|criminals|attackers?|threat actors?|researchers?|police|authorities|feds?|ransomware|cyber|report|data|critical|major|massive|global|chinese|russian|iranian|north korean|microsoft patch|more|over|nearly|about|up to|\d)\b", re.I)
# vendors reporting a flaw in their own product are not victims
VENDOR_ADVISORY = re.compile(r"\b(flaw|bug|vulnerabilit|zero-day|0-day|patch(es|ed)?|CVE-\d|security update|exploited in attacks)\b", re.I)
TRAILING_NOISE = re.compile(r"\s+(supply chain|data|customer|customers|cyber|security|email|network|systems?|platform|incident)$", re.I)
AGENCIES = re.compile(r"^(fbi|cisa|nsa|doj|dhs|police|europol|interpol|nca|ncsc|sec|ftc|ico|government|the government)$", re.I)
VERBISH = re.compile(r"\b(probes?|investigat\w*|possible|alleged|says|warns|claims?|confirms?)\b", re.I)
DESCRIPTOR_PREFIX = re.compile(r"^(?:[A-Z][a-z]+\s+)?(?:giant|firm|company|maker|provider|operator|retailer|chipmaker|insurer|lender|bank|group)\s+", re.I)


class Dicts:
    def __init__(self):
        acts = db.q("SELECT id, name, aliases, crowdstrike, kind FROM actor")
        terms, self.actor_kind = {}, {}
        for a in acts:
            names = [a["name"], a.get("crowdstrike") or ""] + list(a.get("aliases") or [])
            for n in names:
                n = (n or "").strip()
                if len(n) < 4 or n.lower() in COMMON_WORDS or n.isdigit():
                    continue
                terms.setdefault(n, a["id"])
            self.actor_kind[a["id"]] = a["kind"]
        pats = sorted(terms, key=len, reverse=True)
        self.actor_map = {p.lower(): terms[p] for p in pats}
        self.actor_rx = re.compile(r"(?<![\w-])(" + "|".join(re.escape(p) for p in pats) + r")(?![\w-])", re.I) if pats else None
        self.actor_name = {a["id"]: a["name"] for a in acts}
        vendors = {(r["vendor"] or "").strip() for r in db.q("SELECT DISTINCT vendor FROM vuln WHERE kev_added IS NOT NULL")}
        vendors |= {r["vendor"] for r in db.q("SELECT DISTINCT vendor FROM dependency")}
        vendors |= {"Okta", "Snowflake", "Salesforce", "Salesloft", "Zoom", "Slack", "Atlassian", "Cloudflare", "GitHub", "Twilio",
                    "Workday", "ServiceNow", "SAP", "Oracle", "Ivanti", "Fortinet", "Citrix", "SonicWall", "CrowdStrike", "SolarWinds",
                    "Kaseya", "MOVEit", "Progress Software", "CDK Global", "Change Healthcare", "Blue Yonder", "Collins Aerospace",
                    "Cleo", "ConnectWise", "Veeam", "VMware", "Broadcom", "Palo Alto Networks", "Cisco", "Microsoft", "Google", "AWS",
                    "Amazon Web Services", "Azure", "Zscaler", "Proofpoint", "Mimecast", "Dropbox", "Box", "HubSpot", "Datadog", "Akamai"}
        vendors = {v for v in vendors if v and len(v) >= 3 and v.lower() not in {"the", "apple", "google", "microsoft", "n/a"}} | {"Apple", "Google", "Microsoft"}
        vp = sorted(vendors, key=len, reverse=True)
        self.vendor_rx = re.compile(r"(?<![\w-])(" + "|".join(re.escape(v) for v in vp) + r")(?![\w-])")
        self.vendor_canon = {v.lower(): v for v in vp}


def extract_victim(title: str) -> str | None:
    """Named organisation that suffered the incident — never a person, never a vendor announcing its own flaw."""
    if not title or VENDOR_ADVISORY.search(title):
        return None
    for rx in VICTIM_PATTERNS:
        m = rx.search(title)
        if not m:
            continue
        v = m.group("v").strip(" .,-'’")
        if "’s " in v or "'s " in v:  # possessive → usually a person or a role ("CIA's …")
            return None
        # "Employee benefits platform Paylogix" → "Paylogix"; purely generic descriptors → no victim
        words = v.split()
        lower_idx = [i for i, w in enumerate(words) if w[:1].islower()]
        if lower_idx:
            words = words[lower_idx[-1] + 1:]
            if not words:
                return None
            v = " ".join(words)
        v = DESCRIPTOR_PREFIX.sub("", v) if len(v.split()) > 2 else v   # "Healthcare Giant McKesson" → "McKesson"
        prev = None
        while prev != v:
            prev, v = v, TRAILING_NOISE.sub("", v).strip()
        if AGENCIES.match(v) or VERBISH.search(v):
            continue
        if 3 <= len(v) <= 60 and not BAD_VICTIMS.match(v) and len(v.split()) <= 6:
            return v
    return None


def enrich(days: int = 120) -> int:
    matcher.build()
    D = Dicts()
    rows = db.q("SELECT id, kind, title, summary, entities, org_ids, themes FROM item WHERE published > ?", (ts(days),))
    c = db.conn()
    for r in rows:
        text = f"{r['title']}. {r['summary'] or ''}"
        ent = r.get("entities") or {}
        actors = []
        if D.actor_rx:
            for m in D.actor_rx.finditer(text):
                aid = D.actor_map.get(m.group(1).lower())
                if not aid or aid in actors:
                    continue
                if D.actor_kind.get(aid) == "ransomware" and not RW_CONTEXT.search(text):
                    continue
                actors.append(aid)
        ent["actors"] = actors[:8]
        ent["vendors"] = sorted({D.vendor_canon.get(m.group(1).lower(), m.group(1)) for m in D.vendor_rx.finditer(text)} |
                                set(ent.get("vendors") or []))[:10]
        if r["kind"] in ("news", "forum", "chatter", "advisory"):
            ent["victim"] = extract_victim(r["title"])
        org_ids = list(r.get("org_ids") or [])
        if r["kind"] != "filing":
            org_ids = matcher.mentions(r["title"]) or matcher.mentions((r["summary"] or "")[:300])
            if ent.get("victim"):
                oid, _ = matcher.resolve(ent["victim"])
                if oid and oid not in org_ids:
                    org_ids.insert(0, oid)
        c.execute("UPDATE item SET entities=?, org_ids=? WHERE id=?", (json.dumps(ent), json.dumps(org_ids[:6]), r["id"]))
    c.commit()
    # AI Incident Database reports carry an MIT taxonomy subdomain rather than the prose the
    # theme patterns match, so most arrive with no theme at all and never reach the analyst
    # heatmap. Tag them from the taxonomy instead. Not limited to the enrich window: these are
    # tagged once and then left alone.
    for r in db.q("SELECT id, entities, themes FROM item WHERE kind='ai_incident'"):
        want = themes_for_ai((r.get("entities") or {}).get("mit"))
        have = r.get("themes") or []
        if set(want) - set(have):
            c.execute("UPDATE item SET themes=? WHERE id=?", (json.dumps(sorted(set(have) | set(want))), r["id"]))
    c.commit()
    # re-resolve leak rows now that the universe and subsidiaries are known
    for l in db.q("SELECT id, victim, domain, org_id FROM leak WHERE org_id IS NULL AND kind != 'stealer'"):
        oid, how = matcher.resolve(l["victim"], l["domain"] or "")
        if oid:
            c.execute("UPDATE leak SET org_id=?, match=? WHERE id=?", (oid, how, l["id"]))
    c.commit()
    return len(rows)


# ============================================================== 2. incidents
INCIDENT_THEMES = {"Ransomware & extortion", "Data breach & leak", "DDoS", "Supply-chain compromise", "Zero-day exploitation",
                   "Destructive / wiper", "Business email compromise", "Account takeover", "Resilience & outages"}
RW_SECTOR = {  # ransomware.live 'activity' → GICS sector
    "Healthcare": "Health Care", "Financial Services": "Financials", "Finance": "Financials", "Technology": "Information Technology",
    "Manufacturing": "Industrials", "Construction": "Industrials", "Transportation/Logistics": "Industrials",
    "Business Services": "Industrials", "Retail": "Consumer Discretionary", "Consumer Services": "Consumer Discretionary",
    "Hospitality and Tourism": "Consumer Discretionary", "Agriculture and Food Production": "Consumer Staples",
    "Energy": "Energy", "Telecommunication": "Communication Services", "Public Sector": None, "Education": None,
}


AI_ACTOR = re.compile(r"\b(AI (model|agent|hacking|system)|its AI|AI models?|autonomous agent|Claude|ChatGPT|Gemini|LLM|Copilot)\b", re.I)


def _looks_domain(s: str | None) -> bool:
    return bool(re.fullmatch(r"[\w-]+(\.[\w-]+)+", (s or "").strip().lower()))


def build_incidents(days: int = 90) -> int:
    since = ts(days)
    orgs = {o["id"]: o for o in db.q("SELECT id, name, sector, country, domain FROM org")}
    aname = {a["id"]: a["name"] for a in db.q("SELECT id, name FROM actor")}  # items carry actor ids; incidents show names
    groups: dict[str, dict] = {}

    def g(key, **init):
        if key not in groups:
            groups[key] = {"key": key, "sources": [], "item_ids": [], "leak_ids": [], "vendors": set(), "actors": set(), "cves": set(),
                           "sectors": set(), "countries": set(), "themes": Counter(), "kinds": Counter(), **init}
        return groups[key]

    def src(G, publisher, url, title, published, typ):
        G["sources"].append({"publisher": publisher, "url": url, "title": title, "published": published, "type": typ})

    # leak-site listings, forum claims, breaches, DDoS targeting
    for l in db.q("SELECT * FROM leak WHERE published > ? AND kind IN ('leaksite','forum','breach')", (since,)):
        if "*" in (l["victim"] or "") and not l.get("org_id"):  # partially redacted names cannot be attributed
            continue
        if _looks_domain(l["victim"]):
            l["victim"] = l["victim"].lower()
        key = f"org:{l['org_id']}" if l.get("org_id") else "v:" + re.sub(r"[^a-z0-9]", "", norm(reg_domain(l["domain"]).split(".")[0] if l.get("domain") else l["victim"]))
        if len(key) < 5:
            continue
        G = g(key, victim=(orgs.get(l["org_id"], {}).get("name") if l.get("org_id") else l["victim"]), victim_org_id=l.get("org_id"))
        typ = {"leaksite": "Leak-site listing", "forum": "Dark-web claim", "breach": "Breach catalogue"}[l["kind"]]
        src(G, {"leaksite": f"{l['actor']} leak site (via {', '.join((l.get('extra') or {}).get('sources', [l['source_id']]))})",
                "forum": (l.get("extra") or {}).get("publisher", "Dark-web reporting"), "breach": "Have I Been Pwned"}[l["kind"]],
            l["url"], l["title"], l["published"], typ)
        G["leak_ids"].append(l["id"])
        G["kinds"][{"leaksite": "Ransomware & extortion", "forum": "Dark-web sale / leak claim", "breach": "Data breach"}[l["kind"]]] += 2
        if l.get("actor"):
            G["actors"].add(l["actor"])
        if l.get("country"):
            G["countries"].add(l["country"])
        if l.get("sector"):
            G["sectors"].add(l["sector"])
    # DDoSia: one incident per day of target lists
    for r in db.q("SELECT substr(published,1,10) d, count(*) n FROM leak WHERE kind='ddos' AND published > ? GROUP BY 1", (ts(30),)):
        day, n = r["d"], r["n"]
        G = g(f"ddos:{day}", victim=None, victim_org_id=None, title=f"NoName057(16) DDoS campaign — {n} targeted domains ({day})")
        G["kinds"]["DDoS / hacktivism"] += 5
        G["actors"].add("NoName057(16)")
        src(G, "CIRCL witha.name (DDoSia configs)", "https://witha.name/", f"{n} domains on the DDoSia target list", day + "T00:00:00Z", "Target list")
    # filings and news / advisories
    items = db.q("SELECT * FROM item WHERE published > ? AND kind IN ('filing','news','forum','advisory')", (since,))
    for it in items:
        ent = it.get("entities") or {}
        themes = set(it.get("themes") or [])
        oids = it.get("org_ids") or []
        victim = ent.get("victim")
        if it["kind"] == "filing":
            key = f"org:{oids[0]}" if oids else "v:" + re.sub(r"[^a-z0-9]", "", norm(it["title"].split(" files ")[0]))
            G = g(key, victim=orgs.get(oids[0], {}).get("name") if oids else it["title"].split(" files ")[0], victim_org_id=oids[0] if oids else None)
            G["kinds"]["Disclosed incident (SEC 8-K)"] += 3
            src(G, "SEC EDGAR", it["url"], it["title"], it["published"], "Regulatory filing")
            G["item_ids"].append(it["id"])
            continue
        # a *named victim* (extracted from the headline) is required — a mere mention is not a victim
        if victim and it["kind"] in ("news", "forum") and (themes & INCIDENT_THEMES) and "*" not in victim:
            vo, _ = matcher.resolve(victim)
            key = f"org:{vo}" if vo else "v:" + re.sub(r"[^a-z0-9]", "", norm(victim))
            if len(key) >= 5:
                G = g(key, victim=orgs.get(vo, {}).get("name") if vo else victim, victim_org_id=vo)
                for t in themes & INCIDENT_THEMES:
                    G["themes"][t] += 1
                G["vendors"] |= set(ent.get("vendors") or [])
                G["actors"] |= {aname.get(a, a) for a in ent.get("actors") or []}
                G["sectors"] |= set((ent.get("sectors") or []))
                src(G, it["publisher"], it["url"], it["title"], it["published"], it["pub_type"])
                G["item_ids"].append(it["id"])
                continue
        # vulnerability exploitation — keyed by CVE, only for KEV / actively exploited
        for cve in (ent.get("cves") or [])[:3]:
            if "Zero-day exploitation" in themes or db.scalar("SELECT 1 FROM vuln WHERE cve=? AND kev_added IS NOT NULL", (cve,)):
                G = g(f"cve:{cve}", victim=None, victim_org_id=None)
                G["cves"].add(cve)
                G["vendors"] |= set(ent.get("vendors") or [])
                G["actors"] |= {aname.get(a, a) for a in ent.get("actors") or []}
                G["kinds"]["Vulnerability exploitation"] += 1
                src(G, it["publisher"], it["url"], it["title"], it["published"], it["pub_type"])
                G["item_ids"].append(it["id"])
    # KEV additions in the last 30 days without press coverage still form an incident
    for v in db.q("SELECT * FROM vuln WHERE kev_added >= ?", (ts(30)[:10],)):
        G = g(f"cve:{v['cve']}", victim=None, victim_org_id=None)
        G["cves"].add(v["cve"])
        if v.get("vendor"):
            G["vendors"].add(v["vendor"].strip())
        G["kinds"]["Vulnerability exploitation"] += 2
        G["kev"] = v
        src(G, "CISA KEV", f"https://nvd.nist.gov/vuln/detail/{v['cve']}", f"{v['cve']} added to CISA KEV — {v.get('name') or ''}",
            (v["kev_added"] or "") + "T00:00:00Z", "Government / CERT")
    # provider outages (major / critical) in the last 14 days
    for it in db.q("SELECT * FROM item WHERE kind='status' AND published > ?", (ts(14),)):
        ent = it.get("entities") or {}
        if (ent.get("impact") or "") not in ("major", "critical"):
            continue
        vendor = (ent.get("vendors") or [it["publisher"]])[0]
        G = g(f"status:{vendor}:{it['published'][:10]}", victim=vendor, victim_org_id=None, provider=vendor)
        G["vendors"].add(vendor)
        G["kinds"]["Provider outage"] += 3
        src(G, it["publisher"] + " status page", it["url"], it["title"], it["published"], "Service status")
        G["item_ids"].append(it["id"])

    # ---- materialise
    dep_vendors = {r["vendor"].lower() for r in db.q("SELECT DISTINCT vendor FROM dependency")}
    rows, links = [], []
    for key, G in groups.items():
        if not G["sources"]:
            continue
        G["sources"].sort(key=lambda s: s["published"] or "")
        publishers = {s["publisher"] for s in G["sources"]}
        first, last = G["sources"][0]["published"], G["sources"][-1]["published"]
        kind = (G["kinds"] + G["themes"]).most_common(1)[0][0] if (G["kinds"] or G["themes"]) else "Cyber incident"
        kind = {"Ransomware & extortion": "Ransomware & extortion", "Data breach & leak": "Data breach"}.get(kind, kind)
        victim = G.get("victim")
        compromise = any(G["themes"].get(t) for t in ("Data breach & leak", "Ransomware & extortion", "Supply-chain compromise")) or \
            any(G["kinds"].get(k) for k in ("Ransomware & extortion", "Data breach", "Dark-web sale / leak claim"))
        # stories where an AI model/agent is the actor are AI-system incidents, not a compromise of the provider
        ai_story = (not key.startswith(("status:", "cve:", "ddos:")) and not G["leak_ids"] and
                    sum(1 for s in G["sources"] if AI_ACTOR.search(s["title"] or "")) * 2 >= len(G["sources"]))
        is_vendor = (bool(victim and victim.lower() in dep_vendors) and compromise) or bool(G["themes"].get("Supply-chain compromise"))
        if ai_story:
            kind = "AI system incident"
        elif is_vendor and kind not in ("Provider outage", "Vulnerability exploitation"):
            kind = "Supply-chain / provider compromise"
        if G.get("title"):
            title = G["title"]
        elif key.startswith("cve:"):
            cve = key[4:]
            v = G.get("kev") or db.one("SELECT vendor, product, name FROM vuln WHERE cve=?", (cve,)) or {}
            title = f"Active exploitation: {cve}" + (f" — {v.get('vendor', '').strip()} {v.get('product', '') or ''}".rstrip() if v.get("vendor") else "")
        elif key.startswith("status:"):
            title = G["sources"][-1]["title"]
        else:
            title = f"{victim}: {kind.lower()}"
        # severity (explainable)
        n_pub = len(publishers)
        if G.get("victim_org_id"):
            rid = "I-WATCH-VICTIM"
        elif kind == "Supply-chain / provider compromise" and victim and victim.lower() in dep_vendors:
            rid = "I-SUPPLY-WATCH"
        elif key.startswith("cve:") and days_since(last) <= 14 and n_pub >= 3:
            rid = "I-KEV-MASS"
        elif kind == "Provider outage":
            rid = "I-INFO"
        elif n_pub >= 2:
            rid = "I-MULTI"
        elif any(s["type"] == "Leak-site listing" for s in G["sources"]):
            rid = "I-LEAK"
        else:
            rid = "I-SINGLE"
        sev = rule(rid)[0]
        iid = "inc-" + hid(key)
        sectors = {RW_SECTOR.get(s, s) for s in G["sectors"] if s} - {None}
        if G.get("victim_org_id") and orgs.get(G["victim_org_id"], {}).get("sector"):
            sectors.add(orgs[G["victim_org_id"]]["sector"])
        products = [f"{(v['vendor'] or '').strip()}|{(v['product'] or '').strip()}" for v in
                    db.q(f"SELECT vendor, product FROM vuln WHERE cve IN ({','.join('?' * len(G['cves']))})", sorted(G["cves"]))] if G["cves"] else []
        rows.append({"id": iid, "title": title[:240], "kind": kind, "victim": victim, "victim_org_id": G.get("victim_org_id"),
                     "vendors": sorted(G["vendors"])[:10], "products": products[:10], "actors": sorted(G["actors"])[:8], "cves": sorted(G["cves"])[:10],
                     "sectors": sorted(sectors)[:6], "countries": sorted(G["countries"])[:6], "first_seen": first, "last_seen": last,
                     "severity": sev, "severity_rule": rid, "sources": G["sources"][-30:], "source_count": n_pub,
                     "item_count": len(G["sources"]), "summary": G["sources"][-1]["title"][:300]})
        links += [(iid, i) for i in G["item_ids"]]
        links += [(iid, l, "leak") for l in G["leak_ids"]]
    c = db.conn()
    c.execute("DELETE FROM incident")
    c.commit()
    db.upsert("incident", rows)
    c.execute("UPDATE item SET incident_id=NULL WHERE incident_id IS NOT NULL")
    c.execute("UPDATE leak SET incident_id=NULL WHERE incident_id IS NOT NULL")
    for lk in links:
        if len(lk) == 3:
            c.execute("UPDATE leak SET incident_id=? WHERE id=?", (lk[0], lk[1]))
        else:
            c.execute("UPDATE item SET incident_id=? WHERE id=?", lk)
    c.commit()
    return len(rows)


# ============================================================== 3. impact linkage
# What kind of evidence each link rests on. Sector-and-country targeting is an inference,
# and capping it below Critical keeps the top level meaning "we observed this".
LINK_CONFIDENCE = {"DIRECT": "likely", "GROUP": "confirmed", "DEPENDENCY": "confirmed",
                   "EXPOSED_PRODUCT": "likely", "TARGETING": "unconfirmed"}
LINK_TYPES = {
    "DIRECT": "Named victim",
    "GROUP": "Same corporate group (GLEIF)",
    "DEPENDENCY": "Uses the affected provider (public DNS evidence)",
    "EXPOSED_PRODUCT": "Runs the affected product on the internet",
    "TARGETING": "Same sector & country the actor is hitting",
}


PROVIDER_KINDS = {"Supply-chain / provider compromise", "Provider outage", "Data breach", "Ransomware & extortion",
                  "Disclosed incident (SEC 8-K)", "Dark-web sale / leak claim"}
EDGE_VENDORS = {"fortinet", "ivanti", "citrix", "sonicwall", "palo alto networks", "f5", "juniper", "check point", "progress", "fortra",
                "crushftp", "cleo", "connectwise", "beyondtrust", "simplehelp", "veeam", "synacor", "roundcube", "zoho", "solarwinds",
                "kaseya", "barracuda networks", "sophos", "watchguard", "paessler", "commvault", "gitlab", "jenkins", "sitecore",
                "langflow", "berriai"}
GENERIC = {"server", "and", "data", "center", "multiple", "products", "the", "for", "of", "software", "services", "service", "suite",
           "enterprise", "platform", "manager", "microsoft", "google", "apple", "oracle", "cisco", "windows", "linux", "internet",
           "information", "http", "web", "os", "ios", "kernel", "chrome", "chromium", "office", "system", "systems", "client"}


def product_match(vendor: str, kev_product: str, exposed: str) -> bool:
    """Vendors that are essentially one edge product match on vendor; broad vendors (Microsoft, Cisco, Oracle…) need product overlap."""
    if vendor.strip().lower() in EDGE_VENDORS:
        return True
    kp = (kev_product or "").lower()
    a = {w for w in re.findall(r"[a-z0-9]+", kp) if w not in GENERIC and len(w) > 2}
    b = {w for w in re.findall(r"[a-z0-9]+", (exposed or "").lower()) if w not in GENERIC and len(w) > 2}
    common = a & b
    if common == {"exchange"} and "exchange server" not in kp:  # e.g. "Internet Key Exchange" is not Exchange Server
        return False
    return bool(common)


def build_impacts() -> int:
    incs = db.q("SELECT * FROM incident")
    orgs = {o["id"]: o for o in db.q("SELECT id, name, sector, country, domain FROM org")}
    deps = defaultdict(list)
    for d in db.q("SELECT org_id, vendor, category, evidence FROM dependency"):
        deps[d["vendor"].lower()].append(d)
    parent_of = {}
    for a in db.q("SELECT org_id, attrs FROM asset WHERE kind='subsidiary'"):
        k = norm((a.get("attrs") or {}).get("name") or "")
        if k:
            parent_of[k] = a["org_id"]
    edge_by_vendor = defaultdict(list)
    for a in db.q("SELECT org_id, attrs FROM asset WHERE kind='domain'"):
        for e in (a.get("attrs") or {}).get("edge") or []:
            if e.get("vendor"):
                edge_by_vendor[e["vendor"].lower()].append((a["org_id"], e["host"], e["product"]))
    cve_hosts = defaultdict(list)
    cpe_vendor = defaultdict(list)  # "f5" → [(org, ip, product)] from InternetDB CPEs on the org's own hosts
    for a in db.q("SELECT org_id, value, attrs FROM asset WHERE kind='ip'"):
        at = a.get("attrs") or {}
        if at.get("shared") and not at.get("owned"):
            continue
        for cve in at.get("vulns") or []:
            cve_hosts[cve].append((a["org_id"], a["value"]))
        for cpe in at.get("cpes") or []:
            parts = cpe.split(":")
            if len(parts) >= 4:
                cpe_vendor[re.sub(r"[^a-z0-9]", "", parts[2])].append((a["org_id"], a["value"], parts[3].replace("_", " ")))
    # actor victimology for targeting: (actor, sector, country) → count in last 30 days
    vict = Counter()
    for l in db.q("SELECT actor, sector, country FROM leak WHERE kind='leaksite' AND published > ?", (ts(30),)):
        s = RW_SECTOR.get(l["sector"] or "", l["sector"])
        if l["actor"] and s and l["country"]:
            vict[(l["actor"].lower(), s, l["country"])] += 1

    rows = []

    def add(iid, oid, lt, sev, reason, evidence):
        if oid and oid in orgs:
            conf = LINK_CONFIDENCE.get(lt, "likely")
            rows.append({"incident_id": iid, "org_id": oid, "link_type": lt, "severity": cap_for_confidence(sev, conf),
                         "confidence": conf, "reason": reason[:300], "evidence": evidence[:300]})

    for inc in incs:
        iid = inc["id"]
        breachy = inc["kind"] not in ("Provider outage",)
        if inc.get("victim_org_id"):
            add(iid, inc["victim_org_id"], "DIRECT", "critical", "Named as the victim of this incident.",
                (inc.get("sources") or [{}])[-1].get("url") or "")
        victim = inc.get("victim") or ""
        vk = norm(victim)
        if vk in parent_of and parent_of[vk] != inc.get("victim_org_id"):
            add(iid, parent_of[vk], "GROUP", "high", f"{victim} is a subsidiary of this organisation (GLEIF Level 2).", "https://search.gleif.org/")
        # provider dependency: only when the provider itself was breached / disrupted — never for AI-misuse stories,
        # vulnerability advisories about a vendor's product, or DDoS campaigns
        provs = set()
        if inc["kind"] in PROVIDER_KINDS:
            provs = ({victim.lower()} if victim else set())
            if inc["kind"] in ("Supply-chain / provider compromise", "Provider outage"):
                provs |= {v.lower() for v in inc.get("vendors") or []}
        for p in provs:
            for d in deps.get(p, [])[:400]:
                if d["org_id"] == inc.get("victim_org_id"):
                    continue
                add(iid, d["org_id"], "DEPENDENCY", "high" if breachy else "medium",
                    f"Uses {d['vendor']} ({d['category']}); {'provider compromised' if breachy else 'provider outage'}.", d["evidence"])
        # exposed product: KEV vendor on an edge hostname, or the CVE seen on the org's own host
        for cve in inc.get("cves") or []:
            for oid, ip in cve_hosts.get(cve, [])[:200]:
                add(iid, oid, "EXPOSED_PRODUCT", "critical", f"Internet-facing host {ip} reports {cve} (Shodan InternetDB index).", f"https://internetdb.shodan.io/{ip}")
        # product-level match: the exploited vendor AND product must correspond to what the org exposes
        for vp in inc.get("products") or []:
            v, _, kp = vp.partition("|")
            vk = re.sub(r"[^a-z0-9]", "", v.lower())
            for oid, ip, prod in cpe_vendor.get(vk, [])[:200]:
                if product_match(v, kp, prod):  # product seen, vulnerable version not confirmed → High; the CVE itself on the host → Critical (above)
                    add(iid, oid, "EXPOSED_PRODUCT", "high", f"Host {ip} in the organisation's own network runs {v} {prod} (CPE in Shodan InternetDB); vulnerable version not confirmed.",
                        f"https://internetdb.shodan.io/{ip}")
            for oid, host, prod in edge_by_vendor.get(v.lower(), [])[:200]:
                if product_match(v, kp, prod):
                    add(iid, oid, "EXPOSED_PRODUCT", "high", f"Public hostname {host} suggests {prod} — the exploited product ({v} {kp}). Name-based, unconfirmed.", f"https://crt.sh/?q={host}")
        # sector / country targeting by the same actor
        if inc["kind"] in ("Ransomware & extortion",) and inc.get("actors"):
            actor = inc["actors"][0].lower()
            for (a, s, cc), n in vict.items():
                if a != actor or n < 3:
                    continue
                for o in orgs.values():
                    if o["sector"] == s and o["country"] == cc and o["id"] != inc.get("victim_org_id"):
                        add(iid, o["id"], "TARGETING", "low", f"{inc['actors'][0]} listed {n} {s} victims in {cc} in the last 30 days.",
                            f"https://www.ransomware.live/group/{inc['actors'][0]}")
    # keep strongest link per (incident, org, type)
    best = {}
    for r in rows:
        k = (r["incident_id"], r["org_id"], r["link_type"])
        if k not in best or RANK[r["severity"]] < RANK[best[k]["severity"]]:
            best[k] = r
    c = db.conn()
    c.execute("DELETE FROM impact")
    c.commit()
    db.upsert("impact", list(best.values()))
    # an incident that reaches monitored organisations through dependency escalates
    for iid in {r["incident_id"] for r in best.values() if r["link_type"] == "DEPENDENCY"}:
        inc = next(i for i in incs if i["id"] == iid)
        if inc["kind"] == "Supply-chain / provider compromise" and inc["severity"] != "critical":
            c.execute("UPDATE incident SET severity='critical', severity_rule='I-SUPPLY-WATCH' WHERE id=?", (iid,))
    c.commit()
    return len(best)


# ============================================================== 4. findings
CATEGORIES = [
    ("footprint", "Assets & infrastructure"), ("critical", "Critical assets"), ("cloud", "Cloud environments"),
    ("software", "Software, services & third parties"), ("exposure", "Open ports & exposed services"),
    ("vulns", "Vulnerabilities & exploited software"), ("compromise", "Compromised systems & IPs"),
    ("darkweb", "Dark web & credential exposure"), ("chatter", "Threat chatter & targeting"),
    ("hygiene", "Email & domain security"), ("disclosure", "Incidents & disclosures"), ("ai", "AI risk"),
]
RULE_CAT = {"DW-LEAK": "darkweb", "DW-ACCESS": "darkweb", "DW-FORUM": "darkweb", "DW-STEALER": "darkweb", "BR-": "darkweb",
            "DW-DDOS": "chatter", "THR-": "chatter", "INC-": "disclosure", "DISC-": "disclosure", "CMP-": "compromise",
            "VUL-": "vulns", "SURF-RISKY": "exposure", "SURF-TAKEOVER": "exposure", "SURF-EDGE": "critical", "SURF-LARGE": "footprint",
            "HYG-": "hygiene", "TP-": "software", "AI-": "ai",
            "DOM-": "hygiene", "CRT-": "hygiene", "BGP-": "exposure", "LOOK-": "chatter"}
CRITICAL_CLASSES = [  # passive "critical asset" classes from hostname + fingerprint
    ("Identity & SSO", re.compile(r"^(sso|login|auth|id|idp|adfs|sts|okta|ping|saml|oauth|identity)[\d-]*\.", re.I)),
    ("Remote access & VPN", re.compile(r"^(vpn|sslvpn|remote|ra|citrix|gateway|gw|webvpn|connect|access|rdweb|globalprotect|anyconnect|pulse)[\d-]*\.", re.I)),
    ("Email & collaboration", re.compile(r"^(mail|webmail|owa|autodiscover|smtp|exchange|outlook)[\d-]*\.", re.I)),
    ("File transfer", re.compile(r"^(ftp|sftp|mft|transfer|files?|share|moveit|goanywhere)[\d-]*\.", re.I)),
    ("Developer & admin tooling", re.compile(r"^(git|gitlab|jenkins|jira|confluence|admin|cpanel|grafana|kibana|vcenter)[\d-]*\.", re.I)),
    ("APIs & customer portals", re.compile(r"^(api|portal|apps?|secure|my|online|shop|store|pay|payments?)[\d-]*\.", re.I)),
    ("Pre-production", re.compile(r"^(dev|test|staging|stage|uat|qa|sandbox|preprod)[\d-]*\.", re.I)),
]


def rule_cat(rid: str) -> str:
    for p, c in RULE_CAT.items():
        if rid.startswith(p):
            return c
    return "footprint"


def build_findings() -> int:
    orgs = {o["id"]: o for o in db.q("SELECT id, name, sector, country, domain FROM org")}
    out = []

    def F(oid, rid, title, detail, url, source, observed, key="", data=None):
        sev, _ = rule(rid)
        # a caller may override where it knows more than the rule does (a CPE with a version
        # is confirmed; the same product guessed from a hostname is not)
        conf = (data or {}).get("confidence") or confidence_for(rid)
        out.append({"id": hid(oid, rid, key or title), "org_id": oid, "category": rule_cat(rid), "title": title[:240], "detail": (detail or "")[:600],
                    "severity": cap_for_confidence(sev, conf), "confidence": conf,
                    "rule_id": rid, "evidence_url": url, "source_id": source, "observed": observed, "data": data or {}})

    # --- dark web & breaches
    for l in db.q("SELECT * FROM leak WHERE org_id IS NOT NULL"):
        age = days_since(l["published"])
        ex = l.get("extra") or {}
        k, oid = l["kind"], l["org_id"]
        if k == "leaksite":
            if l.get("match") == "subsidiary":
                if age <= 90:
                    F(oid, "DW-LEAK-SUB", f"Subsidiary {l['victim']} listed by {l['actor']}", ex.get("description", ""), l["url"], l["source_id"], l["published"], l["id"])
                continue
            rid = "DW-LEAK-30" if age <= 30 else "DW-LEAK-180" if age <= 180 else "DW-LEAK-OLD"
            F(oid, rid, f"Listed on the {l['actor']} leak site", ex.get("description", "") or l["title"], l["url"], l["source_id"], l["published"], l["id"],
              {"actor": l["actor"], "sources": ex.get("sources")})
        elif k == "forum":
            claim = ex.get("claim")
            rid = "DW-ACCESS-14" if claim == "access" and age <= 14 else "DW-FORUM-30" if age <= 30 else "DW-FORUM-OLD"
            F(oid, rid, l["title"], f"Reported by {ex.get('publisher')} — claim type: {claim}. Unverified until confirmed by the organisation.",
              l["url"], l["source_id"], l["published"], l["id"], {"claim": claim})
        elif k == "breach":
            if l.get("match") != "domain":
                continue
            rid = "BR-PUBLIC-90" if age <= 90 else "BR-PUBLIC-12M" if age <= 365 else "BR-PUBLIC-OLD"
            F(oid, rid, l["title"], f"Breach date {ex.get('breach_date')}; data: {', '.join((ex.get('data_classes') or [])[:8])}.",
              l["url"], "hibp", l["published"], l["id"], {"pwn_count": ex.get("pwn_count"), "data_classes": ex.get("data_classes")})
        elif k == "ddos":
            if age <= 30:
                F(oid, "DW-DDOS-7" if age <= 7 else "DW-DDOS-30", f"{l['domain']} on the NoName057(16) DDoS target list",
                  f"Hosts targeted: {', '.join(ex.get('hosts') or [])}", l["url"], "ddosia", l["published"], l["id"])
        elif k == "stealer":
            emp, usr = ex.get("employees") or 0, ex.get("users") or 0
            le, lu = days_since(ex.get("last_employee")), days_since(ex.get("last_user"))
            if emp and le <= 30:
                rid = "DW-STEALER-30"
            elif (emp and le <= 180) or (usr >= 1000 and lu <= 30):
                rid = "DW-STEALER-EMP"
            elif emp or usr:
                rid = "DW-STEALER-OLD"
            else:
                continue
            F(oid, rid, f"Infostealer exposure: {emp:,} employee and {usr:,} customer devices",
              f"Last employee infection {(ex.get('last_employee') or 'n/a')[:10]}; last customer infection {(ex.get('last_user') or 'n/a')[:10]}. "
              f"Families: {', '.join(list((ex.get('families') or {}).keys())[:5])}.", l["url"], "hudsonrock", l["published"], l["id"], ex)

    # --- compromised IPs in owned space
    for m in db.kv_get("compromised_matches", []) or []:
        rid = "CMP-C2" if m["category"] == "c2" else "CMP-ABUSE" if m["category"] in ("compromised", "attacker", "hijacked") else None
        if rid:
            F(m["org_id"], rid, f"{m['listed']} listed on {m['feed_name']}", f"Inside {m['footprint']} ({m['provenance']}).", m["url"],
              "compromised_ips", db.kv_get("blocklist_checked"), m["listed"] + m["feed"], m)

    # --- exposure, vulnerabilities, edge products, hygiene
    kev = {r["cve"]: r for r in db.q("SELECT cve, epss, exploit_refs, severity, kev_added, vendor FROM vuln")}
    kev_recent = [((r["vendor"] or "").strip(), r["product"] or "") for r in db.q("SELECT vendor, product FROM vuln WHERE kev_added >= ?", (ts(30)[:10],))]

    def recent_kev_for(vendor: str, product: str) -> bool:  # product-level: a Windows CVE says nothing about an Exchange host
        return any(v.lower() == vendor.lower() and product_match(v, kp, product) for v, kp in kev_recent)
    for a in db.q("SELECT org_id, kind, value, attrs, last_seen FROM asset WHERE kind IN ('ip','domain','hostname')"):
        at = a.get("attrs") or {}
        oid = a["org_id"]
        if a["kind"] == "ip":
            if at.get("shared") and not at.get("owned"):
                continue
            vulns = at.get("vulns") or []
            in_kev = [c for c in vulns if c in kev and kev[c].get("kev_added")]
            hi = [c for c in vulns if c in kev and ((kev[c].get("epss") or 0) >= 0.1 or kev[c].get("exploit_refs"))]
            url = f"https://internetdb.shodan.io/{a['value']}"
            if in_kev:
                F(oid, "VUL-KEV-EXPOSED", f"{a['value']} reports {len(in_kev)} actively exploited CVE(s)", f"{', '.join(in_kev[:8])} on {', '.join(at.get('hosts') or [])}. "
                  "Version-inferred by the index — verify.", url, "surface", a["last_seen"], a["value"], {"cves": in_kev})
            elif hi:
                F(oid, "VUL-EXPOSED-HIGH", f"{a['value']} reports high-likelihood CVE(s)", f"{', '.join(hi[:8])}", url, "surface", a["last_seen"], a["value"], {"cves": hi})
            elif vulns:
                F(oid, "VUL-EXPOSED", f"{a['value']} reports {len(vulns)} known CVE(s)", f"{', '.join(vulns[:8])}", url, "surface", a["last_seen"], a["value"], {"cves": vulns[:30]})
            risky = [f"{p}/{RISKY_PORTS[p]}" for p in at.get("ports") or [] if p in RISKY_PORTS]
            confirmed_ai, unconfirmed_ai = fp.ai_services(at.get("ports"), at.get("cpes"), at.get("hosts"))
            if confirmed_ai:
                F(oid, "AI-EXPOSED-SERVICE", f"{a['value']} exposes {', '.join(confirmed_ai)}",
                  f"Hostnames: {', '.join(at.get('hosts') or [])}. Self-hosted AI services are frequently deployed without authentication.",
                  url, "surface", a["last_seen"], a["value"] + ":ai", {"services": confirmed_ai, "confidence": "confirmed"})
            elif unconfirmed_ai:
                F(oid, "AI-EXPOSED-PORT", f"{a['value']} exposes a port used by {', '.join(unconfirmed_ai)}",
                  "The port is shared with much other software, so the product is not confirmed — verify before acting.",
                  url, "surface", a["last_seen"], a["value"] + ":aiport", {"ports": unconfirmed_ai, "confidence": "unconfirmed"})
            if risky:
                F(oid, "SURF-RISKY-PORT", f"{a['value']} exposes {', '.join(risky)}", f"Hostnames: {', '.join(at.get('hosts') or [])}.", url, "surface", a["last_seen"], a["value"], {"ports": at.get("ports")})
        elif a["kind"] == "hostname" and not at.get("edge") and fp.ai_host(a["value"], at.get("cname")):
            plat = fp.ai_host(a["value"], at.get("cname"))
            F(oid, "AI-HOST", f"{a['value']} indicates an AI platform ({plat})",
              (f"CNAME to {at.get('cname')}." if at.get("cname") else "") + " Inventory: confirm it is governed and access-controlled.",
              f"https://crt.sh/?q={a['value']}", "surface", a["last_seen"], a["value"], {"platform": plat, "confidence": "likely"})
        elif a["kind"] == "prefix" and at.get("rpki"):
            rid = prevent.rpki_rule(at["rpki"])
            if rid:
                asn = at.get("rpki_asn")
                F(oid, rid, f"{a['value']} is RPKI {at['rpki']}",
                  f"Announced by AS{asn}; {'no ROA authorises this origin' if at['rpki'] == 'invalid' else 'no Route Origin Authorisation covers this prefix'}.",
                  f"https://stat.ripe.net/data/rpki-validation/data.json?resource=AS{asn}&prefix={a['value']}",
                  "surface", a["last_seen"], a["value"], {"state": at["rpki"], "asn": asn})
        elif a["kind"] == "lookalike":
            rid = at.get("rule")
            if rid:
                mx, ips = at.get("mx") or [], at.get("ips") or []
                how = f"Accepts mail via {', '.join(mx[:2])}." if mx else f"Resolves to {', '.join(ips[:2])}."
                F(oid, rid, f"Lookalike domain {a['value']} is live",
                  f"{how} Registered lookalikes are the usual preparation for phishing and invoice fraud.",
                  f"https://dns.google/resolve?name={a['value']}&type={'MX' if mx else 'A'}",
                  "surface", a["last_seen"], a["value"], {"ips": ips, "mx": mx})
        elif a["kind"] == "hostname" and at.get("dangling"):
            F(oid, "SURF-TAKEOVER", f"{a['value']} → {at.get('cname')} does not resolve", "Takeover-prone CNAME target returns no address.",
              f"https://crt.sh/?q={a['value']}", "surface", a["last_seen"], a["value"])
        elif a["kind"] == "domain":
            h = at.get("hygiene") or {}
            d = a["value"]
            dm, spf = h.get("dmarc"), h.get("spf")
            url = f"https://dns.google/resolve?name=_dmarc.{d}&type=TXT"
            if not dm or dm.get("p") in ("none", ""):
                F(oid, "HYG-DMARC-NONE", f"DMARC {'missing' if not dm else 'p=none'} on {d}", (dm or {}).get("record", "No _dmarc record published."), url, "surface", a["last_seen"], d)
            if not spf:
                F(oid, "HYG-SPF-MISSING", f"No SPF record on {d}", "", f"https://dns.google/resolve?name={d}&type=TXT", "surface", a["last_seen"], d)
            elif spf.get("all") in ("~", "?", "+"):
                F(oid, "HYG-SPF-SOFT", f"SPF on {d} ends in {spf['all']}all", spf.get("record", "")[:200], f"https://dns.google/resolve?name={d}&type=TXT", "surface", a["last_seen"], d)
            if not h.get("dnssec"):
                F(oid, "HYG-DNSSEC", f"{d} is not DNSSEC-signed", "No DS record at the parent zone.", f"https://dns.google/resolve?name={d}&type=DS", "surface", a["last_seen"], d)
            if not h.get("mta_sts"):
                F(oid, "HYG-MTASTS", f"No MTA-STS policy on {d}", "", f"https://dns.google/resolve?name=_mta-sts.{d}&type=TXT", "surface", a["last_seen"], d)
            if not h.get("caa"):
                F(oid, "HYG-CAA", f"No CAA record on {d}", "", f"https://dns.google/resolve?name={d}&type=CAA", "surface", a["last_seen"], d)
            if prevent.spf_lookup_excess(spf):
                F(oid, "HYG-SPF-LOOKUPS", f"SPF on {d} needs {spf['lookups']} DNS lookups (limit is {prevent.SPF_LOOKUP_LIMIT})",
                  "Receivers stop evaluating past the limit and return permerror, so this SPF record no longer protects the domain.",
                  f"https://dns.google/resolve?name={d}&type=TXT", "surface", a["last_seen"], d, {"lookups": spf.get("lookups")})
            if not h.get("dkim_selectors"):
                F(oid, "HYG-DKIM-NONE", f"No DKIM key found on {d}", "None of the common selectors published a key.",
                  f"https://dns.google/resolve?name=selector1._domainkey.{d}&type=TXT", "surface", a["last_seen"], d)
            if not h.get("tls_rpt"):
                F(oid, "HYG-TLSRPT", f"No TLS-RPT record on {d}", "Failed inbound mail encryption is never reported back.",
                  f"https://dns.google/resolve?name=_smtp._tls.{d}&type=TXT", "surface", a["last_seen"], d)
            if prevent.ns_single_provider(h.get("ns")):
                F(oid, "HYG-NS-SINGLE", f"All {len(h['ns'])} nameservers for {d} are with one provider", ", ".join(h["ns"][:4]) + ".",
                  f"https://dns.google/resolve?name={d}&type=NS", "surface", a["last_seen"], d, {"ns": h.get("ns")})

            # --- domain lifecycle (RDAP)
            rd = at.get("rdap") or {}
            rdap_url = f"https://rdap.org/domain/{d}"
            if rd:
                if not rd.get("locked"):
                    F(oid, "DOM-LOCK", f"{d} has no registrar transfer lock",
                      f"Registrar: {rd.get('registrar') or 'unknown'}. Status: {', '.join(rd.get('statuses') or ['none published'])}.",
                      rdap_url, "surface", a["last_seen"], d, {"statuses": rd.get("statuses")})
                left = prevent.days_until(rd.get("expires"))
                rid = prevent.expiry_rule(left)
                if rid:
                    F(oid, rid, f"{d} expires in {left} days" if left >= 0 else f"{d} expired {abs(left)} days ago",
                      f"Registration ends {(rd.get('expires') or '')[:10]}. Registrar: {rd.get('registrar') or 'unknown'}.",
                      rdap_url, "surface", a["last_seen"], d, {"expires": rd.get("expires"), "days": left})

            # --- certificates
            cert = at.get("certs") or {}
            soon = cert.get("soonest")
            if soon and soon.get("days") is not None and soon["days"] <= 14:
                F(oid, "CRT-EXPIRY-14", f"Certificate for {soon['host']} expires in {soon['days']} days",
                  f"Issued by {soon.get('issuer') or 'unknown'}, expires {(soon.get('not_after') or '')[:10]}.",
                  f"https://crt.sh/?q={soon['host']}", "surface", a["last_seen"], soon["host"], {"days": soon["days"]})
            for off in cert.get("caa_offenders") or []:
                F(oid, "CRT-CAA-VIOLATION", f"Certificate for {off.get('cn') or d} issued outside the CAA policy",
                  f"Issuer: {off.get('issuer')}. CAA authorises only {', '.join(cert.get('caa_allowed') or [])}.",
                  f"https://crt.sh/?q={off.get('cn') or d}", "surface", a["last_seen"], off.get("serial") or off.get("cn") or d,
                  {"issuer": off.get("issuer"), "allowed": cert.get("caa_allowed")})
            seen_v = set()
            for e in at.get("edge") or []:
                v = (e.get("vendor") or "")
                if not v or v in seen_v:
                    continue
                seen_v.add(v)
                hosts = [x["host"] for x in at.get("edge") if x.get("vendor") == v][:5]
                rid = "SURF-EDGE-KEV" if recent_kev_for(v, e["product"]) else "SURF-EDGE"
                F(oid, rid, f"{e['product']} exposed ({len(hosts)} host{'s' if len(hosts) > 1 else ''})", f"{', '.join(hosts)}" +
                  (f" — {e['product']} had a CISA KEV addition in the last 30 days." if rid == "SURF-EDGE-KEV" else ""), f"https://crt.sh/?q={hosts[0]}", "surface", a["last_seen"], v,
                  {"vendor": v, "hosts": hosts})
            if (at.get("ct_count") or 0) >= 1500:
                F(oid, "SURF-LARGE", f"{at['ct_count']:,} public hostnames in certificate transparency", "Large external footprint to govern.",
                  f"https://crt.sh/?q=%25.{d}", "surface", a["last_seen"], d)

    # --- generative-AI services evidenced in public DNS
    # fingerprints.py already records these as dependencies with category "AI services";
    # this turns that inventory into a finding so the AI risk category is not blank.
    ai_deps = defaultdict(list)
    for r in db.q("SELECT org_id, vendor, evidence, seen FROM dependency WHERE category='AI services'"):
        ai_deps[r["org_id"]].append(r)
    for oid, rows in ai_deps.items():
        if oid not in orgs:
            continue
        vendors = sorted({r["vendor"] for r in rows})
        F(oid, "AI-SERVICE-DNS", f"Uses {', '.join(vendors)} (domain-verification record in DNS)",
          "Evidence: " + " · ".join(f"{r['vendor']}: {r['evidence']}" for r in rows[:4]) +
          ". Inventory only — confirm the usage is sanctioned and covered by policy.",
          f"https://dns.google/resolve?name={orgs[oid]['domain']}&type=TXT", "surface",
          max(r["seen"] for r in rows), "ai-services", {"vendors": vendors, "confidence": "confirmed"})

    # --- an AI provider the organisation uses had an incident recently
    # This is an AI-risk finding, not a supplier breach: build_impacts deliberately keeps
    # AI-misuse stories out of DEPENDENCY linkage, and nothing here changes that.
    ai_incidents = defaultdict(list)
    for inc in db.q("SELECT id, title, vendors, severity, last_seen FROM incident WHERE last_seen > ?", (ts(30),)):
        if inc["severity"] == "low":          # ignore minor outages
            continue
        for v in inc.get("vendors") or []:
            ai_incidents[str(v).strip().lower()].append(inc)
    for oid, rows in ai_deps.items():
        if oid not in orgs:
            continue
        for vendor in sorted({r["vendor"] for r in rows}):
            hits = ai_incidents.get(vendor.lower()) or []
            if not hits:
                continue
            worst_inc = min(hits, key=lambda i: RANK.get(i["severity"], 9))
            # one finding per provider per organisation, so a single provider incident
            # does not produce a stream of repeats
            F(oid, "AI-PROVIDER-INC", f"{vendor} had an incident in the last 30 days",
              f"{worst_inc['title'][:200]} This organisation's DNS shows it uses {vendor}.",
              f"/incidents/{worst_inc['id']}", "status", worst_inc["last_seen"], f"ai-prov:{vendor}",
              {"vendor": vendor, "incident_id": worst_inc["id"], "confidence": "likely"})

    # --- filings & named-victim reporting
    for it in db.q("SELECT id, title, url, published, org_ids FROM item WHERE kind='filing'"):
        for oid in (it.get("org_ids") or [])[:1]:
            age = days_since(it["published"])
            if "1.05" in it["title"]:
                F(oid, "DISC-8K-90" if age <= 90 else "DISC-8K-OLD", it["title"], "", it["url"], "sec_8k", it["published"], it["id"])
            elif age <= 365:
                F(oid, "DISC-801", it["title"], "", it["url"], "sec_8k", it["published"], it["id"])
    named = defaultdict(lambda: {"pubs": set(), "items": []})
    for it in db.q("SELECT i.* FROM item i WHERE kind IN ('news','advisory') AND published > ?", (ts(30),)):
        ent = it.get("entities") or {}
        if not ent.get("victim"):
            continue
        for oid in (it.get("org_ids") or [])[:1]:
            named[oid]["pubs"].add(it["publisher"])
            named[oid]["items"].append(it)
    for oid, v in named.items():
        last = sorted(v["items"], key=lambda i: i["published"])[-1]
        F(oid, "INC-NAMED-30" if len(v["pubs"]) >= 2 else "INC-NAMED-1", f"Named in incident reporting: {last['title']}",
          f"Publishers: {', '.join(sorted(v['pubs']))}.", last["url"], last["source_id"], last["published"], "named")
    # --- third-party incidents via dependency
    for imp in db.q("SELECT m.*, i.title, i.last_seen, i.kind FROM impact m JOIN incident i ON i.id=m.incident_id WHERE m.link_type='DEPENDENCY'"):
        if days_since(imp["last_seen"]) <= 30 and imp["kind"] != "Provider outage":
            F(imp["org_id"], "TP-VENDOR-INC", f"Provider incident: {imp['title']}", imp["reason"] + f" Evidence: {imp['evidence']}.",
              f"/incidents/{imp['incident_id']}", "pipeline", imp["last_seen"], imp["incident_id"])
    # --- sector targeting context
    vict = Counter()
    for l in db.q("SELECT sector, country FROM leak WHERE kind='leaksite' AND published > ?", (ts(30),)):
        s = RW_SECTOR.get(l["sector"] or "", l["sector"])
        if s and l["country"]:
            vict[(s, l["country"])] += 1
    for o in orgs.values():
        n = vict.get((o["sector"], o["country"]), 0)
        if n >= 10:
            F(o["id"], "THR-SECTOR", f"{n} {o['sector']} leak-site victims in {o['country']} (30 days)", "Sector-level context, not a finding about this organisation.",
              "https://www.ransomware.live/", "ransomware_live", ts(0), "sector")
    # --- AI incidents
    for it in db.q("SELECT id, title, url, published, org_ids FROM item WHERE kind='ai_incident' AND published > ?", (ts(365),)):
        for oid in (it.get("org_ids") or [])[:2]:
            F(oid, "AI-INCIDENT", it["title"], "AI Incident Database report naming this organisation.", it["url"], "ai_incidents", it["published"], it["id"])

    # persist with first_seen continuity
    prev = {r["id"]: r["first_seen"] for r in db.q("SELECT id, first_seen FROM finding")}
    now = db.now()
    uniq = {}
    for f in out:
        f["first_seen"] = prev.get(f["id"], now)
        f["last_seen"] = now
        uniq[f["id"]] = f
    c = db.conn()
    c.execute("DELETE FROM finding")
    c.commit()
    db.upsert("finding", list(uniq.values()))
    return len(uniq)


# ============================================================== 5. actions
def build_actions() -> int:
    """Keep the action queue in step with the findings, and prove closure rather than assert it.

    An action is keyed on the finding id, which is stable across runs, so status set by a person
    survives every rebuild. Three things happen here that a person never has to do:

      - a finding that stops being produced closes its action, stamped verified_closed_at,
        because the next scan no longer sees the problem;
      - a finding that comes back reopens it and counts the reopen;
      - a finding somebody marked false_positive or accepted_risk raises nothing at all, until
        the acceptance expires.
    """
    now = db.now()
    today = now[:10]
    fb = {(r["org_id"], r["source_key"]): r for r in db.q("SELECT * FROM feedback")}
    existing = {r["id"]: r for r in db.q("SELECT * FROM action")}
    live = {}
    for f in db.q("SELECT id, org_id, rule_id, title, severity, confidence FROM finding"):
        if not actionable(f["severity"]):
            continue                                    # Low findings are inventory
        d = fb.get((f["org_id"], f["id"]))
        if d and suppressed(d["decision"], d.get("expires"), today):
            continue
        live[f["id"]] = f

    rows, seen = [], set()
    for fid, f in live.items():
        prev = existing.get(fid)
        book = playbooks.PLAYBOOKS.get(f["rule_id"]) or {}
        days = sla_days(f["severity"])
        if prev:
            hist = list(prev.get("history") or [])
            status, reopened, created = prev["status"], int(prev.get("reopened") or 0), prev["created"]
            verified = prev.get("verified_closed_at")
            if status in TERMINAL and status != "false_positive":
                # it came back: the fix did not hold, or the acceptance lapsed
                hist.append(entry("new", "aegis", now, note=f"Reopened: the finding was raised again after {status}."))
                status, reopened, verified = "new", reopened + 1, None
            rows.append({**prev, "level": f["severity"], "confidence": f.get("confidence"), "title": f["title"][:240],
                         "owner_role": book.get("owner"), "status": status, "reopened": reopened,
                         "verified_closed_at": verified, "created": created, "updated": now, "history": hist[-40:]})
        else:
            rows.append({"id": fid, "org_id": f["org_id"], "source_kind": "finding", "source_key": fid,
                         "rule_id": f["rule_id"], "title": f["title"][:240], "level": f["severity"],
                         "confidence": f.get("confidence"), "owner_role": book.get("owner"), "owner": None,
                         "status": "new", "due": due_date(f["severity"], now) if days else None,
                         "created": now, "updated": now, "verified_closed_at": None, "reopened": 0,
                         "history": [entry("new", "aegis", now, note="Raised from a finding.")]})
        seen.add(fid)

    # anything the scan no longer produces is fixed, and we can say so
    for aid, a in existing.items():
        if aid in seen or a["status"] in ("false_positive", "accepted_risk"):
            continue
        if a["status"] == "resolved":
            rows.append(a)                              # already closed, leave it alone
            continue
        hist = list(a.get("history") or [])
        hist.append(entry("resolved", "aegis", now, note="Verified closed: the finding is no longer produced."))
        rows.append({**a, "status": "resolved", "verified_closed_at": now, "updated": now, "history": hist[-40:]})

    c = db.conn()
    c.execute("DELETE FROM action")
    c.commit()
    db.upsert("action", rows)
    return len(rows)


def posture(org_id: str) -> dict:
    rows = db.q("SELECT severity, category FROM finding WHERE org_id=?", (org_id,))
    counts = Counter(r["severity"] for r in rows)
    return {"level": worst([r["severity"] for r in rows if r["severity"] != "low"]) or ("low" if rows else None),
            "counts": dict(counts), "by_category": {c: worst([r["severity"] for r in rows if r["category"] == c]) for c, _ in CATEGORIES}}


def critical_assets(org_id: str) -> list[dict]:
    out = []
    for a in db.q("SELECT value, attrs FROM asset WHERE org_id=? AND kind='hostname'", (org_id,)):
        at = a.get("attrs") or {}
        cls = next((c for c, rx in CRITICAL_CLASSES if rx.match(a["value"])), None)
        if at.get("edge") and not cls:
            cls = "Remote access & VPN"
        if cls:
            out.append({"host": a["value"], "class": cls, "ips": at.get("ips") or [], "cname": at.get("cname"),
                        "product": (at.get("edge") or [None, None])[1] if at.get("edge") else None, "provider": at.get("cdn")})
    return out


def dedupe_leaks() -> int:
    """Merge leak-site rows that different trackers recorded under differently-spelled group names."""
    from aegis.collectors.darkweb import canon_group, gkey, leak_id, victim_key
    rows = db.q("SELECT * FROM leak WHERE kind='leaksite'")
    # second key: a listing posted as a bare domain ("e-mitsuwa.com") matches a named listing carrying that domain
    by_dom = {}
    for r in rows:
        if r.get("domain") and not _looks_domain(r["victim"]):
            by_dom[(gkey(canon_group(r["actor"] or "")), reg_domain(r["domain"]).split(".")[0])] = victim_key(r["victim"])
    groups = defaultdict(list)
    for r in rows:
        g = canon_group(r["actor"] or "")
        vk = victim_key(r["victim"], r["domain"] or "")
        if _looks_domain(r["victim"]):
            vk = by_dom.get((gkey(g), reg_domain(r["victim"]).split(".")[0]), vk)
        groups[leak_id("ls", vk, gkey(g))].append((r, g))
    c = db.conn()
    merged_n = 0
    for k, lst in groups.items():
        if len(lst) == 1 and lst[0][0]["id"] == k and lst[0][0]["actor"] == lst[0][1]:
            continue
        lst.sort(key=lambda x: x[0]["published"] or "9")
        base = dict(lst[0][0])
        base["actor"] = lst[0][1]
        srcs = set()
        for r, _ in lst:
            ex = r.get("extra") or {}
            srcs |= set(ex.get("sources") or []) | {r["source_id"]}
            for f in ("country", "sector", "domain", "org_id", "match"):
                if not base.get(f) and r.get(f):
                    base[f] = r[f]
        base["extra"] = {**(base.get("extra") or {}), "sources": sorted(srcs)}
        base["id"] = k
        if base.get("sector") in ("Not Found", "Unknown"):
            base["sector"] = None
        for r, _ in lst:
            c.execute("DELETE FROM leak WHERE id=?", (r["id"],))
        c.commit()
        db.upsert("leak", base)
        merged_n += 1
    return merged_n


def run_all() -> dict:
    t = {}
    for name, fn in (("dedupe", dedupe_leaks), ("enrich", enrich), ("incidents", build_incidents), ("impacts", build_impacts),
                     ("findings", build_findings), ("actions", build_actions)):
        try:
            t[name] = fn()
        except Exception as e:
            import traceback
            traceback.print_exc()
            t[name] = f"error: {e}"
    db.kv_set("pipeline_last", {"at": db.now(), **{k: v for k, v in t.items()}})
    print("[pipeline]", t)
    return t
