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

from aegis import db
from aegis.intel import ai as aimod
from aegis.intel.atlas import atlas_for
from aegis.intel.entities import matcher, norm, reg_domain
from aegis.intel.iocs import PLATFORM, BrandIndex, host_of
from aegis.intel.themes import themes_for
from aegis.intel.velocity import deadline, epss_surge, kev_lag, spread
from aegis.rating import RANK, RISKY_PORTS, rule, worst

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
        from aegis.intel.providers import Catalogue
        self.cat = Catalogue()
        vendors |= {t for t in self.cat.terms if len(t) >= 4}  # provider catalogue names and aliases ("Snowflake Data Cloud", "Drift")
        vendors = {v for v in vendors if v and len(v) >= 3 and v.lower() not in {"the", "apple", "google", "microsoft", "n/a", "box", "drift", "segment", "notion", "sitel"}} | {"Apple", "Google", "Microsoft"}
        vp = sorted(vendors, key=len, reverse=True)
        self.vendor_rx = re.compile(r"(?<![\w-])(" + "|".join(re.escape(v) for v in vp) + r")(?![\w-])")
        self.vendor_canon = {v.lower(): v for v in vp}

    def canon(self, v: str) -> str:
        """One name per provider: catalogue alias → canonical ("Snowflake Data Cloud" → "Snowflake")."""
        return self.cat.canonical(v) or self.vendor_canon.get(v.lower(), v)


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


MIT_THEMES = {"2.2": ["AI system security"], "4.2": ["AI-enabled attacks"], "4.3": ["AI-enabled attacks", "AI-enabled fraud & romance scams"],
              "6.5": ["AI governance & regulation"], "2.1": ["Data breach & leak", "AI system security"], "4.1": ["Influence operations & FIMI"]}


def enrich(days: int = 120) -> int:
    matcher.build()
    D = Dicts()
    rows = db.q("SELECT id, kind, title, summary, entities, org_ids, themes FROM item WHERE published > ?", (ts(days),))
    c = db.conn()
    for r in rows:
        text = f"{r['title']}. {r['summary'] or ''}"
        ent = r.get("entities") or {}
        # themes follow the current dictionary (fixes earlier mis-tags when the dictionary improves); AI incidents also carry
        # their MIT subdomain's themes so they appear in the Analyst heatmap
        if r["kind"] != "status":
            th = themes_for(text)
            if r["kind"] == "ai_incident":
                th = list(dict.fromkeys(th + MIT_THEMES.get(ent.get("mit") or "", []) + ["AI incidents & harms"]))
            r["themes"] = th
        ent["atlas"] = atlas_for(text)
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
        ent["vendors"] = sorted({D.canon(m.group(1)) for m in D.vendor_rx.finditer(text)} |
                                {D.canon(v) for v in ent.get("vendors") or []})[:10]
        if r["kind"] in ("news", "forum", "chatter", "advisory"):
            ent["victim"] = extract_victim(r["title"])
        org_ids = list(r.get("org_ids") or [])
        if r["kind"] != "filing":
            org_ids = matcher.mentions(r["title"]) or matcher.mentions((r["summary"] or "")[:300])
            if ent.get("victim"):
                oid, _ = matcher.resolve(ent["victim"])
                if oid and oid not in org_ids:
                    org_ids.insert(0, oid)
        c.execute("UPDATE item SET entities=?, org_ids=?, themes=? WHERE id=?", (json.dumps(ent), json.dumps(org_ids[:6]), json.dumps(r.get("themes") or []), r["id"]))
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


MEGA_PLATFORMS = {"AWS", "Microsoft Azure", "Microsoft 365", "Google Cloud", "Cloudflare", "Akamai", "Apple", "Google", "Microsoft",
                  "GitHub", "Salesforce", "Oracle Cloud", "Adobe"}  # named in too much reporting to infer "this provider was breached"
PROVIDER_BREACH = re.compile(r"\b(breach(ed)?|hack(ed|ers?)?|compromis\w*|intrusion|stolen|steal\w*|leak(ed|s)?|exfiltrat\w*|extort\w*|ransomware|"
                             r"attack(ed)? on|unauthori[sz]ed access|data theft|customers? (data|tenants?) (exposed|accessed))\b", re.I)
# court / arrest follow-ups ("pleads guilty in Snowflake extortions") are not a new compromise of the provider
LAW_FOLLOWUP = re.compile(r"\b(pleads?|pleaded|guilty|charged|sentenced|arrest(ed)?|indict(ed|ment)|extradit\w*|convicted|jailed)\b", re.I)
_BW = r"(breach|hack|compromis|intrusion|steal|stolen|exfiltrat|leak|backdoor|malicious|ransomware|unauthori[sz]ed)"


def provider_is_victim(name: str, title: str) -> bool:
    """The provider must be the one breached — "OpenAI's Artifactory opened a data-stealing channel", "breach at Salesloft",
    "attackers hit Snowflake", "Okta confirms breach" — not merely mentioned ("hackers walk into Dropbox accounts via a Lenovo flaw")."""
    p = re.escape(name)
    rx = re.compile(rf"(\b{p}(?:'s|’s)\b.{{0,60}}{_BW})|({_BW}\w*\s+(?:of|at|on|against|into)\s+{p}(?:'s|’s)?\s+(?:systems|network|infrastructure|environment|internal)?)|"
                    rf"((?:hit|hits|breached|compromised|infiltrated|hacked|attacked)\s+{p}\b)|(\b{p}\s+(?:confirms|discloses|says|reports|warns|suffers|investigat\w*)\b.{{0,80}}{_BW})",
                    re.I)
    return bool(rx.search(title or ""))


def derive_dependencies() -> int:
    """Apply the provider catalogue (shipped + analyst-added patterns) to the records every scan stored — MX, NS, SPF includes,
    TXT and hostname CNAMEs — so a new pattern (e.g. Databricks) reaches existing organisations without a rescan."""
    from aegis.intel.providers import Catalogue
    cat = Catalogue()
    have = {(r["org_id"], cat.canonical(r["vendor"]) or r["vendor"]) for r in db.q("SELECT org_id, vendor FROM dependency WHERE source_id != 'catalogue'")}
    rows, seen = [], set()
    now = db.now()

    def add(oid, kind, value, evidence):
        hit = cat.match(kind, value)
        if not hit or (oid, hit[0]) in have or (oid, hit[0], evidence) in seen:
            return
        seen.add((oid, hit[0], evidence))
        rows.append({"org_id": oid, "vendor": hit[0], "product": None, "category": hit[1], "evidence": evidence[:200], "source_id": "catalogue", "seen": now})
    for a in db.q("SELECT org_id, attrs FROM asset WHERE kind='domain'"):
        h = (a.get("attrs") or {}).get("hygiene") or {}
        for m in h.get("mx") or []:
            add(a["org_id"], "mx", m, f"MX {m}")
        for n in h.get("ns") or []:
            add(a["org_id"], "ns", n, f"NS {n}")
        for i in (h.get("spf") or {}).get("includes") or []:
            add(a["org_id"], "spf", i, f"SPF include:{i}")
        for t in h.get("txt") or []:
            add(a["org_id"], "txt", t, f"TXT {t[:60]}")
    for a in db.q("SELECT org_id, value, attrs FROM asset WHERE kind='hostname'"):
        cn = (a.get("attrs") or {}).get("cname")
        if cn:
            add(a["org_id"], "cname", cn, f"CNAME {a['value']} → {cn}")
    db.replace_set("dependency", rows, "source_id='catalogue'")  # no empty window for readers
    return len(rows)


def build_incidents(days: int = 90) -> int:
    from aegis.intel.providers import Catalogue
    cat = Catalogue()
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
        # a catalogue provider reported as breached / compromised, with no extracted victim ("… Into Snowflake's Internal Jira")
        if it["kind"] in ("news", "research", "forum") and not victim and not VENDOR_ADVISORY.search(it["title"] or "") \
                and PROVIDER_BREACH.search(it["title"] or "") and not LAW_FOLLOWUP.search(it["title"] or ""):
            provs = [p for p in cat.mentioned(it["title"]) if p not in MEGA_PLATFORMS and any(provider_is_victim(a, it["title"]) for a in cat.names_of(p))]
            if provs:
                p = provs[0]
                G = g(f"prov:{p.lower()}", victim=p, victim_org_id=None)
                G["themes"]["Supply-chain compromise"] += 1
                G["vendors"].add(p)
                G["actors"] |= {aname.get(a, a) for a in ent.get("actors") or []}
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
        vendor = cat.canonical(it["publisher"]) or (ent.get("vendors") or [it["publisher"]])[0]
        G = g(f"status:{vendor}:{it['published'][:10]}", victim=vendor, victim_org_id=None, provider=vendor)
        G["vendors"].add(vendor)
        G["kinds"]["Provider outage"] += 3
        src(G, it["publisher"] + " status page", it["url"], it["title"], it["published"], "Service status")
        G["item_ids"].append(it["id"])

    # ---- materialise
    dep_vendors = {(cat.canonical(r["vendor"]) or r["vendor"]).lower() for r in db.q("SELECT DISTINCT vendor FROM dependency")}
    known_providers = {n.lower() for n in cat.rows}
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
        pv = (cat.canonical(victim) or victim or "").lower()  # the victim is a catalogued provider even when no monitored org shows it in DNS
        is_vendor = (bool(victim and (pv in dep_vendors or pv in known_providers)) and compromise) or bool(G["themes"].get("Supply-chain compromise"))
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
            last_t = G["sources"][-1]["title"]
            # some status pages title incidents with a bare ticket number ("Snowflake: INC20000188")
            title = f"{victim} service incident — {len(G['sources'])} status update{'s' if len(G['sources']) > 1 else ''} ({last_t.split(': ', 1)[-1]})" \
                if re.fullmatch(r"[^:]+: *[A-Z]{2,5}\d{5,}", last_t or "") else last_t
        else:
            title = f"{victim}: {kind.lower()}"
        # severity (explainable)
        n_pub = len(publishers)
        if key.startswith("prov:") and n_pub < 2:  # one publisher says a provider was breached: context until corroborated
            rid = "I-PROVIDER-REPORTED"
        elif G.get("victim_org_id"):
            rid = "I-WATCH-VICTIM"
        elif kind == "Supply-chain / provider compromise" and victim and pv in dep_vendors:
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
        sp = spread(G["sources"])
        velocity = {k: sp[k] for k in ("first", "publishers", "publishers_72h", "hours_to_3", "spreading")}
        if key.startswith("cve:"):
            v = G.get("kev") or db.one("SELECT published, kev_added FROM vuln WHERE cve=?", (key[4:],)) or {}
            velocity["kev_lag"] = kev_lag(v.get("published"), v.get("kev_added"))
        rows.append({"id": iid, "velocity": velocity, "title": title[:240], "kind": kind, "victim": victim, "victim_org_id": G.get("victim_org_id"),
                     "vendors": sorted(G["vendors"])[:10], "products": products[:10], "actors": sorted(G["actors"])[:8], "cves": sorted(G["cves"])[:10],
                     "sectors": sorted(sectors)[:6], "countries": sorted(G["countries"])[:6], "first_seen": first, "last_seen": last,
                     "severity": sev, "severity_rule": rid, "sources": G["sources"][-30:], "source_count": n_pub,
                     "item_count": len(G["sources"]), "summary": G["sources"][-1]["title"][:300]})
        links += [(iid, i) for i in G["item_ids"]]
        links += [(iid, l, "leak") for l in G["leak_ids"]]
    c = db.conn()
    db.replace_set("incident", rows)  # no empty window for readers
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
LINK_TYPES = {
    "DIRECT": "Named victim",
    "GROUP": "Same corporate group (GLEIF)",
    "DEPENDENCY": "Uses the affected provider (public DNS evidence)",
    "EXPOSED_PRODUCT": "Runs the affected product on the internet",
    "NAMED_CUSTOMER": "Named as an affected customer in reporting",
    "TARGETING": "Same sector & country the actor is hitting",
}


PROVIDER_KINDS = {"Supply-chain / provider compromise", "Provider outage", "Data breach", "Ransomware & extortion",
                  "Disclosed incident (SEC 8-K)", "Dark-web sale / leak claim"}
EDGE_VENDORS = {"fortinet", "ivanti", "citrix", "sonicwall", "palo alto networks", "f5", "juniper", "check point", "progress", "fortra",
                "crushftp", "cleo", "connectwise", "beyondtrust", "simplehelp", "veeam", "synacor", "roundcube", "zoho", "solarwinds",
                "kaseya", "barracuda networks", "sophos", "watchguard", "paessler", "commvault", "gitlab", "jenkins", "sitecore",
                "n-able", "jfrog", "langflow", "berriai"}
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
    from aegis.intel.providers import Catalogue
    cat = Catalogue()
    incs = db.q("SELECT * FROM incident")
    orgs = {o["id"]: o for o in db.q("SELECT id, name, sector, country, domain FROM org")}
    deps = defaultdict(list)
    for d in db.q("SELECT org_id, vendor, category, evidence FROM dependency"):
        deps[(cat.canonical(d["vendor"]) or d["vendor"]).lower()].append(d)
    inc_items = defaultdict(list)  # incident → reporting items and the organisations they name
    for it in db.q("SELECT incident_id, org_ids, url, title FROM item WHERE incident_id IS NOT NULL"):
        inc_items[it["incident_id"]].append(it)
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
            rows.append({"incident_id": iid, "org_id": oid, "link_type": lt, "severity": sev, "reason": reason[:300], "evidence": evidence[:300]})

    for inc in incs:
        iid = inc["id"]
        breachy = inc["kind"] not in ("Provider outage",) and inc.get("severity_rule") != "I-PROVIDER-REPORTED"
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
            provs = ({(cat.canonical(victim) or victim).lower()} if victim else set())
            if inc["kind"] in ("Supply-chain / provider compromise", "Provider outage"):
                provs |= {(cat.canonical(v) or v).lower() for v in inc.get("vendors") or []}
        # organisations named in the reporting of a provider compromise are likely affected customers — this is how
        # providers invisible in DNS (e.g. a Snowflake or Salesloft campaign) still reach the organisations they hit
        if inc["kind"] == "Supply-chain / provider compromise":
            prov_name = cat.canonical(victim) or victim or "the provider"
            for it in inc_items.get(iid, []):
                for oid in it.get("org_ids") or []:
                    if oid != inc.get("victim_org_id") and orgs.get(oid) and norm(orgs[oid]["name"]) != norm(prov_name):
                        add(iid, oid, "NAMED_CUSTOMER", "high" if breachy else "medium",
                            f"Named in reporting about the {prov_name} incident: “{(it['title'] or '')[:140]}”.", it["url"] or "")
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
    db.replace_set("impact", list(best.values()))  # no empty window for readers
    # an incident that reaches monitored organisations through dependency escalates
    for iid in {r["incident_id"] for r in best.values() if r["link_type"] == "DEPENDENCY"}:
        inc = next(i for i in incs if i["id"] == iid)
        if inc["kind"] == "Supply-chain / provider compromise" and inc["severity"] != "critical" and inc.get("severity_rule") != "I-PROVIDER-REPORTED":
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
    ("impersonation", "Brand impersonation & lookalikes"),
]
RULE_CAT = {"DW-LEAK": "darkweb", "DW-ACCESS": "darkweb", "DW-FORUM": "darkweb", "DW-STEALER": "darkweb", "BR-": "darkweb",
            "DW-DDOS": "chatter", "THR-": "chatter", "INC-": "disclosure", "DISC-": "disclosure", "CMP-": "compromise",
            "VUL-": "vulns", "SURF-RISKY": "exposure", "SURF-TAKEOVER": "exposure", "SURF-EDGE": "critical", "SURF-LARGE": "footprint",
            "HYG-": "hygiene", "TP-": "software", "AI-": "ai",
            # v2.2 — brand impersonation has its own category; a listed own site / IP is a compromise; DNS drift is domain security
            "IOC-BRAND": "impersonation", "NRD-": "impersonation", "PHISH-": "impersonation", "IOC-OWN": "compromise", "WEB-CMS": "vulns",
            "WEB-": "compromise", "DNS-": "hygiene",
            # rules added on the Railway deployment (v2.0.1): keep them out of the "footprint" fallback
            "CRT-": "hygiene", "DOM-": "hygiene", "BGP-": "exposure", "LOOK-": "impersonation"}
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
        out.append({"id": hid(oid, rid, key or title), "org_id": oid, "category": rule_cat(rid), "title": title[:240], "detail": (detail or "")[:600],
                    "severity": sev, "rule_id": rid, "evidence_url": url, "source_id": source, "observed": observed, "data": data or {}})

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
    kev = {r["cve"]: r for r in db.q("SELECT cve, epss, epss_7d, exploit_refs, severity, kev_added, kev_due, published, vendor, product FROM vuln")}
    kev_recent = [((r["vendor"] or "").strip(), r["product"] or "") for r in db.q("SELECT vendor, product FROM vuln WHERE kev_added >= ?", (ts(30)[:10],))]
    kev90 = [f"{(r['vendor'] or '')} {(r['product'] or '')}".lower() for r in db.q("SELECT vendor, product FROM vuln WHERE kev_added >= ?", (ts(90)[:10],))]
    ai_kev = {c: aimod.kev_product(r.get("vendor"), r.get("product")) for c, r in kev.items() if r.get("kev_added") and aimod.kev_product(r.get("vendor"), r.get("product"))}
    ai_kev_products = set(ai_kev.values())
    ai_hosts = defaultdict(list)

    def recent_kev_for(vendor: str, product: str) -> bool:  # product-level: a Windows CVE says nothing about an Exchange host
        return any(v.lower() == vendor.lower() and product_match(v, kp, product) for v, kp in kev_recent)
    for a in db.q("SELECT org_id, kind, value, attrs, last_seen FROM asset WHERE kind IN ('ip','domain','hostname')"):
        at = a.get("attrs") or {}
        oid = a["org_id"]
        if a["kind"] == "hostname":
            prod = aimod.product_from_host(a["value"]) or ("Azure OpenAI" if re.search(r"\.openai\.azure\.com$", at.get("cname") or "") else None)
            if prod:
                ai_hosts[oid].append((a["value"], prod, bool(at.get("ips")), a["last_seen"]))
        if a["kind"] == "ip":
            if at.get("shared") and not at.get("owned"):
                continue
            vulns = at.get("vulns") or []
            url = f"https://internetdb.shodan.io/{a['value']}"
            # AI stack on this host: KEV CVE > product with KEV > port + product > port only
            ai_cves = [c for c in vulns if c in ai_kev]
            ai = aimod.assess_host(at.get("ports") or [], at.get("cpes") or [], [])
            hosts_txt = f"Hostnames: {', '.join(at.get('hosts') or []) or '—'}."
            if ai_cves:
                F(oid, "AI-KEV-EXPOSED", f"{a['value']} reports actively exploited {', '.join(sorted({ai_kev[c] for c in ai_cves}))} CVE(s)",
                  f"{', '.join(ai_cves)}. {hosts_txt} Version-inferred by the index — verify, patch, and rotate any AI provider keys the service held.",
                  url, "surface", a["last_seen"], a["value"] + ":ai", {"cves": ai_cves})
            elif ai and ai["evidence"] == "cpe" and set(ai["products"]) & ai_kev_products:
                F(oid, "AI-KEV-PRODUCT", f"{a['value']} runs {', '.join(ai['products'])} (product with CISA KEV entries)",
                  f"{hosts_txt} Ports {', '.join(map(str, ai['ports'])) or 'n/a'}. Confirm the version against the KEV entries and restrict access.",
                  url, "surface", a["last_seen"], a["value"] + ":ai", ai)
            elif ai and ai["evidence"] == "cpe":
                F(oid, "AI-EXPOSED-SERVICE", f"{a['value']} exposes {', '.join(ai['products'])}", f"{hosts_txt} Ports {', '.join(map(str, ai['ports'])) or 'per CPE'}. "
                  "Self-hosted AI services are often deployed without authentication.", url, "surface", a["last_seen"], a["value"] + ":ai", ai)
            elif ai and ai["evidence"] == "port":
                F(oid, "AI-EXPOSED-PORT", f"{a['value']} exposes port {', '.join(map(str, ai['ports']))} ({', '.join(ai['products'])})",
                  f"{hosts_txt} Port-only evidence (unconfirmed) — check what listens there.", url, "surface", a["last_seen"], a["value"] + ":ai", ai)
            cms = [c for c in at.get("cpes") or [] if any(c.replace("cpe:/a:", "").startswith(p) for p in CMS_CPE)]
            for c in cms[:1]:
                name = next(v for p, v in CMS_CPE.items() if c.replace("cpe:/a:", "").startswith(p))
                if any(name.lower().split()[0] in k for k in kev90):
                    F(oid, "WEB-CMS-KEV", f"{a['value']} runs {name} — CISA KEV added a {name} vulnerability in the last 90 days",
                      f"{hosts_txt} CPE {c}. Check the version and patch; keep offline, verified backups (restores can re-infect).", url, "surface", a["last_seen"], a["value"] + ":cms")
            surge = [c for c in vulns if c in kev and not kev[c].get("kev_added") and epss_surge(kev[c].get("epss"), kev[c].get("epss_7d"))]
            if surge:
                F(oid, "VUL-EPSS-SURGE", f"{a['value']} reports {len(surge)} CVE(s) with surging exploit likelihood",
                  "; ".join(f"{c}: EPSS {kev[c]['epss']:.0%} (was {kev[c]['epss_7d']:.0%} a week ago)" for c in surge[:5]) + f". {hosts_txt}",
                  url, "surface", a["last_seen"], a["value"] + ":surge", {"cves": surge})
            in_kev = [c for c in vulns if c in kev and kev[c].get("kev_added") and c not in ai_kev]
            hi = [c for c in vulns if c in kev and ((kev[c].get("epss") or 0) >= 0.1 or kev[c].get("exploit_refs")) and c not in ai_kev]
            if in_kev:
                F(oid, "VUL-KEV-EXPOSED", f"{a['value']} reports {len(in_kev)} actively exploited CVE(s)", f"{', '.join(in_kev[:8])} on {', '.join(at.get('hosts') or [])}. "
                  "Version-inferred by the index — verify.", url, "surface", a["last_seen"], a["value"], {"cves": in_kev})
            elif hi:
                F(oid, "VUL-EXPOSED-HIGH", f"{a['value']} reports high-likelihood CVE(s)", f"{', '.join(hi[:8])}", url, "surface", a["last_seen"], a["value"], {"cves": hi})
            elif vulns:
                F(oid, "VUL-EXPOSED", f"{a['value']} reports {len(vulns)} known CVE(s)", f"{', '.join(vulns[:8])}", url, "surface", a["last_seen"], a["value"], {"cves": vulns[:30]})
            risky = [f"{p}/{RISKY_PORTS[p]}" for p in at.get("ports") or [] if p in RISKY_PORTS]
            if risky:
                F(oid, "SURF-RISKY-PORT", f"{a['value']} exposes {', '.join(risky)}", f"Hostnames: {', '.join(at.get('hosts') or [])}.", url, "surface", a["last_seen"], a["value"], {"ports": at.get("ports")})
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
    # --- third-party incidents via dependency, or named as an affected customer
    for imp in db.q("SELECT m.*, i.title, i.last_seen, i.kind FROM impact m JOIN incident i ON i.id=m.incident_id WHERE m.link_type IN ('DEPENDENCY','NAMED_CUSTOMER')"):
        if days_since(imp["last_seen"]) > 30 or imp["kind"] == "Provider outage" or imp["severity"] == "medium":
            continue  # medium links are single-source provider reports — shown in the incident linkage, not raised as findings
        if imp["link_type"] == "DEPENDENCY":
            F(imp["org_id"], "TP-VENDOR-INC", f"Provider incident: {imp['title']}", imp["reason"] + f" Evidence: {imp['evidence']}.",
              f"/incidents/{imp['incident_id']}", "pipeline", imp["last_seen"], imp["incident_id"])
        else:
            F(imp["org_id"], "TP-NAMED-CUSTOMER", f"Named in provider-incident reporting: {imp['title']}", imp["reason"],
              imp["evidence"] or f"/incidents/{imp['incident_id']}", "pipeline", imp["last_seen"], imp["incident_id"] + ":named")
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
    # --- AI stack inventory, AI providers and their incidents
    for oid, hs in ai_hosts.items():
        kevh = [h for h in hs if h[1] in ai_kev_products and h[2]]
        for host, prod, _, seen in kevh[:5]:
            F(oid, "AI-KEV-PRODUCT", f"{host} suggests {prod} (product with CISA KEV entries)", "Public hostname — name-based, unconfirmed. "
              "Confirm the version and restrict access; rotate provider keys it holds.", f"https://crt.sh/?q={host}", "surface", seen, host + ":ai")
        F(oid, "AI-HOST", f"AI platforms in public hostnames: {', '.join(sorted({h[1] for h in hs}))}", ", ".join(h[0] for h in hs[:8]),
          f"https://crt.sh/?q={hs[0][0]}", "surface", hs[0][3], "ai-host", {"hosts": [h[0] for h in hs[:20]]})
    ai_deps = defaultdict(dict)
    for d in db.q("SELECT org_id, vendor, evidence FROM dependency WHERE category='AI services'"):
        ai_deps[d["org_id"]][d["vendor"]] = d["evidence"]
    prov_inc = defaultdict(list)  # provider → [(title, url, when)]
    # AI providers post "major" status incidents most weeks — only a full (critical) outage in 14 days counts, plus security incidents in 30
    for it in db.q("SELECT publisher, title, url, published, entities FROM item WHERE kind='status' AND published > ?", (ts(14),)):
        if ((it.get("entities") or {}).get("impact") or "") == "critical":
            prov_inc[it["publisher"]].append((it["title"], it["url"], it["published"]))
    for inc in db.q("SELECT id, title, victim, kind, last_seen, severity_rule FROM incident WHERE last_seen > ?", (ts(30),)):
        if inc["kind"] in PROVIDER_KINDS and inc["kind"] != "Provider outage" and (inc["victim"] or "") in ("OpenAI", "Anthropic") \
                and inc.get("severity_rule") != "I-PROVIDER-REPORTED":  # single-source reports stay context
            prov_inc[inc["victim"]].append((inc["title"], f"/incidents/{inc['id']}", inc["last_seen"]))
    for oid, provs in ai_deps.items():
        F(oid, "AI-SERVICE-DNS", f"Uses generative-AI services: {', '.join(sorted(provs))}",
          "Evidence: " + " · ".join(f"{v}: {e}" for v, e in provs.items()) + ". Governance: keep AI keys in a vault and rotate them; buy only through "
          "authorised channels — third-party 'discount' AI resellers and routers have logged and resold customer conversations (Anthropic, Sept 2026).",
          f"https://dns.google/resolve?name={orgs[oid]['domain']}&type=TXT" if oid in orgs else None, "surface", ts(0), "ai-dns", {"providers": sorted(provs)})
        for p in provs:
            for title, url, when in sorted(prov_inc.get(p, []), key=lambda x: x[2], reverse=True)[:1]:
                F(oid, "AI-PROVIDER-INC", f"AI provider incident — {title}", f"The organisation uses {p} ({provs[p]}).", url, "status_pages", when, "ai-prov:" + p)
    # --- published indicators, lookalikes, phishing, compromised websites
    org_ns = {a["org_id"]: set((a.get("attrs") or {}).get("hygiene", {}).get("ns") or []) | set((a.get("attrs") or {}).get("hygiene", {}).get("mx") or [])
              for a in db.q("SELECT org_id, attrs FROM asset WHERE kind='domain'")}
    phish_regs = set(db.kv_get("phish_regdomains", []) or [])
    agg_phish = defaultdict(list)
    agg_nrd = defaultdict(list)  # one finding per organisation and level — a brand can collect dozens of lookalikes a day
    agg_brand = defaultdict(list)  # same for lookalikes named in threat reports (Microsoft alone has dozens)
    for r in db.q("SELECT * FROM ioc WHERE org_id IS NOT NULL"):
        oid, h, at = r["org_id"], host_of(r["value"]), r.get("attrs") or {}
        live = bool(at.get("a") or at.get("mx"))
        own_infra = org_ns.get(oid, set())
        defensive = bool(own_infra) and bool(set(at.get("ns") or []) & own_infra or set(at.get("mx") or []) & own_infra)
        name = orgs.get(oid, {}).get("name", oid)
        age = days_since(r["published"])
        src_txt = f"Published by {r['publisher']}: “{r['report_title']}”."
        if r["match"] == "brand" and not defensive:
            agg_brand[(oid, "IOC-BRAND-LIVE" if live else "IOC-BRAND")].append((h, r))
        elif r["match"] == "own-domain":
            F(oid, "IOC-OWN-DOMAIN", f"{h} is listed as an indicator of compromise", f"{src_txt} Context: {r['context'] or '—'}",
              r["report_url"], r["source_id"], r["published"], "ioc:" + h, {"ioc": h})
        elif r["match"] == "own-ip":
            F(oid, "IOC-OWN-IP", f"{r['value']} (organisation IP space) is listed as an indicator", f"{src_txt} {r['how'] or ''}",
              r["report_url"], r["source_id"], r["published"], "ioc:" + r["value"], {"ioc": r["value"]})
        elif r["match"] == "nrd" and age <= 30 and not defensive:
            rid = "NRD-PHISH" if live and reg_domain(h) in phish_regs else "NRD-LIVE" if live else "NRD-MATCH"
            agg_nrd[(oid, rid)].append((h, r, at))
        elif r["match"] == "phish-brand" and age <= 14:
            agg_phish[oid].append(r)
        elif r["match"] == "own-site" and age <= 30:
            tags = r.get("tags") or []
            F(oid, "WEB-CLICKFIX" if "clickfix" in tags else "WEB-MALWARE", f"{h} listed by {r['publisher']}" + (" (ClickFix / fake-CAPTCHA lure)" if "clickfix" in tags else ""),
              f"{r['context'] or ''}. Check the site for injected scripts and web shells, patch the CMS, and restore only from verified offline backups.",
              r["report_url"], r["source_id"], r["published"], "web:" + h, {"ioc": r["value"], "tags": tags})
    for (oid, rid), rs in agg_brand.items():
        rs.sort(key=lambda x: x[1]["published"], reverse=True)
        hosts = list(dict.fromkeys(x[0] for x in rs))
        pubs = sorted({x[1]["publisher"] for x in rs})
        ex = rs[0][1]
        F(oid, rid, f"{len(hosts)} lookalike domain{'s' if len(hosts) > 1 else ''} of {orgs.get(oid, {}).get('name', oid)} in threat-report indicators"
          + (" — still resolving" if rid == "IOC-BRAND-LIVE" else ""),
          f"Newest: {', '.join(hosts[:8])}{' …' if len(hosts) > 8 else ''}. Published by {', '.join(pubs[:4])}. Example match: {ex['how']}. "
          "Add them to email and web blocklists (Impersonation → hunt pack / entity blocklist CSV)" + ("; request takedown of the live ones." if rid == "IOC-BRAND-LIVE" else "."),
          ex["report_url"], ex["source_id"], ex["published"], "ioc-brand", {"hosts": hosts[:60], "publishers": pubs})
    for (oid, rid), rs in agg_nrd.items():
        rs.sort(key=lambda x: x[1]["published"], reverse=True)
        doms = [x[0] for x in rs]
        what = {"NRD-PHISH": "resolving and on a phishing feed", "NRD-LIVE": "resolving (web or mail)", "NRD-MATCH": "not resolving yet"}[rid]
        ex = rs[0]
        F(oid, rid, f"{len(rs)} new lookalike domain{'s' if len(rs) > 1 else ''} of {orgs.get(oid, {}).get('name', oid)} — {what}",
          f"Newest: {', '.join(doms[:8])}{' …' if len(doms) > 8 else ''}. Example match: {ex[1]['how']}. Registered in the last 30 days (WhoisDS). "
          "Pre-block in mail and web gateways (blocklist export); request takedown for live ones.",
          f"https://urlscan.io/search/#domain:{doms[0]}", "nrd_whoisds", ex[1]["published"], "nrd", {"domains": doms[:60]})
    for oid, rs in agg_phish.items():
        hosts = sorted({host_of(x["value"]) for x in rs})
        F(oid, "PHISH-BRAND", f"{len(rs)} live phishing URL(s) on lookalikes of {orgs.get(oid, {}).get('name', oid)}", f"Hosts: {', '.join(hosts[:6])}. "
          f"Sources: {', '.join(sorted({x['publisher'] for x in rs}))}.", rs[0]["report_url"], "phish_feeds", max(x["published"] for x in rs), "phish-brand", {"hosts": hosts[:20]})
    for oid, t in (db.kv_get("phishtank_targets", {}) or {}).items():
        if oid in orgs and t.get("n"):
            F(oid, "PHISH-TARGET", f"PhishTank: {t['n']} verified, online phishing page(s) target {t['target']}",
              "Verified by the PhishTank community and still online. Report them for takedown and warn customers/staff.",
              t.get("sample") or "https://phishtank.org/", "phish_feeds", (t.get("latest") or ts(0))[:19] + "Z", "phishtank")
    # --- DNS change / possible hijack (needs three scans)
    snaps = defaultdict(list)
    for s in db.q("SELECT org_id, scanned_at, ns, mx, dnssec, caa FROM snapshot ORDER BY scanned_at DESC"):
        snaps[s["org_id"]].append(s)
    for oid, ss in snaps.items():
        for rid, title, detail in dns_drift(ss):
            d = orgs.get(oid, {}).get("domain") or ""
            F(oid, rid, title.replace("{d}", d), detail, f"https://dns.google/resolve?name={d}&type={'MX' if 'MX' in rid else 'DS' if 'DNSSEC' in rid else 'CAA' if 'CAA' in rid else 'NS'}",
              "surface", ss[0]["scanned_at"], rid)
    # --- domain, certificate & routing hardening (BGP-/CRT-/DOM-/LOOK-, HYG-DKIM/NS/SPF-LOOKUPS/TLSRPT)
    #     rules in aegis/intel/hardening.py; observations stored in org.hardening by collectors/hardening.py
    from aegis.intel.hardening import hardening_findings
    for o in db.q("SELECT id, name, domain, hardening FROM org WHERE hardening IS NOT NULL"):
        try:
            hh = o["hardening"] if isinstance(o["hardening"], dict) else json.loads(o["hardening"])
            for f in hardening_findings(o, hh):
                F(f["org_id"], f["rule_id"], f["title"], f["detail"], f["evidence_url"], f["source_id"], f["observed"], f["key"], f["data"])
        except Exception as e:  # one malformed record never blocks the rest of the findings
            print("[findings] hardening", o["id"], e)

    # persist with first_seen continuity; every Critical/High/Medium finding gets an "act by" date from one deadline rule
    prev = {r["id"]: r["first_seen"] for r in db.q("SELECT id, first_seen FROM finding")}
    now = db.now()
    kevd = {c: {"kev_added": r["kev_added"], "kev_due": r.get("kev_due"), "lag": kev_lag(r.get("published"), r["kev_added"])}
            for c, r in kev.items() if r.get("kev_added")}
    uniq = {}
    from aegis import confidence as conf
    from aegis.actions import suppressed
    sup = suppressed(now)  # analyst decisions: false positive, or accepted risk until its expiry
    for f in out:
        if f["id"] in sup:
            continue
        conf.apply(f)  # confirmed / likely / unconfirmed; unconfirmed never above High
        f["first_seen"] = prev.get(f["id"], now)
        f["last_seen"] = now
        cves = (f.get("data") or {}).get("cves") or []
        f["act_by"], f["deadline_rule"] = deadline(f["rule_id"], f["severity"], f["first_seen"], cves, kevd)
        ex = [kevd[c]["kev_added"] for c in cves if c in kevd]
        if ex:  # how long attackers have been exploiting what this finding is about
            f["data"] = {**(f.get("data") or {}), "exploited_since": min(ex),
                         "fastest_lag": min((kevd[c]["lag"] for c in cves if c in kevd and kevd[c]["lag"] is not None), default=None)}
        uniq[f["id"]] = f
    # replace without an empty window: a page read mid-run never sees zero findings
    db.replace_set("finding", list(uniq.values()))
    return len(uniq)


CMS_CPE = {"wordpress:wordpress": "WordPress", "drupal:drupal": "Drupal", "joomla:joomla": "Joomla", "sitecore:": "Sitecore",
           "adobe:experience_manager": "Adobe Experience Manager", "liferay:": "Liferay", "magento:magento": "Magento", "craftcms:": "Craft CMS",
           "typo3:typo3": "TYPO3", "progress:sitefinity": "Sitefinity"}


def dns_drift(snaps: list[dict]) -> list[tuple[str, str, str]]:
    """snaps newest first. A change must persist across the two newest scans and differ from every earlier scan."""
    if len(snaps) < 3:
        return []
    s0, s1, older = snaps[0], snaps[1], snaps[2:]
    prov = lambda hosts: {reg_domain(h) for h in hosts or []}
    out = []
    ns0, ns1 = set(s0.get("ns") or []), set(s1.get("ns") or [])
    old_ns = set().union(*[set(s.get("ns") or []) for s in older])
    if ns0 and ns0 == ns1 and old_ns and not (ns0 & old_ns) and not (prov(ns0) & prov(old_ns)):
        out.append(("DNS-NS-REPLACED", "Name servers of {d} were replaced",
                    f"Now: {', '.join(sorted(ns0))}. Previously: {', '.join(sorted(old_ns)[:6])}. Confirm with the registrar that this was planned; "
                    "if not, lock the domain, reset registrar credentials and check for rogue certificates."))
    mx0, mx1 = set(s0.get("mx") or []), set(s1.get("mx") or [])
    old_mx = set().union(*[set(s.get("mx") or []) for s in older])
    if mx0 and mx0 == mx1 and old_mx and not (prov(mx0) & prov(old_mx)):
        out.append(("DNS-MX-MOVED", "Mail exchangers of {d} moved to a new provider",
                    f"Now: {', '.join(sorted(mx0))}. Previously: {', '.join(sorted(old_mx)[:6])}. Verify the change was planned (mail can be intercepted)."))
    if ns0 and ns1 and not s0.get("dnssec") and not s1.get("dnssec") and any(s.get("dnssec") for s in older):
        out.append(("DNS-DNSSEC-LOST", "DNSSEC removed from {d}", "A DS record was present on an earlier scan and is absent on the last two. "
                    "Removing DNSSEC is a common step before a DNS hijack — confirm it was intended."))
    if ns0 and ns1 and not (s0.get("caa") or []) and not (s1.get("caa") or []) and any(s.get("caa") for s in older):
        out.append(("DNS-CAA-REMOVED", "CAA record removed from {d}", "Any certificate authority may now issue for the domain. Confirm the change was intended."))
    return out


def match_iocs() -> int:
    """Link published indicators to organisations: own domain, own IP space, or brand impersonation (explainable token + reason)."""
    import bisect
    import ipaddress
    orgs = db.q("SELECT id, name, domain, domains FROM org")
    bi = BrandIndex(orgs)
    from aegis.collectors.surface import cloud_lookup
    fp = []
    for a in db.q("SELECT org_id, kind, value, attrs FROM asset WHERE kind IN ('ip','prefix')"):
        at = a.get("attrs") or {}
        if a["kind"] == "ip" and at.get("shared") and not at.get("owned"):
            continue
        # SPF ip4 blocks often name the mail provider's ranges (e.g. Google's), which are not the organisation's own network
        if (at.get("provenance") or "").startswith("SPF"):
            continue
        try:
            n = ipaddress.ip_network(a["value"], strict=False)
        except ValueError:
            continue
        if n.version == 4:
            fp.append((int(n.network_address), int(n.broadcast_address), a["org_id"], a["value"], at.get("provenance") or "resolved IP"))
    fp.sort()
    starts = [f[0] for f in fp]

    def ip_owner(v):
        try:
            x = int(ipaddress.ip_address(v))
        except ValueError:
            return None
        i = bisect.bisect_right(starts, x) - 1
        for j in range(i, max(-1, i - 50), -1):
            if fp[j][0] <= x <= fp[j][1]:
                return fp[j]
        return None
    upd = []
    for r in db.q("SELECT id, value, type, kind, tags FROM ioc WHERE published > ? OR kind='nrd'", (ts(365),)):
        oid = match = token = how = None
        if r["type"] in ("domain", "url"):
            h = host_of(r["value"])
            tags = r.get("tags") or []
            if r["kind"] == "feed":
                if "own-site" in tags and bi.owner(h):
                    oid, match, how = bi.owner(h), "own-site", f"{h} is under the organisation's own domain"
                elif "brand" in tags:
                    m = bi.match(h)
                    if m:  # phishing pages → PHISH-BRAND; malware / C2 servers on lookalike domains → IOC-BRAND(-LIVE)
                        oid, match, token, how = m["org_id"], "phish-brand" if "phishing" in tags else "brand", m["token"], m["how"]
            elif r["kind"] == "nrd":
                m = bi.match(h)
                if m:
                    oid, match, token, how = m["org_id"], "nrd", m["token"], m["how"]
            else:
                own = bi.owner(h)
                if own and reg_domain(h) not in PLATFORM:
                    oid, match, how = own, "own-domain", f"{h} is under the organisation's own domain"
                else:
                    m = bi.match(h)
                    if m:
                        oid, match, token, how = m["org_id"], "brand", m["token"], m["how"]
        elif r["type"] == "ip" and r["kind"] == "report":
            hit = ip_owner(r["value"]) if not cloud_lookup(r["value"]) else None  # cloud / CDN space is shared, never "own"
            if hit:
                oid, match, how = hit[2], "own-ip", f"inside {hit[3]} ({hit[4]})"
        upd.append((oid, match, token, how, r["id"]))
    c = db.conn()
    c.executemany("UPDATE ioc SET org_id=?, match=?, token=?, how=? WHERE id=?", upd)
    # retention: indicators go stale — unmatched report/feed rows older than 400 days and new-domain rows older than 90 days are dropped
    c.execute("DELETE FROM ioc WHERE org_id IS NULL AND kind IN ('report','feed') AND published < ?", (ts(400),))
    c.execute("DELETE FROM ioc WHERE kind='nrd' AND published < ?", (ts(90),))
    c.commit()
    return sum(1 for u in upd if u[0])


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


def track_cve_exposure() -> int:
    """History of which CVEs each organisation's own internet-facing hosts report (Shodan InternetDB), so fixes can be observed.
    A CVE no longer reported after a newer scan of that organisation gets fixed_at (patched, or the host removed); if it is
    reported again, fixed_at is cleared. Shared infrastructure (CDN / cloud front ends not owned by the organisation) is excluded."""
    now = db.now()
    cur, first = defaultdict(set), {}
    for a in db.q("SELECT org_id, value, attrs, first_seen FROM asset WHERE kind='ip'"):
        at = a.get("attrs") or {}
        if at.get("shared") and not at.get("owned"):
            continue
        for c in at.get("vulns") or []:
            cur[(a["org_id"], c)].add(a["value"])
            k = (a["org_id"], c)
            first[k] = min(first.get(k) or now, a.get("first_seen") or now)
    scanned = {o["id"]: o["deep_scanned"] or "" for o in db.q("SELECT id, deep_scanned FROM org")}
    rows = {(r["org_id"], r["cve"]): r for r in db.q("SELECT * FROM cve_exposure")}
    out = []
    for k, hosts in cur.items():
        r = rows.get(k) or {}
        out.append({"org_id": k[0], "cve": k[1], "first_seen": r.get("first_seen") or first.get(k) or now, "last_seen": now, "fixed_at": None,
                    "hosts": sorted(hosts)[:20]})
    for k, r in rows.items():
        if k in cur or r.get("fixed_at"):
            continue
        if scanned.get(k[0], "") > (r.get("last_seen") or ""):  # a newer scan of this organisation no longer reports it
            out.append({**r, "fixed_at": now})
    db.upsert("cve_exposure", out)
    return len(out)


def _build_actions() -> int:
    from aegis.actions import build_actions  # stage 5 (v2.1 Prevent): actions with lifecycle and verified closure
    return build_actions()


def run_all() -> dict:
    t = {}
    for name, fn in (("dedupe", dedupe_leaks), ("dependencies", derive_dependencies), ("enrich", enrich), ("incidents", build_incidents), ("impacts", build_impacts),
                     ("iocs", match_iocs), ("findings", build_findings), ("cve_exposure", track_cve_exposure), ("actions", _build_actions)):
        try:
            t[name] = fn()
        except Exception as e:
            import traceback
            traceback.print_exc()
            t[name] = f"error: {e}"
    db.kv_set("pipeline_last", {"at": db.now(), **{k: v for k, v in t.items()}})
    print("[pipeline]", t)
    return t
