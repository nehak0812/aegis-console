"""Deep & dark web — metadata only, via reputable third-party trackers. We never fetch .onion, Telegram or paste sites.

Categories: leak-site listings · forum/market claims (access, data, credentials) · infostealer exposure ·
public breaches · hacktivist DDoS targeting. Every row keeps its source link for attribution.
"""
import hashlib
import re
from datetime import datetime, timedelta, timezone

import feedparser

from aegis import db, net
from aegis.collectors.rss import iso, item_id, enrich, store_items, strip_html
from aegis.guard import redact
from aegis.intel.entities import matcher, norm, reg_domain
from aegis.registry import Source, collector


def victim_key(victim: str, domain: str = "") -> str:
    """Key on the victim *name* (every tracker has one); fall back to the domain only when there is no name.
    Trackers disagree on domains far more often than on names."""
    v = (victim or "").strip().lower()
    if not v and domain:
        v = domain.strip().lower()
    if re.fullmatch(r"[\w.-]+\.[a-z]{2,}", v):
        v = reg_domain(v).split(".")[0]
    return re.sub(r"[^a-z0-9]", "", norm(v) if " " in v else v)


def leak_id(kind: str, *parts: str) -> str:
    return kind + "-" + hashlib.sha1("|".join(p or "" for p in parts).encode()).hexdigest()[:20]


_CANON: dict | None = None


def gkey(group: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (group or "").lower())


def canon_group(group: str) -> str:
    """Trackers spell groups differently ("inc ransom" / "incransom"); use the ransomware.live name so profiles link up."""
    global _CANON
    if _CANON is None:
        _CANON = {gkey(r["name"]): r["name"] for r in db.q("SELECT name FROM actor WHERE kind='ransomware'")}
    return _CANON.get(gkey(group), (group or "").strip())


def _looks_domain(s: str) -> bool:
    return bool(re.fullmatch(r"[\w-]+(\.[\w-]+)+", (s or "").strip().lower()))


def store_leaks(rows: list[dict]) -> int:
    """Merge on id; remember every source that reported the same listing."""
    for r in rows:
        if r.get("sector") in ("Not Found", "Unknown", ""):
            r["sector"] = None
        ex = db.one("SELECT source_id, extra, country, sector, domain, org_id, match, published FROM leak WHERE id=?", (r["id"],))
        extra = r.get("extra") or {}
        srcs = set(extra.get("sources", [])) | {r["source_id"]}
        if ex:
            old = ex.get("extra") or {}
            srcs |= set(old.get("sources", [])) | {ex["source_id"]}
            extra = {**old, **{k: v for k, v in extra.items() if v not in (None, "", [])}}
            r["source_id"] = ex["source_id"]
            for f in ("country", "sector", "domain", "org_id", "match"):  # never lose enrichment another tracker supplied
                if not r.get(f) and ex.get(f):
                    r[f] = ex[f]
            if ex.get("published") and (not r.get("published") or ex["published"] < r["published"]):
                r["published"] = ex["published"]  # first sighting wins
        extra["sources"] = sorted(srcs)
        r["extra"] = extra
        if not r.get("org_id"):
            oid, how = matcher.resolve(r.get("victim", ""), r.get("domain", ""))
            r["org_id"], r["match"] = oid, how
    return db.upsert("leak", rows, keep=("incident_id",))


# ---------------------------------------------------------------- leak sites
@collector(Source(
    id="ransomlook", name="RansomLook leak-site tracker", category="Dark web", publisher="RansomLook (CIRCL community)",
    homepage="https://www.ransomlook.io", url="https://www.ransomlook.io/api/last/3", cadence_min=30,
    licence="Data CC BY 4.0 (attribution)", notes="Victim posts from 600+ ransomware/extortion leak sites; group and market liveness. Metadata only."))
def collect_ransomlook() -> int:
    posts = net.get_json("https://www.ransomlook.io/api/last/3", timeout=60) or []
    rows = []
    for p in posts:
        title = redact(strip_html(p.get("post_title"), 200))
        group = canon_group(p.get("group_name") or "")
        if not title or not group:
            continue
        dom = title.lower() if _looks_domain(title) else ""
        if dom:
            title = dom
        rows.append({"id": leak_id("ls", victim_key(title, dom), gkey(group)), "source_id": "ransomlook", "kind": "leaksite",
                     "victim": title, "domain": dom, "actor": group, "published": (p.get("discovered") or "")[:19].replace(" ", "T") + "Z",
                     "title": f"{title} listed by {group}", "url": f"https://www.ransomlook.io/group/{group}",
                     "extra": {"description": redact(strip_html(p.get("description"), 400))}})
    n = store_leaks(rows)
    try:
        db.kv_set("ransomlook_stats", net.get_json("https://www.ransomlook.io/api/stats", timeout=30))
        db.kv_set("ransomlook_markets", net.get_json("https://www.ransomlook.io/api/markets", timeout=30))
    except Exception as e:
        print("[ransomlook] stats/markets:", e)
    return n


@collector(Source(
    id="ransomware_live", name="ransomware.live victims & press-reported attacks", category="Dark web", publisher="ransomware.live",
    homepage="https://www.ransomware.live", url="https://api.ransomware.live/v2/recentvictims", cadence_min=30,
    licence="Free API — attribution required; non-commercial without written approval",
    notes="Adds victim country, sector and domain to leak-site listings, plus press-reported cyberattacks. 1 request/min per endpoint."))
def collect_ransomware_live() -> int:
    victims = net.get_json("https://api.ransomware.live/v2/recentvictims", timeout=60) or []
    rows = []
    for v in victims:
        name = redact(strip_html(v.get("victim"), 200))
        group = canon_group(v.get("group") or "")
        if not name or not group:
            continue
        dom = (v.get("domain") or "").strip().lower()
        url = v.get("url") if str(v.get("url", "")).startswith("https://www.ransomware.live") else f"https://www.ransomware.live/group/{group}"
        rows.append({"id": leak_id("ls", victim_key(name, dom), gkey(group)), "source_id": "ransomware_live", "kind": "leaksite",
                     "victim": name, "domain": dom, "actor": group, "published": v.get("discovered"),
                     "country": (v.get("country") or "").upper() or None, "sector": v.get("activity") or None,
                     "title": f"{name} listed by {group}", "url": url,
                     "extra": {"description": redact(strip_html(v.get("description"), 400)),
                               "attack_date": v.get("attackdate"),
                               "press": (v.get("press") or {}).get("link") if isinstance(v.get("press"), dict) else None}})
    n = store_leaks(rows)
    # press-reported attacks (clearnet press links) → items for incident clustering
    try:
        attacks = net.get_json("https://api.ransomware.live/v2/recentcyberattacks", timeout=60) or []
        items = []
        for a in attacks:
            link = a.get("url") or ""
            title = strip_html(a.get("title") or a.get("victim"), 300)
            if not link or not title:
                continue
            victim = strip_html(a.get("victim"), 120)
            items.append({"id": item_id(link), "source_id": "ransomware_live", "kind": "news", "publisher": "ransomware.live press tracker",
                          "pub_type": "Tracker", "title": title, "summary": f"Victim: {victim}. Domain: {a.get('domain') or '—'}. Claimed by: {a.get('claim_gang') or 'unclaimed'}.",
                          "url": link, "published": (a.get("date") or db.now())[:19].replace(" ", "T") + ("Z" if len(a.get("date") or "") >= 10 else ""),
                          "fetched": db.now(), **enrich(title, victim + " " + (a.get("domain") or ""))})
        n += store_items(items)
    except Exception as e:
        print("[ransomware.live] cyberattacks:", e)
    return n


@collector(Source(
    id="ransomware_groups", name="Ransomware group profiles", category="Dark web", publisher="ransomware.live",
    homepage="https://www.ransomware.live/groups", url="https://api.ransomware.live/v2/groups", cadence_min=1440,
    licence="Free API — attribution required; non-commercial without written approval",
    notes="Group descriptions and aliases for the Adversaries view."))
def collect_groups() -> int:
    groups = net.get_json("https://api.ransomware.live/v2/groups", timeout=60) or []
    rows = []
    for g in groups:
        name = (g.get("name") or "").strip()
        if not name:
            continue
        rows.append({"id": "rw-" + name.lower(), "name": name, "aliases": [a for a in [g.get("altname")] if a],
                     "description": redact(strip_html(g.get("description"), 900)), "kind": "ransomware",
                     "motivation": "Financial (extortion)", "refs": [f"https://www.ransomware.live/group/{name}"],
                     "source_id": "ransomware_groups"})
    global _CANON
    _CANON = None
    return db.upsert("actor", rows, keep=("crowdstrike", "origin", "sectors", "countries", "attack_id"))


# ---------------------------------------------------------------- forum / market claims (reported by outlets)
CLAIM_FEEDS = [
    ("Dark Web Informer", "https://darkwebinformer.com/rss/"),
    ("Brinztech", "https://www.brinztech.com/feed/"),
    ("SOCRadar", "https://socradar.io/feed/"),
    ("DataBreaches.net", "https://databreaches.net/feed/"),
    ("The Cyber Express", "https://thecyberexpress.com/feed/"),
    ("DailyDarkWeb", "https://dailydarkweb.net/feed/"),
]
CONSUMER_ACCOUNT = re.compile(r"online banking|savings account|bank account|customer account|user account|personal account|account of a", re.I)
CLAIM_KIND = [
    # initial access to the organisation's own network — not a single customer's account (that is fraud, classed as data)
    ("access", re.compile(r"initial access|\b(admin|root|shell|rdp|vpn|citrix|domain admin|webshell|network|corporate|server|panel|fortinet|ssl-?vpn)\b[^.]{0,40}\baccess\b[^.]{0,60}\b(sale|sold|offered|advertised|selling|auction)|\baccess\b[^.]{0,20}\b(to|into) (the )?(network|corporate|internal|infrastructure)", re.I)),
    ("credentials", re.compile(r"stealer logs?|credentials?|combolist|combo list|logins?\b.*(leak|sale|offered)", re.I)),
    ("ddos", re.compile(r"\bddos\b|denial[- ]of[- ]service", re.I)),
    ("extortion", re.compile(r"ransomware|extort|leak site", re.I)),
    ("data", re.compile(r"records|database|dataset|data ?(leak|breach|sale|dump)|dump|leaked|offered for sale|for sale|exposes|claimed", re.I)),
]
_ORG_AFTER = re.compile(r"\b(?:from|of|for|at|impacting|targeting|affecting|belonging to)\s+(?:the\s+)?([A-Z][\w&.'’()\- ]{2,70}?)(?=\s+(?:in|on|via|with|by|has|after|allegedly|advertised|offered|leaked|exposed|—|-)\b|[,:;|]|$)")
_ORG_LEAD = re.compile(r"^(?:Alleged\s+|Brinztech Alert:\s*|Claimed\s+)?(?:Data Leak of\s+)?([A-Z][\w&.'’\- ]{2,60}?)\s+(?:Dataset|Database|Data|Records|Customer|User|Employee|Access|Source Code|Documents)\b")


def claim_kind(title: str) -> str | None:
    for k, rx in CLAIM_KIND:
        if k == "access" and CONSUMER_ACCOUNT.search(title):
            continue
        if rx.search(title):
            return k
    return None


def claimed_org(title: str) -> str:
    t = re.sub(r"^Brinztech Alert:\s*", "", title)
    m = _ORG_LEAD.search(t) or _ORG_AFTER.search(t)
    return m.group(1).strip(" .-") if m else ""


@collector(Source(
    id="forum_claims", name="Dark-web forum & market claims (reported)", category="Dark web", publisher="Dark Web Informer · Brinztech · SOCRadar · DataBreaches.net · The Cyber Express · DailyDarkWeb",
    homepage="https://darkwebinformer.com", cadence_min=45, licence="RSS headline + link (publisher terms)",
    feeds=[{"publisher": p, "url": u} for p, u in CLAIM_FEEDS],
    notes="Outlets that report what is posted on BreachForums, XSS, Exploit, DarkForums and Telegram: access sales, database leaks, credential dumps, DDoS claims. Headline + link only; claims are unverified."))
def collect_forum_claims() -> int:
    total = 0
    errors = []
    for pub, url in CLAIM_FEEDS:
        try:
            raw = net.get(url, timeout=25, headers={"Accept": "application/rss+xml, application/xml, */*"})
            feed = feedparser.parse(raw.content)
            items, leaks = [], []
            for e in feed.entries[:50]:
                link, title = e.get("link") or "", strip_html(e.get("title"), 300)
                if not link or not title:
                    continue
                summary = redact(strip_html(e.get("summary") or e.get("description"), 600))
                published = iso(e.get("published_parsed") or e.get("updated_parsed")) or db.now()
                kind = claim_kind(title)
                items.append({"id": item_id(link), "source_id": "forum_claims", "kind": "forum" if kind else "news", "publisher": pub,
                              "pub_type": "Dark-web reporting", "title": title, "summary": summary, "url": link,
                              "published": published, "fetched": db.now(), **enrich(title, summary)})
                if kind:
                    victim = claimed_org(title)
                    oids = matcher.mentions(title)
                    leaks.append({"id": leak_id("fc", link), "source_id": "forum_claims", "kind": "forum", "victim": victim or (title[:80]),
                                  "domain": "", "actor": None, "published": published, "title": title, "url": link,
                                  "org_id": oids[0] if oids else None, "match": "mention" if oids else None,
                                  "extra": {"claim": kind, "publisher": pub, "summary": summary[:300]}})
            total += store_items(items)
            store_leaks(leaks)
        except Exception as ex:
            errors.append(f"{pub}: {ex}")
    if errors and not total:
        raise RuntimeError("; ".join(errors))
    return total


# ---------------------------------------------------------------- public breaches
@collector(Source(
    id="hibp", name="Have I Been Pwned breach catalogue", category="Dark web", publisher="Have I Been Pwned (Troy Hunt)",
    homepage="https://haveibeenpwned.com/PwnedWebsites", url="https://haveibeenpwned.com/api/v3/breaches", cadence_min=360,
    licence="CC BY 4.0 (attribution)", notes="Public catalogue of verified breaches with domain, date, size and data classes. No account-level data."))
def collect_hibp() -> int:
    data = net.get_json("https://haveibeenpwned.com/api/v3/breaches", timeout=60) or []
    rows = []
    for b in data:
        if b.get("IsSpamList") or b.get("IsFabricated") or b.get("IsRetired"):
            continue
        rows.append({"id": "br-" + b["Name"], "source_id": "hibp", "kind": "breach", "victim": b.get("Title") or b["Name"],
                     "domain": (b.get("Domain") or "").lower(), "actor": None, "published": (b.get("AddedDate") or "")[:19] + "Z",
                     "title": f"{b.get('Title')} breach — {int(b.get('PwnCount') or 0):,} accounts",
                     "url": f"https://haveibeenpwned.com/PwnedWebsites#{b['Name']}",
                     "extra": {"breach_date": b.get("BreachDate"), "pwn_count": b.get("PwnCount"), "data_classes": b.get("DataClasses"),
                               "verified": b.get("IsVerified"), "stealer_log": b.get("IsStealerLog"), "malware": b.get("IsMalware"),
                               "description": redact(strip_html(b.get("Description"), 500))}})
    return store_leaks(rows)


# ---------------------------------------------------------------- hacktivist DDoS targeting
def _hosts(obj) -> list[str]:
    out = []
    if isinstance(obj, dict):
        h = obj.get("host")
        if isinstance(h, str):
            out.append(h.lower())
        for v in obj.values():
            if isinstance(v, (dict, list)):
                out += _hosts(v)
    elif isinstance(obj, list):
        for v in obj:
            out += _hosts(v)
    return out


@collector(Source(
    id="ddosia", name="NoName057(16) DDoSia target lists", category="Dark web", publisher="CIRCL — witha.name",
    homepage="https://witha.name", url="https://witha.name/feed.atom", cadence_min=120, licence="Open research data (CIRCL)",
    notes="Decoded target configurations of the pro-Russian hacktivist DDoS project — the only free machine-readable 'plotting' feed. Host + date only."))
def collect_ddosia() -> int:
    feed = feedparser.parse(net.get("https://witha.name/feed.atom", timeout=30).content)
    rows = []
    for e in feed.entries[:8]:
        published = iso(e.get("updated_parsed") or e.get("published_parsed")) or db.now()
        links = [l.get("href") for l in e.get("links", []) if l.get("href")] + [e.get("link") or ""]
        cfg = None
        for l in links:
            if l and l.endswith(".json"):
                cfg = l
                break
        if not cfg:
            m = re.search(r"/(?:config|data)/([\w.-]+)", " ".join(links))
            cfg = f"https://witha.name/api/config/{m.group(1)}" if m else None
        if not cfg:
            continue
        try:
            js = net.get_json(cfg if cfg.startswith("http") else "https://witha.name" + cfg, timeout=40)
        except Exception:
            continue
        for h in sorted(set(_hosts(js))):
            dom = reg_domain(h)
            rows.append({"id": leak_id("dd", dom, published[:10]), "source_id": "ddosia", "kind": "ddos", "victim": dom, "domain": dom,
                         "actor": "NoName057(16)", "published": published, "title": f"{dom} on NoName057(16) DDoSia target list",
                         "url": "https://witha.name/", "extra": {"hosts": [h], "config": cfg}})
    return store_leaks(rows)


# ---------------------------------------------------------------- infostealer exposure (per monitored org)
@collector(Source(
    id="hudsonrock", name="Hudson Rock infostealer exposure", category="Dark web", publisher="Hudson Rock (Cavalier community API)",
    homepage="https://www.hudsonrock.com/free-tools", url="https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain",
    cadence_min=360, licence="Free community API — attribution; confirm terms before commercial use",
    notes="Counts of infostealer-infected machines holding employee / user credentials for an organisation's domain. "
          "Stored: counts, dates, stealer families, hostnames. Never URLs, paths, passwords or identities."))
def collect_hudsonrock() -> int:
    orgs = db.q("SELECT id, name, domain FROM org WHERE tier='watch' AND domain IS NOT NULL ORDER BY name")
    week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    done = {r["org_id"] for r in db.q("SELECT org_id FROM leak WHERE kind='stealer' AND published>?", (week_ago,))}
    n = 0
    for o in orgs:
        if o["id"] in done:
            continue
        if n >= 40:  # spread load: at most 40 domains per run
            break
        url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"
        try:
            js = net.get_json(url, params={"domain": o["domain"]}, timeout=40)
        except Exception as e:
            print("[hudsonrock]", o["domain"], e)
            continue
        if not isinstance(js, dict):
            continue
        hosts = sorted({re.sub(r"^https?://", "", u.get("url", "")).split("/")[0].split(":")[0]
                        for u in (js.get("data") or {}).get("employees_urls", []) if isinstance(u, dict)} - {""})[:40]
        fams = js.get("stealerFamilies") or {}
        fams = {k: v for k, v in fams.items() if k != "total" and isinstance(v, (int, float))}
        db.upsert("leak", {"id": f"st-{o['id']}", "source_id": "hudsonrock", "kind": "stealer", "victim": o["name"],
                           "domain": o["domain"], "actor": None, "published": db.now(), "org_id": o["id"], "match": "domain",
                           "title": f"{o['name']}: {js.get('employees', 0):,} employee and {js.get('users', 0):,} user machines infected",
                           "url": f"{url}?domain={o['domain']}",
                           "extra": {"employees": js.get("employees", 0), "users": js.get("users", 0), "third_parties": js.get("third_parties", 0),
                                     "total": js.get("total", 0), "last_employee": js.get("last_employee_compromised"),
                                     "last_user": js.get("last_user_compromised"),
                                     "families": dict(sorted(fams.items(), key=lambda kv: -kv[1])[:8]), "hosts": hosts,
                                     "applications": [a.get("keyword") for a in js.get("applications", []) if isinstance(a, dict)][:15]}})
        n += 1
    return n


# ---------------------------------------------------------------- source catalogue (names + status only)
CATALOGUE_FILES = {"Forums": "forum.md", "Markets": "markets.md", "Ransomware leak sites": "ransomware_gang.md",
                   "Telegram threat actors": "telegram_threat_actors.md", "Infostealer channels": "telegram_infostealer.md",
                   "Exploit marketplaces": "exploits.md", "Malware-as-a-service": "maas.md"}


@collector(Source(
    id="deepdarkcti", name="deepdarkCTI source catalogue", category="Dark web", publisher="fastfire/deepdarkCTI (GitHub)",
    homepage="https://github.com/fastfire/deepdarkCTI", url="https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/forum.md",
    cadence_min=1440, licence="GPL-3.0 (attribution)",
    notes="Community catalogue of criminal forums, markets, leak sites and Telegram channels with ONLINE/OFFLINE status. Names and status only — no links rendered."))
def collect_catalogue() -> int:
    out = []
    for cat, fn in CATALOGUE_FILES.items():
        try:
            md = net.cached(f"https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/{fn}", 20)
        except Exception as e:
            print("[deepdarkcti]", fn, e)
            continue
        for line in md.splitlines():
            if not line.startswith("|") or "---" in line:
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            if len(cells) < 2 or cells[0].lower() in ("name", "telegram", "url"):
                continue
            name = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", cells[0]).strip()
            name = re.sub(r"https?://\S+", "", name).strip() or "—"
            status = next((c.upper() for c in cells[1:3] if c.upper() in ("ONLINE", "OFFLINE", "EXPIRED", "VALID")), "")
            desc = cells[-1] if len(cells) > 2 and not re.search(r"(?i)pass|user", cells[-1]) else ""
            if name.endswith(".onion") or len(name) > 80:
                name = name[:40]
            out.append({"category": cat, "name": name, "status": status or "UNKNOWN", "description": redact(desc[:160]),
                        "evidence": f"https://github.com/fastfire/deepdarkCTI/blob/main/{fn}"})
    db.kv_set("darkweb_catalogue", out)
    return len(out)
