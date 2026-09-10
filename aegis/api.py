"""AEGIS REST API — read-only intelligence views plus 'add organisation' / 'scan now'. Serves the built console."""
import os
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from aegis import ROOT, db, playbooks, rating, scheduler
from aegis.intel import pipeline
from aegis.intel import prevent
from aegis.intel.entities import country_code, matcher, norm, reg_domain
from aegis.intel.themes import THEME_FAMILY, theme_catalogue

VERSION = os.environ.get("AEGIS_VERSION", "2.0.1")
app = FastAPI(title="AEGIS Cyber Risk Operations Center", version=VERSION)
UTC = timezone.utc

# Optional access control for hosted deployments: set AEGIS_PASSWORD (and optionally AEGIS_USER, default "aegis").
# The browser shows its native sign-in prompt. /api/health stays open for the platform health check.
_PW = os.environ.get("AEGIS_PASSWORD", "")
_USER = os.environ.get("AEGIS_USER", "aegis")


@app.middleware("http")
async def _basic_auth(request, call_next):
    if not _PW or request.url.path == "/api/health":
        return await call_next(request)
    import base64
    import secrets
    hdr = request.headers.get("authorization", "")
    if hdr.lower().startswith("basic "):
        try:
            user, _, pw = base64.b64decode(hdr[6:]).decode("utf-8").partition(":")
            if secrets.compare_digest(user, _USER) and secrets.compare_digest(pw, _PW):
                return await call_next(request)
        except (ValueError, UnicodeDecodeError):
            pass
    return JSONResponse({"detail": "authentication required"}, status_code=401,
                        headers={"WWW-Authenticate": 'Basic realm="AEGIS", charset="UTF-8"'})


@app.get("/api/health")
def health():
    """Liveness for Railway / any orchestrator: the process is up and the database answers."""
    return {"ok": True, "version": VERSION, "orgs": db.scalar("SELECT count(*) FROM org"), "time": db.now()}


def ts(days: float) -> str:
    return (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def ph(n: int) -> str:
    return ",".join("?" * n)


@app.on_event("startup")
def _start():
    scheduler.start()


# ------------------------------------------------------------------ status & navigation
@app.get("/api/status")
def status():
    src = db.q("SELECT id, status, last_ok FROM source")
    enabled = [s for s in src if s["status"] != "DISABLED"]
    ok = [s for s in enabled if s["status"] in ("OK", "EMPTY", "RUNNING") and s["last_ok"]]
    return {"sources_ok": len(ok), "sources_total": len(enabled), "last_update": max((s["last_ok"] or "" for s in src), default=None),
            "running": ", ".join(scheduler.running()[:3]), "pipeline": db.kv_get("pipeline_last")}


@app.get("/api/nav-counts")
def nav_counts():
    return {"incidents_critical": db.scalar("SELECT count(*) FROM incident WHERE severity='critical' AND last_seen > ?", (ts(7),)),
            "orgs_watch": db.scalar("SELECT count(*) FROM org WHERE tier='watch'"),
            "kev_7d": db.scalar("SELECT count(*) FROM vuln WHERE kev_added >= ?", (ts(7)[:10],)),
            "leaks_7d": db.scalar("SELECT count(*) FROM leak WHERE kind IN ('leaksite','forum') AND published > ?", (ts(7),))}


@app.get("/api/rules")
def rules():
    return rating.catalogue()


@app.get("/api/method")
def method():
    return {"rules": rating.catalogue(), "playbooks": playbooks.catalogue(), "playbook_coverage": playbooks.coverage(),
            "owners": playbooks.OWNERS, "effort": playbooks.EFFORT,
            "themes": theme_catalogue(), "categories": pipeline.CATEGORIES,
            "link_types": pipeline.LINK_TYPES, "risky_ports": rating.RISKY_PORTS,
            "bitsight_mapping": BITSIGHT_MAP}


BITSIGHT_MAP = [  # how each Bitsight risk vector is approximated here with free, passive sources
    {"vector": "Botnet infections / Malware servers", "group": "Compromised systems", "aegis": "Compromised systems & IPs", "sources": "abuse.ch Feodo & ThreatFox, Spamhaus DROP, Emerging Threats", "strength": "Partial — C2 servers, not sinkhole telemetry"},
    {"vector": "Unsolicited communications / Potentially exploited", "group": "Compromised systems", "aegis": "Compromised systems & IPs", "sources": "CINS Army, blocklist.de, IPsum", "strength": "Medium"},
    {"vector": "SPF / DMARC / DKIM", "group": "Diligence", "aegis": "Email & domain security", "sources": "DNS-over-HTTPS (Google, Cloudflare)", "strength": "Strong"},
    {"vector": "DNSSEC", "group": "Diligence", "aegis": "Email & domain security", "sources": "DNS-over-HTTPS DS / AD flag", "strength": "Strong"},
    {"vector": "Open ports / Insecure systems", "group": "Diligence", "aegis": "Open ports & exposed services", "sources": "Shodan InternetDB (index lookup)", "strength": "Medium — weekly index"},
    {"vector": "Server software / Patching cadence", "group": "Diligence", "aegis": "Vulnerabilities & exploited software", "sources": "InternetDB CPEs/CVEs × CISA KEV × EPSS", "strength": "Medium — version-inferred"},
    {"vector": "TLS/SSL certificates", "group": "Diligence", "aegis": "Assets & infrastructure", "sources": "Certificate Transparency (crt.sh, Cert Spotter)", "strength": "Medium"},
    {"vector": "Domain squatting", "group": "Diligence", "aegis": "Email & domain security", "sources": "Locally generated confusable variants resolved via DNS-over-HTTPS (A / MX)", "strength": "Medium — common typo and TLD-swap patterns, not homoglyph IDN"},
    {"vector": "Domain lifecycle & registrar lock", "group": "Diligence", "aegis": "Email & domain security", "sources": "RDAP (registry registration data, per-TLD servers from the IANA bootstrap)", "strength": "Strong — authoritative registry record"},
    {"vector": "Routing integrity (BGP / RPKI)", "group": "Diligence", "aegis": "Assets & infrastructure", "sources": "RIPEstat route-origin validation against published ROAs", "strength": "Strong for prefixes announced by an ASN registered to the organisation"},
    {"vector": "Certificate governance", "group": "Diligence", "aegis": "Assets & infrastructure", "sources": "Certificate Transparency (crt.sh) checked against the domain's own CAA policy", "strength": "Medium — recognised certificate authorities only"},
    {"vector": "Exposed credentials", "group": "User behaviour", "aegis": "Dark web & credential exposure", "sources": "Hudson Rock infostealer counts, HIBP breach catalogue", "strength": "Medium — counts only"},
    {"vector": "File sharing / Desktop & mobile software", "group": "User behaviour", "aegis": "—", "sources": "No free passive source", "strength": "Not assessed"},
    {"vector": "Public disclosures (breaches)", "group": "Public disclosures", "aegis": "Incidents & disclosures", "sources": "SEC 8-K 1.05, HIBP, news, leak sites", "strength": "Strong"},
]


# ------------------------------------------------------------------ search
@app.get("/api/search")
def search(q: str = Query(..., min_length=2)):
    like = f"%{q}%"
    out = []
    for o in db.q("SELECT id, name, ticker, domain, country FROM org WHERE name LIKE ? OR ticker LIKE ? OR domain LIKE ? LIMIT 8", (like, q, like)):
        out.append({"kind": "Organisation", "label": o["name"], "sub": f"{o['domain'] or ''} · {o['country'] or ''}", "href": f"/orgs/{o['id']}"})
    for i in db.q("SELECT id, title, severity FROM incident WHERE title LIKE ? ORDER BY last_seen DESC LIMIT 6", (like,)):
        out.append({"kind": "Incident", "label": i["title"], "sub": i["severity"], "href": f"/incidents/{i['id']}"})
    if re.match(r"(?i)cve-\d", q):
        for v in db.q("SELECT cve, vendor, product FROM vuln WHERE cve LIKE ? LIMIT 6", (like,)):
            out.append({"kind": "CVE", "label": v["cve"], "sub": f"{v['vendor'] or ''} {v['product'] or ''}", "href": f"/exposure?cve={v['cve']}"})
    for a in db.q("SELECT id, name, crowdstrike, origin FROM actor WHERE name LIKE ? OR crowdstrike LIKE ? OR aliases LIKE ? LIMIT 6", (like, like, like)):
        out.append({"kind": "Actor", "label": a["name"], "sub": a["crowdstrike"] or a["origin"] or "", "href": f"/adversaries/{a['id']}"})
    for v in db.q("SELECT vendor, count(DISTINCT org_id) n FROM dependency WHERE vendor LIKE ? GROUP BY vendor LIMIT 4", (like,)):
        out.append({"kind": "Provider", "label": v["vendor"], "sub": f"used by {v['n']} monitored orgs", "href": f"/incidents?provider={v['vendor']}"})
    return out


THEME_TREE_ORDER = [f for f in dict.fromkeys(THEME_FAMILY.values()) if f]


# ------------------------------------------------------------------ prevent
# Controls the surface scan already measures for every organisation. Reported as adoption
# percentages across monitored organisations — never as a score, and never ranked.
#
# Each control carries an `applies` test as well as a `has` test. A check that has not run
# for an organisation is excluded from both sides of the percentage rather than counted as a
# failure: "not measured yet" is not the same finding as "not in place", and conflating them
# would be exactly the invented data this platform refuses to produce. It matters most for a
# newly added check, where nearly every organisation is simply still in the scan queue.
CONTROLS = [
    ("dmarc_enforced", "DMARC enforced (p=quarantine or reject)", "Email spoofing",
     lambda h, a: True,
     lambda h, a: (h.get("dmarc") or {}).get("p") in ("quarantine", "reject")),
    ("spf_strict", "SPF ends in -all", "Email spoofing",
     lambda h, a: True,
     lambda h, a: (h.get("spf") or {}).get("all") == "-"),
    ("dkim", "DKIM key published", "Email tampering",
     lambda h, a: True,
     lambda h, a: bool(h.get("dkim_selectors"))),
    ("mta_sts", "MTA-STS policy", "Mail interception",
     lambda h, a: True,
     lambda h, a: bool(h.get("mta_sts"))),
    ("tls_rpt", "TLS reporting", "Undetected mail TLS failure",
     lambda h, a: True,
     lambda h, a: bool(h.get("tls_rpt"))),
    ("dnssec", "DNSSEC signed", "DNS forgery",
     lambda h, a: True,
     lambda h, a: bool(h.get("dnssec"))),
    ("caa", "CAA record", "Certificate mis-issuance",
     lambda h, a: True,
     lambda h, a: bool(h.get("caa"))),
    ("ns_redundant", "DNS served by more than one provider", "Single-provider outage",
     lambda h, a: bool(h.get("ns")),
     lambda h, a: not prevent.ns_single_provider(h.get("ns"))),
    # only counts organisations whose registry record has actually been read
    ("domain_locked", "Registrar transfer lock", "Domain hijack",
     lambda h, a: a.get("rdap") is not None,
     lambda h, a: bool((a.get("rdap") or {}).get("locked"))),
]


def _domain_attrs() -> list[tuple[str, str, dict]]:
    """(org_id, sector, domain-asset attrs) for every organisation that has been scanned."""
    out = []
    sectors = {o["id"]: o["sector"] for o in db.q("SELECT id, sector FROM org")}
    for a in db.q("SELECT org_id, attrs FROM asset WHERE kind='domain'"):
        at = a.get("attrs") or {}
        if at.get("hygiene"):
            out.append((a["org_id"], sectors.get(a["org_id"]) or "Unknown", at))
    return out


_ADOPTION_CACHE: dict = {"at": 0.0, "value": None}
_ADOPTION_TTL = 300  # seconds; the underlying scans only move every 15 minutes


def control_adoption(rows=None) -> list[dict]:
    """Adoption of each control across monitored organisations.

    Cached: computing this reads every organisation's domain attrs (~10 KB each, ~7 MB in
    total), and the organisation page asks for it on every load and every 90-second refetch.
    """
    if rows is None:
        now = time.monotonic()
        if _ADOPTION_CACHE["value"] is not None and now - _ADOPTION_CACHE["at"] < _ADOPTION_TTL:
            return _ADOPTION_CACHE["value"]
        rows = _domain_attrs()
        _ADOPTION_CACHE.update(at=now, value=_adoption(rows))
        return _ADOPTION_CACHE["value"]
    return _adoption(rows)


def _adoption(rows) -> list[dict]:
    out = []
    for cid, label, prevents, applies, test in CONTROLS:
        by_sector: dict[str, list[int]] = {}
        n = measured = 0
        for _, sector, at in rows:
            h = at.get("hygiene") or {}
            if not applies(h, at):
                continue                      # not measured for this organisation — excluded entirely
            measured += 1
            ok = 1 if test(h, at) else 0
            n += ok
            g = by_sector.setdefault(sector, [0, 0])
            g[0] += ok
            g[1] += 1
        out.append({"id": cid, "label": label, "prevents": prevents, "adopted": n, "total": measured,
                    "unmeasured": len(rows) - measured,
                    "pct": round(100 * n / measured) if measured else None,
                    "by_sector": {k: {"adopted": v[0], "total": v[1], "pct": round(100 * v[0] / v[1])} for k, v in sorted(by_sector.items()) if v[1] >= 3}})
    return out


@app.get("/api/prevent")
def prevent_overview():
    """Estate-wide preventive posture: which controls are adopted, and where the work sits."""
    rows = _domain_attrs()
    controls = control_adoption(rows)
    # open preventive findings, grouped by the owner who would fix them
    by_owner: dict[str, dict] = {}
    for f in db.q("SELECT rule_id, severity, org_id FROM finding"):
        p = playbooks.PLAYBOOKS.get(f["rule_id"])
        if not p:
            continue
        g = by_owner.setdefault(p["owner"], {"owner": p["owner"], "findings": 0, "orgs": set(),
                                             "critical": 0, "high": 0, "medium": 0, "low": 0, "rules": {}})
        g["findings"] += 1
        g["orgs"].add(f["org_id"])
        g[f["severity"]] = g.get(f["severity"], 0) + 1
        g["rules"][f["rule_id"]] = g["rules"].get(f["rule_id"], 0) + 1
    owners = []
    for g in by_owner.values():
        top = sorted(g["rules"].items(), key=lambda kv: -kv[1])[:4]
        owners.append({**{k: v for k, v in g.items() if k not in ("orgs", "rules")}, "orgs": len(g["orgs"]),
                       "top_rules": [{"rule_id": r, "count": c, "effort": playbooks.PLAYBOOKS[r]["effort"]} for r, c in top]})
    owners.sort(key=lambda x: (-x["critical"], -x["high"], -x["findings"]))
    return {"scanned": len(rows), "controls": controls, "by_owner": owners,
            "coverage": playbooks.coverage()}


# ------------------------------------------------------------------ overview
@app.get("/api/overview")
def overview(days: int = 30):
    since = ts(days)
    incs = db.q("SELECT id, title, kind, severity, severity_rule, victim, victim_org_id, countries, sectors, actors, last_seen, first_seen, source_count FROM incident WHERE last_seen > ? ORDER BY last_seen DESC", (since,))
    imp = db.q("SELECT incident_id, link_type, count(*) n FROM impact GROUP BY 1,2")
    imp_by = defaultdict(dict)
    for r in imp:
        imp_by[r["incident_id"]][r["link_type"]] = r["n"]
    orgs = {o["id"]: o for o in db.q("SELECT id, name, lat, lon, country, sector FROM org")}
    fnd = db.q("SELECT org_id, severity FROM finding WHERE severity IN ('critical','high')")
    crit_orgs = {f["org_id"] for f in fnd if f["severity"] == "critical"}
    pts = []
    for i in incs[:400]:
        o = orgs.get(i["victim_org_id"]) if i["victim_org_id"] else None
        pts.append({"id": i["id"], "lat": o["lat"] if o else None, "lon": o["lon"] if o else None,
                    "country": (o or {}).get("country") or ((i.get("countries") or [None])[0]), "level": i["severity"],
                    "label": i["title"], "sub": f"{i['kind']} · {i['source_count']} source(s)", "pulse": i["severity"] == "critical" and pipeline.days_since(i["last_seen"]) <= 3})
    # daily activity series
    series = defaultdict(lambda: Counter())
    for r in db.q("SELECT substr(published,1,10) d, kind, count(*) n FROM leak WHERE published > ? AND kind IN ('leaksite','forum','ddos') GROUP BY 1,2", (since,)):
        series[r["d"]][{"leaksite": "Leak-site listings", "forum": "Dark-web claims", "ddos": "DDoS targets"}[r["kind"]]] += r["n"]
    for r in db.q("SELECT kev_added d, count(*) n FROM vuln WHERE kev_added >= ? GROUP BY 1", (since[:10],)):
        series[r["d"]]["KEV additions"] += r["n"]
    for r in db.q("SELECT substr(published,1,10) d, count(*) n FROM item WHERE published > ? AND kind IN ('news','advisory','research') GROUP BY 1", (since,)):
        series[r["d"]]["Reporting"] += r["n"]
    today = ts(0)[:10]
    days_list = sorted(d for d in series if d and since[:10] <= d <= today)  # never plot future-dated records
    skeys = ["Leak-site listings", "Dark-web claims", "DDoS targets", "KEV additions", "Reporting"]
    sev = Counter(i["severity"] for i in incs)
    changed = db.q("SELECT f.id, f.org_id, f.title, f.severity, f.rule_id, f.first_seen, f.evidence_url, o.name org FROM finding f JOIN org o ON o.id=f.org_id "
                   "WHERE f.severity IN ('critical','high') ORDER BY f.first_seen DESC, f.observed DESC LIMIT 14")
    themes = Counter()
    for r in db.q("SELECT themes FROM item WHERE published > ? AND kind IN ('news','research','advisory','forum')", (ts(min(days, 14)),)):
        themes.update(r.get("themes") or [])
    groups = Counter(r["actor"] for r in db.q("SELECT actor FROM leak WHERE kind='leaksite' AND published > ?", (since,)) if r["actor"])
    return {
        "hero": {"critical_orgs": len(crit_orgs), "monitored": len(orgs),
                 "incidents": len(incs), "incidents_critical": sev.get("critical", 0),
                 "orgs_impacted": db.scalar("SELECT count(DISTINCT m.org_id) FROM impact m JOIN incident i ON i.id=m.incident_id WHERE i.last_seen > ? AND m.link_type != 'TARGETING'", (since,)),
                 "kev_added": db.scalar("SELECT count(*) FROM vuln WHERE kev_added >= ?", (since[:10],)),
                 "leak_listings": db.scalar("SELECT count(*) FROM leak WHERE kind='leaksite' AND published > ?", (since,)),
                 "forum_claims": db.scalar("SELECT count(*) FROM leak WHERE kind='forum' AND published > ?", (since,)),
                 "new_findings_24h": db.scalar("SELECT count(*) FROM finding WHERE first_seen > ? AND severity IN ('critical','high')", (ts(1),))},
        "severity": dict(sev),
        "points": pts,
        "series": [{"day": d, **{k: series[d].get(k, 0) for k in skeys}} for d in days_list],  # zero-filled so stacks render
        "incidents": [{**i, "impacts": imp_by.get(i["id"], {})} for i in sorted(incs, key=lambda i: (rating.RANK[i["severity"]], -len(imp_by.get(i["id"], {})), i["last_seen"]), reverse=False)[:12]],
        "changed": changed,
        "themes": [{"theme": t, "family": THEME_FAMILY.get(t), "n": n} for t, n in themes.most_common(12)],
        "groups": [{"group": g, "n": n} for g, n in groups.most_common(10)],
        "kinds": Counter(i["kind"] for i in incs),
    }


# ------------------------------------------------------------------ incidents & linkage
@app.get("/api/incidents")
def incidents(days: int = 30, kind: str | None = None, severity: str | None = None, q: str | None = None, provider: str | None = None, org: str | None = None):
    sql, p = "SELECT * FROM incident WHERE last_seen > ?", [ts(days)]
    if kind:
        sql += " AND kind=?"; p.append(kind)
    if severity:
        sql += " AND severity=?"; p.append(severity)
    if q:
        sql += " AND (title LIKE ? OR victim LIKE ? OR actors LIKE ? OR vendors LIKE ? OR cves LIKE ?)"; p += [f"%{q}%"] * 5
    if provider:
        sql += " AND (vendors LIKE ? OR victim LIKE ?)"; p += [f"%{provider}%"] * 2
    rows = db.q(sql + " ORDER BY last_seen DESC LIMIT 600", p)
    if org:
        ids = {r["incident_id"] for r in db.q("SELECT incident_id FROM impact WHERE org_id=?", (org,))}
        rows = [r for r in rows if r["id"] in ids]
    imp = defaultdict(Counter)
    for r in db.q("SELECT incident_id, link_type, count(*) n FROM impact GROUP BY 1,2"):
        imp[r["incident_id"]][r["link_type"]] = r["n"]
    for r in rows:
        r["impacts"] = dict(imp.get(r["id"], {}))
        r["impacted"] = sum(v for k, v in r["impacts"].items() if k != "TARGETING")
        r.pop("sources", None)
    kinds = Counter(r["kind"] for r in rows)
    return {"incidents": rows, "kinds": kinds, "severity": Counter(r["severity"] for r in rows), "link_types": pipeline.LINK_TYPES}


@app.get("/api/incidents/{iid}")
def incident(iid: str):
    inc = db.one("SELECT * FROM incident WHERE id=?", (iid,))
    if not inc:
        raise HTTPException(404, "incident not found")
    imps = db.q("SELECT m.*, o.name, o.sector, o.country, o.lat, o.lon, o.domain FROM impact m JOIN org o ON o.id=m.org_id WHERE m.incident_id=? "
                "ORDER BY CASE m.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, o.name", (iid,))
    items = db.q("SELECT id, title, url, publisher, pub_type, published, themes FROM item WHERE incident_id=? ORDER BY published DESC", (iid,))
    leaks = db.q("SELECT id, kind, victim, actor, published, url, title, source_id, extra FROM leak WHERE incident_id=? ORDER BY published DESC", (iid,))
    actors = []
    for a in inc.get("actors") or []:
        r = db.one("SELECT id, name, crowdstrike, origin, motivation, kind FROM actor WHERE lower(name)=lower(?) OR id=? LIMIT 1", (a, "rw-" + a.lower()))
        if r:
            actors.append(r)
    vulns = db.q(f"SELECT cve, vendor, product, name, severity, severity_rule, epss, kev_added, ransomware FROM vuln WHERE cve IN ({ph(len(inc['cves'] or []))})", inc["cves"]) if inc.get("cves") else []
    # graph: incident → link type → organisations (capped for readability)
    nodes = [{"id": iid, "label": inc["victim"] or inc["title"][:40], "type": "incident", "level": inc["severity"]}]
    links = []
    per_type = Counter()
    for m in imps:
        if per_type[m["link_type"]] >= (60 if m["link_type"] != "TARGETING" else 25):
            continue
        per_type[m["link_type"]] += 1
        lt = "lt-" + m["link_type"]
        if not any(n["id"] == lt for n in nodes):
            nodes.append({"id": lt, "label": pipeline.LINK_TYPES[m["link_type"]], "type": "link", "level": None})
            links.append({"source": iid, "target": lt})
        nodes.append({"id": m["org_id"], "label": m["name"], "type": "org", "level": m["severity"], "sector": m["sector"]})
        links.append({"source": lt, "target": m["org_id"]})
    # de-duplicate org nodes that appear via several link types
    seen, uniq = set(), []
    for n in nodes:
        if n["id"] not in seen:
            seen.add(n["id"]); uniq.append(n)
    return {**inc, "impacts": imps, "items": items, "leaks": leaks, "actor_profiles": actors, "vulns": vulns,
            "graph": {"nodes": uniq, "links": links}, "link_types": pipeline.LINK_TYPES,
            "by_sector": Counter(m["sector"] or "Unknown" for m in imps), "by_type": Counter(m["link_type"] for m in imps)}


@app.get("/api/linkage/providers")
def providers():
    """Concentration: providers shared by many monitored organisations, and whether they have an active incident."""
    rows = db.q("SELECT vendor, category, count(DISTINCT org_id) n FROM dependency GROUP BY vendor ORDER BY n DESC LIMIT 60")
    scanned = db.scalar("SELECT count(DISTINCT org_id) FROM dependency") or 1
    active = defaultdict(list)
    for i in db.q("SELECT id, title, severity, kind, vendors, victim FROM incident WHERE last_seen > ?", (ts(30),)):
        for v in (i.get("vendors") or []) + ([i["victim"]] if i.get("victim") else []):
            active[v.lower()].append({"id": i["id"], "title": i["title"], "severity": i["severity"], "kind": i["kind"]})
    cats = Counter()
    for r in db.q("SELECT category, count(DISTINCT org_id || vendor) n FROM dependency GROUP BY category"):
        cats[r["category"]] = r["n"]
    return {"scanned_orgs": scanned, "providers": [{**r, "share": r["n"] / scanned, "incidents": active.get(r["vendor"].lower(), [])[:5]} for r in rows],
            "categories": cats}


# ------------------------------------------------------------------ organisations
def _posture_map() -> dict:
    agg = defaultdict(Counter)
    for r in db.q("SELECT org_id, severity, count(*) n FROM finding GROUP BY 1,2"):
        agg[r["org_id"]][r["severity"]] = r["n"]
    return agg


UNKNOWN_SECTOR, UNKNOWN_COUNTRY = "Unknown", "—"  # the labels the facets use for rows with no value


def _in_clause(col: str, values: list[str], blank_label: str) -> tuple[str, list]:
    """OR-of-equals for a multi-select filter, treating the facet's blank label as IS NULL."""
    picked = [v for v in values if v != blank_label]
    parts, p = [], []
    if picked:
        parts.append(f"{col} IN ({ph(len(picked))})"); p += picked
    if len(picked) != len(values):
        parts.append(f"({col} IS NULL OR {col}='')")
    return " AND (" + " OR ".join(parts) + ")", p


def _org_rows(q=None, sector=None, country=None, index=None, level=None):
    """Rows for the organisations table. Shared by the JSON list and the spreadsheet export."""
    sql, p = "SELECT id, name, ticker, domain, country, city, sector, industry, indices, lat, lon, deep_scanned, tier FROM org WHERE 1=1", []
    if q:
        sql += " AND (name LIKE ? OR domain LIKE ? OR ticker LIKE ?)"; p += [f"%{q}%"] * 3
    if sector:
        s, sp = _in_clause("sector", sector, UNKNOWN_SECTOR); sql += s; p += sp
    if country:
        s, cp = _in_clause("country", country, UNKNOWN_COUNTRY); sql += s; p += cp
    if index:
        # indices is a JSON array, so each pick is a substring test
        sql += " AND (" + " OR ".join(["indices LIKE ?"] * len(index)) + ")"; p += [f"%{i}%" for i in index]
    rows = db.q(sql + " ORDER BY name", p)
    pm = _posture_map()
    inc = Counter(r["org_id"] for r in db.q("SELECT m.org_id FROM impact m JOIN incident i ON i.id=m.incident_id WHERE m.link_type != 'TARGETING' AND i.last_seen > ?", (ts(30),)))
    for r in rows:
        c = pm.get(r["id"], Counter())
        r["counts"] = dict(c)
        r["level"] = next((l for l in ("critical", "high", "medium") if c.get(l)), "low" if c else None)
        # no finding yet: distinguish "surface scan still queued" from "scanned, nothing found"
        r["state"] = r["level"] or ("clear" if r["deep_scanned"] else "queued")
        r["incidents_30d"] = inc.get(r["id"], 0)
    if level:
        rows = [r for r in rows if r["state"] == level]
    return rows


@app.get("/api/orgs")
def orgs(q: str | None = None, sector: list[str] | None = Query(None), country: list[str] | None = Query(None),
         index: list[str] | None = Query(None), level: str | None = None):
    rows = _org_rows(q, sector, country, index, level)
    facets = {"sector": Counter(r["sector"] or UNKNOWN_SECTOR for r in rows), "country": Counter(r["country"] or UNKNOWN_COUNTRY for r in rows),
              "level": Counter(r["state"] for r in rows)}
    return {"orgs": rows, "facets": facets}


EXPORT_COLUMNS = [
    ("Organisation", lambda r: r["name"]),
    ("Ticker", lambda r: r["ticker"]),
    ("Domain", lambda r: r["domain"]),
    ("Level", lambda r: r["level"].title() if r["level"] else ("No findings" if r["state"] == "clear" else "Scan queued")),
    ("Critical", lambda r: r["counts"].get("critical", 0)),
    ("High", lambda r: r["counts"].get("high", 0)),
    ("Medium", lambda r: r["counts"].get("medium", 0)),
    ("Low", lambda r: r["counts"].get("low", 0)),
    ("Linked incidents (30d)", lambda r: r["incidents_30d"]),
    ("Sector", lambda r: r["sector"]),
    ("Industry", lambda r: r["industry"]),
    ("Country", lambda r: r["country"]),
    ("City", lambda r: r["city"]),
    ("Lists", lambda r: ", ".join(r["indices"]) if isinstance(r["indices"], list) else (r["indices"] or "")),
    ("Surface scan", lambda r: (r["deep_scanned"] or "")[:19].replace("T", " ") or "queued"),
    ("AEGIS id", lambda r: r["id"]),
]


# NOTE: must stay above /api/orgs/{oid}, or "export" is read as an organisation id.
@app.get("/api/orgs/export")
def orgs_export(q: str | None = None, sector: list[str] | None = Query(None), country: list[str] | None = Query(None),
                index: list[str] | None = Query(None), level: str | None = None):
    """The organisations table as .xlsx, honouring whatever filters the console has applied."""
    from io import BytesIO

    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    rows = _org_rows(q, sector, country, index, level)
    wb = Workbook()
    ws = wb.active
    ws.title = "Organisations"
    ws.append([c[0] for c in EXPORT_COLUMNS])
    for r in rows:
        ws.append([fn(r) for _, fn in EXPORT_COLUMNS])

    head = Font(bold=True, color="FFFFFF")
    fill = PatternFill("solid", fgColor="1F3350")
    for i in range(1, len(EXPORT_COLUMNS) + 1):
        cell = ws.cell(row=1, column=i)
        cell.font, cell.fill = head, fill
        cell.alignment = Alignment(vertical="center", wrap_text=True)
        longest = max([len(str(EXPORT_COLUMNS[i - 1][0]))] + [len(str(ws.cell(row=n, column=i).value or "")) for n in range(2, min(ws.max_row, 400) + 1)])
        ws.column_dimensions[get_column_letter(i)].width = min(42, max(10, longest + 2))
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:{get_column_letter(len(EXPORT_COLUMNS))}{ws.max_row}"

    buf = BytesIO()
    wb.save(buf)
    name = f"aegis-organisations-{datetime.now(UTC).strftime('%Y-%m-%d')}.xlsx"
    return Response(buf.getvalue(), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


def _org_prevent(o: dict, dom: dict | None) -> dict:
    """This organisation's controls, each next to how common it is among its peers.

    Peer context is what turns "no CAA record" into a decision: near-universal absence is
    context, while being the only one in your sector without it is a finding worth acting on.
    """
    at = (dom or {}).get("attrs") or {}
    hyg = at.get("hygiene") or {}
    if not hyg:
        return {"scanned": False, "controls": []}
    sector = o.get("sector") or "Unknown"
    adoption = {c["id"]: c for c in control_adoption()}
    out = []
    for cid, label, prevents, applies, test in CONTROLS:
        a = adoption[cid]
        peers = a["by_sector"].get(sector)
        measured = bool(applies(hyg, at))
        out.append({"id": cid, "label": label, "prevents": prevents,
                    "measured": measured, "has": bool(test(hyg, at)) if measured else None,
                    "estate_pct": a["pct"], "sector": sector if peers else None,
                    "sector_pct": peers["pct"] if peers else None, "sector_n": peers["total"] if peers else None})
    return {"scanned": True, "sector": sector, "controls": out}


@app.get("/api/orgs/{oid}")
def org(oid: str):
    o = db.one("SELECT * FROM org WHERE id=?", (oid,))
    if not o:
        raise HTTPException(404, "organisation not found")
    findings = db.q("SELECT * FROM finding WHERE org_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, observed DESC", (oid,))
    assets = db.q("SELECT kind, value, attrs, first_seen, last_seen FROM asset WHERE org_id=?", (oid,))
    dom = next((a for a in assets if a["kind"] == "domain"), None)
    ips = [a for a in assets if a["kind"] == "ip"]
    hosts = [a for a in assets if a["kind"] == "hostname"]
    prefixes = [a for a in assets if a["kind"] == "prefix"]
    deps = db.q("SELECT vendor, category, evidence, source_id, seen FROM dependency WHERE org_id=? ORDER BY category, vendor", (oid,))
    dep_group = defaultdict(lambda: defaultdict(list))
    for d in deps:
        dep_group[d["category"]][d["vendor"]].append(d["evidence"])
    cloud = Counter()
    for a in ips:
        cl = (a.get("attrs") or {}).get("cloud")
        cloud[(cl or {}).get("provider") or ("Organisation-owned network" if (a.get("attrs") or {}).get("owned") else "Other / on-premises")] += 1
    for h in hosts:
        if (h.get("attrs") or {}).get("cdn"):
            cloud[f"{h['attrs']['cdn']} (via CNAME)"] += 0  # ensure provider listed
    ports = Counter()
    for a in ips:
        for pt in (a.get("attrs") or {}).get("ports") or []:
            ports[pt] += 1
    imps = db.q("SELECT m.link_type, m.severity, m.reason, m.evidence, i.id, i.title, i.kind, i.last_seen, i.severity inc_severity FROM impact m JOIN incident i ON i.id=m.incident_id "
                "WHERE m.org_id=? ORDER BY i.last_seen DESC LIMIT 80", (oid,))
    leaks = db.q("SELECT id, kind, victim, actor, published, title, url, source_id, match, extra FROM leak WHERE org_id=? ORDER BY published DESC LIMIT 100", (oid,))
    mentions = db.q("SELECT id, title, url, publisher, pub_type, kind, published, themes FROM item WHERE org_ids LIKE ? ORDER BY published DESC LIMIT 60", (f'%"{oid}"%',))
    comp = [m for m in (db.kv_get("compromised_matches", []) or []) if m["org_id"] == oid]
    fp_size = (db.kv_get("footprint_sizes", {}) or {}).get(oid, 0)
    sector_actors = []
    if o.get("sector"):
        cnt = Counter(l["actor"] for l in db.q("SELECT actor, sector FROM leak WHERE kind='leaksite' AND published > ? AND country=?", (ts(90), o["country"] or ""))
                      if pipeline.RW_SECTOR.get(l["sector"] or "", l["sector"]) == o["sector"])
        sector_actors = [{"actor": a, "victims": n} for a, n in cnt.most_common(8)]
    cs_ind = (o.get("sector") or "").lower().split()[0] if o.get("sector") else ""
    targeting = [a for a in db.q("SELECT id, name, crowdstrike, origin, motivation, cs_targets, sectors, countries FROM actor WHERE cs_targets IS NOT NULL")
                 if o.get("country") in ((a.get("cs_targets") or {}).get("countries") or []) and
                 any(cs_ind and cs_ind[:5] in i for i in (a.get("cs_targets") or {}).get("industries") or [])][:12]
    crit = pipeline.critical_assets(oid)
    inventory = {"footprint": f"{len(hosts)} hostnames · {len(ips)} IPs" if hosts else None,
                 "critical": f"{len(crit)} critical assets" if crit else None,
                 "cloud": f"{len([c for c in cloud if 'Other' not in c and 'owned' not in c])} cloud providers" if ips else None,
                 "software": f"{len({d['vendor'] for d in deps})} providers in DNS" if deps else None,
                 "exposure": f"{len([a for a in ips if (a.get('attrs') or {}).get('ports')])} indexed hosts" if ips else None,
                 "hygiene": "DNS controls checked" if dom else None,
                 "compromise": f"{(db.kv_get('footprint_sizes', {}) or {}).get(oid, 0):,} addresses checked" if dom else None}
    return {
        "org": o, "posture": pipeline.posture(oid), "categories": pipeline.CATEGORIES, "inventory": inventory,
        "findings": findings, "critical_assets": crit, "prevent": _org_prevent(o, dom),
        "footprint": {"domain": dom, "hostnames": len(hosts), "ct_count": ((dom or {}).get("attrs") or {}).get("ct_count", 0),
                      "ips": [{"ip": a["value"], **(a.get("attrs") or {})} for a in ips], "prefixes": [{"cidr": a["value"], **(a.get("attrs") or {})} for a in prefixes],
                      "host_list": [{"host": h["value"], **(h.get("attrs") or {})} for h in hosts],
                      "subsidiaries": [{"lei": a["value"], **(a.get("attrs") or {})} for a in assets if a["kind"] == "subsidiary"],
                      "parent": next(({"lei": a["value"], **(a.get("attrs") or {})} for a in assets if a["kind"] == "parent"), None),
                      "group": next(((a.get("attrs") or {}) for a in assets if a["kind"] == "group"), None),
                      "lookalikes": [{"domain": a["value"], **(a.get("attrs") or {})} for a in assets if a["kind"] == "lookalike"],
                      "scanned": o.get("deep_scanned")},
        "cloud": [{"provider": k, "ips": v} for k, v in cloud.most_common()],
        "ports": [{"port": k, "service": rating.RISKY_PORTS.get(k), "hosts": v} for k, v in sorted(ports.items())],
        "dependencies": {c: [{"vendor": v, "evidence": ev} for v, ev in vs.items()] for c, vs in dep_group.items()},
        "impacts": imps, "leaks": leaks, "mentions": mentions,
        "compromised": {"matches": comp, "footprint_addresses": fp_size, "checked": db.kv_get("blocklist_checked"),
                        "feeds": db.kv_get("blocklist_stats", {})},
        "threat": {"sector_actors": sector_actors, "crowdstrike_targeting": targeting},
    }


@app.post("/api/orgs")
def add_org(body: dict = Body(...)):
    name, domain = (body.get("name") or "").strip(), reg_domain(body.get("domain") or "")
    if not name:
        raise HTTPException(400, "An organisation name is required.")
    if "." not in domain:
        raise HTTPException(400, "A primary domain is required, e.g. ril.com — it is what the passive scan looks up.")
    country, bad = country_code(body.get("country"))
    if bad:
        raise HTTPException(400, bad)
    oid = "user-" + re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:50]
    db.upsert("org", {"id": oid, "name": name, "legal_name": name, "domain": domain, "domains": [domain], "website": f"https://{domain}",
                      "country": country, "sector": body.get("sector") or None,
                      "indices": ["Added by analyst"], "tier": "watch", "added": db.now(), "source_id": "analyst"})
    matcher.build()
    scheduler.scan_now(oid)
    return {"id": oid}


@app.post("/api/orgs/{oid}/scan")
def rescan(oid: str):
    scheduler.scan_now(oid)
    return {"queued": True}


# ------------------------------------------------------------------ exposure & vulnerabilities
@app.get("/api/exposure")
def exposure(days: int = 30, category: str | None = None):
    kev = db.q("SELECT cve, vendor, product, name, kev_added, ransomware, epss, epss_pct, cvss, severity, severity_rule, exploit_refs, kev_due FROM vuln WHERE kev_added IS NOT NULL")
    weekly = Counter()
    for v in kev:
        try:
            d = datetime.fromisoformat(v["kev_added"])
            if d > datetime.now() - timedelta(days=365):
                weekly[(d - timedelta(days=d.weekday())).strftime("%Y-%m-%d")] += 1
        except ValueError:
            pass
    recent = [v for v in kev if v["kev_added"] >= ts(days)[:10]]
    vend = Counter((v["vendor"] or "").strip() for v in kev if v["kev_added"] >= ts(365)[:10])
    sev = Counter(v["severity"] for v in kev)
    # watchlist exposure matrix (org × category) for heatmap — top organisations by findings
    pm = defaultdict(dict)
    for r in db.q("SELECT org_id, category, severity FROM finding"):
        cur = pm[r["org_id"]].get(r["category"])
        if cur is None or rating.RANK[r["severity"]] < rating.RANK[cur]:
            pm[r["org_id"]][r["category"]] = r["severity"]
    names = {o["id"]: o["name"] for o in db.q("SELECT id, name FROM org")}
    score = lambda m: sorted([rating.RANK[v] for v in m.values()])[:3]
    # Ranking by overall exposure buries a whole category: an organisation with an AI finding
    # and little else never reaches the top 30, so that column reads empty. ?category= ranks
    # by one category first, which is how a reader checks a column that looks blank.
    if category:
        top = sorted(pm.items(), key=lambda kv: (rating.RANK.get(kv[1].get(category), 9), score(kv[1])))[:30]
    else:
        top = sorted(pm.items(), key=lambda kv: score(kv[1]))[:30]
    ports = Counter()
    edge = Counter()
    cloud = Counter()
    scanned = 0
    for a in db.q("SELECT org_id, kind, attrs FROM asset WHERE kind IN ('ip','domain')"):
        at = a.get("attrs") or {}
        if a["kind"] == "ip":
            if not (at.get("shared") and not at.get("owned")):
                for p in at.get("ports") or []:
                    ports[p] += 1
            if at.get("cloud"):
                cloud[at["cloud"]["provider"]] += 1
        else:
            scanned += 1
            for e in {x.get("product") for x in at.get("edge") or [] if x.get("vendor")}:
                edge[e] += 1
    return {
        "kev_total": len(kev), "kev_recent": sorted(recent, key=lambda v: v["kev_added"], reverse=True),
        "kev_weekly": [{"week": w, "n": n} for w, n in sorted(weekly.items())],
        "kev_vendors": [{"vendor": v, "n": n} for v, n in vend.most_common(15)],
        "severity": dict(sev), "ransomware_linked": sum(1 for v in kev if (v["ransomware"] or "").lower() == "known"),
        "top_epss": db.q("SELECT cve, vendor, product, epss, epss_pct, severity, severity_rule, kev_added FROM vuln WHERE epss IS NOT NULL ORDER BY epss DESC LIMIT 60"),
        "matrix": {"orgs": [{"id": k, "name": names.get(k, k), "cells": v} for k, v in top], "categories": pipeline.CATEGORIES},
        "ports": [{"port": p, "service": rating.RISKY_PORTS.get(p) or "", "risky": p in rating.RISKY_PORTS, "n": n} for p, n in ports.most_common(20)],
        "edge_products": [{"product": p, "orgs": n} for p, n in edge.most_common(20)],
        "cloud": [{"provider": p, "ips": n} for p, n in cloud.most_common()],
        "scanned_orgs": scanned,
        "compromised": db.kv_get("compromised_matches", []), "blocklists": db.kv_get("blocklist_stats", {}),
        "exposed_findings": db.q("SELECT f.*, o.name org FROM finding f JOIN org o ON o.id=f.org_id WHERE f.category IN ('vulns','exposure','compromise') "
                                 "ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END LIMIT 200"),
    }


@app.get("/api/vulns/{cve}")
def vuln(cve: str):
    v = db.one("SELECT * FROM vuln WHERE cve=?", (cve.upper(),))
    if not v:
        raise HTTPException(404, "CVE not tracked")
    exposed = []
    for a in db.q("SELECT org_id, value, attrs FROM asset WHERE kind='ip' AND attrs LIKE ?", (f'%{cve.upper()}%',)):
        exposed.append({"org_id": a["org_id"], "ip": a["value"], "hosts": (a.get("attrs") or {}).get("hosts")})
    items = db.q("SELECT id, title, url, publisher, published FROM item WHERE entities LIKE ? ORDER BY published DESC LIMIT 30", (f'%{cve.upper()}%',))
    return {**v, "exposed": exposed, "items": items}


# ------------------------------------------------------------------ dark web & chatter
@app.get("/api/darkweb")
def darkweb(days: int = 30):
    since = ts(days)
    leaks = db.q("SELECT l.*, o.name org_name FROM leak l LEFT JOIN org o ON o.id=l.org_id WHERE l.published > ? AND l.kind IN ('leaksite','forum','ddos') ORDER BY l.published DESC", (since,))
    ls = [l for l in leaks if l["kind"] == "leaksite"]
    fc = [l for l in leaks if l["kind"] == "forum"]
    dd = [l for l in leaks if l["kind"] == "ddos"]
    daily = defaultdict(Counter)
    for l in ls:
        daily[(l["published"] or "")[:10]][l["actor"]] += 1
    top_groups = [g for g, _ in Counter(l["actor"] for l in ls).most_common(7)]
    stream = []
    for d in sorted(daily):
        row = {"day": d}
        for gname in top_groups:
            row[gname] = daily[d].get(gname, 0)
        row["Other groups"] = sum(v for k, v in daily[d].items() if k not in top_groups)
        stream.append(row)
    sectors = Counter(pipeline.RW_SECTOR.get(l["sector"] or "", l["sector"]) or "Unknown" for l in ls)
    countries = Counter(l["country"] or "—" for l in ls)
    # group ↔ sector matrix for chord / heatmap
    gs = defaultdict(Counter)
    for l in ls:
        if l["actor"] in top_groups:
            gs[l["actor"]][pipeline.RW_SECTOR.get(l["sector"] or "", l["sector"]) or "Unknown"] += 1
    stealers = db.q("SELECT l.*, o.name org_name FROM leak l JOIN org o ON o.id=l.org_id WHERE l.kind='stealer' AND json_extract(l.extra,'$.total') > 0 "
                    "ORDER BY json_extract(l.extra,'$.employees') DESC, json_extract(l.extra,'$.users') DESC LIMIT 80")
    stealer_checked = db.scalar("SELECT count(*) FROM leak WHERE kind='stealer'")
    breaches = db.q("SELECT l.*, o.name org_name FROM leak l LEFT JOIN org o ON o.id=l.org_id WHERE l.kind='breach' ORDER BY l.published DESC LIMIT 40")
    chatter = db.q("SELECT id, title, url, publisher, published, themes, org_ids, entities FROM item WHERE kind='chatter' AND published > ? ORDER BY published DESC LIMIT 150", (ts(min(days, 14)),))
    ct = Counter()
    for c in chatter:
        ct.update(c.get("themes") or [])
    claims = Counter((l.get("extra") or {}).get("claim") or "data" for l in fc)
    cat = db.kv_get("darkweb_catalogue", []) or []
    catc = defaultdict(Counter)
    for c in cat:
        catc[c["category"]][c["status"]] += 1
    return {
        "counts": {"leaksite": len(ls), "forum": len(fc), "ddos": len(dd), "stealer_orgs": len(stealers), "stealer_checked": stealer_checked,
                   "watch_listed": len({l["org_id"] for l in ls if l["org_id"]}), "groups": len({l["actor"] for l in ls})},
        "leaksite": ls[:400], "forum": fc[:200], "ddos": dd[:300], "claims": claims,
        "stream": stream, "stream_keys": top_groups + ["Other groups"],
        "groups": [{"group": g, "n": n} for g, n in Counter(l["actor"] for l in ls).most_common(20)],
        "sectors": [{"sector": s, "n": n} for s, n in sectors.most_common()], "countries": dict(countries),
        "group_sector": {g: dict(c) for g, c in gs.items()},
        "stealers": stealers, "breaches": breaches, "chatter": chatter,
        "chatter_themes": [{"theme": t, "n": n} for t, n in ct.most_common(12)],
        "catalogue": {k: dict(v) for k, v in catc.items()}, "catalogue_total": len(cat),
        "ransomlook": db.kv_get("ransomlook_stats"),
    }


# ------------------------------------------------------------------ adversaries
@app.get("/api/actors")
def actors_list(q: str | None = None, kind: str | None = None, origin: str | None = None):
    sql, p = "SELECT id, name, aliases, crowdstrike, origin, motivation, kind, sectors, countries, attack_id, cs_targets, cs_url FROM actor WHERE 1=1", []
    if q:
        sql += " AND (name LIKE ? OR aliases LIKE ? OR crowdstrike LIKE ?)"; p += [f"%{q}%"] * 3
    if kind:
        sql += " AND kind=?"; p.append(kind)
    if origin:
        sql += " AND origin=?"; p.append(origin)
    rows = db.q(sql, p)
    m30, m90 = Counter(), Counter()
    for r in db.q("SELECT entities, published FROM item WHERE published > ?", (ts(90),)):
        for a in (r.get("entities") or {}).get("actors") or []:
            m90[a] += 1
            if r["published"] > ts(30):
                m30[a] += 1
    victims = Counter(l["actor"].lower() for l in db.q("SELECT actor FROM leak WHERE kind='leaksite' AND published > ?", (ts(30),)) if l["actor"])
    for r in rows:
        r["mentions_30d"], r["mentions_90d"] = m30.get(r["id"], 0), m90.get(r["id"], 0)
        r["victims_30d"] = victims.get(r["name"].lower(), 0) if r["kind"] == "ransomware" else 0
        r["activity"] = r["mentions_30d"] + r["victims_30d"]
    rows.sort(key=lambda r: (-r["activity"], -r["mentions_90d"], r["name"]))
    return {"actors": rows[:600], "total": len(rows), "origins": Counter(r["origin"] or "Unknown" for r in rows),
            "kinds": Counter(r["kind"] for r in rows), "motivations": Counter(r["motivation"] or "Unknown" for r in rows)}


@app.get("/api/actors/{aid}")
def actor(aid: str):
    a = db.one("SELECT * FROM actor WHERE id=?", (aid,))
    if not a:
        raise HTTPException(404, "actor not found")
    items = db.q("SELECT id, title, url, publisher, pub_type, published, themes FROM item WHERE entities LIKE ? ORDER BY published DESC LIMIT 60", (f'%"{aid}"%',))
    victims = db.q("SELECT l.victim, l.domain, l.country, l.sector, l.published, l.url, l.org_id, o.name org_name FROM leak l LEFT JOIN org o ON o.id=l.org_id "
                   "WHERE l.kind='leaksite' AND lower(l.actor)=lower(?) ORDER BY l.published DESC LIMIT 200", (a["name"],))
    pubs = Counter(i["publisher"] for i in items)
    return {**a, "items": items, "victims": victims, "publishers": pubs,
            "victim_sectors": Counter(pipeline.RW_SECTOR.get(v["sector"] or "", v["sector"]) or "Unknown" for v in victims),
            "victim_countries": Counter(v["country"] or "—" for v in victims)}


# ------------------------------------------------------------------ analyst view
@app.get("/api/analyst")
def analyst(days: int = 30, family: str | None = None):
    now = datetime.now(UTC)
    # ai_incident belongs here: the AI Incident Database is research reporting like any other
    items = db.q("SELECT id, title, url, publisher, pub_type, kind, published, themes, entities FROM item WHERE published > ? AND kind IN ('news','research','advisory','forum','chatter','ai_incident')", (ts(63),))
    win = [i for i in items if i["published"] > ts(days)]
    # theme counts, momentum, recurrence
    cnt = Counter(t for i in win for t in i.get("themes") or [])
    wk = defaultdict(Counter)
    for i in items:
        age = pipeline.days_since(i["published"])
        if age > 1e8:
            continue
        w = int(age // 7)
        if w < 9:
            for t in i.get("themes") or []:
                wk[w][t] += 1
    # momentum needs a baseline this system collected itself: RSS back-fill under-represents older weeks,
    # so "rising" is only asserted once 28 days of continuous collection exist
    history_days = int(pipeline.days_since(db.scalar("SELECT min(fetched) FROM item")) or 0)
    mature = history_days >= 28
    themes = []
    for t, n in cnt.most_common():
        this = wk[0].get(t, 0)
        prior = sum(wk[w].get(t, 0) for w in range(1, 5)) / 4
        weeks_present = sum(1 for w in range(0, 8) if wk[w].get(t))
        themes.append({"theme": t, "family": THEME_FAMILY.get(t), "n": n, "this_week": this, "prior_avg": round(prior, 1),
                       "momentum": round((this + 1) / (prior + 1), 2), "weeks_present": weeks_present,
                       "recurring": weeks_present >= 6, "rising": mature and (this + 1) / (prior + 1) >= 1.8 and this >= 3})
    # weekly rank series for bump chart (top 8 themes)
    top8 = [t["theme"] for t in themes[:8]]
    bump = []
    ranks = {w: sorted(top8, key=lambda t: (-wk[w].get(t, 0), t)) for w in range(8)}
    for t in top8:
        bump.append({"id": t, "data": [{"x": f"-{w}w" if w else "now", "y": ranks[w].index(t) + 1, "n": wk[w].get(t, 0)} for w in range(7, -1, -1)]})
    # publisher × theme matrix
    by_pub = defaultdict(Counter)
    pub_type = {}
    for i in win:
        pub_type[i["publisher"]] = i["pub_type"]
        for t in i.get("themes") or []:
            by_pub[i["publisher"]][t] += 1
    pubs = sorted(by_pub, key=lambda p: -sum(by_pub[p].values()))[:24]
    # Ranking columns by raw volume alone hides every small family permanently: AI themes carry
    # single-figure counts and never reached the top 14. Take the leaders overall, then guarantee
    # each family one column, keeping volume order so the heatmap still reads left-to-right.
    if family:
        cols = [t["theme"] for t in themes if t["family"] == family]
    else:
        keep = {t["theme"] for t in themes[:10]}
        shown_families = {t["family"] for t in themes[:10] if t["family"]}
        for t in themes:
            if t["family"] and t["family"] not in shown_families:
                shown_families.add(t["family"])
                keep.add(t["theme"])
        cols = [t["theme"] for t in themes if t["theme"] in keep]
    cols = cols[:18]
    matrix = [{"id": p, "type": pub_type.get(p), "data": [{"x": t, "y": by_pub[p].get(t, 0)} for t in cols]} for p in pubs]
    ptype = defaultdict(Counter)
    for i in win:
        ptype[i["pub_type"]]["items"] += 1
        for t in i.get("themes") or []:
            ptype[i["pub_type"]][t] += 1
    # entities with consensus (distinct publishers)
    ent_pubs = defaultdict(lambda: defaultdict(set))
    for i in win:
        e = i.get("entities") or {}
        for k in ("actors", "vendors", "cves"):
            for v in e.get(k) or []:
                ent_pubs[k][v].add(i["publisher"])
    anames = {a["id"]: a["name"] for a in db.q("SELECT id, name FROM actor")}
    top_ent = {k: sorted([{"key": v, "label": anames.get(v, v) if k == "actors" else v, "publishers": len(s),
                           "publisher_list": sorted(s)[:8]} for v, s in d.items()], key=lambda x: -x["publishers"])[:15]
               for k, d in ent_pubs.items()}
    # co-occurrence of themes (lift-ranked)
    pair = Counter()
    single = Counter()
    for i in win:
        ts_ = sorted(set(i.get("themes") or []))
        single.update(ts_)
        for a in range(len(ts_)):
            for b in range(a + 1, len(ts_)):
                pair[(ts_[a], ts_[b])] += 1
    N = max(1, len(win))
    co = sorted([{"a": a, "b": b, "n": n, "lift": round(n * N / (single[a] * single[b]), 2)} for (a, b), n in pair.items() if n >= 3],
                key=lambda x: -x["lift"] * min(x["n"], 20))[:25]
    who = []
    for p in pubs:
        tops = [t for t, _ in by_pub[p].most_common(3)]
        who.append({"publisher": p, "type": pub_type.get(p), "items": sum(1 for i in win if i["publisher"] == p), "focus": tops})
    latest = {}
    for t in cols:
        latest[t] = [{"title": i["title"], "url": i["url"], "publisher": i["publisher"], "published": i["published"]}
                     for i in sorted(win, key=lambda i: i["published"], reverse=True) if t in (i.get("themes") or [])][:6]
    return {"window_items": len(win), "history_days": history_days, "mature": mature, "themes": themes, "bump": bump, "matrix": matrix, "columns": cols,
            "families": [f for f in THEME_TREE_ORDER if any(t["family"] == f for t in themes)], "family": family,
            "publisher_types": {k: dict(v) for k, v in ptype.items()}, "entities": top_ent, "cooccurrence": co,
            "who": who, "latest": latest, "families": sorted(set(THEME_FAMILY.values()))}


@app.get("/api/items")
def items(kind: str | None = None, theme: str | None = None, publisher: str | None = None, actor: str | None = None, vendor: str | None = None,
          cve: str | None = None, org: str | None = None, days: int = 30, q: str | None = None, pub_type: str | None = None, limit: int = 200):
    sql, p = "SELECT id, title, summary, url, publisher, pub_type, kind, published, themes, entities, org_ids, incident_id FROM item WHERE published > ?", [ts(days)]
    for col, val, like in (("kind", kind, False), ("publisher", publisher, False), ("pub_type", pub_type, False)):
        if val:
            sql += f" AND {col}=?"; p.append(val)
    for col, val in (("themes", theme), ("entities", actor), ("entities", vendor), ("entities", cve), ("org_ids", org)):
        if val:
            sql += f" AND {col} LIKE ?"; p.append(f'%"{val}"%' if col != "entities" or not cve else f"%{val}%")
    if q:
        sql += " AND (title LIKE ? OR summary LIKE ?)"; p += [f"%{q}%"] * 2
    return db.q(sql + " ORDER BY published DESC LIMIT ?", p + [min(limit, 500)])


# ------------------------------------------------------------------ AI risk
@app.get("/api/ai")
def ai():
    mit = db.kv_get("mit_ai_risk") or {}
    inc = db.q("SELECT id, title, url, published, entities, org_ids FROM item WHERE kind='ai_incident' ORDER BY published DESC LIMIT 200")
    by_sub = Counter((i.get("entities") or {}).get("mit") or "Unclassified" for i in inc)
    related = db.q("SELECT id, title, url, publisher, published, themes FROM item WHERE published > ? AND kind IN ('news','research','advisory') "
                   "AND (themes LIKE '%AI-enabled attacks%' OR themes LIKE '%AI system security%' OR themes LIKE '%AI governance%') ORDER BY published DESC LIMIT 60", (ts(60),))
    return {"mit": mit, "incidents": inc, "incidents_by_subdomain": by_sub, "aiaaic": db.kv_get("aiaaic"), "cyber_ai_reporting": related}


# ------------------------------------------------------------------ sources
@app.get("/api/sources")
def sources():
    src = db.q("SELECT * FROM source ORDER BY category, name")
    runs = defaultdict(list)
    for r in db.q("SELECT source_id, started, ok, items FROM run_log WHERE started > ? ORDER BY started", (ts(7),)):
        runs[r["source_id"]].append({"t": r["started"], "ok": r["ok"], "n": r["items"]})
    health = db.kv_get("feed_health", {}) or {}
    for s in src:
        s["runs"] = runs.get(s["id"], [])[-24:]
        s["feed_health"] = [h | {"url": u} for u, h in health.items() if h.get("source") == s["id"]]
    return {"sources": src, "blocklists": db.kv_get("blocklist_stats", {}), "cloud_ranges": db.kv_get("cloud_range_stats", {}),
            "counts": {"orgs": db.scalar("SELECT count(*) FROM org"), "items": db.scalar("SELECT count(*) FROM item"),
                       "leaks": db.scalar("SELECT count(*) FROM leak"), "vulns": db.scalar("SELECT count(*) FROM vuln"),
                       "actors": db.scalar("SELECT count(*) FROM actor"), "incidents": db.scalar("SELECT count(*) FROM incident"),
                       "findings": db.scalar("SELECT count(*) FROM finding"), "assets": db.scalar("SELECT count(*) FROM asset"),
                       "dependencies": db.scalar("SELECT count(*) FROM dependency")}}


@app.post("/api/sources/{sid}/run")
def run_source(sid: str):
    scheduler.trigger(sid)
    return {"queued": sid}


# ------------------------------------------------------------------ static console (SPA)
DIST = os.path.join(ROOT, "web", "dist")
if os.path.isdir(os.path.join(DIST, "assets")):
    app.mount("/assets", StaticFiles(directory=os.path.join(DIST, "assets")), name="assets")


@app.get("/{path:path}", include_in_schema=False)
def spa(path: str):
    if path.startswith("api/"):
        return JSONResponse({"detail": "not found"}, status_code=404)
    f = os.path.join(DIST, path)
    if path and os.path.isfile(f):
        return FileResponse(f)
    idx = os.path.join(DIST, "index.html")
    if os.path.exists(idx):
        return FileResponse(idx)
    return JSONResponse({"detail": "console not built — run `npm run build` in web/"}, status_code=503)
