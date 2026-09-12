"""AEGIS REST API — read-only intelligence views plus 'add organisation' / 'scan now'. Serves the built console."""
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from fastapi.responses import Response

from aegis import ROOT, db, rating, scheduler
from aegis.intel import ai as aimod
from aegis.intel import pipeline
from aegis.intel.entities import matcher, norm, reg_domain
from aegis.intel.iocs import host_of
from aegis.intel.themes import THEME_FAMILY, THEME_TREE, theme_catalogue

VERSION = os.environ.get("AEGIS_VERSION", "2.3.0")
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


_START_ERROR = ""  # traceback from a failed scheduler start-up, reported by /api/health


@app.get("/api/health")
def health():
    """Liveness for Railway / any orchestrator: the process is up and the database answers."""
    out = {"ok": True, "version": VERSION, "orgs": db.scalar("SELECT count(*) FROM org"), "time": db.now()}
    if _START_ERROR:
        # still 200: the process is alive and serving, and an orchestrator that kills it here would
        # replace a diagnosable service with a blank 502. Collection is degraded, and says so.
        out.update(ok=False, degraded="scheduler failed to start", error=_START_ERROR)
    return out


def ts(days: float) -> str:
    return (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def ph(n: int) -> str:
    return ",".join("?" * n)


@app.on_event("startup")
def _start():
    global _START_ERROR
    try:
        scheduler.start()
    except Exception:
        # A start-up exception here would otherwise take the whole process down and leave nothing
        # to ask what went wrong. Serve the console on the data already in the database, and put the
        # traceback where it can be read.
        import traceback
        _START_ERROR = traceback.format_exc()[-2000:]
        print("[startup] scheduler.start() failed:\n" + _START_ERROR, flush=True)


# ------------------------------------------------------------------ status & navigation
@app.get("/api/status")
def status():
    src = db.q("SELECT id, status, last_ok FROM source")
    enabled = [s for s in src if s["status"] != "DISABLED"]
    ok = [s for s in enabled if s["status"] in ("OK", "EMPTY", "RUNNING") and s["last_ok"]]
    return {"sources_ok": len(ok), "sources_total": len(enabled), "last_update": max((s["last_ok"] or "" for s in src), default=None),
            "running": ", ".join(scheduler.running()[:3]), "pipeline": db.kv_get("pipeline_last"), "version": VERSION}


@app.get("/api/nav-counts")
def nav_counts():
    return {"incidents_critical": db.scalar("SELECT count(*) FROM incident WHERE severity='critical' AND last_seen > ?", (ts(7),)),
            "orgs_watch": db.scalar("SELECT count(*) FROM org WHERE tier='watch'"),
            "kev_7d": db.scalar("SELECT count(*) FROM vuln WHERE kev_added >= ?", (ts(7)[:10],)),
            "leaks_7d": db.scalar("SELECT count(*) FROM leak WHERE kind IN ('leaksite','forum') AND published > ?", (ts(7),)),
            "impersonation": db.scalar("SELECT count(*) FROM finding WHERE severity IN ('critical','high') AND (rule_id LIKE 'IOC-%' OR rule_id LIKE 'NRD-%' "
                                       "OR rule_id LIKE 'PHISH-%' OR rule_id LIKE 'WEB-%' OR rule_id LIKE 'DNS-%')")}


@app.get("/api/rules")
def rules():
    return rating.catalogue()


@app.get("/api/method")
def method():
    from aegis import confidence as CF, playbooks as PB
    from aegis.intel.velocity import SLA_DAYS
    org_rules = [r["id"] for r in rating.catalogue() if r["applies_to"] == "organisation"]
    return {"rules": rating.catalogue(), "themes": theme_catalogue(), "categories": pipeline.CATEGORIES,
            "link_types": pipeline.LINK_TYPES, "risky_ports": rating.RISKY_PORTS,
            "bitsight_mapping": BITSIGHT_MAP,
            # v2.1 Prevent (production): playbooks for every organisation rule, owner roles, effort, SLA, confidence definitions
            "playbooks": [PB.playbook(r) for r in org_rules if PB.playbook(r)], "owners": PB.OWNERS, "effort": PB.EFFORT,
            "playbook_coverage": PB.coverage(org_rules), "sla": SLA_DAYS, "confidence": CF.DEFINITIONS}


BITSIGHT_MAP = [  # how each Bitsight risk vector is approximated here with free, passive sources
    {"vector": "Botnet infections / Malware servers", "group": "Compromised systems", "aegis": "Compromised systems & IPs", "sources": "abuse.ch Feodo & ThreatFox, Spamhaus DROP, Emerging Threats", "strength": "Partial — C2 servers, not sinkhole telemetry"},
    {"vector": "Unsolicited communications / Potentially exploited", "group": "Compromised systems", "aegis": "Compromised systems & IPs", "sources": "CINS Army, blocklist.de, IPsum", "strength": "Medium"},
    {"vector": "SPF / DMARC / DKIM", "group": "Diligence", "aegis": "Email & domain security", "sources": "DNS-over-HTTPS (Google, Cloudflare)", "strength": "Strong"},
    {"vector": "DNSSEC", "group": "Diligence", "aegis": "Email & domain security", "sources": "DNS-over-HTTPS DS / AD flag", "strength": "Strong"},
    {"vector": "Open ports / Insecure systems", "group": "Diligence", "aegis": "Open ports & exposed services", "sources": "Shodan InternetDB (index lookup)", "strength": "Medium — weekly index"},
    {"vector": "Server software / Patching cadence", "group": "Diligence", "aegis": "Vulnerabilities & exploited software", "sources": "InternetDB CPEs/CVEs × CISA KEV × EPSS", "strength": "Medium — version-inferred"},
    {"vector": "TLS/SSL certificates", "group": "Diligence", "aegis": "Assets & infrastructure", "sources": "Certificate Transparency (crt.sh, Cert Spotter)", "strength": "Medium"},
    {"vector": "Domain squatting", "group": "Diligence", "aegis": "Threat chatter & targeting", "sources": "Newly registered domains (WhoisDS), threat-report IOCs, phishing feeds", "strength": "Medium — gTLD sample, brand + lure rules"},
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
    if "." in q or ("-" in q and len(q) >= 5) or re.fullmatch(r"[\d.:a-f]+", q):
        for i in db.q("SELECT value, publisher, report_title FROM ioc WHERE value LIKE ? GROUP BY value LIMIT 6", (like,)):
            out.append({"kind": "Indicator", "label": i["value"], "sub": f"{i['publisher']} · {i['report_title'] or ''}"[:80], "href": f"/impersonation?q={i['value']}"})
    return out


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
        # how far back each record type goes — a window longer than this cannot show more than was collected
        "coverage": {"collected_since": db.scalar("SELECT min(fetched) FROM item"),
                     "leaks_since": db.scalar("SELECT min(published) FROM leak WHERE kind='leaksite' AND published > ?", (ts(400),)),
                     "lookalikes_since": db.scalar("SELECT min(published) FROM ioc WHERE kind='nrd'")},
        # v2.2 signals for the watch floor: impersonation, AI stack, providers
        "signals": {
            "brands_impersonated": db.scalar("SELECT count(DISTINCT org_id) FROM finding WHERE category='impersonation' AND severity IN ('critical','high')") or 0,
            "new_lookalikes": db.scalar("SELECT count(*) FROM ioc WHERE kind='nrd' AND org_id IS NOT NULL AND published > ?", (since,)) or 0,
            "ai_exposure_orgs": db.scalar("SELECT count(DISTINCT org_id) FROM finding WHERE category='ai' AND severity IN ('critical','high','medium')") or 0,
            "ai_kev": sum(1 for v in db.q("SELECT vendor, product FROM vuln WHERE kev_added >= ?", (since[:10],)) if aimod.kev_product(v["vendor"], v["product"])),
            "provider_incidents": sum(1 for i in incs if i["kind"] in ("Supply-chain / provider compromise", "Provider outage")),
            "provider_reach": db.scalar("SELECT count(DISTINCT m.org_id) FROM impact m JOIN incident i ON i.id=m.incident_id WHERE m.link_type IN ('DEPENDENCY','NAMED_CUSTOMER') "
                                        "AND i.last_seen > ?", (since,)) or 0,
        },
        "speed": _speed_strip(days),
    }


def _speed_strip(days: int = 30) -> dict:
    """Windowed by the console's 7/30/90-day selector (time to exploit uses at least 30 days so the median is meaningful)."""
    from aegis.intel.velocity import exploit_stats
    # time to exploit follows the window, widened to 30 days only when the window holds fewer than 10 exploited CVEs (same rule as /api/speed)
    w = days if db.scalar("SELECT count(*) FROM vuln WHERE kev_added >= ?", (ts(days)[:10],)) >= 10 else max(days, 30)
    st = exploit_stats(db.q("SELECT cve, vendor, published, kev_added FROM vuln WHERE kev_added >= ?", (ts(w)[:10],)))
    now = db.now()
    return {"median_tte": st["median"], "share_7d": st["share_7d"], "zero_day": st["zero_day"], "n": st["n"], "tte_window": w,
            "kev_window": db.scalar("SELECT count(*) FROM vuln WHERE kev_added >= ?", (ts(days)[:10],)),
            "kev_prev": db.scalar("SELECT count(*) FROM vuln WHERE kev_added >= ? AND kev_added < ?", (ts(2 * days)[:10], ts(days)[:10])),
            "act_72h": db.scalar("SELECT count(DISTINCT org_id) FROM finding WHERE deadline_rule='DL-72H'"),
            "overdue": db.scalar("SELECT count(*) FROM finding WHERE act_by IS NOT NULL AND act_by < ?", (now,)),
            "spreading": db.scalar("SELECT count(*) FROM incident WHERE last_seen > ? AND velocity LIKE '%\"spreading\": true%'", (ts(days),))}


# ------------------------------------------------------------------ speed & spread (v2.2)
@app.get("/api/speed")
def speed(days: int = 30):
    """How fast threats become real (time to exploit), how fast they proliferate (spread), and by when organisations must act."""
    from aegis.intel.velocity import FAST_HOURS, LAG_BINS, SLA_DAYS, epss_surge, exploit_stats, kev_lag, spread
    now = db.now()
    kev = db.q("SELECT cve, vendor, product, name, published, kev_added, kev_due, epss, ransomware FROM vuln WHERE kev_added >= ?", (ts(max(365, 2 * days))[:10],))
    s12, s90 = exploit_stats([r for r in kev if r["kev_added"] >= ts(365)[:10]]), exploit_stats([r for r in kev if r["kev_added"] >= ts(90)[:10]])
    # the selected window and the window before it, so every headline number follows the 7/30/90-day selector
    win_rows = [r for r in kev if r["kev_added"] >= ts(days)[:10]]
    prev_rows = [r for r in kev if ts(2 * days)[:10] <= r["kev_added"] < ts(days)[:10]]

    def _stats(rows):
        if not rows:
            return {"n": 0, "median": None, "share_7d": None, "within_7d": 0, "zero_day": 0}
        s = exploit_stats(rows)
        return {k: s.get(k) for k in ("n", "median", "share_7d", "within_7d", "zero_day")}
    # same rule as the Situation page: time to exploit follows the window, widened to 30 days only when it holds < 10 exploited CVEs
    tte_days = days if len(win_rows) >= 10 else max(days, 30)
    tte_rows = [r for r in kev if r["kev_added"] >= ts(tte_days)[:10]]
    swin = {**_stats(tte_rows), "window": tte_days}
    sprev = {**_stats([r for r in kev if ts(2 * tte_days)[:10] <= r["kev_added"] < ts(tte_days)[:10]]), "window": tte_days}
    weekly = Counter()
    for r in kev:
        d = datetime.fromisoformat(r["kev_added"][:10])
        if d > datetime.now() - timedelta(days=182):
            weekly[(d - timedelta(days=d.weekday())).strftime("%Y-%m-%d")] += 1
    exposed = defaultdict(set)  # cve → organisations whose own hosts report it
    for a in db.q("SELECT org_id, attrs FROM asset WHERE kind='ip'"):
        at = a.get("attrs") or {}
        if not (at.get("shared") and not at.get("owned")):
            for c in at.get("vulns") or []:
                exposed[c].add(a["org_id"])
    prod_orgs = Counter()
    for m in db.q("SELECT i.cves, m.org_id FROM impact m JOIN incident i ON i.id=m.incident_id WHERE m.link_type='EXPOSED_PRODUCT'"):
        for c in m.get("cves") or []:
            prod_orgs[(c, m["org_id"])] += 1
    names = {o["id"]: o["name"] for o in db.q("SELECT id, name FROM org")}
    po_by = defaultdict(set)
    for (c, o) in prod_orgs:
        po_by[c].add(o)
    # the race: every CVE newly exploited in the window, placed by days from disclosure to confirmed exploitation
    race = []
    for r in tte_rows:
        lag = kev_lag(r["published"], r["kev_added"])
        if lag is None:
            continue
        hit = set(exposed.get(r["cve"], ())) | po_by.get(r["cve"], set())
        race.append({"cve": r["cve"], "vendor": r["vendor"], "product": r["product"], "lag": lag, "kev_added": r["kev_added"],
                     "orgs": len(hit), "ransomware": r["ransomware"] == "Known"})
    # how often attackers beat each deadline rule: share of those CVEs exploited within the rule's window of disclosure
    rules = [(FAST_HOURS / 24, f"{FAST_HOURS}-hour clock"), (SLA_DAYS["critical"], f"{SLA_DAYS['critical']}-day deadline"),
             (SLA_DAYS["high"], f"{SLA_DAYS['high']}-day deadline"), (SLA_DAYS["medium"], f"{SLA_DAYS['medium']}-day deadline")]
    beaten = [{"days": d, "label": lab, "n": sum(1 for x in race if x["lag"] <= d), "of": len(race),
               "share": (sum(1 for x in race if x["lag"] <= d) / len(race)) if race else None} for d, lab in rules]
    fast = []
    for r in sorted(kev, key=lambda r: r["kev_added"], reverse=True):
        lag = kev_lag(r["published"], r["kev_added"])
        if r["kev_added"] >= ts(days)[:10] and lag is not None and lag <= 7:
            po = {o for (c, o) in prod_orgs if c == r["cve"]}
            hit = set(exposed.get(r["cve"], ())) | po
            fast.append({**r, "lag": lag, "exposed_hosts_orgs": len(exposed.get(r["cve"], ())), "product_orgs": len(po),
                         "orgs": sorted([{"id": o, "name": names.get(o, o)} for o in hit], key=lambda x: x["name"])[:8]})
    incs = db.q("SELECT id, title, kind, severity, severity_rule, sources, velocity, cves, first_seen, last_seen FROM incident WHERE last_seen > ?", (ts(days),))
    imp_by = defaultdict(list)  # incident → organisations it reaches (victim, group, provider, named customer, exposed product)
    for m in db.q("SELECT incident_id, org_id, link_type, severity, reason FROM impact WHERE link_type != 'TARGETING'"):
        imp_by[m["incident_id"]].append(m)
    reach = {k: len(v) for k, v in imp_by.items()}
    spreading = []
    for i in incs:
        v = i.get("velocity") or {}
        if v.get("publishers", 0) >= 2:
            sp = spread(i.get("sources") or [])
            orgs = sorted(imp_by.get(i["id"], []), key=lambda m: rating.RANK.get(m["severity"], 9))
            spreading.append({"id": i["id"], "title": i["title"], "kind": i["kind"], "severity": i["severity"], "last_seen": i["last_seen"],
                              "reach": len({m["org_id"] for m in imp_by.get(i["id"], [])}), "links": reach.get(i["id"], 0), "kev_lag": v.get("kev_lag"),
                              "orgs": [{"id": m["org_id"], "name": names.get(m["org_id"], m["org_id"]), "link": m["link_type"]} for m in orgs[:6]],
                              **{k: sp[k] for k in ("publishers", "publishers_72h", "hours_to_3", "spreading", "curve", "first")}})
    # organisations in the path of fast-moving threats: reached by a spreading incident or one exploited within 7 days of disclosure
    path = defaultdict(lambda: {"threats": [], "worst": None})
    threat_reach = []  # each fast-moving incident and how many monitored organisations it reaches
    for i in incs:
        v = i.get("velocity") or {}
        fast_i = bool(v.get("spreading")) or (v.get("kev_lag") is not None and v["kev_lag"] <= 7)
        if not fast_i:
            continue
        why = ("spreading" if v.get("spreading") else "") + (" · " if v.get("spreading") and v.get("kev_lag") is not None and v["kev_lag"] <= 7 else "") + \
              ((("zero-day" if v["kev_lag"] <= 0 else f"exploited {v['kev_lag']}d after disclosure") if v.get("kev_lag") is not None and v["kev_lag"] <= 7 else ""))
        reached = {m["org_id"] for m in imp_by.get(i["id"], [])}
        if reached:
            threat_reach.append({"id": i["id"], "title": i["title"], "severity": i["severity"], "why": why.strip(" ·"), "orgs": len(reached),
                                 "publishers_72h": v.get("publishers_72h"), "kev_lag": v.get("kev_lag")})
        for m in imp_by.get(i["id"], []):
            p = path[m["org_id"]]
            p["threats"].append({"id": i["id"], "title": i["title"], "link": m["link_type"], "severity": m["severity"], "why": why.strip(" ·")})
            if p["worst"] is None or rating.RANK.get(m["severity"], 9) < rating.RANK.get(p["worst"], 9):
                p["worst"] = m["severity"]
    dl = defaultdict(lambda: {"n72": 0, "next": None})
    for f in db.q("SELECT org_id, act_by, deadline_rule FROM finding WHERE act_by IS NOT NULL"):
        d = dl[f["org_id"]]
        d["n72"] += f["deadline_rule"] == "DL-72H"
        d["next"] = min(d["next"] or f["act_by"], f["act_by"])
    in_path = sorted([{"org_id": o, "name": names.get(o, o), "worst": p["worst"], "n": len(p["threats"]), "threats": p["threats"][:5],
                       "act_72h": dl[o]["n72"], "next_act_by": dl[o]["next"]} for o, p in path.items()],
                     key=lambda r: (rating.RANK.get(r["worst"], 9), -r["n"], r["next_act_by"] or "9"))
    spreading.sort(key=lambda x: (not x["spreading"], -x["publishers_72h"], x["hours_to_3"] if x["hours_to_3"] is not None else 1e9))
    surges = []  # not-yet-exploited CVEs whose exploit likelihood is rising; "surge" = meets the VUL-EPSS-SURGE threshold
    for r in db.q("SELECT cve, vendor, product, epss, epss_7d, epss_30d, severity, severity_rule FROM vuln WHERE kev_added IS NULL AND epss IS NOT NULL AND epss_7d IS NOT NULL"):
        delta = r["epss"] - r["epss_7d"]
        if epss_surge(r["epss"], r["epss_7d"]) or delta >= 0.05 or (r["epss"] >= 0.05 and r["epss_7d"] > 0 and r["epss"] / r["epss_7d"] >= 2):
            surges.append({**r, "delta": delta, "surge": epss_surge(r["epss"], r["epss_7d"]), "exposed_orgs": len(exposed.get(r["cve"], ()))})
    surges.sort(key=lambda r: (not r["surge"], -r["exposed_orgs"], -r["delta"]))
    clocks = db.q("SELECT f.id, f.org_id, f.title, f.severity, f.rule_id, f.deadline_rule, f.act_by, f.first_seen, f.data FROM finding f "
                  "WHERE f.act_by IS NOT NULL ORDER BY f.act_by LIMIT 400")
    for f in clocks:
        f["org"] = names.get(f["org_id"], f["org_id"])
        f["overdue"] = f["act_by"] < now
        f["exploited_since"] = (f.get("data") or {}).get("exploited_since")
        f.pop("data", None)
    by_rule = Counter(r["deadline_rule"] for r in db.q("SELECT deadline_rule FROM finding WHERE deadline_rule IS NOT NULL"))
    # what is due, by when (current state): a 14-day calendar by level, and every organisation placed by its next act-by date
    d0 = datetime.fromisoformat(now[:10])
    days14 = [(d0 + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(15)]
    cal, later, org_next = defaultdict(Counter), Counter(), {}

    def _until(iso: str) -> float:
        """Days from now until an ISO timestamp; negative = already past (days_since clamps future dates, so it can't be used here)."""
        from datetime import timezone as _tz
        t = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return ((t if t.tzinfo else t.replace(tzinfo=_tz.utc)) - datetime.now(_tz.utc)).total_seconds() / 86400
    for f in db.q("SELECT org_id, severity, act_by, deadline_rule FROM finding WHERE act_by IS NOT NULL"):
        until = _until(f["act_by"])
        if until < 0:
            cal["overdue"][f["severity"]] += 1
        elif f["act_by"][:10] in days14:
            cal[f["act_by"][:10]][f["severity"]] += 1
        else:
            later["15–30 days" if until <= 30 else "31–90 days" if until <= 90 else "over 90 days"] += 1
        o = org_next.get(f["org_id"])
        if o is None or f["act_by"] < o["act_by"]:
            org_next[f["org_id"]] = {"act_by": f["act_by"], "severity": f["severity"], "rule": f["deadline_rule"]}
    calendar = [{"day": "overdue", **cal.get("overdue", {})}] + [{"day": d, **cal.get(d, {})} for d in days14]

    def _bucket(until):
        return "overdue" if until < 0 else "72h" if until <= 3 else "7d" if until <= 7 else "30d" if until <= 30 else "later"
    board = defaultdict(list)
    for o, nx in org_next.items():
        board[_bucket(_until(nx["act_by"]))].append({"id": o, "name": names.get(o, o), "severity": nx["severity"], "act_by": nx["act_by"],
                                                                   "rule": nx["rule"], "fast": o in path})
    for b in board.values():
        b.sort(key=lambda x: (not x["fast"], rating.RANK.get(x["severity"], 9), x["act_by"]))
    # impersonation speed: newly registered lookalikes that already resolved when first checked (≤ 3 days after registration)
    nrd = db.q("SELECT published, attrs FROM ioc WHERE kind='nrd' AND org_id IS NOT NULL AND published >= ?", (ts(days),))
    checked = [(r, r.get("attrs") or {}) for r in nrd if (r.get("attrs") or {}).get("checked")]
    live_fast = sum(1 for r, at in checked if (at.get("a") or at.get("mx")) and pipeline.days_since(r["published"]) - pipeline.days_since(at["checked"]) <= 3)
    # ransomware tempo: last 7 days vs the prior 28-day weekly average, per group — asserted only once 28 days of history exist
    history = int(pipeline.days_since(db.scalar("SELECT min(fetched) FROM item")) or 0)
    g7, g28 = Counter(), Counter()
    for l in db.q("SELECT actor, published FROM leak WHERE kind='leaksite' AND published > ?", (ts(35),)):
        if l["actor"]:
            (g7 if l["published"] > ts(7) else g28)[l["actor"]] += 1
    tempo = sorted([{"group": g, "last7": n, "baseline": round(g28.get(g, 0) / 4, 1)} for g, n in g7.items()], key=lambda r: -r["last7"])[:15]
    return {
        "exploit": {"y12": {k: v for k, v in s12.items() if k != "vendors"}, "q90": {k: v for k, v in s90.items() if k != "vendors"},
                    "vendors": [v for v in s12["vendors"] if v["n"] >= 3][:20], "bins_order": [b[0] for b in LAG_BINS]},
        "kev_weekly": [{"week": w, "n": n} for w, n in sorted(weekly.items())],
        "kev_window": len(win_rows), "kev_prev": len(prev_rows),
        "win": swin, "prev": sprev, "race": race, "beaten": beaten,
        "sla": {"edge_hours": FAST_HOURS, **SLA_DAYS},
        "calendar": calendar, "later": later,
        "board": {k: {"n": len(v), "orgs": v[:60]} for k, v in board.items()},
        "threats": sorted(threat_reach, key=lambda t: (-t["orgs"], rating.RANK.get(t["severity"], 9)))[:12],
        "coverage": {"collected_since": db.scalar("SELECT min(fetched) FROM item"),
                     "lookalikes_since": db.scalar("SELECT min(published) FROM ioc WHERE kind='nrd'")},
        "fast": fast[:40], "spreading": spreading[:25], "spread_h3": [s["hours_to_3"] for s in spreading], "surges": surges[:40], "in_path": in_path[:80], "in_path_total": len(in_path),
        "clocks": {"by_rule": by_rule, "overdue": sum(1 for f in clocks if f["overdue"]), "due_72h": sum(1 for f in clocks if not f["overdue"] and f["deadline_rule"] == "DL-72H"),
                   "orgs_72h": len({f["org_id"] for f in clocks if f["deadline_rule"] == "DL-72H"}), "rows": clocks[:200]},
        "lookalike_speed": {"checked": len(checked), "live_within_3d": live_fast, "total": len(nrd)},
        "tempo": {"mature": history >= 28, "history_days": history, "groups": tempo},
    }


# ------------------------------------------------------------------ prevent: actions, playbooks, preventive controls (v2.1, reconciled with production)
@app.get("/api/actions")
def actions_queue(org: str | None = None, level: str | None = None, status: str | None = None, owner_role: str | None = None,
                  overdue: bool = False, open_only: bool = True, limit: int = 400, days: int = 30):
    """The action queue. Defaults to what is still open, because that is the working view."""
    from aegis import actions as A
    names = {o["id"]: o["name"] for o in db.q("SELECT id, name FROM org")}
    r = A.queue(org, level, status, owner_role, overdue, open_only, limit, days=days)
    for a in r["actions"]:
        a["org"] = names.get(a["org_id"], a["org_id"])
    return r


@app.post("/api/actions/{aid}/status")
def action_status(aid: str, body: dict = Body(...)):
    """Move one action along. Rejected transitions say why rather than failing quietly.
    Body: {status, by, reason?, expires? (accepted_risk), owner?}. There is no sign-in, so `by` is the name typed in the console."""
    from aegis import actions as A
    ok, msg, a = A.set_status(aid, (body.get("status") or "").strip(), body.get("by"), body.get("reason"), body.get("expires"), body.get("owner"))
    if not ok:
        raise HTTPException(404 if a is None else 400, msg)
    return A.decorate(a)


@app.get("/api/prevent")
def prevent_overview(days: int = 30):
    """Estate-wide preventive posture: which controls are adopted, and where the work sits."""
    from aegis import actions as A, playbooks as PB, prevent as P
    est = P.estate()
    by_owner = defaultdict(lambda: {"findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "orgs": set(), "rules": Counter()})
    for f in db.q("SELECT org_id, rule_id, severity FROM finding"):
        o = by_owner[(PB.playbook(f["rule_id"]) or {}).get("owner") or "Unassigned"]
        o["findings"] += 1
        o[f["severity"]] += 1
        o["orgs"].add(f["org_id"])
        o["rules"][f["rule_id"]] += 1
    owners = sorted([{"owner": k, "findings": v["findings"], "critical": v["critical"], "high": v["high"], "medium": v["medium"], "low": v["low"],
                      "orgs": len(v["orgs"]), "top_rules": [{"rule_id": r, "count": n, "effort": (PB.playbook(r) or {}).get("effort")} for r, n in v["rules"].most_common(4)]}
                     for k, v in by_owner.items()], key=lambda x: -x["findings"])
    org_rules = [r["id"] for r in rating.catalogue() if r["applies_to"] == "organisation"]
    return {"scanned": est["scanned"], "controls": est["controls"], "by_owner": owners, "coverage": PB.coverage(org_rules),
            "kpi": A.queue(limit=0, days=days)["kpi"]}


# ------------------------------------------------------------------ supply chain: providers of providers, ownership, screening (Exiger-inspired)
# A provider's own DNS hosting (NS: if it fails, the provider is unreachable) and mail hosting (MX: the route for supplier-email
# compromise). SPF includes are sending services (marketing, ticketing) and TXT tokens only show an account — neither is counted.
INFRA_KINDS = {"mx", "ns"}


def _supplier_view() -> dict | None:
    """Infrastructure-only fourth-party concentration, plus ownership, Secure by Design and screening per provider.
    Returns None until the supplier_intel collector has run."""
    intel = db.kv_get("supplier_intel") or {}
    if not intel:
        return None
    from aegis.intel.providers import Catalogue
    cat = Catalogue()
    users = defaultdict(set)
    for d in db.q("SELECT org_id, vendor FROM dependency"):
        users[cat.canonical(d["vendor"]) or d["vendor"]].add(d["org_id"])

    def infra(p):
        return [f for f in (intel.get(p) or {}).get("fourth_parties") or [] if (f.get("kind") or "").lower() in INFRA_KINDS]
    via = defaultdict(set)
    for p in intel:
        for f in infra(p):
            if f["provider"] != p:
                via[f["provider"]].add(p)
    conc = []
    for x, ps in via.items():
        ind = set().union(*[users.get(p, set()) for p in ps]) - users.get(x, set())
        conc.append({"name": x, "category": next((f.get("category") for p in ps for f in infra(p) if f["provider"] == x), None),
                     "direct": len(users.get(x, set())), "indirect": len(ind), "total": len(users.get(x, set()) | ind),
                     "carried_by": sorted([{"provider": p, "dependents": len(users.get(p, set()))} for p in ps], key=lambda r: -r["dependents"])[:8]})
    conc.sort(key=lambda r: -r["total"])
    rows = []
    for p, d in intel.items():
        fp = infra(p)
        rows.append({"name": p, "category": d.get("category"), "domain": d.get("domain"), "dependents": len(users.get(p, set())),
                     "fourth": [{"name": f["provider"], "category": f.get("category"), "kind": f.get("kind"), "evidence": f.get("evidence"), "source": f.get("source")} for f in fp],
                     "fourth_all": len(d.get("fourth_parties") or []), "lei": d.get("lei"), "legal_name": d.get("legal_name"), "country": d.get("country"),
                     "parent": d.get("parent"), "sbd_pledge": d.get("sbd_pledge"), "screening": d.get("sanctions") or [], "checked": d.get("checked")})
    rows.sort(key=lambda r: -r["dependents"])
    top = [r for r in rows if r["fourth"]][:10]
    links = [{"source": f"P:{r['name']}", "target": f"F:{f['name']}", "value": max(1, r["dependents"])} for r in top for f in {x["name"]: x for x in r["fourth"]}.values()]
    nodes = sorted({l["source"] for l in links} | {l["target"] for l in links})
    meta = db.kv_get("supplier_intel_meta") or {}
    return {"totals": {"providers": len(rows), "with_infra_fourth": sum(1 for r in rows if r["fourth"]), "infra_links": sum(len(r["fourth"]) for r in rows),
                       "distinct_infra_fourth": len(conc), "with_lei": sum(1 for r in rows if r["lei"]), "with_parent": sum(1 for r in rows if r["parent"]),
                       "sbd_signers": sum(1 for r in rows if r["sbd_pledge"]), "screening_to_review": sum(1 for r in rows if r["screening"])},
            "concentration": conc[:30], "providers": rows, "sankey": {"nodes": [{"id": n} for n in nodes], "links": links},
            "meta": {"run_at": meta.get("run_at"), "sources": meta.get("sources"), "screening_note": meta.get("screening_note")}}


@app.get("/api/suppliers")
def suppliers():
    """Who the providers rely on (infrastructure evidence only), where that concentrates, who owns them, and screening signals to review."""
    v = _supplier_view()
    if v is None:
        return {"collected": False}
    try:
        active = {a.get("vendor"): a for a in (providers(30).get("active") or [])}
    except Exception:
        active = {}
    for r in v["providers"]:
        a = active.get(r["name"])
        r["issue"] = {"severity": a.get("severity"), "title": a.get("title") or a.get("kind"), "id": a.get("id") or a.get("incident_id")} if a else None
    return {"collected": True, **v}


# ------------------------------------------------------------------ vendor fixes, and whether organisations applied them
FIX_LABEL = {"patch": "vendor patch published", "advisory": "vendor advisory / mitigation published", "none": "no vendor fix found", "unchecked": "not yet checked"}


def _fix_state(v: dict) -> str:
    f = v.get("fix") or {}
    if f.get("patch"):
        return "patch"
    if f.get("advisory") or f.get("mitigation"):
        return "advisory"
    return "none" if v.get("fix_checked") else "unchecked"


@app.get("/api/fixes")
def fixes(days: int = 30, all_cves: bool = False):
    """Exploited CVEs on monitored organisations' own hosts: has the vendor published a fix (CVE record references, CISA KEV notes),
    and which organisations no longer show the flaw on a later scan (fix observed) versus still do. Passive by design:
    'no longer observed' means patched or the host was removed — AEGIS cannot see inside the network."""
    import json as _json
    import statistics
    names = {o["id"]: o["name"] for o in db.q("SELECT id, name FROM org")}
    by = defaultdict(list)
    for r in db.q("SELECT * FROM cve_exposure"):
        by[r["cve"]].append(r)
    vul = {v["cve"]: v for v in db.q("SELECT cve, vendor, product, name, kev_added, kev_due, fix, fix_checked, ransomware, epss, severity FROM vuln "
                                      "WHERE cve IN (SELECT value FROM json_each(?))", (_json.dumps(list(by)),))}
    today = db.now()[:10]
    rows, orgs_still = [], set()
    for cve, rs in by.items():
        v = vul.get(cve) or {"cve": cve}
        if not all_cves and not v.get("kev_added"):
            continue
        still = [r for r in rs if not r["fixed_at"]]
        done = [r for r in rs if r["fixed_at"]]
        orgs_still |= {r["org_id"] for r in still}
        f = v.get("fix") or {}
        oldest = min((max(r["first_seen"] or "", v.get("kev_added") or "") for r in still), default=None)
        rows.append({"cve": cve, "vendor": v.get("vendor"), "product": v.get("product"), "name": v.get("name"), "kev_added": v.get("kev_added"),
                     "kev_due": v.get("kev_due"), "ransomware": v.get("ransomware") == "Known", "severity": v.get("severity"), "epss": v.get("epss"),
                     "fix": {"state": _fix_state(v), "label": FIX_LABEL[_fix_state(v)], "urls": (f.get("urls") or [])[:3],
                             "fixed_versions": f.get("fixed_versions") or [], "source": f.get("source")},
                     "exposed_now": len(still), "fixed": len(done), "fixed_window": sum(1 for r in done if r["fixed_at"] >= ts(days)),
                     "cisa_overdue": bool(still and v.get("kev_due") and v["kev_due"] < today),
                     "days_exposed": round(pipeline.days_since(oldest)) if oldest else None,
                     "still": [{"id": r["org_id"], "name": names.get(r["org_id"], r["org_id"]), "since": r["first_seen"], "hosts": r.get("hosts") or []} for r in still][:12],
                     "done": [{"id": r["org_id"], "name": names.get(r["org_id"], r["org_id"]), "fixed_at": r["fixed_at"]} for r in done][:12]})
    rows.sort(key=lambda r: (-r["exposed_now"], -r["fixed"], r["cve"]))
    dx = [r["days_exposed"] for r in rows if r["days_exposed"] is not None]
    summary = {"cves": len(rows), "with_fix": sum(1 for r in rows if r["fix"]["state"] in ("patch", "advisory")),
               "patch": sum(1 for r in rows if r["fix"]["state"] == "patch"), "unchecked": sum(1 for r in rows if r["fix"]["state"] == "unchecked"),
               "exposures": sum(r["exposed_now"] + r["fixed"] for r in rows), "still": sum(r["exposed_now"] for r in rows),
               "fixed": sum(r["fixed"] for r in rows), "fixed_window": sum(r["fixed_window"] for r in rows), "orgs_still": len(orgs_still),
               "cisa_overdue": sum(1 for r in rows if r["cisa_overdue"]), "median_days_exposed": round(statistics.median(dx)) if dx else None,
               "tracking_since": db.scalar("SELECT min(last_seen) FROM cve_exposure")}
    return {"window": days, "summary": summary, "cves": rows[:200]}


# ------------------------------------------------------------------ the risk chain: who is exposed to what is happening now
LINK_WORD = {"GROUP": "corporate group", "DEPENDENCY": "uses the provider", "NAMED_CUSTOMER": "named customer", "EXPOSED_PRODUCT": "runs the product"}
EXPLOITABLE_RULES = ("VUL-KEV-EXPOSED", "SURF-EDGE-KEV", "CMP-C2", "CMP-ABUSE", "DW-STEALER-30", "DW-ACCESS-14", "SURF-RISKY-PORT", "IOC-BRAND-LIVE", "NRD-PHISH")


def _line_of_fire(days: int) -> dict:
    """Organisations most exposed to what is happening now but not named as a victim in the window. Three explainable reasons,
    never a forecast: (1) in the path of a fast-moving incident (runs the product, uses the provider, named customer, group);
    (2) its sector is under active extortion (3+ leak-site victims) and it has an exploitable Critical/High exposure;
    (3) a provider it uses has a High/Critical incident."""
    names = {o["id"]: o for o in db.q("SELECT id, name, sector FROM org")}
    since = ts(days)
    reasons = defaultdict(list)
    direct = {m["org_id"] for m in db.q("SELECT m.org_id FROM impact m JOIN incident i ON i.id=m.incident_id WHERE m.link_type='DIRECT' AND i.last_seen > ?", (since,))}
    for r in db.q("SELECT m.org_id, m.link_type, i.id, i.title, i.velocity FROM impact m JOIN incident i ON i.id=m.incident_id "
                  "WHERE m.link_type NOT IN ('TARGETING','DIRECT') AND i.last_seen > ?", (since,)):
        v = r.get("velocity") or {}
        if v.get("spreading") or (v.get("kev_lag") is not None and v["kev_lag"] <= 7):
            reasons[r["org_id"]].append({"kind": "path", "text": f"{LINK_WORD.get(r['link_type'], r['link_type'])} — {r['title'][:90]}", "to": f"/incidents/{r['id']}"})
    sec_vict, sec_groups = Counter(), defaultdict(Counter)
    for l in db.q("SELECT sector, actor FROM leak WHERE kind='leaksite' AND published > ?", (since,)):
        s = pipeline.RW_SECTOR.get(l["sector"] or "", l["sector"]) or None
        if s and s not in ("Unknown", "Not Found", "Other"):
            sec_vict[s] += 1
            if l["actor"]:
                sec_groups[s][l["actor"]] += 1
    for f in db.q(f"SELECT org_id, rule_id, title FROM finding WHERE severity IN ('critical','high') AND rule_id IN ({','.join('?' * len(EXPLOITABLE_RULES))})",
                  EXPLOITABLE_RULES):
        s = (names.get(f["org_id"]) or {}).get("sector")
        if s and sec_vict.get(s, 0) >= 3:
            g = ", ".join(x for x, _ in sec_groups[s].most_common(2))
            reasons[f["org_id"]].append({"kind": "sector", "text": f"{sec_vict[s]} {s} organisations listed on leak sites ({g}); this one has {f['rule_id']}: {f['title'][:70]}",
                                         "to": f"/orgs/{f['org_id']}"})
    for r in db.q("SELECT m.org_id, i.id, i.title FROM impact m JOIN incident i ON i.id=m.incident_id WHERE m.link_type IN ('DEPENDENCY','NAMED_CUSTOMER') "
                  "AND m.severity IN ('critical','high') AND i.last_seen > ?", (since,)):
        reasons[r["org_id"]].append({"kind": "provider", "text": f"provider incident — {r['title'][:90]}", "to": f"/incidents/{r['id']}"})
    pm = _posture_map()
    out = []
    for oid, rs in reasons.items():
        if oid in direct or oid not in names:
            continue
        seen, uniq = set(), []
        for x in rs:
            if (x["kind"], x["text"]) not in seen:
                seen.add((x["kind"], x["text"]))
                uniq.append(x)
        c = pm.get(oid, Counter())
        lvl = next((l for l in ("critical", "high", "medium") if c.get(l)), "low" if c else None)
        out.append({"id": oid, "name": names[oid]["name"], "sector": names[oid]["sector"], "level": lvl, "kinds": sorted({x["kind"] for x in uniq}),
                    "reasons": uniq[:4], "n": len(uniq)})
    out.sort(key=lambda r: (-len(r["kinds"]), rating.RANK.get(r["level"] or "low", 9), -r["n"], r["name"]))
    return {"total": len(out), "orgs": out, "by_kind": dict(Counter(k for r in out for k in r["kinds"])),
            "sectors_under_extortion": [{"sector": s, "victims": n, "groups": [g for g, _ in sec_groups[s].most_common(3)]} for s, n in sec_vict.most_common(6)]}


# ------------------------------------------------------------------ the Situation (landing) page
LANDING_DOMAINS = [  # risk domains for the portfolio view, each a group of finding categories
    ("exposed", "Exposed & exploitable", ("exposure", "vulns", "critical")), ("compromise", "Compromised", ("compromise",)),
    ("darkweb", "Dark web & leaks", ("darkweb",)), ("third", "Third parties", ("software",)), ("impersonation", "Impersonation", ("impersonation",)),
    ("hygiene", "Email & domain", ("hygiene",)), ("ai", "AI", ("ai",)), ("disclosure", "Incidents & targeting", ("disclosure", "chatter")),
]


@app.get("/api/landing")
def landing(days: int = 30):
    """The Situation page: the few numbers and pictures that matter most, each linking to the page that explains it.
    Windowed items follow `days`; the watchlist grid, domains, deadlines and actions are the current state."""
    from aegis import actions as A
    orgs_ = db.q("SELECT id, name, sector, deep_scanned FROM org")
    pm = _posture_map()
    grid = []
    for o in orgs_:
        c = pm.get(o["id"], Counter())
        lvl = next((l for l in ("critical", "high", "medium") if c.get(l)), "low" if c else ("clear" if o["deep_scanned"] else "queued"))
        grid.append({"id": o["id"], "name": o["name"], "sector": o["sector"] or "Unknown", "level": lvl})
    sect = {g["id"]: g["sector"] for g in grid}
    hi = defaultdict(set)  # organisations with a Medium-or-above finding in each domain (Critical/High alone leaves hygiene and third parties blank)
    for f in db.q("SELECT org_id, category FROM finding WHERE severity IN ('critical','high','medium')"):
        for did, _, cats in LANDING_DOMAINS:
            if f["category"] in cats:
                hi[did].add(f["org_id"])
    # third-party risk arrives as incident links, not findings: organisations reached through a provider (DNS evidence or named
    # customer) by a High-or-Critical provider incident (breach / compromise) in the last 30 days — routine outages (Medium) excluded
    for m in db.q("SELECT m.org_id FROM impact m JOIN incident i ON i.id=m.incident_id WHERE m.link_type IN ('DEPENDENCY','NAMED_CUSTOMER') "
                  "AND m.severity IN ('critical','high') AND i.last_seen > ?", (ts(30),)):
        hi["third"].add(m["org_id"])
    sector_n = Counter(g["sector"] for g in grid if g["level"] != "queued")
    heat = [{"id": s, "data": [{"x": lbl, "y": (round(100 * sum(1 for o in hi[did] if sect.get(o) == s) / n) or None) if n else None,
                                "n": sum(1 for o in hi[did] if sect.get(o) == s), "of": n, "domain": did} for did, lbl, _ in LANDING_DOMAINS]}
            for s, n in sector_n.most_common() if s != "Unknown"]
    sp, ov = speed(days), overview(days)
    q = A.queue(limit=0)["kpi"]
    # raised vs verified closed, per week (12 weeks)
    now_dt = datetime.now(UTC)
    wk = []
    acts = db.q("SELECT created, verified_closed_at FROM action")
    for w in range(11, -1, -1):
        s, e = now_dt - timedelta(days=7 * (w + 1)), now_dt - timedelta(days=7 * w)
        si, ei = s.strftime("%Y-%m-%dT%H:%M:%SZ"), e.strftime("%Y-%m-%dT%H:%M:%SZ")
        wk.append({"week": (s + timedelta(days=1)).strftime("%d %b"), "raised": sum(1 for a in acts if si <= (a["created"] or "") < ei),
                   "closed": sum(1 for a in acts if a["verified_closed_at"] and si <= a["verified_closed_at"] < ei)})
    wk = [x for i, x in enumerate(wk) if x["raised"] or x["closed"] or i >= len(wk) - 4]
    # supply-chain concentration: direct dependents from DNS; indirect ones through a provider's own providers, when collected
    direct = [{"name": r["vendor"], "direct": r["n"]} for r in db.q("SELECT vendor, count(DISTINCT org_id) n FROM dependency GROUP BY vendor ORDER BY n DESC LIMIT 8")]
    fourth = None
    try:
        sv = _supplier_view()  # infrastructure-only fourth parties; optional — the landing page works without it
        fourth = sv["concentration"] if sv else None
    except Exception:
        fourth = None
    spreading = [s for s in sp["spreading"] if s["spreading"]]
    act72 = (sp["board"].get("overdue", {}).get("n", 0) + sp["board"].get("72h", {}).get("n", 0))
    fast_n = sum(1 for r in sp["race"] if r["lag"] <= 7)
    brief = [
        {"text": f"{sp['kev_window']} CVEs were newly confirmed exploited in the last {days} days — {fast_n} of them within a week of disclosure.", "to": "/speed#race"},
        {"text": f"{len(spreading)} incident{'s are' if len(spreading) != 1 else ' is'} spreading across independent publishers"
                 + (f"; the widest reaches {max(s['reach'] for s in spreading)} monitored organisations." if spreading else "."), "to": "/speed#spread"},
        {"text": f"{act72} organisations must act within 72 hours; {q['overdue']} actions are overdue and {q['verified_closed_30d']} were verified closed in 30 days.", "to": "/prevent"},
    ]
    if fourth:
        f0 = fourth[0]
        brief.append({"text": f"{f0['name']} hosts the DNS or mail of providers used by {f0['indirect']} monitored organisations that do not use it "
                              f"directly — {f0['total']} depend on it in all.", "to": "/suppliers"})
    changes_f = db.q("SELECT f.id, f.org_id, f.title, f.severity, f.rule_id, f.first_seen, o.name org FROM finding f JOIN org o ON o.id=f.org_id "
                     "WHERE f.first_seen > ? AND f.severity IN ('critical','high') ORDER BY CASE f.severity WHEN 'critical' THEN 0 ELSE 1 END, f.first_seen DESC LIMIT 7", (ts(1),))
    changes_i = db.q("SELECT id, title, severity, kind, first_seen FROM incident WHERE first_seen > ? ORDER BY CASE severity WHEN 'critical' THEN 0 "
                     "WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, first_seen DESC LIMIT 7", (ts(1),))
    # ---- the risk chain: where → who → how → how fast → who next → dependence → who is behind → what is discussed → what analysts say
    kinds = Counter(ov.get("kinds") or {})
    ctry = Counter(p.get("country") for p in ov["points"] if p.get("country"))
    byl = defaultdict(set)
    for m in db.q("SELECT m.org_id, m.link_type FROM impact m JOIN incident i ON i.id=m.incident_id WHERE m.link_type != 'TARGETING' AND i.last_seen > ?", (ts(days),)):
        byl[m["link_type"]].add(m["org_id"])
    how_label = {"DIRECT": "named as the victim", "GROUP": "part of the victim's corporate group", "EXPOSED_PRODUCT": "runs the exploited product",
                 "DEPENDENCY": "uses the affected provider", "NAMED_CUSTOMER": "named as an affected customer"}
    lof = _line_of_fire(days)
    act = actors_list(days=days)
    dw = darkweb(days)
    an = analyst(days)
    # shared providers: where exposure concentrates before anything happens (from Incidents & impact → provider concentration)
    pvd = providers(days)
    conc = {"scanned": pvd["scanned_orgs"], "active_n": len(pvd["active"]),
            "top": [{"vendor": p["vendor"], "category": p["category"], "orgs": p["n"], "worst": p["worst"], "issues": len(p["incidents"])} for p in pvd["providers"][:8]],
            # providers with an issue now, those reaching monitored organisations first (catalogue-only providers reach none observed)
            "with_issue": sorted([{"vendor": p["vendor"], "orgs": p["n"] + p["named"], "worst": p["worst"], "title": p["incidents"][0]["title"], "id": p["incidents"][0]["id"]}
                                  for p in pvd["active"] if p["incidents"]], key=lambda p: (not p["orgs"], rating.RANK.get(p["worst"], 9), -p["orgs"]))[:5]}
    # speed, classified: days from disclosure to exploitation, and hours from first report to 3 independent publishers
    from aegis.intel.velocity import LAG_BINS, lag_bin
    tte_bins = [{"band": lbl, "n": sum(1 for r in sp["race"] if lag_bin(r["lag"]) == lbl), "at_orgs": sum(1 for r in sp["race"] if lag_bin(r["lag"]) == lbl and r["orgs"])}
                for lbl, _, _ in LAG_BINS]
    h3 = sp["spread_h3"]
    spread_bands = [{"band": lbl, "n": sum(1 for h in h3 if h is not None and h >= lo and (hi is None or h < hi))}
                    for lbl, lo, hi in (("Within 24 hours", 0, 24), ("24–48 hours", 24, 48), ("48–72 hours", 48, 72), ("Slower than 72 hours", 72, None))]
    spread_bands.append({"band": "Not yet at 3 publishers", "n": sum(1 for h in h3 if h is None)})
    fx = fixes(days)
    fxs = {"summary": fx["summary"], "cves": [{k: c[k] for k in ("cve", "vendor", "product", "exposed_now", "fixed", "fix")} for c in fx["cves"][:6]]}
    focus = [o for k in ("overdue", "72h", "7d") for o in (sp["board"].get(k) or {}).get("orgs", [])]
    chain = {
        "where": {"incidents": ov["hero"]["incidents"], "critical": ov["hero"]["incidents_critical"],
                  "kinds": [{"kind": k, "n": n} for k, n in kinds.most_common(6)], "countries": [{"country": c, "n": n} for c, n in ctry.most_common(6)]},
        "how": {"reached": len(set().union(*byl.values())) if byl else 0,
                "by_link": [{"link": k, "label": how_label.get(k, k), "orgs": len(v)} for k, v in sorted(byl.items(), key=lambda kv: -len(kv[1]))]},
        "next": {"total": lof["total"], "by_kind": lof["by_kind"], "sectors_under_extortion": lof["sectors_under_extortion"], "orgs": lof["orgs"][:12]},
        "actors": {"active": sum(1 for a in act["actors"] if a["activity"] > 0),
                   "top": [{k: a[k] for k in ("id", "name", "kind", "activity", "victims_30d", "mentions_30d")} for a in act["actors"][:6] if a["activity"] > 0]},
        "discussion": {"leak_listings": dw["counts"]["leaksite"], "forum_claims": dw["counts"]["forum"], "claims": dict(dw["claims"]),
                       "monitored_listed": dw["counts"]["watch_listed"], "chatter_themes": dw["chatter_themes"][:6], "chatter_n": len(dw["chatter"]), "groups": dw["groups"][:5]},
        "analysts": {"items": db.scalar("SELECT count(*) FROM item WHERE published > ? AND kind IN ('news','research','advisory')", (ts(days),)),
                     "themes": [{k: t.get(k) for k in ("theme", "family", "n", "this_week", "rising")} for t in (an.get("themes") or [])[:8]]},
        "concentration": conc,
        "focus_org": (focus[0]["id"] if focus else next((g["id"] for g in grid if g["level"] == "critical"), None)),
        "urgent_orgs": [{"id": o["id"], "name": o["name"], "severity": o["severity"]} for o in focus[:20]],
    }
    return {
        "window": days, "monitored": len(grid), "brief": brief, "chain": chain,
        "grid": grid, "level_counts": Counter(g["level"] for g in grid),
        "now": {"critical_orgs": sum(1 for g in grid if g["level"] == "critical"), "act_72h": act72, "overdue": q["overdue"],
                "verified_closed_30d": q["verified_closed_30d"], "open_actions": q["open"], "median_days_to_close": q.get("median_days_to_close")},
        "pressures": {
            "exploit": {"median": sp["win"]["median"], "share_7d": sp["win"]["share_7d"], "window": sp["win"]["window"], "kev_window": sp["kev_window"],
                        "kev_prev": sp["kev_prev"], "weekly": sp["kev_weekly"][-12:], "bins": tte_bins},
            "spread": {"spreading": len(spreading), "top": [{k: s[k] for k in ("id", "title", "severity", "publishers_72h", "reach")} for s in spreading[:4]],
                       "bands": spread_bands},
            "supply": {"direct": direct, "fourth": (fourth or [])[:6], "provider_incidents": ov["signals"]["provider_incidents"], "provider_reach": ov["signals"]["provider_reach"]},
            "impersonation": {"lookalikes": ov["signals"]["new_lookalikes"], "live_within_3d": sp["lookalike_speed"]["live_within_3d"],
                              "checked": sp["lookalike_speed"]["checked"], "brands": ov["signals"]["brands_impersonated"]},
            "darkweb": {"leak_listings": ov["hero"]["leak_listings"], "forum_claims": ov["hero"]["forum_claims"],
                        "monitored_listed": db.scalar("SELECT count(DISTINCT org_id) FROM leak WHERE org_id IS NOT NULL AND published > ?", (ts(days),))},
        },
        "domains": {"heat": heat, "totals": [{"id": did, "label": lbl, "orgs": len(hi[did])} for did, lbl, _ in LANDING_DOMAINS]},
        "act": {"calendar": sp["calendar"], "weekly": wk}, "fixes": fxs,
        "changes": {"findings": changes_f, "incidents": changes_i},
        "points": ov["points"], "severity": ov["severity"], "incidents": ov["hero"]["incidents"], "coverage": ov.get("coverage"),
    }


# ------------------------------------------------------------------ what is the risk for one organisation, and what must it do
@app.get("/api/orgs/{oid}/brief")
def org_brief(oid: str, days: int = 30):
    """The whole chain, boiled down for one organisation — each part links to its evidence. Windowed parts follow `days`."""
    from aegis import actions as A
    from aegis.intel.providers import Catalogue
    o = db.one("SELECT id, name, sector, domain FROM org WHERE id=?", (oid,))
    if not o:
        raise HTTPException(404, "organisation not found")
    fnd = db.q("SELECT id, title, severity, rule_id, category FROM finding WHERE org_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
               "WHEN 'medium' THEN 2 ELSE 3 END, observed DESC", (oid,))
    counts = Counter(f["severity"] for f in fnd)
    level = next((l for l in ("critical", "high", "medium") if counts.get(l)), "low" if fnd else None)
    acts = [A.decorate(a) for a in db.q("SELECT * FROM action WHERE org_id=?", (oid,))]
    open_a = [a for a in acts if a["open"]]
    in72 = ts(-3)
    due72 = [a for a in open_a if a.get("due") and a["due"] <= in72]
    must = [{"id": a["id"], "title": a["title"], "level": a["level"], "due": a["due"], "owner_role": a["owner_role"], "rule_id": a["rule_id"],
             "confidence": a.get("confidence"), "first_step": ((a.get("playbook") or {}).get("steps") or [None])[0]}
            for a in sorted(open_a, key=lambda a: (a.get("due") or "9", A.RANK.get(a["level"], 9)))[:5]]
    reach = db.q("SELECT i.id, i.title, i.severity, i.kind, i.velocity, m.link_type FROM impact m JOIN incident i ON i.id=m.incident_id "
                 "WHERE m.org_id=? AND m.link_type != 'TARGETING' AND i.last_seen > ? LIMIT 80", (oid, ts(days)))
    for r in reach:
        v = r.pop("velocity") or {}
        r["fast"] = bool(v.get("spreading") or (v.get("kev_lag") is not None and v["kev_lag"] <= 7))
        r["how"] = {"DIRECT": "named victim", **LINK_WORD}.get(r["link_type"], r["link_type"])
    reach.sort(key=lambda r: (not r["fast"], rating.RANK.get(r["severity"], 9)))
    cat = Catalogue()
    provs = sorted({cat.canonical(d["vendor"]) or d["vendor"] for d in db.q("SELECT vendor FROM dependency WHERE org_id=?", (oid,))})
    issues = [r for r in reach if r["link_type"] in ("DEPENDENCY", "NAMED_CUSTOMER")]
    intel = db.kv_get("supplier_intel") or {}
    fourth = Counter()
    for p in provs:
        for f in (intel.get(p) or {}).get("fourth_parties") or []:
            if (f.get("kind") or "") in INFRA_KINDS and f["provider"] not in provs and f["provider"] != p:
                fourth[f["provider"]] += 1
    groups = Counter()
    for l in db.q("SELECT sector, actor FROM leak WHERE kind='leaksite' AND published > ?", (ts(days),)):
        if l["actor"] and pipeline.RW_SECTOR.get(l["sector"] or "", l["sector"]) == o["sector"]:
            groups[l["actor"]] += 1
    listed = db.q("SELECT actor, published, url FROM leak WHERE org_id=? AND kind='leaksite' AND published > ? ORDER BY published DESC LIMIT 3", (oid, ts(days)))
    ment = db.q("SELECT id, title, url, publisher, pub_type, kind, published FROM item WHERE org_ids LIKE ? AND published > ? ORDER BY published DESC LIMIT 60",
                (f'%"{oid}"%', ts(days)))
    lof = next((r for r in _line_of_fire(days)["orgs"] if r["id"] == oid), None)
    top = fnd[0] if fnd else None
    s = [f"{o['name']} is at {level.title() if level else 'no finding yet'}" + (f" — {top['title']}" if top and level in ("critical", "high", "medium") else "") + "."]
    s.append(f"{len(open_a)} action{'s' if len(open_a) != 1 else ''} open, {len(due72)} due within 72 hours.")
    if reach:
        nf = sum(1 for r in reach if r["fast"])
        s.append(f"{len(reach)} incident{'s' if len(reach) != 1 else ''} in the last {days} days reach it" + (f", {nf} of them fast-moving." if nf else "."))
    if issues:
        s.append(f"{len(issues)} of them arrive through its providers.")
    if listed:
        s.append(f"It was listed on a leak site by {listed[0]['actor']}.")
    elif groups:
        s.append(f"{sum(groups.values())} {o['sector']} organisations were listed on leak sites in the window ({', '.join(g for g, _ in groups.most_common(2))}).")
    return {"id": oid, "name": o["name"], "sector": o["sector"], "domain": o["domain"], "window": days, "level": level, "counts": dict(counts),
            "why": {"rule_id": top["rule_id"], "title": top["title"], "severity": top["severity"]} if top else None, "sentence": " ".join(s),
            "must_do": must, "open": len(open_a), "due_72h": len(due72),
            "reached_by": reach[:6], "reached_n": len(reach),
            "exposures": [{"title": f["title"], "rule_id": f["rule_id"], "severity": f["severity"]} for f in fnd if f["severity"] in ("critical", "high")][:6],
            "dependence": {"providers": len(provs), "issues": issues[:5], "fourth": [{"name": k, "via": n} for k, n in fourth.most_common(6)]},
            "actors": {"sector_groups": [{"group": g, "victims": n} for g, n in groups.most_common(4)], "listed": listed},
            "discussion": {"mentions": len(ment), "forum_or_chatter": sum(1 for m in ment if m["kind"] in ("chatter", "forum")), "latest": ment[:4]},
            "line_of_fire": (lof or {}).get("reasons", [])}


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
    # summary for the page's visual band: who is reached (distinct organisations), through which link, by incident type, and the daily tempo
    kind_of = {r["id"]: r["kind"] for r in rows}
    cell, by_link, reached = defaultdict(set), defaultdict(set), set()
    for m in db.q("SELECT incident_id, org_id, link_type FROM impact WHERE link_type != 'TARGETING'"):
        k = kind_of.get(m["incident_id"])
        if k:
            cell[(k, m["link_type"])].add(m["org_id"]); by_link[m["link_type"]].add(m["org_id"]); reached.add(m["org_id"])
    daily = defaultdict(Counter)
    for r in rows:
        if r.get("first_seen") and r["first_seen"] >= ts(days):
            daily[r["first_seen"][:10]][r["severity"]] += 1
    summary = {
        "reached": len(reached), "by_link": {k: len(v) for k, v in by_link.items()},
        "matrix": [{"kind": k, "link": lt, "orgs": len(v)} for (k, lt), v in cell.items()],
        "daily": [{"day": d, **daily[d]} for d in sorted(daily)],
        "new_24h": sum(1 for r in rows if r.get("first_seen") and r["first_seen"] >= ts(1)),
        "spreading": sum(1 for r in rows if (r.get("velocity") or {}).get("spreading")),
    }
    return {"incidents": rows, "kinds": kinds, "severity": Counter(r["severity"] for r in rows), "link_types": pipeline.LINK_TYPES, "summary": summary}


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
    from aegis.intel.velocity import spread
    return {**inc, "spread": spread(inc.get("sources") or []), "impacts": imps, "items": items, "leaks": leaks, "actor_profiles": actors, "vulns": vulns,
            "graph": {"nodes": uniq, "links": links}, "link_types": pipeline.LINK_TYPES,
            "by_sector": Counter(m["sector"] or "Unknown" for m in imps), "by_type": Counter(m["link_type"] for m in imps)}


@app.get("/api/linkage/providers")
def providers(days: int = 30):
    """Provider concentration from the catalogue + DNS evidence, with every provider that has an issue now — including providers
    public DNS cannot reveal, whose reach comes from organisations named as affected customers in reporting."""
    from aegis.intel.providers import Catalogue
    cat = Catalogue()
    canon = lambda v: cat.canonical(v) or v  # noqa: E731
    scanned = db.scalar("SELECT count(DISTINCT org_id) FROM asset WHERE kind='domain'") or 1
    dep = defaultdict(lambda: {"orgs": set(), "category": None, "kinds": Counter()})
    for r in db.q("SELECT org_id, vendor, category, evidence FROM dependency"):
        d = dep[canon(r["vendor"])]
        d["orgs"].add(r["org_id"])
        d["category"] = d["category"] or cat.category(canon(r["vendor"])) or r["category"]
        d["kinds"][(r["evidence"] or "").split(" ")[0].replace("include:", "")] += 1
    active, named = defaultdict(list), defaultdict(set)
    sev_rank = lambda s: rating.RANK.get(s, 9)  # noqa: E731
    reach = defaultdict(Counter)
    for m in db.q("SELECT incident_id, link_type, count(*) n FROM impact GROUP BY 1, 2"):
        reach[m["incident_id"]][m["link_type"]] = m["n"]
    for i in db.q("SELECT id, title, severity, kind, vendors, victim, last_seen FROM incident WHERE last_seen > ?", (ts(days),)):
        names = set()
        if i.get("victim") and (cat.canonical(i["victim"]) or i["victim"] in dep):
            names.add(canon(i["victim"]))
        if i["kind"] in ("Supply-chain / provider compromise", "Provider outage"):
            names |= {canon(v) for v in i.get("vendors") or [] if cat.canonical(v) or v in dep}
        elif i["kind"] == "Vulnerability exploitation":
            # an exploited product is a provider issue only for platforms customers run or connect to (RMM, MFT, DevOps, identity…);
            # a Chrome or Magento CVE is not an incident at Google or Adobe as a provider
            names |= {canon(v) for v in i.get("vendors") or [] if cat.canonical(v) and canon(v) not in pipeline.MEGA_PLATFORMS
                      and cat.category(canon(v)) in ("MSP / RMM", "File transfer", "Developer & collaboration", "Identity & access", "Security", "DNS & CDN")}
        for n in names:
            active[n].append({"id": i["id"], "title": i["title"], "severity": i["severity"], "kind": i["kind"], "last_seen": i["last_seen"],
                              "dependency": reach[i["id"]].get("DEPENDENCY", 0), "named": reach[i["id"]].get("NAMED_CUSTOMER", 0),
                              "exposed": reach[i["id"]].get("EXPOSED_PRODUCT", 0)})
    for m in db.q("SELECT m.org_id, i.victim FROM impact m JOIN incident i ON i.id=m.incident_id WHERE m.link_type='NAMED_CUSTOMER' AND i.last_seen > ?", (ts(days),)):
        named[canon(m["victim"] or "")].add(m["org_id"])
    rows = []
    for n in set(dep) | set(active):
        d = dep.get(n) or {"orgs": set(), "category": None, "kinds": Counter()}
        inc = sorted(active.get(n, []), key=lambda x: (sev_rank(x["severity"]), x["last_seen"]), reverse=False)
        rows.append({"vendor": n, "category": d["category"] or cat.category(n) or "Other", "n": len(d["orgs"]), "share": len(d["orgs"]) / scanned,
                     "named": len(named.get(n, set())), "incidents": inc[:6], "observable": cat.observable(n) if n in cat.rows else True,
                     "catalogued": n in cat.rows, "source": (cat.rows.get(n) or {}).get("source"), "evidence_kinds": dict(d["kinds"].most_common(4)),
                     "worst": inc[0]["severity"] if inc else None})
    rows.sort(key=lambda r: -r["n"])
    act = sorted([r for r in rows if r["incidents"]], key=lambda r: (sev_rank(r["worst"]), -(r["n"] + r["named"])))
    cats = Counter()
    for r in rows:
        cats[r["category"]] += r["n"]
    return {"scanned_orgs": scanned, "providers": rows[:150], "active": act[:40], "categories": cats, "catalogue_size": len(cat.rows),
            "unobserved_with_issues": [r["vendor"] for r in act if r["n"] == 0]}


PROVIDER_KINDS_UI = ("cname", "txt", "spf", "mx", "ns")


def _to_regex(kind: str, s: str) -> str:
    """Analysts type plain values ("snowflakecomputing.com", "databricks-verification="); regexes are accepted as-is."""
    s = s.strip().lower()
    if any(ch in s for ch in "^$\\|()[]*+?"):
        re.compile(s)
        return s
    e = re.escape(s.lstrip("."))
    return {"cname": rf"(^|\.){e}$", "txt": rf"^{e}", "mx": rf"(^|\.){e}$", "ns": rf"(^|\.){e}$", "spf": e}[kind]


@app.get("/api/providers")
def provider_list():
    counts = Counter()
    for r in db.q("SELECT vendor, count(DISTINCT org_id) n FROM dependency GROUP BY vendor"):
        counts[r["vendor"]] = r["n"]
    rows = db.q("SELECT * FROM provider ORDER BY category, name")
    for r in rows:
        r["orgs"] = counts.get(r["name"], 0)
    return {"providers": rows, "categories": sorted({r["category"] for r in rows if r.get("category")})}


@app.post("/api/providers")
def provider_add(body: dict = Body(...)):
    """Add or update a provider: name, category, aliases (as they appear in headlines) and optional DNS patterns.
    The next pipeline run applies the patterns to every stored scan and links the provider's incidents."""
    name = (body.get("name") or "").strip()
    if len(name) < 2:
        raise HTTPException(400, "name is required")
    pats = {}
    try:
        for k in PROVIDER_KINDS_UI:
            vals = body.get(k) or []
            vals = [v for v in (vals.split(",") if isinstance(vals, str) else vals) if str(v).strip()]
            pats[k] = [_to_regex(k, str(v)) for v in vals][:10]
    except re.error as e:
        raise HTTPException(400, f"invalid pattern: {e}")
    aliases = body.get("aliases") or []
    aliases = [a.strip() for a in (aliases.split(",") if isinstance(aliases, str) else aliases) if a.strip()][:15]
    prev = db.one("SELECT * FROM provider WHERE name=?", (name,))
    if prev and prev.get("source") == "catalogue":  # extend a shipped provider rather than replace it
        old = prev.get("patterns") or {}
        pats = {k: list(dict.fromkeys((old.get(k) or []) + pats.get(k, []))) for k in PROVIDER_KINDS_UI}
        aliases = list(dict.fromkeys(list(prev.get("aliases") or []) + aliases))
    db.upsert("provider", {"name": name, "category": body.get("category") or (prev or {}).get("category") or "Other", "aliases": aliases,
                           "patterns": pats, "observable": 1 if any(pats.values()) or (prev or {}).get("observable", 1) else 0,
                           "status_url": body.get("status_url") or (prev or {}).get("status_url"), "source": "analyst",
                           "added": (prev or {}).get("added") or db.now(), "notes": (body.get("notes") or "")[:300]})
    import threading
    threading.Thread(target=scheduler.run_pipeline, daemon=True).start()
    return {"ok": True, "name": name, "patterns": pats, "aliases": aliases}


@app.delete("/api/providers/{name}")
def provider_delete(name: str):
    r = db.one("SELECT source FROM provider WHERE name=?", (name,))
    if not r:
        raise HTTPException(404, "provider not found")
    if r["source"] != "analyst":
        raise HTTPException(400, "shipped catalogue providers cannot be deleted (add patterns or aliases instead)")
    db.x("DELETE FROM provider WHERE name=?", (name,))
    from aegis.intel.providers import sync_catalogue
    sync_catalogue()  # restores the shipped entry if an analyst had extended one
    return {"ok": True}


# ------------------------------------------------------------------ organisations
def _posture_map() -> dict:
    agg = defaultdict(Counter)
    for r in db.q("SELECT org_id, severity, count(*) n FROM finding GROUP BY 1,2"):
        agg[r["org_id"]][r["severity"]] = r["n"]
    return agg


def _in_clause(col: str, values: list[str], blank_label: str, params: list) -> str:
    """SQL for a multi-select filter, treating the facet's blank label as IS NULL."""
    picked = [v for v in values if v != blank_label]
    parts = []
    if picked:
        parts.append(f"{col} IN ({ph(len(picked))})"); params += picked
    if len(picked) != len(values):
        parts.append(f"({col} IS NULL OR {col}='')")
    return " AND (" + " OR ".join(parts) + ")"


@app.get("/api/orgs")
def orgs(q: str | None = None, sector: list[str] | None = Query(None), country: list[str] | None = Query(None),
         index: list[str] | None = Query(None), level: str | None = None,
         provider: str | None = None, days: int = 30):
    sql, p = "SELECT id, name, ticker, domain, country, city, sector, industry, indices, lat, lon, deep_scanned, tier FROM org WHERE 1=1", []
    if q:
        sql += " AND (name LIKE ? OR domain LIKE ? OR ticker LIKE ?)"; p += [f"%{q}%"] * 3
    # several values OR together; the facets' blank labels mean "no value recorded", which is
    # IS NULL rather than a literal to match
    if sector:
        sql += _in_clause("sector", sector, "Unknown", p)
    if country:
        sql += _in_clause("country", country, "—", p)
    if index:
        sql += " AND (" + " OR ".join(["indices LIKE ?"] * len(index)) + ")"; p += [f"%{i}%" for i in index]
    rows = db.q(sql + " ORDER BY name", p)
    if provider:  # organisations whose public DNS shows the provider (catalogue-canonical name)
        from aegis.intel.providers import Catalogue
        cat = Catalogue()
        pv = (cat.canonical(provider) or provider).lower()
        users = {d["org_id"] for d in db.q("SELECT org_id, vendor FROM dependency") if (cat.canonical(d["vendor"]) or d["vendor"]).lower() == pv}
        rows = [r for r in rows if r["id"] in users]
    pm = _posture_map()
    inc = Counter(r["org_id"] for r in db.q("SELECT m.org_id FROM impact m JOIN incident i ON i.id=m.incident_id WHERE m.link_type != 'TARGETING' AND i.last_seen > ?", (ts(30),)))
    incw = inc if days == 30 else Counter(r["org_id"] for r in db.q("SELECT m.org_id FROM impact m JOIN incident i ON i.id=m.incident_id "
                                                                      "WHERE m.link_type != 'TARGETING' AND i.last_seen > ?", (ts(days),)))
    lookw = Counter(r["org_id"] for r in db.q("SELECT org_id FROM ioc WHERE org_id IS NOT NULL AND match IN ('brand','nrd','phish-brand') AND published > ?", (ts(days),)))
    dl = defaultdict(lambda: {"n72": 0, "next": None})
    for f in db.q("SELECT org_id, act_by, deadline_rule FROM finding WHERE act_by IS NOT NULL"):
        d = dl[f["org_id"]]
        d["n72"] += f["deadline_rule"] == "DL-72H"
        d["next"] = min(d["next"] or f["act_by"], f["act_by"])
    look = Counter(r["org_id"] for r in db.q("SELECT org_id FROM ioc WHERE org_id IS NOT NULL AND match IN ('brand','nrd','phish-brand')"))
    for r in rows:
        r["act_72h"], r["next_act_by"], r["lookalikes"] = dl[r["id"]]["n72"], dl[r["id"]]["next"], look.get(r["id"], 0)
        c = pm.get(r["id"], Counter())
        r["counts"] = dict(c)
        r["level"] = next((l for l in ("critical", "high", "medium") if c.get(l)), "low" if c else None)
        # no finding yet: distinguish "surface scan still queued" from "scanned, nothing found"
        r["state"] = r["level"] or ("clear" if r["deep_scanned"] else "queued")
        r["incidents_30d"] = inc.get(r["id"], 0)
        r["incidents_window"], r["lookalikes_window"] = incw.get(r["id"], 0), lookw.get(r["id"], 0)  # follow the 7/30/90-day selector
    if level:
        rows = [r for r in rows if r["state"] == level]
    facets = {"sector": Counter(r["sector"] or "Unknown" for r in rows), "country": Counter(r["country"] or "—" for r in rows),
              "level": Counter(r["state"] for r in rows)}
    return {"orgs": rows, "facets": facets}


@app.get("/api/orgs/export")
def orgs_export(q: str | None = None, sector: list[str] | None = Query(None), country: list[str] | None = Query(None), index: list[str] | None = Query(None), level: str | None = None,
                provider: str | None = None, days: int = 30):
    """The organisations table as .xlsx, honouring whatever filters the console has applied."""
    import io
    from openpyxl import Workbook
    from openpyxl.styles import Font
    rows = orgs(q, sector, country, index, level, provider, days)["orgs"]
    wb = Workbook()
    ws = wb.active
    ws.title = "Organisations"
    head = ["Organisation", "Ticker", "Domain", "Level", "Critical", "High", "Medium", "Low", "Next act-by", "72h actions",
            f"Incidents reaching it ({days}d)", "Lookalikes", "Sector", "Country", "Lists", "Surface scan", "AEGIS link"]
    ws.append(head)
    for c in ws[1]:
        c.font = Font(bold=True)
    for r in rows:
        cn = r.get("counts") or {}
        ws.append([r["name"], r.get("ticker"), r.get("domain"), r.get("level") or ("no findings" if r.get("state") == "clear" else "scan queued"),
                   cn.get("critical", 0), cn.get("high", 0), cn.get("medium", 0), cn.get("low", 0), (r.get("next_act_by") or "")[:10], r.get("act_72h", 0),
                   r.get("incidents_window", 0), r.get("lookalikes", 0), r.get("sector"), r.get("country"), ", ".join(r.get("indices") or []),
                   (r.get("deep_scanned") or "")[:10], f"/orgs/{r['id']}"])
    ws.freeze_panes = "A2"
    buf = io.BytesIO()
    wb.save(buf)
    return Response(buf.getvalue(), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f'attachment; filename="aegis-organisations-{db.now()[:10]}.xlsx"'})


@app.get("/api/orgs/{oid}")
def org(oid: str):
    o = db.one("SELECT * FROM org WHERE id=?", (oid,))
    if not o:
        raise HTTPException(404, "organisation not found")
    from aegis import actions as _A, prevent as _P
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
    imps = db.q("SELECT m.link_type, m.severity, m.reason, m.evidence, i.id, i.title, i.kind, i.last_seen, i.severity inc_severity, i.velocity, i.cves "
                "FROM impact m JOIN incident i ON i.id=m.incident_id WHERE m.org_id=? ORDER BY i.last_seen DESC LIMIT 80", (oid,))
    for m in imps:  # fast-moving first: spreading, or exploited within 7 days of disclosure
        v = m.get("velocity") or {}
        m["fast"] = bool(v.get("spreading")) or (v.get("kev_lag") is not None and v["kev_lag"] <= 7)
    imps.sort(key=lambda m: (not m["fast"], rating.RANK.get(m["severity"], 9), pipeline.days_since(m["last_seen"])))
    provider_issues = {}  # provider (as shown in the third-party map) → worst active issue reaching this organisation through it
    for m in imps:
        mm = re.match(r"^Uses (.+?) \(", m["reason"] or "")
        if m["link_type"] == "DEPENDENCY" and mm:
            v = mm.group(1)
            if v not in provider_issues or rating.RANK[m["severity"]] < rating.RANK[provider_issues[v]["severity"]]:
                provider_issues[v] = {"severity": m["severity"], "id": m["id"], "title": m["title"], "kind": m["kind"]}
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
    ai_services = sorted({d["vendor"] for d in deps if d["category"] == "AI services"})
    idp = sorted({d["vendor"] for d in deps if d["vendor"] in ("Microsoft 365", "Google Workspace", "Okta", "Cisco Duo", "Ping Identity", "OneLogin")})
    identity = []
    if idp:
        identity = db.q("SELECT id, title, url, publisher, published, themes FROM item WHERE published > ? AND kind IN ('news','research','advisory') "
                        "AND (themes LIKE '%Device-code & token theft%' OR themes LIKE '%MFA & identity bypass%') ORDER BY published DESC LIMIT 8", (ts(30),))
    org_iocs = db.q("SELECT value, type, kind, publisher, report_title, report_url, published, match, how, attrs, tags FROM ioc WHERE org_id=? ORDER BY published DESC LIMIT 100", (oid,))
    inventory = {"footprint": f"{len(hosts)} hostnames · {len(ips)} IPs" if hosts else None,
                 "ai": f"AI services in DNS: {', '.join(ai_services)}" if ai_services else None,
                 "impersonation": f"{len(org_iocs)} lookalike / indicator record(s)" if org_iocs else None,
                 "critical": f"{len(crit)} critical assets" if crit else None,
                 "cloud": f"{len([c for c in cloud if 'Other' not in c and 'owned' not in c])} cloud providers" if ips else None,
                 "software": f"{len({d['vendor'] for d in deps})} providers in DNS" if deps else None,
                 "exposure": f"{len([a for a in ips if (a.get('attrs') or {}).get('ports')])} indexed hosts" if ips else None,
                 "hygiene": "DNS controls checked" if dom else None,
                 "compromise": f"{(db.kv_get('footprint_sizes', {}) or {}).get(oid, 0):,} addresses checked" if dom else None}
    return {
        "org": o, "posture": pipeline.posture(oid), "categories": pipeline.CATEGORIES, "inventory": inventory,
        "findings": findings, "critical_assets": crit,
        "actions": sorted([_A.decorate(a) for a in db.q("SELECT * FROM action WHERE org_id=?", (oid,))],
                          key=lambda a: (not a["open"], not a["overdue"], _A.RANK.get(a["level"], 9), a.get("due") or "9")),
        "prevent": _P.for_org(oid),
        "footprint": {"domain": dom, "hostnames": len(hosts), "ct_count": ((dom or {}).get("attrs") or {}).get("ct_count", 0),
                      "ips": [{"ip": a["value"], **(a.get("attrs") or {})} for a in ips], "prefixes": [{"cidr": a["value"], **(a.get("attrs") or {})} for a in prefixes],
                      "host_list": [{"host": h["value"], **(h.get("attrs") or {})} for h in hosts],
                      "subsidiaries": [{"lei": a["value"], **(a.get("attrs") or {})} for a in assets if a["kind"] == "subsidiary"],
                      "parent": next(({"lei": a["value"], **(a.get("attrs") or {})} for a in assets if a["kind"] == "parent"), None),
                      "group": next(((a.get("attrs") or {}) for a in assets if a["kind"] == "group"), None),
                      "scanned": o.get("deep_scanned")},
        "cloud": [{"provider": k, "ips": v} for k, v in cloud.most_common()],
        "ports": [{"port": k, "service": rating.RISKY_PORTS.get(k), "hosts": v} for k, v in sorted(ports.items())],
        "dependencies": {c: [{"vendor": v, "evidence": ev} for v, ev in vs.items()] for c, vs in dep_group.items()},
        "impacts": imps, "leaks": leaks, "mentions": mentions,
        "compromised": {"matches": comp, "footprint_addresses": fp_size, "checked": db.kv_get("blocklist_checked"),
                        "feeds": db.kv_get("blocklist_stats", {})},
        "threat": {"sector_actors": sector_actors, "crowdstrike_targeting": targeting},
        # context, not a finding: current identity-attack reporting for organisations whose DNS shows a cloud identity provider
        "identity": {"providers": idp, "items": identity},
        "iocs": org_iocs, "provider_issues": provider_issues,
        "impersonation": _org_impersonation(oid),
    }


def _org_impersonation(oid: str) -> dict:
    rows = _lookalikes(oid)
    pt = (db.kv_get("phishtank_targets", {}) or {}).get(oid) or {}
    return {"total": len(rows), "live": sum(1 for r in rows if r["live"]), "new_30d": sum(1 for r in rows if pipeline.days_since(r["published"]) <= 30),
            "phishtank": pt.get("n", 0), "phishtank_url": pt.get("sample"),
            "lures": [{"lure": l, "n": n} for l, n in Counter(r["lure"] for r in rows).most_common()],
            "sources": [{"source": s, "n": n} for s, n in Counter(r["source"] for r in rows).most_common()],
            "timeline": _weekly(rows, list(SRC_LABEL.values())), "timeline_keys": [k for k in SRC_LABEL.values() if any(r["source"] == k for r in rows)],
            "tlds": [{"tld": "." + t, "n": n} for t, n in Counter(r["tld"] for r in rows).most_common(8)],
            "rows": rows[:200]}


@app.post("/api/orgs")
def add_org(body: dict = Body(...)):
    name, domain = (body.get("name") or "").strip(), reg_domain(body.get("domain") or "")
    if not name or "." not in domain:
        raise HTTPException(400, "name and a valid domain are required")
    oid = "user-" + re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:50]
    db.upsert("org", {"id": oid, "name": name, "legal_name": name, "domain": domain, "domains": [domain], "website": f"https://{domain}",
                      "country": (body.get("country") or "").upper()[:2] or None, "sector": body.get("sector") or None,
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
    from aegis.intel.velocity import kev_lag
    kev = db.q("SELECT cve, vendor, product, name, kev_added, ransomware, epss, epss_pct, cvss, severity, severity_rule, exploit_refs, kev_due, published FROM vuln WHERE kev_added IS NOT NULL")
    for v in kev:
        v["lag"] = kev_lag(v.get("published"), v["kev_added"])  # disclosure → confirmed exploitation, days
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
    # ?category= ranks by one column first, so e.g. organisations with AI findings show even if they are not the most exposed overall
    top = sorted(pm.items(), key=lambda kv: ((rating.RANK.get(kv[1].get(category), 9),) if category else ()) + tuple(score(kv[1])))[:30]
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
        "matrix": {"orgs": [{"id": k, "name": names.get(k, k), "cells": v} for k, v in top], "categories": pipeline.CATEGORIES, "ranked_by": category,
                   "with_category": {c: sum(1 for m in pm.values() if c in m) for c, _ in pipeline.CATEGORIES}},
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
    up = db.q("SELECT e.org_id, o.name, e.first_seen, e.fixed_at FROM cve_exposure e JOIN org o ON o.id=e.org_id WHERE e.cve=? ORDER BY o.name", (cve.upper(),))
    return {**v, "exposed": exposed, "items": items, "fix_state": _fix_state(v), "fix_label": FIX_LABEL[_fix_state(v)],
            "uptake": {"still": [u for u in up if not u["fixed_at"]], "fixed": [u for u in up if u["fixed_at"]]}}


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
def actors_list(q: str | None = None, kind: str | None = None, origin: str | None = None, days: int = 30):
    """Activity (reporting mentions + leak-site victims) follows the 7/30/90-day selector; the *_30d keys hold the selected window."""
    sql, p = "SELECT id, name, aliases, crowdstrike, origin, motivation, kind, sectors, countries, attack_id, cs_targets, cs_url FROM actor WHERE 1=1", []
    if q:
        sql += " AND (name LIKE ? OR aliases LIKE ? OR crowdstrike LIKE ?)"; p += [f"%{q}%"] * 3
    if kind:
        sql += " AND kind=?"; p.append(kind)
    if origin:
        sql += " AND origin=?"; p.append(origin)
    rows = db.q(sql, p)
    m30, m90 = Counter(), Counter()
    for r in db.q("SELECT entities, published FROM item WHERE published > ?", (ts(max(90, days)),)):
        for a in (r.get("entities") or {}).get("actors") or []:
            m90[a] += 1
            if r["published"] > ts(days):
                m30[a] += 1
    victims = Counter(l["actor"].lower() for l in db.q("SELECT actor FROM leak WHERE kind='leaksite' AND published > ?", (ts(days),)) if l["actor"])
    for r in rows:
        r["mentions_30d"], r["mentions_90d"] = m30.get(r["id"], 0), m90.get(r["id"], 0)
        r["victims_30d"] = victims.get(r["name"].lower(), 0) if r["kind"] == "ransomware" else 0
        r["activity"] = r["mentions_30d"] + r["victims_30d"]
    rows.sort(key=lambda r: (-r["activity"], -r["mentions_90d"], r["name"]))
    return {"actors": rows[:600], "total": len(rows), "window": days, "origins": Counter(r["origin"] or "Unknown" for r in rows),
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
    items = db.q("SELECT id, title, url, publisher, pub_type, kind, published, themes, entities FROM item WHERE published > ? "
                 "AND kind IN ('news','research','advisory','forum','chatter','ai_incident')", (ts(63),))
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
    # columns: one family's themes, or the top 10 overall plus the top theme of every other family (so AI never drops out)
    if family and family in THEME_TREE:
        cols = [t["theme"] for t in themes if t["family"] == family]
    else:
        cols = [t["theme"] for t in themes[:10]]
        for fam in THEME_TREE:
            best = next((t["theme"] for t in themes if t["family"] == fam), None)
            if best and best not in cols:
                cols.append(best)
        cols = [t["theme"] for t in themes if t["theme"] in cols]
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
            "publisher_types": {k: dict(v) for k, v in ptype.items()}, "entities": top_ent, "cooccurrence": co,
            "who": who, "latest": latest, "families": list(THEME_TREE), "family": family}


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
def ai(days: int = 30):
    mit = db.kv_get("mit_ai_risk") or {}
    # everything below follows the 7/30/90-day selector except the MIT taxonomy (a reference catalogue) and AIAAIC (aggregate context)
    inc = db.q("SELECT id, title, url, published, entities, org_ids FROM item WHERE kind='ai_incident' AND published > ? ORDER BY published DESC LIMIT 200", (ts(days),))
    by_sub = Counter((i.get("entities") or {}).get("mit") or "Unclassified" for i in inc)
    related = db.q("SELECT id, title, url, publisher, published, themes FROM item WHERE published > ? AND kind IN ('news','research','advisory') "
                   "AND (themes LIKE '%AI-enabled attacks%' OR themes LIKE '%AI system security%' OR themes LIKE '%AI governance%') ORDER BY published DESC LIMIT 60", (ts(days),))
    # --- AI stack watch (v2.2)
    kev_ai = []
    for v in db.q("SELECT cve, vendor, product, name, kev_added, ransomware, epss, severity, severity_rule FROM vuln WHERE kev_added IS NOT NULL ORDER BY kev_added DESC"):
        p = aimod.kev_product(v["vendor"], v["product"])
        if p:
            kev_ai.append({**v, "ai_product": p})
    kev_ai_all = len(kev_ai)
    kev_ai = [v for v in kev_ai if (v.get("kev_added") or "") >= ts(days)[:10]]
    adv = [a for a in db.kv_get("ai_advisories", []) or [] if a.get("published", "") >= ts(days)[:10]]
    findings = db.q("SELECT f.id, f.org_id, f.title, f.detail, f.severity, f.rule_id, f.evidence_url, f.observed, o.name org FROM finding f JOIN org o ON o.id=f.org_id "
                    "WHERE f.category='ai' ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, f.observed DESC")
    atlas = db.kv_get("atlas") or {}
    techs = atlas.get("techniques") or {}
    tcount, tlatest = Counter(), {}
    for it in db.q("SELECT title, url, publisher, published, entities FROM item WHERE published > ? AND entities LIKE '%AML.T%' ORDER BY published DESC", (ts(days),)):
        for t in (it.get("entities") or {}).get("atlas") or []:
            if t["id"] in techs or not techs:
                tcount[t["id"]] += 1
                tlatest.setdefault(t["id"], {"title": it["title"], "url": it["url"], "publisher": it["publisher"], "term": t["term"]})
    vendor_reports = db.q("SELECT id, title, url, publisher, published, themes FROM item WHERE published > ? AND (source_id='anthropic_reports' OR publisher LIKE 'OpenAI%' "
                          "OR (publisher LIKE 'Google%' AND (title LIKE '%AI%' OR title LIKE '%Gemini%'))) ORDER BY published DESC LIMIT 30", (ts(max(days, 90)),))
    ai_fam = [t for t, f in THEME_FAMILY.items() if f == "AI & emerging"]
    th = Counter()
    for r in db.q("SELECT themes FROM item WHERE published > ? AND kind IN ('news','research','advisory','ai_incident')", (ts(days),)):
        th.update(t for t in r.get("themes") or [] if t in ai_fam or t in ("Autonomous / agentic intrusion", "Device-code & token theft"))
    stack = {
        "kev": kev_ai, "kev_all": kev_ai_all, "window": days, "advisories": adv[:150], "advisories_by_package": Counter(a["package"] for a in adv),
        "huntr": (db.kv_get("ai_huntr", []) or [])[:60], "malware": (db.kv_get("ai_malware", []) or [])[:40],
        "findings": findings, "findings_by_rule": Counter(f["rule_id"] for f in findings),
        "orgs_with_findings": len({f["org_id"] for f in findings if f["severity"] != "low"}),
        "providers": db.q("SELECT vendor, count(DISTINCT org_id) n FROM dependency WHERE category='AI services' GROUP BY vendor ORDER BY n DESC"),
        "atlas": {"release": atlas.get("release"), "techniques": len(techs), "case_studies": (atlas.get("case_studies") or [])[:12],
                  "tagged": [{"id": k, "name": (techs.get(k) or {}).get("name") or k, "n": n, "url": (techs.get(k) or {}).get("url"), "latest": tlatest.get(k)} for k, n in tcount.most_common(12)]},
        "offensive": sorted([{"repo": k, **v} for k, v in (db.kv_get("offensive_ai", {}) or {}).items()], key=lambda r: -(r.get("stars") or 0)),
        "vendor_reports": vendor_reports, "themes": [{"theme": t, "n": n} for t, n in th.most_common()],
    }
    return {"mit": mit, "incidents": inc, "incidents_by_subdomain": by_sub, "aiaaic": db.kv_get("aiaaic"), "cyber_ai_reporting": related, "stack": stack}


# ------------------------------------------------------------------ impersonation, indicators & website abuse (v2.2)
IMP_RULES = ("IOC-", "NRD-", "PHISH-", "WEB-", "DNS-")


@app.get("/api/impersonation")
def impersonation(days: int = 30, q: str | None = None):
    rank = "CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END"
    f = db.q(f"SELECT f.id, f.org_id, f.title, f.detail, f.severity, f.rule_id, f.evidence_url, f.observed, f.first_seen, o.name org FROM finding f "
             f"JOIN org o ON o.id=f.org_id WHERE {' OR '.join(f'f.rule_id LIKE ?' for _ in IMP_RULES)} ORDER BY {rank}, f.observed DESC", [p + "%" for p in IMP_RULES])
    brand = [x for x in f if x["rule_id"].startswith(("IOC-BRAND", "NRD-", "PHISH-"))]
    web = [x for x in f if x["rule_id"].startswith(("WEB-", "IOC-OWN"))]
    dns = [x for x in f if x["rule_id"].startswith("DNS-")]
    # reporting, matches and lookalikes follow the 7/30/90-day selector; findings (brand / web / DNS lists) are the current state
    reports = db.q("SELECT publisher, report_title, report_url, source_id, max(published) published, count(*) n, "
                   "sum(CASE WHEN org_id IS NOT NULL THEN 1 ELSE 0 END) matched FROM ioc WHERE kind='report' AND published > ? "
                   "GROUP BY report_url ORDER BY published DESC LIMIT 80", (ts(days),))
    matched = db.q("SELECT i.value, i.type, i.publisher, i.report_title, i.report_url, i.published, i.match, i.how, i.attrs, o.name org, i.org_id FROM ioc i "
                   "JOIN org o ON o.id=i.org_id WHERE i.kind='report' AND i.published > ? ORDER BY i.published DESC LIMIT 200", (ts(days),))
    search = db.q("SELECT value, type, kind, publisher, report_title, report_url, published, context, org_id, match, how FROM ioc WHERE value LIKE ? ORDER BY published DESC LIMIT 50",
                  (f"%{q}%",)) if q else []
    types = Counter(r["type"] for r in db.q("SELECT type FROM ioc WHERE kind='report'"))
    pubs = [{"publisher": r["publisher"], "n": r["n"]} for r in db.q("SELECT publisher, count(*) n FROM ioc WHERE kind='report' GROUP BY publisher ORDER BY n DESC LIMIT 12")]
    names = {o["id"]: o["name"] for o in db.q("SELECT id, name FROM org")}
    nrd = db.q("SELECT org_id, count(*) n FROM ioc WHERE kind='nrd' AND org_id IS NOT NULL AND published > ? GROUP BY org_id ORDER BY n DESC LIMIT 15", (ts(days),))
    pt = sorted([{"org_id": k, "org": names.get(k, k), **v} for k, v in (db.kv_get("phishtank_targets", {}) or {}).items()], key=lambda r: -r["n"])[:15]
    news = db.kv_get("news_domains", {}) or {}
    ident = db.q("SELECT id, title, url, publisher, published FROM item WHERE published > ? AND kind IN ('news','research','advisory') AND "
                 "(themes LIKE '%Device-code & token theft%' OR themes LIKE '%MFA & identity bypass%') ORDER BY published DESC LIMIT 25", (ts(days),))
    infl = db.q("SELECT id, title, url, publisher, published FROM item WHERE published > ? AND themes LIKE '%Influence operations & FIMI%' ORDER BY published DESC LIMIT 25", (ts(days),))
    vis = _impersonation_visuals(ident_n=len(ident), days=days)
    return {
        "visuals": vis,
        "stats": {"iocs": sum(types.values()), "reports": len(reports), "brand": len(brand), "brand_hi": sum(1 for x in brand if x["severity"] in ("critical", "high")),
                  "web": len(web), "dns": len(dns), "nrd_30d": db.scalar("SELECT count(*) FROM ioc WHERE kind='nrd' AND org_id IS NOT NULL AND published > ?", (ts(30),)),
                  "nrd_window": db.scalar("SELECT count(*) FROM ioc WHERE kind='nrd' AND org_id IS NOT NULL AND published > ?", (ts(days),)), "window": days,
                  "iocs_window": db.scalar("SELECT count(*) FROM ioc WHERE kind='report' AND published > ?", (ts(days),)),
                  "orgs": len({x["org_id"] for x in f if x["severity"] in ("critical", "high")})},
        "brand": brand, "web": web, "dns": dns, "reports": reports, "matched": matched, "search": search, "types": types, "publishers": pubs,
        "nrd_by_org": [{"org_id": r["org_id"], "org": names.get(r["org_id"], r["org_id"]), "n": r["n"]} for r in nrd],
        "nrd_stats": [{"day": k, **v} for k, v in sorted((db.kv_get("nrd_stats", {}) or {}).items())],
        "news_domains": [{"day": k, "count": v.get("count"), "sample": (v.get("sample") or [])[:24]} for k, v in sorted(news.items(), reverse=True)[:14]],
        "phishtank": pt, "clickfix": db.kv_get("clickfix_stats", {}), "identity": ident, "influence": infl,
    }


SRC_LABEL = {"report": "Threat-report indicator", "nrd": "Newly registered domain", "phish": "Phishing feed", "malware": "Malware / C2 feed"}


def _lookalikes(org_id: str | None = None) -> list[dict]:
    """One row per (organisation, lookalike host) with its source, lure theme and liveness."""
    from aegis.intel.iocs import lure_theme
    sql = ("SELECT i.value, i.kind, i.publisher, i.published, i.org_id, i.match, i.attrs, i.tags, o.name org FROM ioc i JOIN org o ON o.id=i.org_id "
           "WHERE i.match IN ('brand','nrd','phish-brand')")
    rows = db.q(sql + (" AND i.org_id=?" if org_id else "") + " ORDER BY i.published DESC", (org_id,) if org_id else ())
    out, seen = [], set()
    for r in rows:
        h = host_of(r["value"])
        if (r["org_id"], h) in seen:
            continue
        seen.add((r["org_id"], h))
        at = r.get("attrs") or {}
        src = "nrd" if r["kind"] == "nrd" else "report" if r["kind"] == "report" else "phish" if "phishing" in (r.get("tags") or []) else "malware"
        out.append({"host": h, "org_id": r["org_id"], "org": r["org"], "source": SRC_LABEL[src], "lure": lure_theme(h), "publisher": r["publisher"],
                    "published": r["published"], "live": bool(at.get("a") or at.get("mx")), "checked": bool(at.get("checked")),
                    "ns": (at.get("ns") or [None])[0], "tld": h.rsplit(".", 1)[-1]})
    return out


def _weekly(rows: list[dict], keys: list[str], key: str = "source", weeks: int = 12) -> list[dict]:
    now = datetime.now(UTC)
    buckets = []
    for w in range(weeks - 1, -1, -1):
        start = now - timedelta(days=7 * (w + 1))
        buckets.append({"week": (start + timedelta(days=1)).strftime("%Y-%m-%d"), **{k: 0 for k in keys}, "_s": start, "_e": now - timedelta(days=7 * w)})
    for r in rows:
        try:
            d = datetime.fromisoformat((r["published"] or "").replace("Z", "+00:00"))
        except ValueError:
            continue
        for b in buckets:
            if b["_s"] < d <= b["_e"] and r[key] in b:
                b[r[key]] += 1
                break
    return [{k: v for k, v in b.items() if not k.startswith("_")} for b in buckets]


def _impersonation_visuals(ident_n: int = 0, days: int | None = None) -> dict:
    rows = _lookalikes()
    if days:  # lookalikes registered / published in the selected window
        rows = [r for r in rows if (r.get("published") or "") >= ts(days)]
    brands = Counter(r["org"] for r in rows)
    top = [b for b, _ in brands.most_common(12)]
    lures = Counter(r["lure"] for r in rows)
    lure_order = [l for l, _ in lures.most_common()]
    heat = [{"id": b, "oid": next(r["org_id"] for r in rows if r["org"] == b),
             "data": [{"x": l, "y": sum(1 for r in rows if r["org"] == b and r["lure"] == l)} for l in lure_order]} for b in top]
    # source → lure → brand flow (top brands; the rest grouped)
    links = Counter()
    for r in rows:
        b = r["org"] if r["org"] in top[:10] else "Other brands"
        links[(r["source"], r["lure"])] += 1
        links[(r["lure"], b)] += 1
    node_ids = {s for s, _ in links} | {t for _, t in links}
    sankey = {"nodes": [{"id": n} for n in sorted(node_ids)], "links": [{"source": s, "target": t, "value": v} for (s, t), v in links.items()]}
    feed = db.q("SELECT tags FROM ioc WHERE kind='feed' AND org_id IS NOT NULL")
    clickfix_web = db.scalar("SELECT count(*) FROM finding WHERE rule_id='WEB-CLICKFIX'") or 0
    cf = db.kv_get("clickfix_stats", {}) or {}
    framework = [  # indicative ATT&CK mapping of what AEGIS observes, left to right along an impersonation campaign
        {"stage": "Resource development", "technique": "T1583.001 Acquire infrastructure: domains", "n": len(rows),
         "orgs": len({r["org_id"] for r in rows}), "what": "lookalike domains registered or published", "tab": "brand"},
        {"stage": "Resource development", "technique": "T1608 Stage capabilities", "n": sum(1 for r in rows if r["live"]),
         "orgs": len({r["org_id"] for r in rows if r["live"]}), "what": "lookalikes resolving (web or mail set up)", "tab": "brand"},
        {"stage": "Initial access", "technique": "T1566 Phishing · T1656 Impersonation", "n": sum(1 for r in rows if r["source"] == SRC_LABEL["phish"]) +
         sum(v.get("n", 0) for v in (db.kv_get("phishtank_targets", {}) or {}).values()),
         "orgs": db.scalar("SELECT count(DISTINCT org_id) FROM finding WHERE rule_id LIKE 'PHISH-%'") or 0, "what": "live phishing pages on lookalikes / targeting the brand", "tab": "brand"},
        {"stage": "Execution", "technique": "T1189 Drive-by · T1204.004 Malicious copy-paste (ClickFix)", "n": clickfix_web,
         "orgs": db.scalar("SELECT count(DISTINCT org_id) FROM finding WHERE rule_id='WEB-CLICKFIX'") or 0,
         "what": f"owned sites serving ClickFix lures (feeds list {cf.get('URLhaus', 0) + cf.get('ThreatFox', 0):,} ClickFix URLs overall)", "tab": "web"},
        {"stage": "Credential access", "technique": "T1528 Steal application access token · T1557 AiTM", "n": ident_n, "orgs": None,
         "what": "device-code / token-theft reporting in the window (context)", "tab": "context"},
        {"stage": "Command & control", "technique": "T1071 Application-layer protocol on lookalikes", "n": sum(1 for r in rows if r["source"] == SRC_LABEL["malware"]),
         "orgs": len({r["org_id"] for r in rows if r["source"] == SRC_LABEL["malware"]}), "what": "malware / C2 servers on lookalike domains", "tab": "reports"},
    ]
    pubs = Counter(r["publisher"] for r in rows if r["source"] == SRC_LABEL["report"])
    return {
        "brands": [{"org": b, "oid": next(r["org_id"] for r in rows if r["org"] == b), "n": n,
                    "live": sum(1 for r in rows if r["org"] == b and r["live"])} for b, n in brands.most_common(15)],
        "lures": [{"lure": l, "n": n} for l, n in lures.most_common()], "heat": heat, "heat_cols": lure_order, "sankey": sankey,
        "timeline": _weekly(rows, list(SRC_LABEL.values())), "timeline_keys": [k for k in SRC_LABEL.values() if any(r["source"] == k for r in rows)],
        "tlds": [{"tld": "." + t, "n": n} for t, n in Counter(r["tld"] for r in rows).most_common(12)],
        "hosting": [{"ns": reg_domain(n), "n": c} for n, c in Counter(reg_domain(r["ns"]) for r in rows if r["ns"]).most_common(10)],
        "live": {"resolving": sum(1 for r in rows if r["live"]), "not": sum(1 for r in rows if r["checked"] and not r["live"]),
                 "unchecked": sum(1 for r in rows if not r["checked"])},
        "reporters": [{"publisher": p, "n": n} for p, n in pubs.most_common(10)], "framework": framework, "total": len(rows),
        "feeds_matched": len(feed),
    }


@app.get("/api/iocs/export")
def ioc_export(report: str | None = None, org: str | None = None, days: int = 90):
    """Hunt pack: indicators as CSV for the SOC (mail/web gateways, EDR, SIEM look-backs)."""
    import csv
    import io
    sql, p = "SELECT value, type, kind, publisher, report_title, report_url, published, org_id, match, how FROM ioc WHERE published > ?", [ts(days)]
    if report:
        sql += " AND report_url=?"; p.append(report)
    if org:
        sql += " AND org_id=?"; p.append(org)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["indicator", "type", "source_kind", "publisher", "report", "report_url", "published", "matched_org", "match", "reason"])
    for r in db.q(sql + " ORDER BY published DESC LIMIT 50000", p):
        w.writerow([r["value"], r["type"], r["kind"], r["publisher"], r["report_title"], r["report_url"], (r["published"] or "")[:10], r["org_id"] or "", r["match"] or "", r["how"] or ""])
    return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="aegis-indicators.csv"'})


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
