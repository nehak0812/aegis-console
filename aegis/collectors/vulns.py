"""Exploited software: CISA KEV (full catalogue) + FIRST EPSS exploit probability → explainable vuln severity."""
import json

from aegis import db, net
from aegis.rating import rule, vuln_rule
from aegis.registry import Source, collector

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"


@collector(Source(
    id="cisa_kev", name="CISA Known Exploited Vulnerabilities", category="Vulnerabilities", publisher="CISA",
    homepage="https://www.cisa.gov/known-exploited-vulnerabilities-catalog", url=KEV_URL, cadence_min=180,
    licence="US Government public domain",
    notes="Authoritative list of CVEs exploited in the wild, incl. known ransomware use and remediation due dates."))
def collect_kev() -> int:
    data = net.get_json(KEV_URL, timeout=60)
    rows = []
    for v in data.get("vulnerabilities", []):
        rows.append({
            "cve": v["cveID"], "vendor": v.get("vendorProject"), "product": v.get("product"),
            "name": v.get("vulnerabilityName"), "description": v.get("shortDescription"),
            "kev_added": v.get("dateAdded"), "kev_due": v.get("dueDate"),
            "ransomware": v.get("knownRansomwareCampaignUse"), "cwes": v.get("cwes") or [],
            # what CISA tells agencies to do, and the vendor advisories it cites — evidence that a fix or mitigation exists
            "kev_action": (v.get("requiredAction") or "")[:400] or None, "kev_notes": (v.get("notes") or "")[:800] or None,
            "updated": db.now(),
        })
    db.upsert("vuln", rows, keep=("epss", "epss_pct", "cvss", "exploit_refs", "published", "severity", "severity_rule"))
    rate_all()
    return len(rows)


def _epss_batch(cves: list[str]) -> dict[str, tuple[float, float]]:
    out = {}
    for i in range(0, len(cves), 90):
        chunk = cves[i:i + 90]
        js = net.get_json(EPSS_API, params={"cve": ",".join(chunk)}, timeout=40)
        for d in js.get("data", []):
            out[d["cve"]] = (float(d.get("epss", 0)), float(d.get("percentile", 0)))
    return out


@collector(Source(
    id="first_epss", name="FIRST EPSS exploit prediction", category="Vulnerabilities", publisher="FIRST.org",
    homepage="https://www.first.org/epss/", url=EPSS_API, cadence_min=720, licence="Free to use (FIRST EPSS terms)",
    notes="Daily probability (0–1) that a CVE will be exploited in the next 30 days. Pulled for KEV CVEs, CVEs on "
          "monitored organisations' exposed hosts, CVEs named in news, plus the global top 300."))
def collect_epss() -> int:
    wanted = {r["cve"] for r in db.q("SELECT cve FROM vuln")}
    top = net.get_json(EPSS_API, params={"order": "!epss", "limit": 300}, timeout=40).get("data", [])
    scores = {d["cve"]: (float(d["epss"]), float(d["percentile"])) for d in top}
    scores.update(_epss_batch(sorted(wanted - set(scores))))
    rows = [{"cve": c, "epss": s[0], "epss_pct": s[1], "updated": db.now()} for c, s in scores.items()]
    db.upsert("vuln", rows, keep=("vendor", "product", "name", "description", "kev_added", "kev_due", "ransomware",
                                  "cwes", "cvss", "exploit_refs", "published", "severity", "severity_rule"))
    rate_all()
    return len(rows)


EPSS_DAILY = "https://epss.empiricalsecurity.com/epss_scores-{}.csv.gz"


@collector(Source(
    id="epss_trend", name="FIRST EPSS history (7 and 30 days ago)", category="Vulnerabilities", publisher="FIRST.org (daily score files)",
    homepage="https://www.first.org/epss/data_stats", url="https://epss.empiricalsecurity.com/", cadence_min=720,
    licence="Free to use (FIRST EPSS terms)",
    notes="Two daily files (all CVEs, ~2.6 MB each) give every tracked CVE's exploit likelihood a week and a month ago, so AEGIS can see "
          "which vulnerabilities are surging towards exploitation before CISA confirms it (rule VUL-EPSS-SURGE)."))
def collect_epss_trend() -> int:
    import csv
    import gzip
    import io
    from datetime import date, timedelta
    have = {r["cve"] for r in db.q("SELECT cve FROM vuln")}
    n = 0
    for days, col in ((7, "epss_7d"), (30, "epss_30d")):
        raw = None
        for back in (0, 1, 2):  # the newest file can lag a day
            try:
                raw = net.cached(EPSS_DAILY.format((date.today() - timedelta(days=days + back)).isoformat()), 24 * 7, binary=True, timeout=120)
                break
            except Exception as e:
                print("[epss_trend]", days, back, e)
        if not raw:
            continue
        txt = (gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw).decode("utf-8", errors="replace")
        rows = []
        for r in csv.DictReader(io.StringIO("\n".join(l for l in txt.splitlines() if not l.startswith("#")))):
            if r.get("cve") in have:
                rows.append((float(r["epss"]), r["cve"]))
        c = db.conn()
        c.executemany(f"UPDATE vuln SET {col}=? WHERE cve=?", rows)
        c.commit()
        n += len(rows)
    if not n:
        raise RuntimeError("no EPSS history file could be read")
    return n


def ensure_cves(cves: set[str]) -> None:
    """Make sure CVEs seen elsewhere (exposed hosts, news) exist and have EPSS."""
    have = {r["cve"] for r in db.q("SELECT cve FROM vuln")}
    new = sorted(c for c in cves if c not in have)
    if not new:
        return
    scores = _epss_batch(new[:900])
    db.upsert("vuln", [{"cve": c, "epss": scores.get(c, (None, None))[0], "epss_pct": scores.get(c, (None, None))[1],
                        "updated": db.now()} for c in new[:900]])
    rate_all()


def rate_all() -> None:
    from datetime import date
    rows = db.q("SELECT cve, kev_added, ransomware, epss, cvss, exploit_refs FROM vuln")
    today = date.today()
    upd = []
    for r in rows:
        refs = r.get("exploit_refs") or []
        tooled = any(x.get("src") in ("Metasploit", "Nuclei") for x in refs if isinstance(x, dict))
        age = None
        if r["kev_added"]:
            try:
                age = (today - date.fromisoformat(r["kev_added"][:10])).days
            except ValueError:
                pass
        rid = vuln_rule(bool(r["kev_added"]), (r["ransomware"] or "").lower() == "known", r["epss"], r["cvss"],
                        kev_age_days=age, tooled=tooled, public_exploit=bool(refs))
        upd.append((rule(rid)[0], rid, r["cve"]))
    c = db.conn()
    c.executemany("UPDATE vuln SET severity=?, severity_rule=? WHERE cve=?", upd)
    c.commit()


MSF = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
NUCLEI = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
EXPLOITDB = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"


@collector(Source(
    id="exploit_refs", name="Public exploit availability", category="Vulnerabilities",
    publisher="Rapid7 Metasploit · ProjectDiscovery Nuclei · OffSec Exploit-DB", homepage="https://www.exploit-db.com",
    url=MSF, cadence_min=1440, licence="Metasploit: BSD · Nuclei: MIT · Exploit-DB: GPL (metadata)",
    feeds=[{"publisher": "Nuclei templates", "url": NUCLEI}, {"publisher": "Exploit-DB", "url": EXPLOITDB}],
    notes="Marks which CVEs have a public exploit module or proof-of-concept — a key input to the explainable vulnerability rules."))
def collect_exploit_refs() -> int:
    import csv
    import io
    import json
    refs: dict[str, list] = {}
    try:
        for key, m in json.loads(net.cached(MSF, 24, timeout=180)).items():
            if m.get("type") != "exploit":
                continue
            for r in m.get("references") or []:
                if str(r).upper().startswith("CVE-"):
                    refs.setdefault(r.upper(), []).append({"src": "Metasploit", "ref": m.get("fullname") or key,
                                                           "url": "https://github.com/rapid7/metasploit-framework/blob/master" + (m.get("path") or "")})
    except Exception as e:
        print("[exploit_refs] msf", e)
    try:
        for line in net.cached(NUCLEI, 24, timeout=120).splitlines():
            try:
                t = json.loads(line)
            except ValueError:
                continue
            cid = (t.get("ID") or "").upper()
            if cid.startswith("CVE-"):
                refs.setdefault(cid, []).append({"src": "Nuclei", "ref": (t.get("Info") or {}).get("Name"),
                                                 "url": "https://github.com/projectdiscovery/nuclei-templates/blob/main/" + (t.get("file_path") or "")})
    except Exception as e:
        print("[exploit_refs] nuclei", e)
    try:
        for row in csv.DictReader(io.StringIO(net.cached(EXPLOITDB, 24, timeout=180))):
            for code in (row.get("codes") or "").split(";"):
                if code.upper().startswith("CVE-"):
                    refs.setdefault(code.upper(), []).append({"src": "Exploit-DB", "ref": row.get("description", "")[:120],
                                                              "url": f"https://www.exploit-db.com/exploits/{row.get('id')}"})
    except Exception as e:
        print("[exploit_refs] exploitdb", e)
    have = {r["cve"] for r in db.q("SELECT cve FROM vuln")}
    c = db.conn()
    n = 0
    for cve, lst in refs.items():
        if cve in have:
            c.execute("UPDATE vuln SET exploit_refs=? WHERE cve=?", (json.dumps(lst[:8]), cve))
            n += 1
    c.commit()
    db.kv_set("exploit_ref_count", len(refs))
    rate_all()
    return n


def _cve_path(cve: str) -> str:
    _, year, num = cve.split("-")
    return f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{int(num) // 1000}xxx/{cve}.json"


@collector(Source(
    id="cve_details", name="CVE records (CVSS, description, affected product)", category="Vulnerabilities",
    publisher="CVE Program — cvelistV5 (incl. CISA ADP Vulnrichment)", homepage="https://github.com/CVEProject/cvelistV5",
    url="https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json", cadence_min=120,
    licence="CVE terms of use (free)", notes="Fills CVSS, publication date, description and affected vendor/product for tracked CVEs (400 per run)."))
def collect_cve_details() -> int:
    from concurrent.futures import ThreadPoolExecutor
    todo = [r["cve"] for r in db.q("SELECT cve FROM vuln WHERE published IS NULL ORDER BY kev_added DESC, epss DESC LIMIT 400")]

    def one(cve):
        try:
            js = net.get_json(_cve_path(cve), timeout=20, retries=1, ok_404=True)
        except Exception:
            return None
        if not js:
            return {"cve": cve, "published": "n/a"}
        cna = (js.get("containers") or {}).get("cna") or {}
        score = None
        for m in (cna.get("metrics") or []) + [m for a in (js.get("containers") or {}).get("adp", []) for m in a.get("metrics", [])]:
            for k in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                if isinstance(m, dict) and k in m and m[k].get("baseScore") is not None:
                    score = max(score or 0, float(m[k]["baseScore"]))
        aff = (cna.get("affected") or [{}])[0]
        desc = next((d.get("value") for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en")), None)
        return {"cve": cve, "published": ((js.get("cveMetadata") or {}).get("datePublished") or "n/a")[:10], "cvss": score,
                "desc": (desc or "")[:600], "vendor": aff.get("vendor"), "product": aff.get("product")}
    with ThreadPoolExecutor(8) as ex:
        res = [r for r in ex.map(one, todo) if r]
    c = db.conn()
    for r in res:
        c.execute("UPDATE vuln SET published=?, cvss=COALESCE(?, cvss), description=COALESCE(description, ?), "
                  "vendor=COALESCE(vendor, ?), product=COALESCE(product, ?) WHERE cve=?",
                  (r["published"], r.get("cvss"), r.get("desc") or None, r.get("vendor"), r.get("product"), r["cve"]))
    c.commit()
    rate_all()
    return len(res)


# ------------------------------------------------------------------ vendor fixes: has the vendor published one?
FIX_TAGS = {"patch", "vendor-advisory", "mitigation", "release-notes"}


def fix_from_record(js: dict) -> dict:
    """What a CVE record (cvelistV5, CNA + ADP containers) says about a fix: references tagged patch / vendor-advisory /
    mitigation / release-notes, and fixed versions (an 'affected' range with 'lessThan' ends where the fix begins)."""
    cont = js.get("containers") or {}
    refs = list((cont.get("cna") or {}).get("references") or [])
    for a in cont.get("adp") or []:
        refs += a.get("references") or []
    tagged, seen = [], set()
    for r in refs:
        tags = {str(t).lower() for t in (r.get("tags") or [])} & FIX_TAGS
        if tags and r.get("url") and r["url"] not in seen:
            seen.add(r["url"])
            tagged.append({"url": r["url"], "tags": sorted(tags)})
    fixed = set()
    for a in (cont.get("cna") or {}).get("affected") or []:
        for v in a.get("versions") or []:
            if v.get("status") == "affected" and v.get("lessThan") and v["lessThan"] not in ("*", "unspecified"):
                # an affected range; the fix is at its upper bound. 'version' is sometimes a release branch (Citrix: 14.1 before build 66.59)
                base = str(v.get("version") or "")
                branch = f" {base}" if base not in ("", "0", "*", "n/a", "unspecified") and not v["lessThan"].startswith(base) else ""
                fixed.add(f"{a.get('product') or ''}{branch} before {v['lessThan']}".strip())
    return {"patch": any("patch" in t["tags"] or "release-notes" in t["tags"] for t in tagged), "advisory": any("vendor-advisory" in t["tags"] for t in tagged),
            "mitigation": any("mitigation" in t["tags"] for t in tagged), "fixed_versions": sorted(fixed)[:6], "urls": tagged[:6], "source": "CVE record"}


def kev_note_urls(notes: str | None) -> list[str]:
    """Vendor advisory links CISA cites in a KEV entry's notes (NVD links excluded — they are not the vendor)."""
    import re
    return [u.rstrip(".;,)") for u in re.findall(r"https?://[^\s;]+", notes or "") if "nvd.nist.gov" not in u][:4]


@collector(Source(
    id="cve_fixes", name="Vendor fix evidence (CVE records)", category="Vulnerabilities",
    publisher="CVE Program — cvelistV5 (CNA and CISA ADP references)", homepage="https://github.com/CVEProject/cvelistV5",
    url="https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json", cadence_min=180, licence="CVE terms of use (free)",
    notes="For exploited CVEs and CVEs on monitored organisations' own hosts: whether the vendor published a patch, advisory or mitigation "
          "(tagged references, fixed versions), with CISA KEV advisory notes as a fallback. Re-checked every 14 days until a patch appears."))
def collect_cve_fixes() -> int:
    from concurrent.futures import ThreadPoolExecutor
    from aegis.intel.pipeline import ts
    exposed = {c for a in db.q("SELECT attrs FROM asset WHERE kind='ip' AND attrs LIKE '%\"vulns\": [\"CVE%'") for c in (a.get("attrs") or {}).get("vulns") or []}
    cands = db.q("SELECT cve, kev_added, kev_notes, fix, fix_checked FROM vuln WHERE kev_added IS NOT NULL OR cve IN (SELECT value FROM json_each(?))",
                 (json.dumps(sorted(exposed)),))
    stale = ts(14)

    def due(r):
        f = r.get("fix") or {}
        nurls = set(kev_note_urls(r.get("kev_notes")))
        notes_new = bool(nurls) and not (nurls & {u["url"] for u in f.get("urls") or []})  # KEV advisory notes arrived after the last check
        return not r.get("fix_checked") or notes_new or (not f.get("patch") and (r.get("fix_checked") or "") < stale)
    todo = sorted([r for r in cands if due(r)], key=lambda r: (r["cve"] not in exposed, r.get("fix_checked") is not None, -(len(r.get("kev_added") or ""))))[:300]

    def one(r):
        try:
            js = net.get_json(_cve_path(r["cve"]), timeout=20, retries=1, ok_404=True)
        except Exception:
            return None
        f = fix_from_record(js) if js else {"patch": False, "advisory": False, "mitigation": False, "fixed_versions": [], "urls": [], "source": "CVE record not found"}
        # the vendor advisories CISA cites in KEV count as a published advisory, added to whatever the CVE record tags
        notes = [u for u in kev_note_urls(r.get("kev_notes")) if u not in {x["url"] for x in f["urls"]}]
        if notes:
            f.update(advisory=True, urls=(f["urls"] + [{"url": u, "tags": ["cited by CISA KEV"]} for u in notes])[:8],
                     source=f"{f['source']} + CISA KEV notes" if f["urls"] else "CISA KEV notes")
        return r["cve"], f
    with ThreadPoolExecutor(8) as ex:
        res = [x for x in ex.map(one, todo) if x]
    c = db.conn()
    now = db.now()
    c.executemany("UPDATE vuln SET fix=?, fix_checked=? WHERE cve=?", [(json.dumps(f), now, cve) for cve, f in res])
    c.commit()
    return len(res)
