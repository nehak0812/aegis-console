"""Indicators from published threat reports — stored as indicator + short context + report link, never the report body.

- AI-vendor misuse reports: Anthropic threat-intelligence pages (no RSS; the hub page is read for new report links).
- MISP OSINT feeds: CIRCL and botvrij.eu (TLP:CLEAR), structured attributes with `to_ids`.
- Vendor IOC repositories on GitHub: Cisco Talos (CC0), Palo Alto Unit 42 (GPL-3.0), Meta threat-research (MIT, influence ops).
Matching to organisations (brand impersonation, own domain, own IP) happens in the pipeline so it follows the universe.
"""
import hashlib
import os
import re
from datetime import datetime, timedelta, timezone

from aegis import db, net
from aegis.collectors.rss import enrich as rss_enrich, item_id, store_items, strip_html
from aegis.intel.iocs import _domain_ok, _ip_ok, extract
from aegis.registry import Source, collector

UTC = timezone.utc


def ioc_id(value: str, typ: str, report_url: str) -> str:
    return hashlib.sha1(f"{typ}|{value}|{report_url}".encode()).hexdigest()[:20]


def store_iocs(rows: list[dict]) -> int:
    now = db.now()
    for r in rows:
        r.setdefault("first_seen", now)
        r["last_seen"] = now
        r["context"] = (r.get("context") or "")[:200]
    # liveness checks and organisation matches survive a re-ingest
    return db.upsert("ioc", rows, keep=("first_seen", "attrs", "org_id", "match", "token", "how"))


def _rows(iocs: list[dict], **meta) -> list[dict]:
    return [{"id": ioc_id(i["value"], i["type"], meta["report_url"]), "value": i["value"], "type": i["type"], "context": i.get("context"), **meta}
            for i in iocs]


# ------------------------------------------------------------------ Anthropic threat intelligence
ANTH_HUB = "https://www.anthropic.com/threat-intelligence"
ANTH_SEED = ["https://www.anthropic.com/threat-intelligence-report-september-2026"]


@collector(Source(
    id="anthropic_reports", name="Anthropic threat-intelligence reports (indicators)", category="Threat intel", publisher="Anthropic",
    homepage=ANTH_HUB, url=ANTH_HUB, cadence_min=1440, licence="Public reports; indicators + link only (robots.txt: Allow)",
    notes="Anthropic publishes no RSS. The hub page is read daily for report links; each report's defanged indicators "
          "(e.g. ms365-live[.]com) are extracted. Only indicators, a short context snippet and the report URL are stored."))
def collect_anthropic() -> int:
    hub = net.get_text(ANTH_HUB, timeout=40)
    links = set(ANTH_SEED)
    for h in re.findall(r'href="((?:https://www\.anthropic\.com)?/(?:threat-intelligence-report[^"#?]*|news/[^"#?]*(?:misuse|malicious|disrupting|threat|countering|espionage)[^"#?]*))"', hub, re.I):
        links.add(h if h.startswith("http") else "https://www.anthropic.com" + h)
    total, items = 0, []
    for url in sorted(links)[:25]:
        try:
            page = net.cached(url, 24 * 7, timeout=60)
        except Exception as e:
            print("[anthropic]", url, e)
            continue
        title = strip_html((re.search(r"<title>(.*?)</title>", page, re.S | re.I) or [None, url])[1], 240).replace(" \\ Anthropic", "").strip()
        desc = strip_html((re.search(r'<meta[^>]+name="description"[^>]+content="([^"]*)"', page) or [None, ""])[1], 600)
        pub = (re.search(r'"datePublished"\s*:\s*"([\d\-T:.Z+]+)"', page) or [None, None])[1]
        published = (pub[:10] + "T00:00:00Z") if pub else db.now()
        text = re.sub(r"<[^>]+>", " ", page)  # scripts kept: framework pages carry the report text as JSON; extract() de-escapes
        iocs = extract(text, defanged_only=True, publisher_host="www.anthropic.com")
        total += store_iocs(_rows(iocs, kind="report", source_id="anthropic_reports", publisher="Anthropic Threat Intelligence",
                                  report_title=title, report_url=url, published=published, tags=["ai-vendor"]))
        items.append({"id": item_id(url), "source_id": "anthropic_reports", "kind": "research", "publisher": "Anthropic Threat Intelligence",
                      "pub_type": "Vendor research", "title": title, "summary": desc, "url": url, "published": published, "fetched": db.now(),
                      **rss_enrich(title, desc)})
    store_items(items)
    return total


# ------------------------------------------------------------------ MISP OSINT feeds
MISP_FEEDS = [("CIRCL OSINT feed", "https://www.circl.lu/doc/misp/feed-osint/"), ("botvrij.eu OSINT feed", "https://www.botvrij.eu/data/feed-osint/")]
MISP_TYPES = {"domain": "domain", "hostname": "domain", "url": "url", "ip-dst": "ip", "ip-src": "ip", "sha256": "sha256"}


def _misp_values(a: dict) -> list[tuple[str, str]]:
    t, v = a.get("type", ""), str(a.get("value", "")).strip()
    if t in ("domain|ip", "hostname|port", "ip-dst|port", "ip-src|port"):
        left, _, right = v.partition("|")
        out = []
        if t == "domain|ip":
            out = [("domain", left), ("ip", right)]
        elif t == "hostname|port":
            out = [("domain", left)]
        else:
            out = [("ip", left)]
        return out
    return [(MISP_TYPES[t], v)] if t in MISP_TYPES else []


@collector(Source(
    id="misp_osint", name="MISP OSINT feeds (CIRCL, botvrij.eu)", category="Threat intel", publisher="CIRCL · botvrij.eu",
    homepage="https://www.circl.lu/doc/misp/feed-osint/", url="https://www.circl.lu/doc/misp/feed-osint/manifest.json", cadence_min=720,
    licence="TLP:CLEAR OSINT feeds (free)", feeds=[{"publisher": p, "url": u + "manifest.json"} for p, u in MISP_FEEDS],
    notes="Structured indicators from 1,700+ OSINT events. Only events updated in the last 60 days, only attributes marked for detection (to_ids)."))
def collect_misp() -> int:
    seen = db.kv_get("misp_seen", {}) or {}
    cutoff = (datetime.now(UTC) - timedelta(days=60)).timestamp()
    total, errs = 0, []
    for pub, base in MISP_FEEDS:
        try:
            man = net.get_json(base + "manifest.json", timeout=120)
        except Exception as e:
            errs.append(f"{pub}: {e}")
            continue
        evs = sorted([(k, v) for k, v in man.items() if int(v.get("timestamp") or 0) >= cutoff and seen.get(k) != v.get("timestamp")],
                     key=lambda kv: -int(kv[1].get("timestamp") or 0))[:40]
        for uuid, meta in evs:
            try:
                ev = (net.get_json(f"{base}{uuid}.json", timeout=60) or {}).get("Event") or {}
            except Exception as e:
                errs.append(f"{uuid}: {e}")
                continue
            attrs = list(ev.get("Attribute") or []) + [a for o in ev.get("Object") or [] for a in o.get("Attribute") or []]
            link = next((a["value"] for a in attrs if a.get("type") == "link" and str(a.get("value", "")).startswith("http")), f"{base}{uuid}.json")
            rows = []
            for a in attrs[:3000]:
                if not a.get("to_ids"):
                    continue
                for typ, val in _misp_values(a):
                    if (typ == "domain" and not _domain_ok(val)) or (typ == "ip" and not _ip_ok(val)) or not val:
                        continue
                    rows.append({"type": typ, "value": val.lower() if typ != "url" else val, "context": (a.get("comment") or ev.get("info") or "")[:200]})
            total += store_iocs(_rows(rows, kind="report", source_id="misp_osint", publisher=f"{pub} — {(ev.get('Orgc') or {}).get('name') or ''}".strip(" —"),
                                      report_title=(ev.get("info") or uuid)[:240], report_url=link,
                                      published=f"{ev.get('date') or db.now()[:10]}T00:00:00Z",
                                      tags=[t.get("name") for t in ev.get("Tag") or []][:10]))
            seen[uuid] = meta.get("timestamp")
    db.kv_set("misp_seen", seen)
    if errs:
        print("[misp_osint]", "; ".join(errs)[:300])
    return total


# ------------------------------------------------------------------ vendor IOC repositories (GitHub)
REPOS = [  # publisher, repo, branch, licence, path filter, date-in-path pattern, prose (defanged-only)
    ("Cisco Talos", "Cisco-Talos/IOCs", "main", "CC0-1.0", r"^\d{4}/\d{2}/.+\.(txt|csv|json)$", r"^(\d{4})/(\d{2})/", False),
    ("Palo Alto Unit 42", "PaloAltoNetworks/Unit42-timely-threat-intel", "main", "GPL-3.0", r"\.txt$", r"(\d{4})-(\d{2})-(\d{2})", True),
    ("Meta threat-research", "facebook/threat-research", "main", "MIT", r"^indicators/.+\.(md|tsv|csv)$", None, True),
]


def _gh_headers() -> dict:
    tok = os.environ.get("GITHUB_TOKEN", "").strip()
    return {"Accept": "application/vnd.github+json", **({"Authorization": f"Bearer {tok}"} if tok else {})}


@collector(Source(
    id="ioc_repos", name="Vendor IOC repositories (Talos, Unit 42, Meta)", category="Threat intel",
    publisher="Cisco Talos (CC0) · Palo Alto Unit 42 (GPL-3.0) · Meta threat-research (MIT)", homepage="https://github.com/Cisco-Talos/IOCs",
    url="https://api.github.com/repos/Cisco-Talos/IOCs", cadence_min=1440, licence="CC0 · GPL-3.0 (attribution, share-alike) · MIT",
    feeds=[{"publisher": p, "url": f"https://github.com/{r}"} for p, r, *_ in REPOS],
    notes="Indicator files published with vendor research. One GitHub API call per repository per day (set GITHUB_TOKEN to lift the "
          "60/hour anonymous limit); files are then read from raw.githubusercontent.com. Only files from the last 120 days."))
def collect_repos() -> int:
    seen = db.kv_get("ioc_repo_seen", {}) or {}
    cutoff = datetime.now(UTC) - timedelta(days=120)
    total, errs = 0, []
    for pub, repo, branch, lic, pfilter, dated, prose in REPOS:
        try:
            tree = (net.get_json(f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1", headers=_gh_headers(), timeout=60) or {}).get("tree") or []
        except Exception as e:
            errs.append(f"{pub}: {e}")
            continue
        files = []
        for f in tree:
            p = f.get("path", "")
            if f.get("type") != "blob" or not re.search(pfilter, p, re.I) or re.search(r"readme|license", p, re.I) or seen.get(f"{repo}:{p}") == f.get("sha"):
                continue
            when = None
            if dated:
                m = re.search(dated, p)
                if not m:
                    continue
                try:
                    when = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)) if m.lastindex and m.lastindex >= 3 else 1, tzinfo=UTC)
                except ValueError:
                    continue
                if when < cutoff:
                    continue
            files.append((p, f.get("sha"), when))
        files.sort(key=lambda x: x[2] or datetime.min.replace(tzinfo=UTC), reverse=True)
        for p, sha, when in files[:30]:
            try:
                raw = net.get_text(f"https://raw.githubusercontent.com/{repo}/{branch}/{p}", timeout=40)
            except Exception as e:
                errs.append(f"{p}: {e}")
                continue
            iocs = extract(raw, defanged_only=prose, publisher_host="github.com")
            title = re.sub(r"[-_]+", " ", p.rsplit("/", 1)[-1].rsplit(".", 1)[0]).strip()
            total += store_iocs(_rows(iocs, kind="report", source_id="ioc_repos", publisher=pub, report_title=title[:240],
                                      report_url=f"https://github.com/{repo}/blob/{branch}/{p}",
                                      published=(when or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ"), tags=[lic]))
            seen[f"{repo}:{p}"] = sha
    db.kv_set("ioc_repo_seen", seen)
    if errs:
        print("[ioc_repos]", "; ".join(errs)[:300])
        if not total and len(errs) >= len(REPOS):
            raise RuntimeError("; ".join(errs)[:300])
    return total
