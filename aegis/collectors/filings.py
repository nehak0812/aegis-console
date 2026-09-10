"""SEC EDGAR full-text search: 8-K Item 1.05 (material cybersecurity incident) and Item 8.01 cyber disclosures."""
import re
from datetime import date, timedelta

from aegis import db, net
from aegis.collectors.rss import enrich, item_id, store_items
from aegis.intel.entities import matcher
from aegis.registry import Source, collector

EFTS = "https://efts.sec.gov/LATEST/search-index"


def _hits(params: dict, max_pages: int = 3) -> list[dict]:
    out = []
    for p in range(max_pages):
        js = net.get_json(EFTS, params={**params, "from": p * 100}, timeout=40)
        hits = (js.get("hits") or {}).get("hits") or []
        out += hits
        if len(hits) < 100:
            break
    return out


def _name(display: str) -> str:
    return re.sub(r"\s*\((?:CIK|[A-Z0-9.\-, ]+)\)?.*$", "", display or "").strip().title() or display


@collector(Source(
    id="sec_8k", name="SEC 8-K cybersecurity disclosures", category="Registry", publisher="U.S. SEC EDGAR",
    homepage="https://www.sec.gov/edgar/search/", url=EFTS, cadence_min=60, licence="US Government public domain",
    notes="Item 1.05 material cybersecurity incidents (since Dec 2023) and Item 8.01 voluntary cyber-incident disclosures (12 months). "
          "Matched to organisations by CIK — the strongest possible identity match."))
def collect_8k() -> int:
    today = date.today().isoformat()
    queries = [
        ({"forms": "8-K", "items": "1.05", "startdt": "2023-12-01", "enddt": today}, "Item 1.05 — material cybersecurity incident"),
        ({"q": '"cybersecurity incident"', "forms": "8-K", "items": "8.01",
          "startdt": (date.today() - timedelta(days=365)).isoformat(), "enddt": today}, "Item 8.01 — cybersecurity incident disclosure"),
    ]
    by_cik = {r["cik"]: r["id"] for r in db.q("SELECT id, cik FROM org WHERE cik IS NOT NULL")}
    rows = []
    for params, label in queries:
        for h in _hits(params):
            s = h.get("_source") or {}
            adsh, _, fname = (h.get("_id") or "").partition(":")
            ciks = s.get("ciks") or []
            if not adsh or not ciks:
                continue
            cik = ciks[0].zfill(10)
            name = _name((s.get("display_names") or [""])[0])
            url = f"https://www.sec.gov/Archives/edgar/data/{int(cik)}/{adsh.replace('-', '')}/{fname}"
            oid = by_cik.get(cik) or matcher.name(name)
            title = f"{name} files SEC 8-K {label}"
            summary = f"Form {s.get('form')} filed {s.get('file_date')} · items {', '.join(s.get('items') or [])} · {', '.join(s.get('biz_locations') or [])}"
            e = enrich(title, "cybersecurity incident disclosure 8-K")
            if oid:
                e["org_ids"] = [oid]
            rows.append({"id": item_id(url), "source_id": "sec_8k", "kind": "filing", "publisher": "SEC EDGAR",
                         "pub_type": "Regulatory filing", "title": title, "summary": summary, "url": url,
                         "published": (s.get("file_date") or today) + "T00:00:00Z", "fetched": db.now(), **e})
    # de-duplicate amendments of the same filing index
    return store_items(rows)
