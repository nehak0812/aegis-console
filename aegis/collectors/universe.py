"""Organisation universe from real registries only: S&P 500 constituents (CIK) + FTSE 100 / DAX / CAC 40 /
EURO STOXX 50 membership, enriched from Wikidata (website, HQ coordinates, LEI, country, industry).
No coordinates, domains or sectors are ever invented — missing values stay empty."""
import csv
import io
import re

from aegis import db, net
from aegis.intel.entities import matcher, reg_domain
from aegis.registry import Source, collector

SP500 = "https://raw.githubusercontent.com/datasets/s-and-p-500-companies/main/data/constituents.csv"
WD = "https://query.wikidata.org/sparql"
INDEX = {"Q466496": "FTSE 100", "Q155718": "DAX 40", "Q648828": "CAC 40", "Q981010": "EURO STOXX 50"}

Q_FIELDS = """
  OPTIONAL { ?company p:P856 ?ws . ?ws ps:P856 ?website . ?ws wikibase:rank ?wrank . FILTER NOT EXISTS { ?ws pq:P582 ?wend } }
  OPTIONAL { ?company p:P159 ?hqSt . ?hqSt ps:P159 ?hq .
             OPTIONAL { ?hqSt pq:P625 ?qcoord } OPTIONAL { ?hq wdt:P625 ?icoord }
             OPTIONAL { ?hq rdfs:label ?hqLabel_ . FILTER(LANG(?hqLabel_) = "en") } }
  BIND(COALESCE(?qcoord, ?icoord) AS ?coord)
  OPTIONAL { ?company wdt:P1278 ?lei }
  OPTIONAL { ?company wdt:P946 ?isin }
  OPTIONAL { ?company wdt:P17 ?cty . ?cty wdt:P297 ?cc }
  OPTIONAL { ?company wdt:P452 ?ind . ?ind rdfs:label ?industryLabel_ . FILTER(LANG(?industryLabel_) = "en") }
  OPTIONAL { ?company skos:altLabel ?alt . FILTER(LANG(?alt) = "en") }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "en". }
"""
Q_AGG = """(GROUP_CONCAT(DISTINCT CONCAT(STR(?wrank), "|", STR(?website)); separator=" ") AS ?websites)
  (SAMPLE(?coord) AS ?hqCoord) (SAMPLE(?hqLabel_) AS ?hqCity) (SAMPLE(?lei) AS ?lei) (SAMPLE(?isin) AS ?isin)
  (SAMPLE(?cc) AS ?country) (GROUP_CONCAT(DISTINCT ?industryLabel_; separator="|") AS ?industries)
  (GROUP_CONCAT(DISTINCT ?alt; separator="|") AS ?alts)"""

GICS_MAP = [
    ("Financials", r"bank|insur|financ|asset management|investment|reinsur|stock exchange|payment|brokerage|wealth"),
    ("Health Care", r"pharma|biotech|medic|health|diagnostic|life science"),
    ("Utilities", r"electric|utilit|water supply|power generation|power station|gas distribution"),
    ("Energy", r"oil|petroleum|natural gas|energy industry|fossil|refin"),
    ("Information Technology", r"software|semiconductor|information technology|computer|electronic|it service|cloud"),
    ("Communication Services", r"telecom|media|broadcast|publish|advertis|entertainment|internet|video game|mass media"),
    ("Consumer Staples", r"food|beverage|tobacco|personal care|supermarket|grocer|brew|drink|household|cosmetic"),
    ("Consumer Discretionary", r"automo|apparel|luxury|retail|hotel|fashion|restaurant|car manufact|vehicle|clothing|leisure|travel|e-commerce|home improvement"),
    ("Materials", r"chemical|mining|steel|metal|building material|cement|paper|packaging|glass|gold|copper"),
    ("Industrials", r"aerospace|defen[cs]e|engineering|construction|transport|logistic|airline|machinery|industrial|conglomerate|shipping|rail|electrical equipment|staffing|consult"),
    ("Real Estate", r"real estate|property|reit"),
]
BAD_HOSTS = re.compile(r"wiki|facebook|twitter|x\.com|linkedin|youtube|instagram|consumerrights|bloomberg|reuters", re.I)


def sector_from(industries: str) -> str | None:
    for s, rx in GICS_MAP:
        if re.search(rx, industries or "", re.I):
            return s
    return None


def pick_website(websites: str, name: str) -> str | None:
    """Preferred-rank first, then a domain whose label resembles the company name; skip junk hosts."""
    cands = []
    for tok in (websites or "").split():
        rank, _, url = tok.partition("|")
        if not url or BAD_HOSTS.search(url):
            continue
        d = reg_domain(url)
        score = 0 if rank.endswith("PreferredRank") else 1
        label = d.split(".")[0]
        words = re.findall(r"[a-z0-9]+", name.lower())
        if not any(w[:4] in label for w in words if len(w) >= 3):
            score += 2
        if not d.endswith((".com", ".co.uk", ".de", ".fr", ".nl", ".com.cn")):
            score += 0.5
        cands.append((score, len(d), d))
    return sorted(cands)[0][2] if cands else None


def parse_point(p: str | None) -> tuple[float | None, float | None]:
    m = re.match(r"Point\(([-\d.eE]+) ([-\d.eE]+)\)", p or "")
    return (float(m.group(2)), float(m.group(1))) if m else (None, None)


def sparql(query: str) -> list[dict]:
    r = net.post(WD, data={"query": query, "format": "json"}, headers={"Accept": "application/sparql-results+json"}, timeout=120)
    return [{k: v.get("value") for k, v in b.items()} for b in r.json()["results"]["bindings"]]


def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:60]


@collector(Source(
    id="universe", name="Organisation universe (index constituents)", category="Registry",
    publisher="datasets/s-and-p-500-companies · Wikidata · SEC CIK", homepage="https://www.wikidata.org",
    url=SP500, cadence_min=10080, licence="S&P list: ODC-PDDL · Wikidata: CC0",
    feeds=[{"publisher": "Wikidata SPARQL", "url": WD}],
    notes="S&P 500 (by SEC CIK) plus current FTSE 100, DAX 40, CAC 40 and EURO STOXX 50 members, with official website, "
          "HQ coordinates, LEI and industry from Wikidata. Weekly refresh; values Wikidata lacks stay blank."))
def collect_universe() -> int:
    rows: dict[str, dict] = {}
    # --- S&P 500
    sp = list(csv.DictReader(io.StringIO(net.cached(SP500, 24))))
    ciks = {r["CIK"].zfill(10): r for r in sp if r.get("CIK")}
    wd = {}
    keys = sorted(ciks)
    for i in range(0, len(keys), 170):
        vals = " ".join(f'"{c}"' for c in keys[i:i + 170])
        q = f"SELECT ?cik ?company {Q_AGG} WHERE {{ VALUES ?cik {{ {vals} }} ?company wdt:P5531 ?cik . {Q_FIELDS} }} GROUP BY ?cik ?company"
        for b in sparql(q):
            wd.setdefault(b["cik"], b)
    for cik, r in ciks.items():
        w = wd.get(cik, {})
        lat, lon = parse_point(w.get("hqCoord"))
        dom = pick_website(w.get("websites", ""), r["Security"])
        oid = "us-" + slug(r["Symbol"])
        rows[oid] = {"id": oid, "name": r["Security"], "legal_name": r["Security"], "ticker": r["Symbol"], "cik": cik,
                     "lei": w.get("lei"), "isin": w.get("isin"), "domain": dom, "domains": [dom] if dom else [],
                     "website": f"https://{dom}" if dom else None, "country": w.get("country") or "US",
                     "city": (r.get("Headquarters Location") or "").split(",")[0] or w.get("hqCity"),
                     "lat": lat, "lon": lon, "sector": r.get("GICS Sector"), "industry": r.get("GICS Sub-Industry"),
                     "indices": ["S&P 500"], "wikidata": (w.get("company") or "").rsplit("/", 1)[-1] or None,
                     "aliases": [a for a in (w.get("alts") or "").split("|") if 3 <= len(a) <= 60][:8],
                     "tier": "watch", "source_id": "universe"}
    # --- European / UK indices
    vals = " ".join(f"wd:{q}" for q in INDEX)
    q = (f"SELECT ?company ?companyLabel ?index {Q_AGG} WHERE {{ VALUES ?index {{ {vals} }} "
         f"?company p:P361 ?st . ?st ps:P361 ?index . FILTER NOT EXISTS {{ ?st pq:P582 ?ended }} {Q_FIELDS} }} "
         f"GROUP BY ?company ?companyLabel ?index")
    by_q: dict[str, dict] = {}
    for b in sparql(q):
        qid = b["company"].rsplit("/", 1)[-1]
        idx = INDEX.get(b["index"].rsplit("/", 1)[-1])
        if qid in by_q:
            by_q[qid]["indices"].append(idx)
            continue
        lat, lon = parse_point(b.get("hqCoord"))
        name = b.get("companyLabel") or qid
        dom = pick_website(b.get("websites", ""), name)
        by_q[qid] = {"id": "wd-" + qid.lower(), "name": name, "legal_name": name, "ticker": None, "cik": None,
                     "lei": b.get("lei"), "isin": b.get("isin"), "domain": dom, "domains": [dom] if dom else [],
                     "website": f"https://{dom}" if dom else None, "country": b.get("country"), "city": b.get("hqCity"),
                     "lat": lat, "lon": lon, "sector": sector_from(b.get("industries", "")),
                     "industry": (b.get("industries") or "").split("|")[0] or None, "indices": [idx], "wikidata": qid,
                     "aliases": [a for a in (b.get("alts") or "").split("|") if 3 <= len(a) <= 60][:8],
                     "tier": "watch", "source_id": "universe"}
    have_dom = {r["domain"]: k for k, r in rows.items() if r["domain"]}
    for r in by_q.values():
        if r["domain"] and r["domain"] in have_dom:  # dual-listed (e.g. in S&P and EURO STOXX): merge index lists
            rows[have_dom[r["domain"]]]["indices"] = sorted(set(rows[have_dom[r["domain"]]]["indices"]) | set(r["indices"]))
            continue
        rows[r["id"]] = r
    for r in rows.values():
        if r["lat"] is None:
            r.pop("lat"); r.pop("lon")
    n = db.upsert("org", list(rows.values()), keep=("added", "deep_scanned"))
    db.x("UPDATE org SET added=COALESCE(added, ?)", (db.now(),))
    matcher.build()
    return n
