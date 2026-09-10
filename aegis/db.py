"""SQLite storage. One connection per thread, WAL mode, JSON stored as TEXT.

Every row that reaches the UI carries a source_id and an evidence URL; nothing here is synthetic.
"""
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Iterable

from aegis import DATA_DIR

DB_PATH = os.environ.get("AEGIS_DB", os.path.join(DATA_DIR, "aegis.sqlite"))
_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS source (
  id TEXT PRIMARY KEY, name TEXT, category TEXT, publisher TEXT, url TEXT, homepage TEXT,
  cadence_min INTEGER, licence TEXT, access TEXT, feeds TEXT, notes TEXT,
  status TEXT DEFAULT 'PENDING', last_run TEXT, last_ok TEXT, last_error TEXT,
  items_last_run INTEGER DEFAULT 0, items_total INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS run_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT, source_id TEXT, started TEXT, finished TEXT,
  ok INTEGER, items INTEGER, error TEXT
);
CREATE INDEX IF NOT EXISTS ix_runlog_src ON run_log(source_id, started);

CREATE TABLE IF NOT EXISTS org (
  id TEXT PRIMARY KEY, name TEXT, legal_name TEXT, ticker TEXT, cik TEXT, lei TEXT,
  domain TEXT, domains TEXT, website TEXT, country TEXT, city TEXT, lat REAL, lon REAL,
  sector TEXT, industry TEXT, indices TEXT, wikidata TEXT, aliases TEXT,
  tier TEXT DEFAULT 'universe', added TEXT, deep_scanned TEXT, source_id TEXT
);
CREATE INDEX IF NOT EXISTS ix_org_domain ON org(domain);

-- Generic content: news, research, advisories, chatter, forum-post reports, filings, AI incidents, status incidents
CREATE TABLE IF NOT EXISTS item (
  id TEXT PRIMARY KEY, source_id TEXT, kind TEXT, publisher TEXT, pub_type TEXT,
  title TEXT, summary TEXT, url TEXT, published TEXT, fetched TEXT,
  themes TEXT, entities TEXT, org_ids TEXT, severity TEXT, severity_rule TEXT, incident_id TEXT
);
CREATE INDEX IF NOT EXISTS ix_item_pub ON item(published);
CREATE INDEX IF NOT EXISTS ix_item_kind ON item(kind, published);

CREATE TABLE IF NOT EXISTS vuln (
  cve TEXT PRIMARY KEY, vendor TEXT, product TEXT, name TEXT, description TEXT,
  kev_added TEXT, kev_due TEXT, ransomware TEXT, cwes TEXT, cvss REAL, epss REAL, epss_pct REAL,
  exploit_refs TEXT, published TEXT, severity TEXT, severity_rule TEXT, updated TEXT
);
CREATE INDEX IF NOT EXISTS ix_vuln_kev ON vuln(kev_added);

CREATE TABLE IF NOT EXISTS actor (
  id TEXT PRIMARY KEY, name TEXT, aliases TEXT, crowdstrike TEXT, origin TEXT, motivation TEXT,
  sectors TEXT, countries TEXT, description TEXT, refs TEXT, attack_id TEXT, kind TEXT, source_id TEXT
);

CREATE TABLE IF NOT EXISTS leak (
  id TEXT PRIMARY KEY, source_id TEXT, kind TEXT, victim TEXT, domain TEXT, actor TEXT,
  published TEXT, country TEXT, sector TEXT, title TEXT, url TEXT, org_id TEXT, match TEXT,
  extra TEXT, incident_id TEXT
);
CREATE INDEX IF NOT EXISTS ix_leak_pub ON leak(published);
CREATE INDEX IF NOT EXISTS ix_leak_org ON leak(org_id);

CREATE TABLE IF NOT EXISTS asset (
  org_id TEXT, kind TEXT, value TEXT, attrs TEXT, source_id TEXT, first_seen TEXT, last_seen TEXT,
  PRIMARY KEY (org_id, kind, value)
);

CREATE TABLE IF NOT EXISTS dependency (
  org_id TEXT, vendor TEXT, product TEXT, category TEXT, evidence TEXT, source_id TEXT, seen TEXT,
  PRIMARY KEY (org_id, vendor, evidence)
);
CREATE INDEX IF NOT EXISTS ix_dep_vendor ON dependency(vendor);

CREATE TABLE IF NOT EXISTS finding (
  id TEXT PRIMARY KEY, org_id TEXT, category TEXT, title TEXT, detail TEXT, severity TEXT,
  rule_id TEXT, evidence_url TEXT, source_id TEXT, observed TEXT, first_seen TEXT, last_seen TEXT, data TEXT
);
CREATE INDEX IF NOT EXISTS ix_finding_org ON finding(org_id, severity);

CREATE TABLE IF NOT EXISTS incident (
  id TEXT PRIMARY KEY, title TEXT, kind TEXT, victim TEXT, victim_org_id TEXT, vendors TEXT,
  products TEXT, actors TEXT, cves TEXT, sectors TEXT, countries TEXT, first_seen TEXT, last_seen TEXT,
  severity TEXT, severity_rule TEXT, sources TEXT, source_count INTEGER, item_count INTEGER, summary TEXT
);
CREATE INDEX IF NOT EXISTS ix_incident_last ON incident(last_seen);

CREATE TABLE IF NOT EXISTS impact (
  incident_id TEXT, org_id TEXT, link_type TEXT, severity TEXT, reason TEXT, evidence TEXT,
  PRIMARY KEY (incident_id, org_id, link_type)
);
CREATE INDEX IF NOT EXISTS ix_impact_org ON impact(org_id);

CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT, updated TEXT);
"""

JSON_COLS = {"domains", "indices", "aliases", "themes", "entities", "org_ids", "cwes", "exploit_refs",
             "sectors", "countries", "refs", "extra", "attrs", "data", "vendors", "products", "actors",
             "cves", "sources", "feeds", "tools", "techniques", "cs_targets", "evidence"}

# columns added after first release — applied idempotently by init()
MIGRATIONS = {
    "actor": {"tools": "TEXT", "techniques": "TEXT", "cs_targets": "TEXT", "cs_url": "TEXT", "misp_uuid": "TEXT"},
    "org": {"sub_industry": "TEXT", "isin": "TEXT"},
}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def conn() -> sqlite3.Connection:
    c = getattr(_local, "c", None)
    if c is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        c = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.execute("PRAGMA busy_timeout=30000")
        _local.c = c
    return c


def init() -> None:
    c = conn()
    c.executescript(SCHEMA)
    for table, cols in MIGRATIONS.items():
        have = {r[1] for r in c.execute(f"PRAGMA table_info({table})").fetchall()}
        for col, typ in cols.items():
            if col not in have:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
    c.commit()


def _decode(row: sqlite3.Row) -> dict:
    d = dict(row)
    for k, v in d.items():
        if k in JSON_COLS and isinstance(v, str) and v[:1] in "[{":
            try:
                d[k] = json.loads(v)
            except ValueError:
                pass
    return d


def q(sql: str, params: Iterable[Any] = ()) -> list[dict]:
    return [_decode(r) for r in conn().execute(sql, tuple(params)).fetchall()]


def one(sql: str, params: Iterable[Any] = ()) -> dict | None:
    r = conn().execute(sql, tuple(params)).fetchone()
    return _decode(r) if r else None


def scalar(sql: str, params: Iterable[Any] = ()):
    r = conn().execute(sql, tuple(params)).fetchone()
    return r[0] if r else None


def x(sql: str, params: Iterable[Any] = ()) -> None:
    c = conn()
    c.execute(sql, tuple(params))
    c.commit()


def _enc(v: Any) -> Any:
    if isinstance(v, (list, dict, tuple, set)):
        return json.dumps(list(v) if isinstance(v, (set, tuple)) else v, ensure_ascii=False)
    return v


def upsert(table: str, rows: list[dict] | dict, keep: Iterable[str] = ()) -> int:
    """INSERT … ON CONFLICT DO UPDATE. Columns listed in `keep` retain their existing value on update."""
    if isinstance(rows, dict):
        rows = [rows]
    if not rows:
        return 0
    c = conn()
    pk = [r[5] for r in c.execute(f"PRAGMA table_info({table})").fetchall() if r[5]]
    pkcols = [r[1] for r in sorted(c.execute(f"PRAGMA table_info({table})").fetchall(), key=lambda r: r[5]) if r[5]]
    keep = set(keep) | set(pkcols)
    for r in rows:
        cols = list(r.keys())
        upd = ", ".join(f"{k}=excluded.{k}" for k in cols if k not in keep) or f"{pkcols[0]}={pkcols[0]}"
        sql = (f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))}) "
               f"ON CONFLICT({', '.join(pkcols)}) DO UPDATE SET {upd}")
        c.execute(sql, [_enc(r[k]) for k in cols])
    c.commit()
    return len(rows)


def kv_get(k: str, default=None):
    r = one("SELECT v FROM kv WHERE k=?", (k,))
    if not r:
        return default
    try:
        return json.loads(r["v"])
    except (TypeError, ValueError):
        return r["v"]


def kv_set(k: str, v: Any) -> None:
    x("INSERT INTO kv(k,v,updated) VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated=excluded.updated",
      (k, json.dumps(v, ensure_ascii=False), now()))
