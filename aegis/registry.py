"""Collector registry. Each collector declares its source metadata; the scheduler runs it on its cadence
and records health, item counts and errors in the `source` / `run_log` tables (shown on the Sources page)."""
import time
import traceback
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse

from aegis import db
from aegis.guard import allow_host


@dataclass
class Source:
    id: str
    name: str
    category: str            # Threat intel | Vulnerabilities | Attack surface | Dark web | Chatter | Research | News | Government | Registry | AI risk | Service status
    publisher: str
    homepage: str
    cadence_min: int
    licence: str             # e.g. "Public domain", "CC0", "CC BY 4.0", "Free API — terms apply"
    access: str = "Open"     # Open | Free key | Consent
    url: str = ""
    feeds: list = field(default_factory=list)
    notes: str = ""


@dataclass
class Job:
    source: Source
    fn: Callable[[], int]
    enabled: bool = True


JOBS: dict[str, Job] = {}


def collector(src: Source, enabled: bool = True):
    def wrap(fn: Callable[[], int]):
        JOBS[src.id] = Job(src, fn, enabled)
        for u in [src.url, *[f.get("url", "") if isinstance(f, dict) else f for f in src.feeds]]:
            if u:
                allow_host(urlparse(u).netloc)
        return fn
    return wrap


def sync_sources() -> None:
    for j in JOBS.values():
        s = j.source
        db.upsert("source", {
            "id": s.id, "name": s.name, "category": s.category, "publisher": s.publisher, "url": s.url,
            "homepage": s.homepage, "cadence_min": s.cadence_min, "licence": s.licence, "access": s.access,
            "feeds": s.feeds, "notes": s.notes,
            **({} if j.enabled else {"status": "DISABLED"}),
        }, keep=("status", "last_run", "last_ok", "last_error", "items_last_run", "items_total"))
        if not j.enabled:
            db.x("UPDATE source SET status='DISABLED' WHERE id=?", (s.id,))
        elif db.scalar("SELECT status FROM source WHERE id=?", (s.id,)) == "DISABLED":
            db.x("UPDATE source SET status='PENDING' WHERE id=?", (s.id,))


def run(source_id: str) -> int:
    job = JOBS[source_id]
    started = db.now()
    t0 = time.time()
    db.x("UPDATE source SET status='RUNNING', last_run=? WHERE id=?", (started, source_id))
    try:
        n = int(job.fn() or 0)
        status = "OK" if n > 0 else "EMPTY"
        db.x("UPDATE source SET status=?, last_ok=?, last_error=NULL, items_last_run=?, "
             "items_total=COALESCE(items_total,0)+? WHERE id=?", (status, db.now(), n, n, source_id))
        db.x("INSERT INTO run_log(source_id,started,finished,ok,items,error) VALUES(?,?,?,?,?,NULL)",
             (source_id, started, db.now(), 1, n))
        print(f"[collect] {source_id}: {n} items in {time.time() - t0:.1f}s")
        return n
    except Exception as e:  # a failing source degrades, it never fabricates
        msg = f"{type(e).__name__}: {e}"[:500]
        db.x("UPDATE source SET status='DEGRADED', last_error=? WHERE id=?", (msg, source_id))
        db.x("INSERT INTO run_log(source_id,started,finished,ok,items,error) VALUES(?,?,?,?,?,?)",
             (source_id, started, db.now(), 0, 0, msg))
        print(f"[collect] {source_id} FAILED: {msg}")
        traceback.print_exc(limit=2)
        return 0
