"""Autonomous operation: every source runs on its own cadence, the intelligence pipeline re-runs after collection,
and a catch-up pass on start-up brings stale sources current. No human action is needed to keep data live."""
import random
import threading
import time
from datetime import datetime, timedelta, timezone

from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.schedulers.background import BackgroundScheduler

from aegis import db, registry
from aegis.intel import pipeline

# importing registers the collectors
from aegis.collectors import (actors, ai_risk, ai_stack, blocklists, chatter, darkweb, feeds, filings, gleif,  # noqa: F401
                              hardening, phishing, reports, status, surface, universe, vulns)

CATCH_UP_ORDER = ["universe", "actors", "cisa_kev", "first_epss", "ransomlook", "ransomware_live", "ransomware_groups", "hibp",
                  "forum_claims", "sec_8k", "pub_news", "pub_gov", "pub_vendor", "psirt", "pub_analyst", "ddosia", "status_pages",
                  "hn", "mastodon", "reddit", "mit_ai_risk", "ai_incidents", "cloud_ranges", "exploit_refs", "cve_details",
                  "deepdarkcti", "gleif", "surface", "compromised_ips", "hudsonrock",
                  # v2.2 AI-era threats
                  "mitre_atlas", "ai_stack", "pub_ai_sec", "pub_influence", "anthropic_reports", "misp_osint", "ioc_repos",
                  "phish_feeds", "nrd_whoisds", "ioc_liveness", "offensive_ai", "epss_trend",
                  "hardening"]  # domain / certificate / routing hardening — last: it reads what surface stored
from aegis.collectors import supplier_intel  # noqa: F401,E402 — fourth parties, GLEIF ownership, entity screening, SbD pledge
CATCH_UP_ORDER.append("supplier_intel")  # daily; runs after the org scans so the console has provider context

_sched: BackgroundScheduler | None = None
_pipe_lock = threading.Lock()


def run_pipeline() -> None:
    if not _pipe_lock.acquire(blocking=False):
        return
    try:
        pipeline.run_all()
    finally:
        _pipe_lock.release()


def _stale(src_id: str) -> bool:
    s = db.one("SELECT last_ok, cadence_min, status FROM source WHERE id=?", (src_id,))
    if not s or not s["last_ok"]:
        return True
    last = datetime.fromisoformat(s["last_ok"].replace("Z", "+00:00"))
    return datetime.now(timezone.utc) - last > timedelta(minutes=s["cadence_min"] or 60)


def catch_up() -> None:
    db.x("UPDATE source SET status='PENDING' WHERE status='RUNNING'")
    ran = 0
    for sid in CATCH_UP_ORDER:
        job = registry.JOBS.get(sid)
        if job and job.enabled and _stale(sid):
            registry.run(sid)
            ran += 1
            if sid in ("sec_8k", "pub_news", "surface"):  # early pipeline passes so the console fills quickly
                run_pipeline()
    run_pipeline()
    print(f"[scheduler] catch-up complete ({ran} sources refreshed)")


def start() -> None:
    global _sched
    db.init()
    registry.sync_sources()
    from aegis.intel.providers import sync_catalogue
    sync_catalogue()
    _sched = BackgroundScheduler(executors={"default": ThreadPoolExecutor(4)},
                                 job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 3600})
    for sid, job in registry.JOBS.items():
        if not job.enabled:
            continue
        cad = max(10, job.source.cadence_min)
        first = datetime.now() + timedelta(minutes=cad, seconds=random.randint(0, 120))
        _sched.add_job(registry.run, "interval", args=[sid], minutes=cad, id=sid, next_run_time=first)
    _sched.add_job(run_pipeline, "interval", minutes=15, id="pipeline", next_run_time=datetime.now() + timedelta(minutes=15))
    _sched.start()
    threading.Thread(target=catch_up, daemon=True, name="catch-up").start()


def trigger(source_id: str) -> None:
    threading.Thread(target=lambda: (registry.run(source_id), run_pipeline()), daemon=True).start()


def scan_now(org_id: str) -> None:
    def go():
        o = db.one("SELECT id, name, domain FROM org WHERE id=?", (org_id,))
        if o and o["domain"]:
            surface.store_scan(o, surface.scan_org(o))
        run_pipeline()
    threading.Thread(target=go, daemon=True).start()


def running() -> list[str]:
    return [r["id"] for r in db.q("SELECT id FROM source WHERE status='RUNNING'")]
