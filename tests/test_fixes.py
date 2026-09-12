"""Vendor fixes and their uptake: fix evidence from CVE records / KEV notes, and the exposure history that observes a fix."""
import importlib
import os
import tempfile

import pytest


@pytest.fixture()
def fresh_db(monkeypatch):
    d = tempfile.mkdtemp()
    monkeypatch.setenv("AEGIS_DB", os.path.join(d, "t.sqlite"))
    from aegis import db
    importlib.reload(db)
    db._local.__dict__.clear()
    db.init()
    yield db
    db._local.__dict__.clear()


def test_fix_from_record_fixture():
    from aegis.collectors.vulns import fix_from_record
    record_fixture = {"containers": {
        "cna": {"references": [{"url": "https://vendor.example/advisory/1", "tags": ["vendor-advisory"]},
                               {"url": "https://vendor.example/patch/1", "tags": ["patch"]},
                               {"url": "https://blog.example/writeup", "tags": ["technical-description"]}],
                "affected": [{"product": "Gateway", "versions": [{"version": "0", "status": "affected", "lessThan": "14.1.2"}]}]},
        "adp": [{"references": [{"url": "https://cisa.example/mitigation", "tags": ["mitigation"]}]}]}}
    f = fix_from_record(record_fixture)
    assert f["patch"] and f["advisory"] and f["mitigation"]
    assert f["fixed_versions"] == ["Gateway before 14.1.2"]
    branch = fix_from_record({"containers": {"cna": {"affected": [{"product": "ADC", "versions": [
        {"version": "14.1", "status": "affected", "lessThan": "66.59", "versionType": "patch"}]}]}}})
    assert branch["fixed_versions"] == ["ADC 14.1 before 66.59"]
    assert all("writeup" not in u["url"] for u in f["urls"])
    none = fix_from_record({"containers": {"cna": {"references": [{"url": "https://x.example", "tags": []}]}}})
    assert not none["patch"] and not none["advisory"] and none["urls"] == []


def test_kev_note_urls_exclude_nvd():
    from aegis.collectors.vulns import kev_note_urls
    notes_fixture = "https://sec.vendor.example/adv/2026-01 ; https://nvd.nist.gov/vuln/detail/CVE-2026-0001"
    assert kev_note_urls(notes_fixture) == ["https://sec.vendor.example/adv/2026-01"]


def test_exposure_history_observes_fix_and_reappearance(fresh_db):
    db = fresh_db
    from aegis.intel import pipeline
    db.upsert("org", {"id": "o1", "name": "Org", "deep_scanned": "2026-01-01T00:00:00Z"})
    db.upsert("asset", {"org_id": "o1", "kind": "ip", "value": "192.0.2.10", "attrs": {"vulns": ["CVE-2026-0001"], "owned": True},
                        "first_seen": "2025-12-01T00:00:00Z"})
    pipeline.track_cve_exposure()
    r = db.one("SELECT * FROM cve_exposure WHERE org_id='o1'")
    assert r["cve"] == "CVE-2026-0001" and r["fixed_at"] is None and r["first_seen"] == "2025-12-01T00:00:00Z"
    db.upsert("asset", {"org_id": "o1", "kind": "ip", "value": "192.0.2.10", "attrs": {"vulns": [], "owned": True}})
    pipeline.track_cve_exposure()                                    # no newer scan of the organisation yet → not claimed as fixed
    assert db.one("SELECT fixed_at FROM cve_exposure")["fixed_at"] is None
    db.x("UPDATE org SET deep_scanned='2099-01-01T00:00:00Z'")
    pipeline.track_cve_exposure()                                    # a newer scan no longer reports it → fix observed
    assert db.one("SELECT fixed_at FROM cve_exposure")["fixed_at"]
    db.upsert("asset", {"org_id": "o1", "kind": "ip", "value": "192.0.2.10", "attrs": {"vulns": ["CVE-2026-0001"], "owned": True}})
    pipeline.track_cve_exposure()                                    # reported again → reopened
    assert db.one("SELECT fixed_at FROM cve_exposure")["fixed_at"] is None


def test_init_upgrades_an_older_narrower_table(monkeypatch):
    """Production may already have action / feedback tables from its own build: init adds the columns this version writes."""
    import sqlite3
    path = os.path.join(tempfile.mkdtemp(), "old.sqlite")
    old = sqlite3.connect(path)
    old.execute("CREATE TABLE feedback (source_key TEXT PRIMARY KEY, org_id TEXT, legacy_note TEXT)")
    old.execute("INSERT INTO feedback VALUES ('k1', 'o1', 'kept')")
    old.commit()
    old.close()
    monkeypatch.setenv("AEGIS_DB", path)
    from aegis import db
    importlib.reload(db)
    db._local.__dict__.clear()
    db.init()
    cols = {r["name"] for r in db.q("PRAGMA table_info(feedback)")}
    assert {"rule_id", "kind", "reason", "expires", "by", "at", "legacy_note"} <= cols
    assert db.one("SELECT legacy_note FROM feedback WHERE source_key='k1'")["legacy_note"] == "kept"
    db._local.__dict__.clear()


def test_shared_infrastructure_is_not_counted(fresh_db):
    db = fresh_db
    from aegis.intel import pipeline
    db.upsert("org", {"id": "o1", "name": "Org", "deep_scanned": "2026-01-01T00:00:00Z"})
    db.upsert("asset", {"org_id": "o1", "kind": "ip", "value": "198.51.100.7", "attrs": {"vulns": ["CVE-2026-0002"], "shared": True}})
    pipeline.track_cve_exposure()
    assert db.scalar("SELECT count(*) FROM cve_exposure") == 0
