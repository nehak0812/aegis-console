"""Prevent (v2.1, reconciled with production): confidence, action lifecycle, verified closure, suppression, playbooks, controls."""
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest


@pytest.fixture()
def fresh_db(monkeypatch):
    d = tempfile.mkdtemp()
    monkeypatch.setenv("AEGIS_DB", os.path.join(d, "t.sqlite"))
    import importlib
    from aegis import db
    importlib.reload(db)
    db._local.__dict__.clear()
    db.init()
    from aegis import actions
    importlib.reload(actions)
    yield db, actions
    db._local.__dict__.clear()


def _finding_fixture(db, fid="f1", sev="high", rule="HYG-DMARC-NONE"):
    db.upsert("finding", {"id": fid, "org_id": "o1", "category": "hygiene", "title": "t", "detail": "", "severity": sev, "rule_id": rule,
                          "evidence_url": "https://example.test", "source_id": "surface", "observed": db.now(), "first_seen": db.now(),
                          "last_seen": db.now(), "data": {}, "act_by": "2030-01-01T00:00:00Z", "deadline_rule": "DL-30D", "confidence": "confirmed"})


def test_confidence_cap():
    from aegis import confidence as c
    f = c.apply({"rule_id": "DW-ACCESS-14", "severity": "critical", "data": {}})
    assert f["confidence"] == "unconfirmed" and f["severity"] == "high" and f["data"]["capped_from"] == "critical"
    g = c.apply({"rule_id": "CMP-C2", "severity": "critical", "data": {}})
    assert g["confidence"] == "confirmed" and g["severity"] == "critical"
    assert c.confidence("SURF-EDGE-KEV") == "unconfirmed" and c.confidence("SURF-RISKY-PORT") == "confirmed"


def test_action_created_verified_closed_and_reopened(fresh_db):
    db, actions = fresh_db
    _finding_fixture(db)
    actions.build_actions()
    a = db.one("SELECT * FROM action WHERE id='f1'")
    assert a["status"] == "new" and a["due"] == "2030-01-01T00:00:00Z" and a["owner_role"] == "Email & DNS administration"
    db.x("DELETE FROM finding")                    # the finding disappears on a later scan → the platform proves the fix
    actions.build_actions()
    a = db.one("SELECT * FROM action WHERE id='f1'")
    assert a["status"] == "resolved" and a["verified_closed_at"]
    _finding_fixture(db)                           # it comes back → reopened
    actions.build_actions()
    a = db.one("SELECT * FROM action WHERE id='f1'")
    assert a["status"] == "new" and a["reopened"] == 1 and a["verified_closed_at"] is None


def test_transitions_and_reasons(fresh_db):
    db, actions = fresh_db
    _finding_fixture(db)
    actions.build_actions()
    ok, msg, _ = actions.set_status("f1", "false_positive", "tester")
    assert not ok and "reason" in msg.lower()
    ok, msg, _ = actions.set_status("f1", "flying", "tester")
    assert not ok
    ok, _, a = actions.set_status("f1", "acknowledged", "tester")
    assert ok and a["history"][-1]["by"] == "tester"
    ok, msg, _ = actions.set_status("f1", "accepted_risk", "tester", "compensating control")
    assert not ok and "expiry" in msg.lower()


def test_suppression_and_expiry(fresh_db):
    db, actions = fresh_db
    _finding_fixture(db)
    actions.build_actions()
    future = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    ok, _, _ = actions.set_status("f1", "accepted_risk", "tester", "vendor fix pending", future)
    assert ok and "f1" in actions.suppressed()
    db.x("UPDATE feedback SET expires='2000-01-01T00:00:00Z' WHERE source_key='f1'")  # expired → no longer suppressed
    assert "f1" not in actions.suppressed()
    actions.build_actions()
    assert db.one("SELECT status FROM action WHERE id='f1'")["status"] == "new"
    ok, _, _ = actions.set_status("f1", "false_positive", "tester", "not our host")
    assert ok and actions.suppressed()["f1"] == "false_positive"


def test_every_organisation_rule_has_a_playbook():
    from aegis import playbooks, rating
    org_rules = [r["id"] for r in rating.catalogue() if r["applies_to"] == "organisation"]
    cov = playbooks.coverage(org_rules)
    assert cov["missing"] == [], cov["missing"]


def test_replace_set_keeps_readers_whole(fresh_db):
    """replace_set swaps a table's contents without an empty window, and only inside the given scope."""
    db, _ = fresh_db
    _finding_fixture(db, "a")
    _finding_fixture(db, "b")
    db.upsert("dependency", [{"org_id": "o1", "vendor": "V1", "evidence": "e1", "source_id": "catalogue"},
                             {"org_id": "o1", "vendor": "V2", "evidence": "e2", "source_id": "surface"}])
    rows = [dict(db.one("SELECT * FROM finding WHERE id='b'")), {**dict(db.one("SELECT * FROM finding WHERE id='b'")), "id": "c"}]
    db.replace_set("finding", rows)
    assert {r["id"] for r in db.q("SELECT id FROM finding")} == {"b", "c"}
    db.replace_set("dependency", [], "source_id='catalogue'")
    assert [r["vendor"] for r in db.q("SELECT vendor FROM dependency")] == ["V2"]   # other sources untouched


def test_redirect_hops_are_allow_listed():
    """net.py checks every request, including redirect hops: off-site hops to non-allow-listed hosts are refused."""
    import httpx
    from aegis import net
    tok = net._origin.set("rdap.verisign.com")
    try:
        net._redirect_guard(httpx.Request("GET", "https://rdap.verisign.com/com/v1/domain/example.com"))   # allow-listed
        with pytest.raises(Exception):
            net._redirect_guard(httpx.Request("GET", "https://attacker-controlled.example.net/steal"))
    finally:
        net._origin.reset(tok)


def test_prevent_controls_measure():
    from aegis.prevent import measure
    m = measure({"spf": {"record": "v=spf1 include:_spf.google.com -all", "all": "-"}, "dmarc": {"p": "reject"}, "dnssec": False,
                 "mta_sts": False, "tls_rpt": True, "caa": ["0 issue \"digicert.com\""], "dkim_selectors": [], "ns": ["ns-1.awsdns-01.com", "ns-2.awsdns-02.net"]})
    assert m["spf_strict"] is True and m["dmarc_enforced"] is True and m["tls_rpt"] is True and m["caa"] is True
    assert m["ns_redundant"] is False          # both AWS
    assert m["domain_locked"] is None           # not measured without RDAP
    m2 = measure({"spf": {"record": "v=spf1 ~all", "all": "~"}, "dmarc": {"p": "none"}, "ns": ["a.ns.cloudflare.com", "ns1.p01.dynect.net"]})
    assert m2["spf_strict"] is False and m2["dmarc_enforced"] is False and m2["ns_redundant"] is True
