"""Actions ("Prevent", reconciled with production v2.0.1 + Prevent).

Every Critical, High or Medium finding becomes a tracked action: owner role and playbook, a due date (the finding's act-by date
from its deadline rule), a status lifecycle with history, and closure the platform proves itself — when the finding is no
longer observed on a later scan the action is resolved with `verified_closed_at`; if it comes back, it is reopened.
`false_positive` suppresses the finding; `accepted_risk` suppresses it until its expiry. Table and field names match the
production deployment so its existing actions and history carry over.
"""
import statistics
from collections import Counter
from datetime import datetime, timedelta, timezone

from aegis import db
from aegis.playbooks import OWNERS, playbook

STATUSES = ["new", "acknowledged", "in_progress", "resolved", "accepted_risk", "false_positive"]
OPEN = {"new", "acknowledged", "in_progress"}
ALLOWED = {
    "new": {"acknowledged", "in_progress", "resolved", "accepted_risk", "false_positive"},
    "acknowledged": {"new", "in_progress", "resolved", "accepted_risk", "false_positive"},
    "in_progress": {"acknowledged", "resolved", "accepted_risk", "false_positive"},
    "resolved": {"acknowledged", "in_progress"},
    "accepted_risk": {"acknowledged", "in_progress"},
    "false_positive": {"new", "acknowledged"},
}
NEEDS_REASON = {"accepted_risk", "false_positive"}
RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sla_due(f: dict) -> str:
    from aegis.intel.velocity import SLA_DAYS
    start = _parse(f.get("first_seen")) or datetime.now(timezone.utc)
    return _iso(start + timedelta(days=SLA_DAYS.get(f.get("severity"), 90)))


def suppressed(now: str | None = None) -> dict[str, str]:
    """source_key → kind for findings the analysts marked false positive, or accepted as a risk that has not yet expired."""
    now = now or db.now()
    out = {}
    for r in db.q("SELECT source_key, kind, expires FROM feedback"):
        if r["kind"] == "false_positive" or (r["kind"] == "accepted_risk" and (r.get("expires") or "") > now):
            out[r["source_key"]] = r["kind"]
    return out


def _note(a: dict, status: str, by: str, note: str | None = None, at: str | None = None) -> list:
    h = list(a.get("history") or [])
    h.append({"status": status, "by": by, "at": at or db.now(), **({"note": note} if note else {})})
    return h[-50:]


def build_actions() -> int:
    """Pipeline stage after findings: create, update, verify-close and reopen actions."""
    now = db.now()
    findings = db.q("SELECT id, org_id, rule_id, title, severity, confidence, act_by, first_seen FROM finding "
                    "WHERE severity IN ('critical','high','medium')")
    acts = {a["source_key"]: a for a in db.q("SELECT * FROM action")}
    sup = suppressed(now)
    seen, out = set(), []
    for f in findings:
        seen.add(f["id"])
        pb = playbook(f["rule_id"]) or {}
        due = f.get("act_by") or _sla_due(f)
        a = acts.get(f["id"])
        if not a:
            out.append({"id": f["id"], "org_id": f["org_id"], "source_kind": "finding", "source_key": f["id"], "rule_id": f["rule_id"],
                        "title": f["title"], "level": f["severity"], "confidence": f.get("confidence"), "owner_role": pb.get("owner"),
                        "owner": None, "status": "new", "due": due, "created": now, "updated": now, "verified_closed_at": None, "reopened": 0,
                        "history": [{"status": "new", "by": "aegis", "at": now, "note": "Raised from a finding."}]})
            continue
        upd = {**a, "title": f["title"], "level": f["severity"], "confidence": f.get("confidence"), "due": due, "updated": now,
               "owner_role": a.get("owner_role") or pb.get("owner")}
        if a["status"] == "resolved":
            upd.update(status="new", reopened=(a.get("reopened") or 0) + 1, verified_closed_at=None,
                       history=_note(a, "new", "aegis", "Reopened: the finding was observed again on the latest scan.", now))
        elif a["status"] in ("accepted_risk", "false_positive") and f["id"] not in sup:
            upd.update(status="new", history=_note(a, "new", "aegis", "Re-opened: the accepted-risk period ended.", now))
        out.append(upd)
    for key, a in acts.items():
        if key in seen or key in sup or a["status"] not in OPEN:
            continue
        out.append({**a, "status": "resolved", "verified_closed_at": now, "updated": now,
                    "history": _note(a, "resolved", "aegis", "Verified closed: the finding is no longer observed on the latest scan.", now)})
    db.upsert("action", out)
    return len(out)


def set_status(aid: str, status: str, by: str | None = None, reason: str | None = None, expires: str | None = None,
               owner: str | None = None) -> tuple[bool, str, dict | None]:
    """Move one action along. Returns (ok, message, action). Rejections say why."""
    a = db.one("SELECT * FROM action WHERE id=?", (aid,))
    if not a:
        return False, "No such action.", None
    by = (by or "").strip() or "unnamed analyst"
    if status == a["status"] and not owner:
        return False, f"The action is already {status.replace('_', ' ')}.", a
    if status != a["status"]:
        if status not in STATUSES:
            return False, f"Unknown status {status!r}. Allowed: {', '.join(STATUSES)}.", a
        if status not in ALLOWED.get(a["status"], set()):
            return False, f"Cannot move from {a['status'].replace('_', ' ')} to {status.replace('_', ' ')}.", a
        if status in NEEDS_REASON and not (reason or "").strip():
            return False, "A reason is required for this status.", a
        if status == "accepted_risk":
            exp = _parse(expires)
            if not exp or exp <= datetime.now(timezone.utc):
                return False, "Accepted risk needs an expiry date in the future.", a
            expires = _iso(exp)
    now = db.now()
    upd = {**a, "updated": now}
    if owner is not None:
        upd["owner"] = owner.strip() or None
    if status != a["status"]:
        upd["status"] = status
        upd["history"] = _note(a, status, by, (reason or "").strip() or None, now)
        if status in NEEDS_REASON:
            db.upsert("feedback", {"source_key": a["source_key"], "org_id": a["org_id"], "rule_id": a["rule_id"], "kind": status,
                                   "reason": reason.strip(), "expires": expires, "by": by, "at": now})
        else:
            db.x("DELETE FROM feedback WHERE source_key=?", (a["source_key"],))
    db.upsert("action", upd)
    return True, "Updated.", db.one("SELECT * FROM action WHERE id=?", (aid,))


def decorate(a: dict, now: str | None = None) -> dict:
    now = now or db.now()
    return {**a, "open": a["status"] in OPEN, "overdue": a["status"] in OPEN and bool(a.get("due")) and a["due"] < now,
            "playbook": playbook(a.get("rule_id"))}


def queue(org: str | None = None, level: str | None = None, status: str | None = None, owner_role: str | None = None,
          overdue: bool = False, open_only: bool = True, limit: int = 400, orgs: set | None = None, days: int = 30) -> dict:
    """`days` sets the window for the closure KPIs (verified closed, median days to close); open/overdue are the current state."""
    now = db.now()
    rows = [decorate(a, now) for a in db.q("SELECT * FROM action")]
    if orgs is not None:
        rows = [a for a in rows if a["org_id"] in orgs]
    base = rows
    if org:
        rows = [a for a in rows if a["org_id"] == org]
    if level:
        rows = [a for a in rows if a["level"] == level]
    if status:
        rows = [a for a in rows if a["status"] == status]
    elif open_only:
        rows = [a for a in rows if a["open"]]
    if owner_role:
        rows = [a for a in rows if a["owner_role"] == owner_role]
    if overdue:
        rows = [a for a in rows if a["overdue"]]
    rows.sort(key=lambda a: (not a["overdue"], RANK.get(a["level"], 9), a.get("due") or "9"))
    opened = [a for a in base if a["open"]]
    closed30 = [a for a in base if a.get("verified_closed_at") and a["verified_closed_at"] >= _iso(datetime.now(timezone.utc) - timedelta(days=days))]
    raised_w = sum(1 for a in base if (a.get("created") or "") >= _iso(datetime.now(timezone.utc) - timedelta(days=days)))
    ttc = [((_parse(a["verified_closed_at"]) - _parse(a["created"])).total_seconds() / 86400) for a in closed30 if _parse(a["created"])]
    kpi = {"open": len(opened), "by_level": dict(Counter(a["level"] for a in opened)), "overdue": sum(1 for a in opened if a["overdue"]),
           "verified_closed_30d": len(closed30), "median_days_to_close": round(statistics.median(ttc), 1) if ttc else None,
           "window": days, "raised_window": raised_w,  # verified_closed_30d holds the selected window (name kept for production compatibility)
           "by_owner": dict(Counter(a["owner_role"] or "Unassigned" for a in opened)),
           "by_status": dict(Counter(a["status"] for a in base))}
    return {"actions": rows[:limit], "total": len(rows), "kpi": kpi, "statuses": STATUSES, "owner_roles": OWNERS}
