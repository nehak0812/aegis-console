"""The action lifecycle — pure functions, no network and no database.

A finding says something is wrong. An action is the record of somebody doing something about
it: who owns it, by when, what state it is in, and how it ended. The distinction that matters
is closure. An action is not resolved because a person ticked a box; it is resolved because the
finding stopped being produced on a later scan, which the platform can prove. Reopening happens
the same way, without anyone being asked.

There is no sign-in, so "who" is whatever name the console collects at the time. It is recorded
as an assertion, never as an identity.
"""
import os
from datetime import datetime, timedelta

OPEN = ("new", "acknowledged", "in_progress")
TERMINAL = ("resolved", "accepted_risk", "false_positive")
STATUSES = OPEN + TERMINAL

# Reasons are required where the status suppresses a finding that is still true: somebody is
# choosing to live with it, and that choice needs a name and a rationale attached.
NEEDS_REASON = ("accepted_risk", "false_positive")
NEEDS_EXPIRY = ("accepted_risk",)

# Forward through the working states, or out to a terminal state at any point. resolved is
# reachable by hand, but the platform sets it itself when the finding disappears.
TRANSITIONS: dict[str, tuple[str, ...]] = {
    "new": ("acknowledged", "in_progress", "resolved", "accepted_risk", "false_positive"),
    "acknowledged": ("in_progress", "resolved", "accepted_risk", "false_positive"),
    "in_progress": ("resolved", "acknowledged", "accepted_risk", "false_positive"),
    # a terminal state can be reopened by hand, and the pipeline reopens it on its own if the
    # finding comes back
    "resolved": ("new", "in_progress"),
    "accepted_risk": ("new", "in_progress"),
    "false_positive": ("new",),
}

# Days to fix, by level. Overridable per deployment: 7 / 30 / 90 is a common default, not a
# universal truth, and an organisation with a different policy should not have to fork the code.
SLA_DEFAULT = {"critical": 7, "high": 30, "medium": 90}


def sla_days(level: str) -> int | None:
    """Days allowed for a level, or None where the level is inventory rather than an action."""
    if level not in SLA_DEFAULT:
        return None
    raw = os.environ.get(f"AEGIS_SLA_{level.upper()}")
    if raw:
        try:
            return max(1, int(raw))
        except ValueError:
            pass
    return SLA_DEFAULT[level]


def due_date(level: str, created: str) -> str | None:
    """When this should be done by, from the level and the day it was raised."""
    days = sla_days(level)
    if days is None or not created:
        return None
    try:
        start = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (start + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def overdue(due: str | None, status: str, now: str) -> bool:
    """Only an open action can be overdue; a closed one that ran late is history, not a task."""
    return bool(due) and status in OPEN and due < now


def actionable(level: str) -> bool:
    """Low findings are inventory. Raising an action for each would bury the ones that matter."""
    return level in SLA_DEFAULT


def can_transition(current: str, nxt: str) -> bool:
    return nxt in TRANSITIONS.get(current, ())


def validate(current: str, nxt: str, reason: str | None = None, expires: str | None = None) -> str | None:
    """None if the change is allowed, otherwise why it is not."""
    if nxt not in STATUSES:
        return f"{nxt!r} is not a status."
    if current == nxt:
        return f"Already {nxt}."
    if not can_transition(current, nxt):
        return f"Cannot go from {current} to {nxt}."
    if nxt in NEEDS_REASON and not (reason or "").strip():
        return f"{nxt} needs a reason."
    if nxt in NEEDS_EXPIRY and not (expires or "").strip():
        return f"{nxt} needs an expiry date."
    return None


def suppressed(decision: str | None, expires: str | None, today: str) -> bool:
    """Is a finding currently suppressed by earlier feedback?

    false_positive suppresses until somebody withdraws it. accepted_risk suppresses only until
    its expiry, so an accepted risk resurfaces for a decision rather than disappearing for good.
    """
    if decision == "false_positive":
        return True
    if decision == "accepted_risk":
        return bool(expires) and expires > today
    return False


def entry(status: str, by: str | None, at: str, reason: str | None = None, note: str | None = None) -> dict:
    """One row of an action's history. Append-only; nothing here is ever rewritten."""
    e = {"status": status, "by": (by or "").strip()[:80] or "unattributed", "at": at}
    if reason:
        e["reason"] = reason.strip()[:300]
    if note:
        e["note"] = note[:200]
    return e
