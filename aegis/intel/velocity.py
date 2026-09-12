"""Speed & spread — how fast threats become real, how fast they proliferate, and by when an organisation has to act.

Three clocks, all computed from dates AEGIS already collects (no scores):
1. disclosure → exploitation: days from a CVE's publication to its CISA KEV addition ("time to exploit"; ≤ 0 = zero-day);
2. exploitation → proliferation: how many independent publishers report an incident within 72 hours of the first report;
3. exposure → action: an "act by" date on every finding, set by one named deadline rule (DL-*), shorter for the classes
   attackers are known to exploit within days.
"""
import os
import statistics
from datetime import date, datetime, timedelta, timezone

UTC = timezone.utc
LAG_BINS = [("Zero-day (at or before disclosure)", None, 0), ("1–7 days", 1, 7), ("8–30 days", 8, 30),
            ("31–90 days", 31, 90), ("91–365 days", 91, 365), ("Over a year", 366, None)]
SLA_DAYS = {"critical": int(os.environ.get("AEGIS_SLA_CRITICAL", 7)), "high": int(os.environ.get("AEGIS_SLA_HIGH", 30)),
            "medium": int(os.environ.get("AEGIS_SLA_MEDIUM", 90))}
FAST_HOURS = int(os.environ.get("AEGIS_SLA_EXPLOITED_EDGE_HOURS", 72))
# finding rules that describe something attackers act on within days — the 72-hour clock applies regardless of CVE timing
ACT_NOW = {"WEB-CLICKFIX", "IOC-BRAND-LIVE", "NRD-PHISH", "NRD-LIVE", "DW-ACCESS-14", "CMP-C2",
           "DNS-NS-REPLACED", "VUL-EPSS-SURGE", "DW-STEALER-30", "PHISH-BRAND"}
# exploited product indicated by a hostname or software fingerprint (version not confirmed): verify within a week
EXPLOITED_PRODUCT = {"SURF-EDGE-KEV", "AI-KEV-PRODUCT", "WEB-CMS-KEV"}
# context records (past disclosures, old listings, sector context, inventory) are not something to "act by"
NO_DEADLINE = ("DISC-", "INC-NAMED", "THR-", "DW-LEAK-OLD", "DW-FORUM-OLD", "BR-PUBLIC-12M", "BR-PUBLIC-OLD", "AI-INCIDENT", "TP-CONCENTRATION",
               "DW-STEALER-OLD", "DW-DDOS-30")


def _d(s) -> date | None:
    if not s:
        return None
    try:
        return date.fromisoformat(str(s)[:10])
    except ValueError:
        return None


def kev_lag(published, kev_added) -> int | None:
    """Days from CVE publication to CISA KEV addition; ≤ 0 means exploited at or before disclosure."""
    p, k = _d(published), _d(kev_added)
    return (k - p).days if p and k else None


def lag_bin(lag: int | None) -> str | None:
    if lag is None:
        return None
    for name, lo, hi in LAG_BINS:
        if (lo is None or lag >= lo) and (hi is None or lag <= hi):
            return name
    return None


def exploit_stats(rows: list[dict], min_vendor: int = 3) -> dict:
    """rows: [{cve, vendor, published, kev_added}] → median time-to-exploit, share within 7 days, zero-days, bins, trend, vendors."""
    lags = [(r, kev_lag(r.get("published"), r.get("kev_added"))) for r in rows]
    lags = [(r, x) for r, x in lags if x is not None]
    vals = [x for _, x in lags]
    bins = [{"bin": n, "n": sum(1 for x in vals if lag_bin(x) == n)} for n, _, _ in LAG_BINS]
    q = {}
    for r, x in lags:
        k = _d(r["kev_added"])
        q.setdefault(f"{k.year} Q{(k.month - 1) // 3 + 1}", []).append(x)
    ven = {}
    for r, x in lags:
        ven.setdefault((r.get("vendor") or "").strip() or "Unknown", []).append(x)
    vendors = sorted([{"vendor": v, "median": statistics.median(xs), "n": len(xs), "fast": sum(1 for x in xs if x <= 7)}
                      for v, xs in ven.items() if len(xs) >= min_vendor], key=lambda r: (r["median"], -r["n"]))
    return {"n": len(vals), "median": statistics.median(vals) if vals else None,
            "within_7d": sum(1 for x in vals if x <= 7), "zero_day": sum(1 for x in vals if x <= 0),
            "share_7d": (sum(1 for x in vals if x <= 7) / len(vals)) if vals else None, "bins": bins,
            "by_quarter": [{"quarter": k, "median": statistics.median(v), "n": len(v)} for k, v in sorted(q.items())],
            "vendors": vendors}


def _ts(s) -> datetime | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(str(s).replace("Z", "+00:00").replace(" ", "T"))
        return d if d.tzinfo else d.replace(tzinfo=UTC)
    except ValueError:
        return None


def spread(sources: list[dict]) -> dict:
    """Proliferation of one incident across independent publishers: cumulative curve, publishers within 72 hours of the
    first report, hours until the third publisher. 'Spreading' = 3+ independent publishers within 72 hours."""
    pts = sorted([(t, s.get("publisher")) for s in sources for t in [_ts(s.get("published"))] if t], key=lambda x: x[0])
    if not pts:
        return {"publishers": 0, "publishers_72h": 0, "hours_to_3": None, "spreading": False, "curve": []}
    first = pts[0][0]
    seen, curve, h3 = [], [], None
    for t, p in pts:
        if p not in seen:
            seen.append(p)
            h = round((t - first).total_seconds() / 3600, 1)
            curve.append({"h": h, "publishers": len(seen), "publisher": p})
            if len(seen) == 3:
                h3 = h
    p72 = len({p for t, p in pts if (t - first).total_seconds() <= 72 * 3600})
    return {"first": first.strftime("%Y-%m-%dT%H:%M:%SZ"), "publishers": len(seen), "publishers_72h": p72, "hours_to_3": h3,
            "spreading": p72 >= 3, "curve": curve[:40]}


def epss_surge(epss, epss_7d) -> bool:
    """Exploit likelihood jumped in a week: +0.20 absolute, or tripled to at least 0.10."""
    if epss is None or epss_7d is None:
        return False
    return (epss - epss_7d) >= 0.2 or (epss >= 0.1 and epss_7d > 0 and epss / epss_7d >= 3)


def deadline(rule_id: str, severity: str, first_seen: str | None, cves: list[str] | None, kev: dict) -> tuple[str | None, str | None]:
    """→ (act_by ISO, deadline rule id). kev: {cve: {"kev_added", "kev_due", "lag"}}. Low findings get no deadline."""
    if rule_id.startswith(NO_DEADLINE):
        return None, None
    start = _ts(first_seen) or datetime.now(UTC)
    cves = [c for c in cves or [] if c in kev]
    if rule_id in EXPLOITED_PRODUCT:
        return (start + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ"), "DL-7D-EXPLOITED"
    fast = [c for c in cves if (kev[c].get("lag") is not None and kev[c]["lag"] <= 7) or ((_d(kev[c].get("kev_added")) or date.min) >= date.today() - timedelta(days=30))]
    if fast or rule_id in ACT_NOW:
        return (start + timedelta(hours=FAST_HOURS)).strftime("%Y-%m-%dT%H:%M:%SZ"), "DL-72H"
    fresh_due = [_d(kev[c].get("kev_due")) for c in cves if kev[c].get("kev_due") and (_d(kev[c].get("kev_added")) or date.min) >= date.today() - timedelta(days=60)]
    fresh_due = [d for d in fresh_due if d]
    if fresh_due:
        due = min(min(fresh_due), (start + timedelta(days=SLA_DAYS["critical"])).date())
        return datetime(due.year, due.month, due.day, 23, 59, tzinfo=UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), "DL-CISA"
    if severity in SLA_DAYS:
        return (start + timedelta(days=SLA_DAYS[severity])).strftime("%Y-%m-%dT%H:%M:%SZ"), {"critical": "DL-7D", "high": "DL-30D", "medium": "DL-90D"}[severity]
    return None, None
