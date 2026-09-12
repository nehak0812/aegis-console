"""Preventive controls, measured passively from public DNS and RDAP (reconciled with production's /api/prevent).

Each control is adopted (True), not adopted (False) or not measured (None) per organisation. Adoption is shown as
percentages across the estate and by sector — never as a score.
"""
from collections import Counter, defaultdict

from aegis import db

CONTROLS = [
    {"id": "dmarc_enforced", "label": "DMARC enforced (p=quarantine or reject)", "prevents": "Email spoofing"},
    {"id": "spf_strict", "label": "SPF ends in -all", "prevents": "Email spoofing"},
    {"id": "dkim", "label": "DKIM key published", "prevents": "Email tampering"},
    {"id": "mta_sts", "label": "MTA-STS policy", "prevents": "Mail interception"},
    {"id": "tls_rpt", "label": "TLS reporting", "prevents": "Undetected mail TLS failure"},
    {"id": "dnssec", "label": "DNSSEC signed", "prevents": "DNS forgery"},
    {"id": "caa", "label": "CAA record", "prevents": "Certificate mis-issuance"},
    {"id": "ns_redundant", "label": "DNS served by more than one provider", "prevents": "Single-provider outage"},
    {"id": "domain_locked", "label": "Registrar transfer lock", "prevents": "Domain hijack"},
]
NS_FAMILY = (("awsdns", "AWS"), ("azure-dns", "Azure"), ("cloudflare", "Cloudflare"), ("nsone", "NS1"), ("ultradns", "UltraDNS"),
             ("akam", "Akamai"), ("googledomains", "Google"), ("google.com", "Google"), ("dynect", "Oracle Dyn"), ("markmonitor", "MarkMonitor"),
             ("cscdns", "CSC"), ("verisigndns", "Verisign"))


def _ns_provider(host: str) -> str:
    h = host.lower().rstrip(".")
    for tok, name in NS_FAMILY:
        if tok in h:
            return name
    parts = h.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else h


def _spf_all(spf) -> str | None:
    if isinstance(spf, dict):
        a = spf.get("all")  # surface.spf_parse keeps only the qualifier: "-", "~", "+" or "?"
        if a:
            a = str(a)
            return a if a.endswith("all") else f"{a}all"
        rec = spf.get("record") or ""
    else:
        rec = spf or ""
    toks = [t for t in str(rec).split() if t.endswith("all")]
    return toks[-1] if toks else None


def measure(h: dict, hard: dict | None = None) -> dict:
    """h = the surface scan's hygiene dict; hard = the hardening record (DKIM / NS / RDAP), when collected."""
    hard = hard or {}
    dm = h.get("dmarc") or {}
    ns = h.get("ns") or []
    spf_all = _spf_all(h.get("spf"))
    hdns = hard.get("dns") or {}   # the hardening collector: dns.dkim_present, rdap.locked (see collectors/hardening.py)
    dkim = bool(h.get("dkim_selectors")) or hdns.get("dkim_present") is True
    lock = hard.get("locked") if "locked" in hard else (hard.get("rdap") or {}).get("locked")
    return {
        "dmarc_enforced": (dm.get("p") in ("quarantine", "reject")) if h.get("dmarc") is not None or "dmarc" in h else None,
        "spf_strict": (spf_all == "-all") if h.get("spf") else False if "spf" in h else None,
        "dkim": dkim if ("dkim_selectors" in h or hard) else None,
        "mta_sts": bool(h.get("mta_sts")) if "mta_sts" in h else None,
        "tls_rpt": bool(h.get("tls_rpt")) if "tls_rpt" in h else None,
        "dnssec": bool(h.get("dnssec")) if "dnssec" in h else None,
        "caa": bool(h.get("caa")) if "caa" in h else None,
        "ns_redundant": (len({_ns_provider(n) for n in ns}) > 1) if ns else None,
        "domain_locked": lock if isinstance(lock, bool) else None,
    }


def _hardening_by_org() -> dict:
    """The hardening collector's per-organisation record: the org.hardening JSON column (kv fallbacks for older builds)."""
    try:
        out = {r["id"]: r["hardening"] for r in db.q("SELECT id, hardening FROM org WHERE hardening IS NOT NULL") if isinstance(r.get("hardening"), dict)}
        if out:
            return out
    except Exception:  # column not present on an older database
        pass
    m = db.kv_get("hardening") or {}
    if isinstance(m, dict) and m:
        return m
    out = {}
    for r in db.q("SELECT k, v FROM kv WHERE k LIKE 'hardening:%'"):
        try:
            import json
            out[r["k"].split(":", 1)[1]] = json.loads(r["v"])
        except (ValueError, TypeError):
            pass
    return out


def estate() -> dict:
    orgs = {o["id"]: o for o in db.q("SELECT id, sector FROM org")}
    hard = _hardening_by_org()
    per = {}
    for a in db.q("SELECT org_id, attrs FROM asset WHERE kind='domain'"):
        h = (a.get("attrs") or {}).get("hygiene")
        if h is not None and a["org_id"] in orgs:
            per[a["org_id"]] = measure(h, hard.get(a["org_id"]))
    controls = []
    for c in CONTROLS:
        vals = {oid: m[c["id"]] for oid, m in per.items()}
        measured = {k: v for k, v in vals.items() if v is not None}
        by_sector = defaultdict(Counter)
        for oid, v in measured.items():
            s = orgs[oid].get("sector") or "Unknown"
            by_sector[s]["total"] += 1
            by_sector[s]["adopted"] += bool(v)
        adopted = sum(1 for v in measured.values() if v)
        controls.append({**c, "adopted": adopted, "total": len(measured), "unmeasured": len(vals) - len(measured),
                         "pct": round(100 * adopted / len(measured)) if measured else None,
                         "by_sector": {s: {"adopted": v["adopted"], "total": v["total"], "pct": round(100 * v["adopted"] / v["total"])}
                                       for s, v in sorted(by_sector.items()) if v["total"]}})
    return {"scanned": len(per), "controls": controls, "per_org": per}


def for_org(oid: str, est: dict | None = None) -> dict:
    est = est or estate()
    o = db.one("SELECT sector FROM org WHERE id=?", (oid,)) or {}
    mine = est["per_org"].get(oid)
    sector = o.get("sector") or "Unknown"
    out = []
    for c in est["controls"]:
        sec = c["by_sector"].get(sector) or {}
        out.append({"id": c["id"], "label": c["label"], "prevents": c["prevents"], "measured": bool(mine) and mine.get(c["id"]) is not None,
                    "has": (mine or {}).get(c["id"]), "estate_pct": c["pct"], "sector": sector, "sector_pct": sec.get("pct"), "sector_n": sec.get("total")})
    return {"scanned": bool(mine), "sector": sector, "controls": out}
