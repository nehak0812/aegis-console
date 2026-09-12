"""Supplier intelligence (daily): for each provider in supplier.PROVIDER_DOMAINS —
(a) fourth parties from the provider's own public DNS (MX, NS, TXT, SPF includes one level deep) via DNS-over-HTTPS;
(b) ownership from GLEIF (LEI, legal name, country, ultimate parent) — confident single matches only;
(c) sanctions / export-control screening of legal name, aliases and ultimate parent against the US Consolidated Screening
    List and the UK Sanctions List, ENTITIES only (individuals are dropped before anything is stored);
(d) CISA Secure by Design pledge signers.
Nothing is fetched from a provider's own website. A part that fails keeps the previous real value (with its own checked
date) or stays None; nothing is invented, and the source is marked DEGRADED."""
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from aegis import db, net
from aegis.intel import supplier as S
from aegis.registry import Source, collector

DOH = ["https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"]
GLEIF = "https://api.gleif.org/api/v1"
CSL_URL = "https://data.trade.gov/downloadable_consolidated_screening_list/v1/consolidated.csv"
UK_URL = "https://sanctionslist.fcdo.gov.uk/docs/UK-Sanctions-List.csv"
SBD_URL = "https://www.cisa.gov/securebydesign/pledge/secure-design-pledge-signers"
ENTITY_KEY = "supplier_screen_entities"  # parsed entity rows only — never the full files
_RTYPE = {"NS": 2, "MX": 15, "TXT": 16}


def _ago(**kw) -> str:
    return (datetime.now(timezone.utc) - timedelta(**kw)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _catalogue():
    from aegis.intel.providers import CATALOGUE, KINDS, Catalogue
    rows = db.q("SELECT * FROM provider")
    if not rows:  # fresh database: use the shipped catalogue as-is
        rows = [{"name": p["name"], "category": p["category"], "aliases": p.get("aliases") or [],
                 "patterns": {k: p.get(k) or [] for k in KINDS}, "observable": 0 if p.get("observable") is False else 1} for p in CATALOGUE]
    return Catalogue(rows)


# ------------------------------------------------------------------ (a) DNS
def _doh(name: str, rtype: str) -> tuple[list[str] | None, str]:
    """Answers of one type (None when every resolver failed) and the query URL kept as evidence."""
    for base in DOH:
        try:
            js = net.get_json(base, params={"name": name, "type": rtype}, headers={"Accept": "application/dns-json"}, timeout=12, retries=1)
        except Exception:
            continue
        if not js or js.get("Status") not in (0, 3):  # 0 NOERROR, 3 NXDOMAIN; SERVFAIL etc. -> next resolver
            continue
        ans = [a.get("data", "") for a in js.get("Answer", []) if a.get("type") == _RTYPE[rtype]]
        return [a.strip('"').replace('" "', "") for a in ans], f"{base}?{urlencode({'name': name, 'type': rtype})}"
    return None, ""


def _dns_records(domain: str) -> dict | None:
    got = {t: _doh(domain, t) for t in ("MX", "NS", "TXT")}
    if all(v[0] is None for v in got.values()):
        return None
    txt = got["TXT"][0] or []
    rec = {"domain": domain, "mx": [m.split()[-1].rstrip(".").lower() for m in got["MX"][0] or [] if m],
           "ns": [n.rstrip(".").lower() for n in got["NS"][0] or [] if n], "txt": txt, "spf": S.spf_includes(txt),
           "spf_nested": {}, "failed": [t for t, v in got.items() if v[0] is None],
           "sources": {t.lower(): v[1] for t, v in got.items() if v[1]}}
    for inc in rec["spf"][:10]:  # SPF includes one level deep
        t, url = _doh(inc, "TXT")
        if t is None:
            rec["failed"].append(f"TXT {inc}")
            continue
        rec["spf_nested"][inc] = S.spf_includes(t)
        rec["sources"][f"spf:{inc}"] = url
    return rec


# ------------------------------------------------------------------ (b) GLEIF
def _record(lei: str) -> dict:
    js = net.get_json(f"{GLEIF}/lei-records/{lei}", timeout=30) or {}
    a = (js.get("data") or {}).get("attributes") or {}
    ent = a.get("entity") or {}
    return {"lei": lei, "name": (ent.get("legalName") or {}).get("name"), "country": (ent.get("legalAddress") or {}).get("country"),
            "hq_country": (ent.get("headquartersAddress") or {}).get("country"), "entity_status": ent.get("status"),
            "registration_status": (a.get("registration") or {}).get("status")}


def _ownership(legal: str, country: str) -> dict:
    params = {"field": "entity.legalName", "q": legal}
    search_url = f"{GLEIF}/fuzzycompletions?{urlencode(params)}"
    cands: dict[str, str] = {}
    for d in (net.get_json(f"{GLEIF}/fuzzycompletions", params=params, timeout=30) or {}).get("data", []):
        lei = ((((d.get("relationships") or {}).get("lei-records") or {}).get("data")) or {}).get("id")
        if lei:
            cands[lei] = (d.get("attributes") or {}).get("value") or ""
    if "," not in legal:  # GLEIF filters treat commas as OR-lists; exact filter only for comma-free names
        js = net.get_json(f"{GLEIF}/lei-records", params={"filter[entity.legalName]": legal, "page[size]": 10}, timeout=30) or {}
        for d in js.get("data", []):
            cands[d["id"]] = ((((d.get("attributes") or {}).get("entity") or {}).get("legalName")) or {}).get("name") or ""
    nn = S.norm_name(legal)
    recs = [_record(lei) for lei, n in list(cands.items()) if S.norm_name(n) == nn][:6]
    lei, why = S.gleif_choose(legal, country, recs)
    res = {"lei": lei, "legal_name": None, "country": None, "parent": None, "ownership_status": "matched" if lei else "no confident match",
           "ownership_note": why, "sources": {"gleif_search": search_url}}
    if not lei:
        return res
    me = next(r for r in recs if r["lei"] == lei)
    res.update(legal_name=me["name"], country=me["country"])
    rel_url = f"{GLEIF}/lei-records/{lei}/ultimate-parent-relationship"
    res["sources"].update(gleif=f"{GLEIF}/lei-records/{lei}", gleif_record=f"https://search.gleif.org/#/record/{lei}", gleif_parent=rel_url)
    rel = net.get_json(rel_url, timeout=30, ok_404=True)
    r = (((rel or {}).get("data") or {}).get("attributes") or {}).get("relationship") or {}
    pid = (r.get("endNode") or {}).get("id")
    if pid and pid != lei and r.get("status", "ACTIVE") == "ACTIVE":
        p = _record(pid)
        res["parent"] = {"lei": pid, "name": p["name"], "country": p["country"], "url": f"https://search.gleif.org/#/record/{pid}",
                         "source": f"{GLEIF}/lei-records/{pid}"}
    else:
        res["ownership_note"] += "; no ultimate parent reported to GLEIF"
    return res


# ------------------------------------------------------------------ (c) screening lists
def _screen_lists(degraded: list[str]) -> dict:
    cache = db.kv_get(ENTITY_KEY, {}) or {}
    changed = False
    for key, url, parse in (("us", CSL_URL, S.parse_csl), ("uk", UK_URL, S.parse_uk)):
        c = cache.get(key) or {}
        if c.get("fetched", "") > _ago(hours=20):
            continue
        try:
            text = net.get(url, timeout=240, retries=1).content.decode("utf-8-sig", errors="replace")
            rows, dropped = parse(text)
            if len(rows) < 500:
                raise ValueError(f"only {len(rows)} entity rows parsed — format changed?")
            cache[key] = {"fetched": db.now(), "url": url, "entities": len(rows), "dropped_non_entity": dropped, "rows": rows}
            changed = True
        except Exception as e:
            degraded.append(f"screening {key}: {type(e).__name__}: {str(e)[:160]}" + (f" (kept list fetched {c['fetched']})" if c else ""))
    if changed:
        db.kv_set(ENTITY_KEY, cache)
    return cache


def _names(name: str, e: dict, cat, parent: bool) -> list[str]:
    """Names to match for a provider: its catalogue name, aliases (>=5 chars normalised, so 'OCI' / 'AEM' never screen),
    configured and GLEIF legal names, corporate-group names, and (for screening) the ultimate parent."""
    out = [name] + [a for a in cat.names_of(name)[1:] if len(S.norm_name(a)) >= 5]
    out += [(S.PROVIDER_LEGAL.get(name) or ("",))[0], e.get("legal_name")] + S.GROUP_NAMES.get(name, [])
    if parent:
        out.append((e.get("parent") or {}).get("name"))
    return [n for n in dict.fromkeys(out) if n]


@collector(Source(
    id="supplier_intel", name="Supplier intelligence (fourth parties · ownership · screening)", category="Registry",
    publisher="Public DNS (Google / Cloudflare DoH) · GLEIF · US ITA Consolidated Screening List · UK FCDO Sanctions List · CISA",
    homepage="https://www.cisa.gov/securebydesign/pledge", url=CSL_URL, cadence_min=1440,
    licence="Free public data: DoH resolvers · GLEIF (CC0) · US ITA CSL · UK Sanctions List · CISA",
    feeds=[{"publisher": "UK FCDO", "url": UK_URL}, {"publisher": "CISA", "url": SBD_URL},
           {"publisher": "GLEIF", "url": f"{GLEIF}/lei-records"}, {"publisher": "Google Public DNS", "url": DOH[0]}],
    notes="For ~110 major providers: the providers THEY rely on (fourth parties, from their own public MX/NS/TXT/SPF), GLEIF "
          "ownership and ultimate parent, exact-name screening of legal name / aliases / parent against sanctions and export-"
          "control ENTITY lists (individuals dropped; a screening signal for human review), and CISA Secure by Design pledge status."))
def collect_supplier_intel() -> int:
    t0 = time.time()
    now = db.now()
    cat = _catalogue()
    prev = db.kv_get("supplier_intel", {}) or {}
    degraded: list[str] = []
    out: dict[str, dict] = {}
    for name, domain in S.PROVIDER_DOMAINS.items():
        p = prev.get(name) or {}
        out[name] = {"provider": name, "category": cat.category(name) or p.get("category"), "domain": domain,
                     "dns": p.get("dns"), "fourth_parties": p.get("fourth_parties"),
                     "lei": p.get("lei"), "legal_name": p.get("legal_name"), "country": p.get("country"), "parent": p.get("parent"),
                     "ownership_status": p.get("ownership_status"), "ownership_note": p.get("ownership_note"),
                     "sanctions": p.get("sanctions"), "sanctions_lists": p.get("sanctions_lists"),
                     "sbd_pledge": p.get("sbd_pledge"), "sbd_match": p.get("sbd_match"),
                     "checked": dict(p.get("checked") or {}), "sources": dict(p.get("sources") or {})}

    # (a) fourth parties
    domains = sorted(set(S.PROVIDER_DOMAINS.values()))
    with ThreadPoolExecutor(4) as ex:
        recs = dict(zip(domains, ex.map(_dns_records, domains)))
    dns_failed = [d for d, r in recs.items() if r is None]
    for name, e in out.items():
        r = recs.get(e["domain"])
        if r is None:
            continue
        e["dns"] = {"mx": r["mx"][:10], "ns": r["ns"][:10], "spf_includes": r["spf"][:15],
                    "spf_nested": {k: v[:15] for k, v in r["spf_nested"].items()}, "failed_queries": r["failed"]}
        e["fourth_parties"] = S.fourth_parties(name, r, cat)
        e["checked"]["dns"] = now
        e["sources"]["dns"] = {k: v for k, v in r["sources"].items() if not k.startswith("spf:")}
    if len(dns_failed) > 0.2 * len(domains):
        degraded.append(f"dns: {len(dns_failed)}/{len(domains)} domains unresolved")

    # (b) ownership — refreshed weekly per provider (legal structure changes slowly; GLEIF is paced by net.py)
    cache: dict[str, dict] = {}
    g_err = 0
    for name, e in out.items():
        legal = S.PROVIDER_LEGAL.get(name)
        if not legal:
            e.update(ownership_status="no legal name configured", ownership_note=None)
            continue
        if (e["checked"].get("ownership") or "") > _ago(days=7) and e.get("ownership_status") in ("matched", "no confident match"):
            continue
        try:
            if legal not in cache:
                cache[legal] = _ownership(*legal)
            res = dict(cache[legal])
        except Exception as ex:
            g_err += 1
            print("[supplier_intel] gleif", name, type(ex).__name__, ex)
            continue
        e["sources"].update(res.pop("sources"))
        e.update(res)
        e["checked"]["ownership"] = now
    if g_err > 0.2 * max(1, len(S.PROVIDER_LEGAL)):
        degraded.append(f"gleif: {g_err} lookups failed")

    # (c) sanctions / export-control screening — entities only
    lists = _screen_lists(degraded)
    rows = [r for k in ("us", "uk") for r in (lists.get(k) or {}).get("rows") or []]
    if rows:
        used = [{"list": k, "url": v["url"], "fetched": v["fetched"]} for k, v in lists.items() if v.get("rows")]
        by_key: dict[str, set] = {}
        all_names = []
        for name, e in out.items():
            for n in _names(name, e, cat, parent=True):
                by_key.setdefault(S.norm_name(n), set()).add(name)
                all_names.append(n)
        hits = S.screen(all_names, rows)
        for e in out.values():
            e["sanctions"] = []
            e["sanctions_lists"] = used
            e["checked"]["sanctions"] = now
            e["sources"].update(us_csl=CSL_URL, uk_sanctions=UK_URL)
        for h in hits:
            for name in by_key.get(h["key"], ()):
                if not any((x["list"], x["id"]) == (h["list"], h["id"]) for x in out[name]["sanctions"]):
                    out[name]["sanctions"].append({k: v for k, v in h.items() if k != "key"})

    # (d) CISA Secure by Design pledge
    try:
        page = net.get_curl(SBD_URL, timeout=60).decode("utf-8", errors="replace")  # CISA's CDN rejects python TLS clients
        signers = S.parse_sbd(page)
        if len(signers) < 50:
            raise ValueError(f"only {len(signers)} signers parsed — page layout changed?")
        idx = {S.norm_name(s): s for s in signers}
        for name, e in out.items():
            hit = next((idx[k] for k in (S.norm_name(n) for n in _names(name, e, cat, parent=False)) if k in idx), None)
            e.update(sbd_pledge=bool(hit), sbd_match=hit)
            e["checked"]["sbd"] = now
            e["sources"]["sbd"] = SBD_URL
    except Exception as ex:
        signers = None
        degraded.append(f"sbd: {type(ex).__name__}: {str(ex)[:160]}")

    db.kv_set("supplier_intel", out)
    counts = {
        "providers": len(out), "with_dns": sum(1 for e in out.values() if e["fourth_parties"] is not None),
        "with_fourth_parties": sum(1 for e in out.values() if e["fourth_parties"]),
        "fourth_party_links": sum(len(e["fourth_parties"] or []) for e in out.values()),
        "with_lei": sum(1 for e in out.values() if e["lei"]), "with_parent": sum(1 for e in out.values() if e["parent"]),
        "sanctions_matches": sum(len(e["sanctions"] or []) for e in out.values()),
        "providers_with_sanctions_match": sum(1 for e in out.values() if e["sanctions"]),
        "sbd_signers": sum(1 for e in out.values() if e["sbd_pledge"]), "sbd_signers_on_page": len(signers) if signers else None,
        "screen_entities": {k: v.get("entities") for k, v in lists.items()},
        "screen_dropped_non_entity": {k: v.get("dropped_non_entity") for k, v in lists.items()},
        "dns_failed_domains": dns_failed,
    }
    db.kv_set("supplier_intel_meta", {"run_at": now, "duration_s": round(time.time() - t0, 1), "counts": counts, "degraded": degraded,
                                      "sources": {"doh": DOH, "gleif": GLEIF, "us_csl": CSL_URL, "uk_sanctions": UK_URL, "sbd": SBD_URL},
                                      "screening_note": S.SCREEN_NOTE})
    print(f"[supplier_intel] {counts['providers']} providers · {counts['with_fourth_parties']} with fourth parties · "
          f"{counts['with_parent']} with GLEIF parent · {counts['sanctions_matches']} screening matches · {counts['sbd_signers']} SbD signers"
          + (f" · DEGRADED: {'; '.join(degraded)}" if degraded else ""))
    if degraded:  # results of healthy parts are stored above; the registry records the source as DEGRADED
        raise RuntimeError("supplier_intel degraded — " + "; ".join(degraded))
    return len(out)
