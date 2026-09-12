"""Domain, certificate and routing hardening — passive. For a batch of surface-scanned organisations (oldest first):

· DNS over HTTPS (the same resolvers as the surface scan): DKIM keys on common selectors, TLS-RPT, SPF lookup count
  (recursive), nameserver providers, CAA sets up the name tree, and A/MX of a capped set of lookalike candidates;
· registry RDAP (server from the IANA bootstrap): expiry date and transfer-lock status of the primary domain;
· RIPEstat RPKI validation of the prefixes the surface scan found announced by ASNs registered to the organisation;
· certificate transparency (crt.sh rows the surface scan already fetched): expiring certificates on live hostnames,
  certificates issued after the observed CAA policy.

Nothing here contacts the organisation's hosts. Results are stored per organisation in org.hardening (JSON); a failed
check stores its error — never a guessed value — and a run where most checks fail marks the source DEGRADED.
Rules and findings: aegis/intel/hardening.py."""
import ipaddress
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from aegis import db, net
from aegis.collectors.surface import doh_status, private
from aegis.guard import host_allowed
from aegis.intel import hardening as hd
from aegis.registry import Source, collector

BATCH = int(os.environ.get("AEGIS_HARDENING_BATCH", 40))
RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
RDAP_FALLBACK = {"de": "https://rdap.denic.de/"}  # DENIC is not in the IANA bootstrap (checked Sept 2026); .ie / .eu have no RDAP
MAX_CAA_QUERIES = 60        # CAA lookups per organisation per run (apex first, then the name tree of recent certificates)
MAX_EXPIRY_LOOKUPS = 30     # liveness checks of hostnames whose certificate is about to expire
MAX_PREFIXES = 60           # RPKI validations per organisation
MAX_LOOKALIKE_QUERIES = 100  # A + MX lookups per organisation (≈50 candidates)
LOOKALIKE_HITS = 10         # stop once this many registered lookalikes are found
_IPV4 = re.compile(r"\d+\.\d+\.\d+\.\d+")


def _dns(name: str, rtype: str) -> list[str] | None:
    """Answers, [] for no record / NXDOMAIN, None if no resolver answered."""
    ans, _, ok = doh_status(name, rtype)
    return ans if ok else None


def _pmap(fn, items, workers: int = 6) -> list:
    with ThreadPoolExecutor(workers) as ex:
        return list(ex.map(fn, items))


# ------------------------------------------------------------------ checks
def check_dns(d: str) -> dict:
    q = {f"DKIM:{s}": (f"{s}._domainkey.{d}", "TXT") for s in hd.DKIM_SELECTORS}
    q.update({"TLSRPT": (f"_smtp._tls.{d}", "TXT"), "NS": (d, "NS"), "MX": (d, "MX"), "TXT": (d, "TXT")})
    res = dict(zip(q, _pmap(lambda nt: _dns(*nt), list(q.values()))))
    if all(res[k] is None for k in ("NS", "MX", "TXT")):
        return {"error": "DNS over HTTPS unavailable", "checked": db.now()}
    dkim = {k.split(":", 1)[1]: v for k, v in res.items() if k.startswith("DKIM:")}
    mx_raw = res["MX"] or []
    mx = [m.split()[-1].rstrip(".").lower() for m in mx_raw if m.split()]
    ns = sorted({n.rstrip(".").lower() for n in res["NS"] or [] if n})
    spf = hd.spf_record(res["TXT"] or [])
    cache = {d: res["TXT"]}

    def resolver(name):
        if name not in cache:
            cache[name] = _dns(name, "TXT")
        if cache[name] is None:
            raise LookupError(name)
        return cache[name]
    trace: dict = {}
    n = hd.spf_lookup_count(spf, resolver, domain=d, trace=trace) if spf else None
    return {"checked": db.now(), "dkim_present": hd.dkim_present(dkim),
            "dkim_selectors_found": sorted(s for s, v in dkim.items() if v and hd.dkim_record(v)),
            "tlsrpt": None if res["TLSRPT"] is None else hd.tlsrpt_present(res["TLSRPT"]),
            "ns": ns[:12] if res["NS"] is not None else None, "ns_providers": hd.ns_providers(ns),
            "mx": [m for m in mx if m][:8] if res["MX"] is not None else None, "null_mx": bool(mx) and not any(mx),
            "spf": (spf or "")[:500] or None, "spf_lookups": n,
            "spf_trace": {k: (v[:30] if isinstance(v, list) else v) for k, v in trace.items()}}


def rdap_server(d: str) -> str | None:
    tld = d.lower().rstrip(".").rsplit(".", 1)[-1]
    try:
        for tlds, urls in net.cached_json(RDAP_BOOTSTRAP, 24).get("services", []):
            if tld in [t.lower() for t in tlds]:
                return next((u for u in urls if u.startswith("https://")), urls[0] if urls else None)
    except Exception as e:
        if tld not in RDAP_FALLBACK:
            raise RuntimeError(f"IANA RDAP bootstrap unavailable: {e}") from e
    return RDAP_FALLBACK.get(tld)


def check_rdap(d: str) -> dict:
    now = db.now()
    base = rdap_server(d)
    if not base:
        return {"error": f"no RDAP service for .{d.rsplit('.', 1)[-1]}", "coverage": True, "checked": now}
    url = base.rstrip("/") + "/domain/" + d
    if not host_allowed(urlparse(url).netloc):
        return {"error": f"RDAP server {urlparse(url).netloc} is not on the passive allow-list", "coverage": True, "checked": now}
    r = net.get(url, headers={"Accept": "application/rdap+json"}, timeout=25, retries=1, ok_404=True)
    if r is None:
        return {"error": "domain not found at the registry RDAP server", "coverage": True, "checked": now, "url": url}
    if not host_allowed(r.url.host):  # net.py follows redirects; refuse data from a host outside the allow-list
        return {"error": f"RDAP redirected to {r.url.host} (not allow-listed); response discarded", "checked": now}
    return {"checked": now, "url": url, **hd.rdap_domain_status(r.json())}


def check_rpki(org_id: str) -> dict:
    now = db.now()
    pairs = set()
    for a in db.q("SELECT value, attrs FROM asset WHERE org_id=? AND kind='prefix'", (org_id,)):
        m = re.search(r"announced by AS(\d+)", ((a.get("attrs") or {}).get("provenance") or ""))
        if m and ":" not in a["value"]:
            pairs.add((a["value"], m.group(1)))

    def key(p):
        try:
            n = ipaddress.ip_network(p[0], strict=False)
            return (n.prefixlen, int(n.network_address))
        except ValueError:
            return (99, 0)
    pairs = sorted(pairs, key=key)[:MAX_PREFIXES]  # widest (aggregate) announcements first
    if not pairs:
        return {"checked": now, "results": [], "note": "no prefixes announced by an ASN registered to the organisation"}

    def one(p):
        prefix, asn = p
        try:
            js = net.get_json("https://stat.ripe.net/data/rpki-validation/data.json",
                              params={"resource": f"AS{asn}", "prefix": prefix, "sourceapp": "aegis"}, timeout=30, retries=1)
            dat = (js or {}).get("data") or {}
            if not dat.get("status"):
                return None
            return {"prefix": prefix, "asn": asn, "status": dat["status"],
                    "roas": [{k: r.get(k) for k in ("origin", "prefix", "max_length", "validity")} for r in (dat.get("validating_roas") or [])[:10]]}
        except Exception:
            return None
    res = _pmap(one, pairs, 4)
    ok = [r for r in res if r]
    if not ok:
        return {"error": "RIPEstat RPKI validation unavailable", "checked": now}
    return {"checked": now, "results": ok, "failed": len(res) - len(ok)}


def check_certs(d: str, dom_attrs: dict, caa_seen: dict) -> tuple[dict, dict, dict]:
    """→ (certs section, caa_by_domain observed now, updated caa_seen {domain: {policy, first_seen}})."""
    now = db.now()
    if "ct_certs" not in dom_attrs:
        return ({"error": "no crt.sh certificate details yet (stored by the next surface scan)", "coverage": True, "checked": now},
                {}, caa_seen)
    recent = dom_attrs.get("ct_certs") or []
    # CAA up the name tree: apex first, then the parents of names on the most recent certificates
    doms = [d]
    for c in recent:
        for n in c.get("names") or []:
            doms.extend(hd.caa_chain(n))
    doms = list(dict.fromkeys(doms))[:MAX_CAA_QUERIES]
    caa_by_domain = {}
    for x, recs in zip(doms, _pmap(lambda x: _dns(x, "CAA"), doms)):
        if recs is None:
            continue  # lookup failed: not observed (names depending on it are "not evaluable")
        pol = hd.caa_policy(recs)
        caa_by_domain[x] = [f'0 {p.split(" ", 1)[0]} "{p.split(" ", 1)[1] if " " in p else ""}"' for p in pol]
        old = caa_seen.get(x)
        if not pol:
            caa_seen.pop(x, None)
        elif not old or old.get("policy") != pol:  # a changed policy is a new policy: its clock restarts
            caa_seen[x] = {"policy": pol, "first_seen": now}
    if doms and not caa_by_domain:
        raise RuntimeError("CAA lookups failed")
    first = {x: v["first_seen"] for x, v in caa_seen.items() if x in caa_by_domain}
    floor = min(first.values(), default=None)
    evaluable = [c for c in recent if floor and (c.get("not_before") or "")[:19] > floor[:19]][:60]
    # certificates about to expire: count only hostnames that resolve now
    exp = dom_attrs.get("ct_expiring") or {}
    hosts = list(exp)[:MAX_EXPIRY_LOOKUPS]
    live = {}
    for h, a in zip(hosts, _pmap(lambda h: _dns(h, "A"), hosts)):
        ips = [x for x in a or [] if _IPV4.fullmatch(x) and not private(x)]
        if ips:
            live[h] = {**exp[h], "ips": ips[:3]}
    return ({"checked": now, "recent": evaluable, "expiring_live": live, "expiring_checked": len(hosts)}, caa_by_domain, caa_seen)


def check_lookalikes(o: dict, d: str, org_ns, org_mx, org_ips) -> dict:
    now = db.now()
    cands = hd.lookalike_permutations(d, o.get("country"), cap=60, exclude=o.get("domains") or [])
    hits, queries, answered = [], 0, 0
    for i in range(0, len(cands), 10):
        chunk = cands[i:i + 10]
        if queries + 2 * len(chunk) > MAX_LOOKALIKE_QUERIES:
            break
        a = _pmap(lambda c: _dns(c, "A"), chunk)
        mx = _pmap(lambda c: _dns(c, "MX"), chunk)
        queries += 2 * len(chunk)
        for c, ra, rm in zip(chunk, a, mx):
            if ra is None and rm is None:
                continue
            answered += 1
            ips = [x for x in ra or [] if _IPV4.fullmatch(x) and not private(x)]
            mxh = [h for h in (m.split()[-1].rstrip(".").lower() for m in rm or [] if m.split()) if h]  # null MX "0 ." = no mail
            if ips or mxh:
                hits.append({"domain": c, "a": ips[:4], "mx": mxh[:4]})
        if len(hits) >= LOOKALIKE_HITS:
            break
    if cands and not answered:
        return {"error": "DNS over HTTPS unavailable for lookalike checks", "checked": now}
    for h, ns in zip(hits, _pmap(lambda h: _dns(h["domain"], "NS"), hits)):
        h["ns"] = sorted({x.rstrip(".").lower() for x in ns or []})[:4]
        h["defensive"] = hd.lookalike_defensive(h, d, org_ns, org_mx, org_ips)
    return {"checked": now, "candidates": len(cands), "queried": queries // 2, "hits": hits[:LOOKALIKE_HITS]}


# ------------------------------------------------------------------ per organisation
def scan_org(o: dict) -> tuple[dict, list[str]]:
    d = o["domain"].lower()
    prev = o.get("hardening") or {}
    if isinstance(prev, str):
        prev = json.loads(prev)
    dom = db.one("SELECT attrs FROM asset WHERE org_id=? AND kind='domain' AND value=?", (o["id"], d)) or {}
    dattrs = dom.get("attrs") or {}
    hyg = dattrs.get("hygiene") or {}
    org_ips = {ip for r in db.q("SELECT attrs FROM asset WHERE org_id=? AND kind='hostname' AND value IN (?, ?)", (o["id"], d, f"www.{d}"))
               for ip in (r.get("attrs") or {}).get("ips") or []}
    h = {"domain": d, "checked": db.now(), "caa_seen": dict(prev.get("caa_seen") or {})}
    errors = []

    def run(key, fn):
        try:
            h[key] = fn()
        except Exception as e:
            h[key] = {"error": f"{type(e).__name__}: {e}"[:200], "checked": db.now()}
        if h[key].get("error") and not h[key].get("coverage"):
            errors.append(f"{key}: {h[key]['error']}")
    run("dns", lambda: check_dns(d))
    if not h["dns"].get("error") and h["dns"].get("dkim_present") is not True and hyg.get("dkim_selectors"):
        # the surface scan found a key on a provider selector (e.g. mandrill, pp1, mimecast…): DKIM is published
        h["dns"]["dkim_present"] = True
        h["dns"]["dkim_selectors_found"] = sorted(set(h["dns"].get("dkim_selectors_found") or []) | set(hyg["dkim_selectors"]))
    run("rdap", lambda: check_rdap(d))
    run("rpki", lambda: check_rpki(o["id"]))

    def certs():
        sec, h["caa_by_domain"], h["caa_seen"] = check_certs(d, dattrs, dict(h["caa_seen"]))
        return sec
    run("certs", certs)
    h["caa_first_seen"] = {x: v["first_seen"] for x, v in h["caa_seen"].items()}
    dns = h.get("dns") or {}
    run("lookalikes", lambda: check_lookalikes(o, d, dns.get("ns") or hyg.get("ns") or [], dns.get("mx") or hyg.get("mx") or [], org_ips))
    return h, errors


@collector(Source(
    id="hardening", name="Domain, certificate & routing hardening (passive)", category="Attack surface",
    publisher="Google & Cloudflare DNS-over-HTTPS · registry RDAP (IANA bootstrap) · crt.sh CT logs · RIPEstat RPKI validation",
    homepage="https://data.iana.org/rdap/", url=RDAP_BOOTSTRAP, cadence_min=1440,
    licence="DoH, registry RDAP, crt.sh and RIPEstat: free public services",
    feeds=[{"publisher": "IANA RDAP bootstrap", "url": RDAP_BOOTSTRAP},
           {"publisher": "RIPEstat RPKI validation", "url": "https://stat.ripe.net/data/rpki-validation/data.json"},
           {"publisher": "crt.sh", "url": "https://crt.sh/"}, {"publisher": "Google DoH", "url": "https://dns.google/resolve"}],
    notes=f"Daily, {BATCH} surface-scanned organisations per run (oldest first): DKIM / TLS-RPT / SPF lookups / nameserver "
          "providers, domain expiry and transfer lock (RDAP), RPKI of owned prefixes, expiring and CAA-unauthorised "
          "certificates, registered lookalikes. Public records only — nothing is sent to the organisation's hosts."))
def collect_hardening() -> int:
    orgs = db.q("SELECT id, name, domain, domains, country, hardening FROM org WHERE domain IS NOT NULL AND deep_scanned IS NOT NULL "
                "ORDER BY hardening IS NOT NULL, json_extract(hardening, '$.checked') LIMIT ?", (BATCH,))

    def one(o):
        try:
            h, errs = scan_org(o)
        except Exception as e:
            return 0, [f"{o['domain']}: {type(e).__name__}: {e}"]
        db.x("UPDATE org SET hardening=? WHERE id=?", (json.dumps(h, ensure_ascii=False), o["id"]))
        return 1, [f"{o['domain']} {e}" for e in errs]
    with ThreadPoolExecutor(2) as ex:
        res = list(ex.map(one, orgs))
    done = sum(r[0] for r in res)
    errs = [e for r in res for e in r[1]]
    for e in errs[:20]:
        print("[hardening]", e)
    # a source that mostly failed is DEGRADED (registry.run records the error); partial results already stored are real
    if orgs and (done == 0 or len(errs) > 5 * len(orgs) / 2):
        raise RuntimeError(f"{len(errs)} hardening checks failed across {len(orgs)} organisations; e.g. {errs[0] if errs else 'n/a'}")
    return done
