"""External attack surface — passive only. For each monitored organisation:
DNS hygiene (SPF, DMARC, DNSSEC, MTA-STS, CAA, DKIM) · software & third parties from DNS · public hostnames from
Certificate Transparency · cloud environment attribution (official provider IP ranges) · open ports / CPEs / CVEs
from Shodan InternetDB (index lookup, never a scan) · edge / remote-access products · owned IP space.
Nothing here connects to the organisation's own hosts — only public resolvers and third-party indexes."""
import bisect
import ipaddress
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from aegis import CACHE_DIR, db, net
from aegis.guard import allow_host
from aegis.intel import fingerprints as fp
from aegis.intel import prevent
from aegis.intel.entities import norm
from aegis.registry import Source, collector

DOH = ["https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"]
CLOUD_FILE = os.path.join(CACHE_DIR, "cloud_ranges.json")
RPKI_MAX = 25          # prefixes validated per organisation per scan (one RIPEstat call each)
LOOKALIKE_MAX = 40     # generated variants resolved per organisation per scan (two DNS lookups each)
INTERESTING = re.compile(r"^(www|mail|webmail|smtp|vpn|sslvpn|remote|portal|sso|login|auth|id|idp|adfs|sts|owa|autodiscover|"
                         r"citrix|gateway|gw|api|apps?|jira|confluence|git|gitlab|jenkins|ftp|sftp|mft|transfer|secure|"
                         r"connect|access|ra|rdweb|extranet|partner|dev|test|staging|uat|admin|cpanel|intranet|shop|store|"
                         r"careers|investor|ir|support|help|status|cdn|static)[\d-]*\.", re.I)


# ------------------------------------------------------------------ DNS over HTTPS
def doh(name: str, rtype: str) -> tuple[list[str], bool]:
    for base in DOH:
        try:
            js = net.get_json(base, params={"name": name, "type": rtype}, headers={"Accept": "application/dns-json"}, timeout=12, retries=1)
        except Exception:
            continue
        if js is None:
            continue
        want = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28, "DS": 43, "CAA": 257}.get(rtype)
        ans = [a.get("data", "") for a in js.get("Answer", []) if want is None or a.get("type") == want]
        return [a.strip('"').replace('" "', "") for a in ans], bool(js.get("AD"))
    return [], False


# ------------------------------------------------------------------ cloud ranges
def _load_cloud() -> tuple[list, list]:
    if not os.path.exists(CLOUD_FILE):
        return [], []
    with open(CLOUD_FILE) as f:
        rows = json.load(f)
    rows.sort(key=lambda r: r[0])
    return rows, [r[0] for r in rows]


_CLOUD: tuple[list, list] | None = None


def cloud_lookup(ip: str):
    global _CLOUD
    if _CLOUD is None:
        _CLOUD = _load_cloud()
    rows, starts = _CLOUD
    try:
        v = int(ipaddress.ip_address(ip))
    except ValueError:
        return None
    i = bisect.bisect_right(starts, v) - 1
    # ranges can nest; walk back a few candidates for the most specific containing range
    best = None
    for j in range(i, max(-1, i - 40), -1):
        s, e, prov, svc = rows[j]
        if s <= v <= e and (best is None or (e - s) < (best[1] - best[0])):
            best = rows[j]
    return {"provider": best[2], "service": best[3]} if best else None


@collector(Source(
    id="cloud_ranges", name="Cloud & CDN provider IP ranges", category="Attack surface",
    publisher="AWS · Microsoft Azure · Google Cloud · Oracle · Cloudflare · Fastly · DigitalOcean", homepage="https://ip-ranges.amazonaws.com/ip-ranges.json",
    url="https://ip-ranges.amazonaws.com/ip-ranges.json", cadence_min=1440, licence="Published by each provider for public use",
    feeds=[{"publisher": "Google Cloud", "url": "https://www.gstatic.com/ipranges/cloud.json"},
           {"publisher": "Cloudflare", "url": "https://www.cloudflare.com/ips-v4"},
           {"publisher": "Oracle", "url": "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json"},
           {"publisher": "Fastly", "url": "https://api.fastly.com/public-ip-list"},
           {"publisher": "Azure", "url": "https://www.microsoft.com/en-us/download/details.aspx?id=56519"},
           {"publisher": "DigitalOcean", "url": "https://www.digitalocean.com/geo/google.csv"}],
    notes="Official range files used to attribute an organisation's public IPs to cloud environments (which provider, which service)."))
def collect_cloud() -> int:
    out = []

    def add(cidr, prov, svc):
        try:
            n = ipaddress.ip_network(cidr.strip(), strict=False)
        except ValueError:
            return
        if n.version == 4:
            out.append([int(n.network_address), int(n.broadcast_address), prov, svc or ""])
    try:
        for p in net.cached_json("https://ip-ranges.amazonaws.com/ip-ranges.json", 24)["prefixes"]:
            add(p["ip_prefix"], "AWS", p.get("service"))
    except Exception as e:
        print("[cloud] aws", e)
    try:
        for p in net.cached_json("https://www.gstatic.com/ipranges/cloud.json", 24)["prefixes"]:
            if "ipv4Prefix" in p:
                add(p["ipv4Prefix"], "Google Cloud", p.get("service"))
    except Exception as e:
        print("[cloud] gcp", e)
    try:
        for line in net.cached("https://www.cloudflare.com/ips-v4", 24).split():
            add(line, "Cloudflare", "CDN")
    except Exception as e:
        print("[cloud] cloudflare", e)
    try:
        for r in net.cached_json("https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json", 24)["regions"]:
            for c in r.get("cidrs", []):
                add(c["cidr"], "Oracle Cloud", r.get("region"))
    except Exception as e:
        print("[cloud] oracle", e)
    try:
        for a in net.cached_json("https://api.fastly.com/public-ip-list", 24).get("addresses", []):
            add(a, "Fastly", "CDN")
    except Exception as e:
        print("[cloud] fastly", e)
    try:
        page = net.cached("https://www.microsoft.com/en-us/download/details.aspx?id=56519", 24 * 3)
        m = re.search(r"https://download\.microsoft\.com/download/[^\"']+ServiceTags_Public_\d+\.json", page)
        if m:
            for v in net.cached_json(m.group(0), 24 * 3, timeout=180)["values"]:
                if "." in v["name"]:  # skip regional duplicates
                    continue
                for c in v["properties"].get("addressPrefixes", []):
                    add(c, "Microsoft Azure", v["name"])
    except Exception as e:
        print("[cloud] azure", e)
    try:
        for line in net.cached("https://www.digitalocean.com/geo/google.csv", 24).splitlines():
            if line and not line.startswith("#"):
                add(line.split(",")[0], "DigitalOcean", "")
    except Exception as e:
        print("[cloud] do", e)
    with open(CLOUD_FILE, "w") as f:
        json.dump(out, f)
    global _CLOUD
    _CLOUD = None
    stats = {}
    for r in out:
        stats[r[2]] = stats.get(r[2], 0) + 1
    db.kv_set("cloud_range_stats", stats)
    return len(out)


# ------------------------------------------------------------------ helpers
def private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_reserved or a.is_loopback or a.is_multicast or a.is_link_local or a in ipaddress.ip_network("100.64.0.0/10")
    except ValueError:
        return True


def spf_parse(txts: list[str]) -> dict | None:
    rec = next((t for t in txts if t.lower().startswith("v=spf1")), None)
    if not rec:
        return None
    toks = rec.split()
    allq = next((t[:-3] or "+" for t in toks if t.lower().endswith("all")), None)
    return {"record": rec[:500], "all": allq, "includes": [t.split(":", 1)[1] for t in toks if t.lower().startswith(("include:", "redirect="[:8])) and ":" in t],
            "ip4": [t.split(":", 1)[1] for t in toks if t.lower().startswith("ip4:")],
            "lookups": sum(1 for t in toks if re.match(r"(?i)^[+~?-]?(include:|a\b|a:|mx\b|mx:|ptr|exists:|redirect=)", t))}


def ct_hostnames(domain: str) -> tuple[list[str], str, list[dict]]:
    """Public hostnames from Certificate Transparency, plus the certificate metadata
    on the same response (issuer and expiry) — used for CRT-* without a second request,
    which matters because crt.sh is paced at one call every 3 seconds."""
    names: set[str] = set()
    certs: list[dict] = []
    src = ""
    try:
        js = net.get_json("https://crt.sh/", params={"q": f"%.{domain}", "output": "json", "exclude": "expired"}, timeout=60, retries=1)
        for r in js or []:
            for n in (r.get("name_value") or "").split("\n"):
                names.add(n.strip().lower().lstrip("*."))
            if len(certs) < 600:
                certs.append({"serial": str(r.get("serial_number") or "")[:40], "issuer": (r.get("issuer_name") or "")[:200],
                              "not_after": r.get("not_after"), "cn": (r.get("common_name") or "").strip().lower().lstrip("*.")})
        src = "crt.sh"
    except Exception:
        pass
    if not names:
        try:
            js = net.get_json("https://api.certspotter.com/v1/issuances",
                              params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"}, timeout=40, retries=1)
            for r in js or []:
                for n in r.get("dns_names", []):
                    names.add(n.strip().lower().lstrip("*."))
            src = "Cert Spotter"
        except Exception:
            pass
    names = {n for n in names if n == domain or n.endswith("." + domain)}
    return sorted(names), src, certs


# ------------------------------------------------------------------ RDAP (domain lifecycle)
_RDAP_BASES: dict[str, str] = {}


def rdap_bootstrap() -> dict[str, str]:
    """IANA's authoritative TLD -> RDAP base map, and the only place RDAP hosts are trusted.

    Each server is registered on the passive allow-list here rather than reached by
    following rdap.org's redirect, so every RDAP host we talk to is one IANA publishes.
    """
    global _RDAP_BASES
    if _RDAP_BASES:
        return _RDAP_BASES
    out: dict[str, str] = {}
    try:
        js = json.loads(net.cached("https://data.iana.org/rdap/dns.json", 24))
    except Exception as e:
        print("[surface] rdap bootstrap", e)
        return out
    for entry in js.get("services", []):
        if len(entry) < 2:
            continue
        tlds, urls = entry[0], entry[1]
        base = next((u for u in urls if str(u).startswith("https://")), None)
        if not base:
            continue
        allow_host(urlparse(base).netloc)
        for t in tlds:
            out[str(t).strip().lower()] = base.rstrip("/")
    _RDAP_BASES = out
    return out


def rdap(domain: str) -> dict | None:
    base = rdap_bootstrap().get(domain.rsplit(".", 1)[-1].lower())
    if not base:
        return None
    try:
        return net.get_json(f"{base}/domain/{domain}", timeout=20, retries=1, ok_404=True)
    except Exception:
        return None


def rpki_state(asn: str, cidr: str) -> str | None:
    """RIPEstat route-origin validation for one (prefix, origin AS) pair."""
    try:
        js = net.get_json("https://stat.ripe.net/data/rpki-validation/data.json",
                          params={"resource": f"AS{asn}", "prefix": cidr, "sourceapp": "aegis"}, timeout=25, retries=1)
        return ((js or {}).get("data") or {}).get("status")
    except Exception:
        return None


def cymru(ip: str) -> dict | None:
    rev = ".".join(reversed(ip.split(".")))
    txt, _ = doh(f"{rev}.origin.asn.cymru.com", "TXT")
    if not txt:
        return None
    parts = [p.strip() for p in txt[0].split("|")]
    asn = parts[0].split()[0] if parts and parts[0] else None
    info = {"asn": asn, "prefix": parts[1] if len(parts) > 1 else None, "cc": parts[2] if len(parts) > 2 else None}
    if asn:
        t2, _ = doh(f"AS{asn}.asn.cymru.com", "TXT")
        if t2:
            info["as_name"] = t2[0].split("|")[-1].strip()
    return info


def internetdb(ip: str) -> dict | None:
    try:
        return net.get_json(f"https://internetdb.shodan.io/{ip}", timeout=15, retries=1, ok_404=True)
    except Exception:
        return None


# ------------------------------------------------------------------ the per-org scan
def scan_org(o: dict) -> dict:
    d = o["domain"]
    now = db.now()
    assets, deps = [], []

    def dep(vendor, category, evidence, source="dns"):
        deps.append({"org_id": o["id"], "vendor": vendor, "product": None, "category": category, "evidence": evidence[:200], "source_id": source, "seen": now})

    q = {}
    with ThreadPoolExecutor(8) as ex:
        jobs = {k: ex.submit(doh, name, t) for k, (name, t) in {
            "A": (d, "A"), "MX": (d, "MX"), "NS": (d, "NS"), "TXT": (d, "TXT"), "DMARC": (f"_dmarc.{d}", "TXT"),
            "MTASTS": (f"_mta-sts.{d}", "TXT"), "TLSRPT": (f"_smtp._tls.{d}", "TXT"), "CAA": (d, "CAA"), "DS": (d, "DS"),
            "WWW": (f"www.{d}", "CNAME"), **{f"DKIM:{s}": (f"{s}._domainkey.{d}", "TXT") for s in fp.DKIM_SELECTORS}}.items()}
        for k, f in jobs.items():
            q[k] = f.result()

    mx = [m.split()[-1].rstrip(".").lower() for m in q["MX"][0] if m]
    ns = [n.rstrip(".").lower() for n in q["NS"][0]]
    txt = q["TXT"][0]
    spf = spf_parse(txt)
    dmarc_rec = next((t for t in q["DMARC"][0] if t.lower().startswith("v=dmarc1")), None)
    dmarc = None
    if dmarc_rec:
        tags = dict(re.findall(r"(\w+)\s*=\s*([^;]+)", dmarc_rec))
        dmarc = {"record": dmarc_rec[:300], "p": tags.get("p", "").strip().lower(), "pct": tags.get("pct", "100").strip(),
                 "sp": tags.get("sp", "").strip().lower(), "rua": bool(tags.get("rua"))}
    dkim = [k.split(":")[1] for k, v in q.items() if k.startswith("DKIM:") and any("p=" in x or "k=" in x for x in v[0])]
    hygiene = {"spf": spf, "dmarc": dmarc, "dnssec": bool(q["DS"][0]), "mta_sts": bool(q["MTASTS"][0]), "tls_rpt": bool(q["TLSRPT"][0]),
               "caa": q["CAA"][0][:6], "dkim_selectors": dkim, "mx": mx[:6], "ns": ns[:8]}

    for m in mx:
        hit = fp.match(fp.MX_C, m)
        if hit:
            dep(hit[0], hit[1], f"MX {m}")
    own_ns = [n for n in ns if n.endswith(d)]
    for n in ns:
        hit = fp.match(fp.NS_C, n)
        if hit:
            dep(hit[0], hit[1], f"NS {n}")
    if own_ns:
        hygiene["self_hosted_dns"] = True
    for t in txt:
        hit = fp.match(fp.TXT_C, t)
        if hit:
            dep(hit[0], hit[1], f"TXT {t[:60]}…" if len(t) > 60 else f"TXT {t}")
    for inc in (spf or {}).get("includes", []):
        hit = fp.match(fp.SPF_C, inc)
        if hit:
            dep(hit[0], hit[1], f"SPF include:{inc}")

    # --- certificate transparency hostnames
    names, ct_src, certs = ct_hostnames(d)
    edge = []
    for n in names:
        e = fp.edge_product(n)
        if e:
            edge.append({"host": n, "vendor": e[0], "product": e[1]})
    pick = [d, f"www.{d}"] + [e["host"] for e in edge[:25]] + [n for n in names if INTERESTING.match(n)][:40]
    pick = list(dict.fromkeys(pick))[:60]

    resolved: dict[str, dict] = {}
    with ThreadPoolExecutor(8) as ex:
        a_jobs = {h: ex.submit(doh, h, "A") for h in pick}
        c_jobs = {h: ex.submit(doh, h, "CNAME") for h in pick}
        for h in pick:
            ips = [x for x in a_jobs[h].result()[0] if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", x)]
            cn = [x.rstrip(".").lower() for x in c_jobs[h].result()[0]]
            resolved[h] = {"ips": ips, "cname": cn[0] if cn else None}
    ip_hosts: dict[str, list[str]] = {}
    for h, r in resolved.items():
        cloud_by_cname = None
        if r["cname"]:
            hit = fp.match(fp.CNAME_C, r["cname"])
            if hit:
                dep(hit[0], hit[1], f"CNAME {h} → {r['cname']}", "ct")
                cloud_by_cname = hit[0]
            if fp.TAKEOVER_PRONE.search(r["cname"]) and not r["ips"]:
                r["dangling"] = True
        r["edge"] = fp.edge_product(h)
        for ip in r["ips"]:
            ip_hosts.setdefault(ip, []).append(h)
        assets.append({"org_id": o["id"], "kind": "hostname", "value": h, "source_id": "surface",
                       "attrs": {**r, "edge": list(r["edge"]) if r["edge"] else None, "cdn": cloud_by_cname}, "first_seen": now, "last_seen": now})

    # --- IPs: cloud attribution, ASN, InternetDB
    ips = [ip for ip in ip_hosts if not private(ip)][:45]
    with ThreadPoolExecutor(6) as ex:
        idb = dict(zip(ips, ex.map(internetdb, ips)))
        asn = dict(zip(ips, ex.map(cymru, ips)))
    org_tokens = [t for t in re.findall(r"[a-z0-9]{3,}", norm(o["name"])) if t not in {"the", "and", "group", "company", "holdings", "international"}]
    owned_asns = set()
    for ip in ips:
        cl = cloud_lookup(ip)
        info = idb.get(ip) or {}
        a = asn.get(ip) or {}
        tags = info.get("tags") or []
        as_name = (a.get("as_name") or "").lower()
        owned = bool(org_tokens) and any(t in as_name for t in org_tokens[:2]) and not cl
        if owned and a.get("asn"):
            owned_asns.add(a["asn"])
        shared = bool(cl) or "cdn" in tags or "cloud" in tags
        if cl:
            dep(cl["provider"], "Cloud platform", f"IP {ip} in {cl['provider']} range ({cl['service'] or 'published range'})", "cloud_ranges")
        assets.append({"org_id": o["id"], "kind": "ip", "value": ip, "source_id": "surface", "first_seen": now, "last_seen": now,
                       "attrs": {"hosts": ip_hosts[ip][:6], "ports": info.get("ports") or [], "cpes": (info.get("cpes") or [])[:15],
                                 "vulns": (info.get("vulns") or [])[:80], "tags": tags, "cloud": cl, "asn": a.get("asn"),
                                 "as_name": a.get("as_name"), "prefix": a.get("prefix"), "cc": a.get("cc"),
                                 "owned": owned, "shared": shared, "indexed": bool(info)}})

    # --- owned IP space: SPF-declared blocks + prefixes announced by ASNs registered to the organisation
    prefixes = [{"cidr": c, "prov": "SPF ip4 (declared by the organisation)"} for c in (spf or {}).get("ip4", [])[:40]]
    for a in sorted(owned_asns)[:4]:
        try:
            js = net.get_json("https://stat.ripe.net/data/announced-prefixes/data.json", params={"resource": f"AS{a}", "sourceapp": "aegis"}, timeout=30)
            for p in (js.get("data") or {}).get("prefixes", [])[:150]:
                if ":" not in p["prefix"]:
                    prefixes.append({"cidr": p["prefix"], "prov": f"announced by AS{a} (registered to organisation)", "asn": a})
        except Exception as e:
            print("[surface] ripestat", a, e)
    # --- routing integrity: is each announced prefix covered by a matching ROA?
    rpki: dict[str, str] = {}
    checkable = [p for p in prefixes if p.get("asn")][:RPKI_MAX]
    if checkable:
        with ThreadPoolExecutor(4) as ex:
            for p, st in zip(checkable, ex.map(lambda x: rpki_state(x["asn"], x["cidr"]), checkable)):
                if st:
                    rpki[p["cidr"]] = st
    for p in prefixes:
        at = {"provenance": p["prov"]}
        if p["cidr"] in rpki:
            at["rpki"] = rpki[p["cidr"]]
            at["rpki_asn"] = p["asn"]
        assets.append({"org_id": o["id"], "kind": "prefix", "value": p["cidr"], "source_id": "surface", "first_seen": now, "last_seen": now,
                       "attrs": at})

    # --- domain lifecycle: registrar transfer lock and expiry, from the TLD's own RDAP server
    rd = prevent.rdap_summary(rdap(d))

    # --- certificates: soonest expiry on a hostname that actually resolves, and CAA conformance
    live = {h for h, r in resolved.items() if r.get("ips")}
    allowed = prevent.caa_allowed(hygiene.get("caa"))
    soonest, offenders = None, []
    seen_issuers: set[str] = set()
    for c in certs:
        if c["cn"] in live:
            left = prevent.days_until(c["not_after"])
            if left is not None and left >= 0 and (soonest is None or left < soonest["days"]):
                soonest = {"days": left, "host": c["cn"], "not_after": c["not_after"], "issuer": c["issuer"]}
        iss = c["issuer"]
        if iss and iss not in seen_issuers and prevent.caa_violation(iss, allowed):
            seen_issuers.add(iss)
            offenders.append({"issuer": iss, "serial": c["serial"], "cn": c["cn"]})
    cert_info = {"checked": len(certs), "soonest": soonest, "caa_allowed": sorted(allowed) if allowed is not None else None,
                 "caa_offenders": offenders[:5]}

    # --- lookalike domains: generated locally, resolved through public resolvers only
    cands = prevent.lookalikes(d, LOOKALIKE_MAX)
    if cands:
        with ThreadPoolExecutor(8) as ex:
            a_jobs = {c: ex.submit(doh, c, "A") for c in cands}
            m_jobs = {c: ex.submit(doh, c, "MX") for c in cands}
            for c in cands:
                a_rec = [x for x in a_jobs[c].result()[0] if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", x)]
                mx_rec = [m.split()[-1].rstrip(".").lower() for m in m_jobs[c].result()[0] if m]
                if not a_rec and not mx_rec:
                    continue
                assets.append({"org_id": o["id"], "kind": "lookalike", "value": c, "source_id": "surface", "first_seen": now, "last_seen": now,
                               "attrs": {"ips": a_rec[:4], "mx": mx_rec[:4], "rule": prevent.lookalike_rule(bool(mx_rec), bool(a_rec))}})

    assets.append({"org_id": o["id"], "kind": "domain", "value": d, "source_id": "surface", "first_seen": now, "last_seen": now,
                   "attrs": {"hygiene": hygiene, "ct_count": len(names), "ct_source": ct_src, "edge": edge[:40],
                             "hostnames_sample": names[:400], "resolved": len(resolved), "owned_asns": sorted(owned_asns),
                             "rdap": rd, "certs": cert_info}})
    return {"assets": assets, "deps": deps}


def store_scan(o: dict, res: dict) -> None:
    c = db.conn()
    # replace the previous snapshot (kept as history in first_seen of carried-over rows)
    prev = {(r["kind"], r["value"]): r["first_seen"] for r in db.q("SELECT kind, value, first_seen FROM asset WHERE org_id=?", (o["id"],))}
    c.execute("DELETE FROM asset WHERE org_id=?", (o["id"],))
    c.execute("DELETE FROM dependency WHERE org_id=? AND source_id IN ('dns','ct','cloud_ranges')", (o["id"],))
    c.commit()
    for a in res["assets"]:
        a["first_seen"] = prev.get((a["kind"], a["value"]), a["first_seen"])
    db.upsert("asset", res["assets"])
    seen = set()
    uniq = []
    for dpd in res["deps"]:
        k = (dpd["vendor"], dpd["evidence"])
        if k not in seen:
            seen.add(k)
            uniq.append(dpd)
    db.upsert("dependency", uniq)
    db.x("UPDATE org SET deep_scanned=? WHERE id=?", (db.now(), o["id"]))


@collector(Source(
    id="surface", name="External attack surface (passive)", category="Attack surface",
    publisher="Google & Cloudflare DNS-over-HTTPS · crt.sh / Cert Spotter CT logs · Shodan InternetDB · Team Cymru · RIPEstat",
    homepage="https://internetdb.shodan.io/", url="https://dns.google/resolve", cadence_min=15,
    licence="DoH, CT, RIPEstat, Team Cymru: free · Shodan InternetDB: free for non-commercial use",
    feeds=[{"publisher": "crt.sh", "url": "https://crt.sh/"}, {"publisher": "Cert Spotter", "url": "https://api.certspotter.com/v1/issuances"},
           {"publisher": "Shodan InternetDB", "url": "https://internetdb.shodan.io/"}, {"publisher": "RIPEstat", "url": "https://stat.ripe.net/"}],
    notes="Rotates through monitored organisations (~6 per run, full cycle every few days). Reads public DNS and third-party indexes only — "
          "no packets are ever sent to the organisation's hosts."))
def collect_surface() -> int:
    orgs = db.q("SELECT id, name, domain FROM org WHERE tier='watch' AND domain IS NOT NULL ORDER BY deep_scanned IS NOT NULL, deep_scanned LIMIT 12")

    def one(o):
        try:
            store_scan(o, scan_org(o))
            return 1
        except Exception as e:
            print("[surface]", o["domain"], e)
            db.x("UPDATE org SET deep_scanned=? WHERE id=?", (db.now(), o["id"]))
            return 0
    # two organisations in parallel; per-host pacing in net.py keeps every third-party index within its limits
    with ThreadPoolExecutor(2) as ex:
        return sum(ex.map(one, orgs))
