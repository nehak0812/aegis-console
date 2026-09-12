"""Domain, certificate and routing hardening: pure, testable checks behind 13 organisation rules
(BGP-RPKI-*, CRT-*, DOM-*, HYG-DKIM-NONE, HYG-NS-SINGLE, HYG-SPF-LOOKUPS, HYG-TLSRPT, LOOK-*).

No network in here. The collector (aegis/collectors/hardening.py) reads public DNS over HTTPS, registry RDAP,
certificate-transparency logs and RIPEstat, and passes the records in. Nothing ever contacts the organisation's hosts.
"""
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Callable

from aegis.intel.entities import reg_domain
from aegis.rating import rule

UTC = timezone.utc

# ------------------------------------------------------------------ constants
DKIM_SELECTORS = ["selector1", "selector2", "google", "default", "k1", "k2", "s1", "s2", "dkim", "mail", "smtp",
                  "mxvault", "everlytickey1", "zoho", "amazonses", "sig1", "protonmail"]
SPF_LIMIT = 10  # RFC 7208 §4.6.4

# nameserver host → provider; one provider can spread its nameservers over several TLDs (Route 53 uses four)
NS_PROVIDERS = [
    (re.compile(r"(^|\.)awsdns-\d+\.(com|net|org|co\.uk)$"), "AWS Route 53"),
    (re.compile(r"(^|\.)azure-dns\.(com|net|org|info)$"), "Azure DNS"),
    (re.compile(r"(^|\.)(cloudflare\.com|foundationdns\.(com|net|org))$"), "Cloudflare"),
    (re.compile(r"(^|\.)(nsone\.net|ns1global\.(net|org))$"), "NS1"),
    (re.compile(r"(^|\.)ultradns\.(com|net|org|biz|info|co\.uk)$"), "UltraDNS"),
    (re.compile(r"(^|\.)(akam\.net|akamai\.net|akamaiedge\.net|akamaitech\.net|akamaistream\.net)$"), "Akamai"),
    (re.compile(r"(^|\.)(googledomains\.com|google\.com)$"), "Google"),
]

# issuer (O= / CN= of the issuing CA) → CAA identifiers that authorise it (RFC 8659 §4.2; CA-published identifier lists)
CAA_ISSUERS = [
    (re.compile(r"digicert|geotrust|rapidssl|thawte|symantec|encryption everywhere", re.I),
     {"digicert.com", "www.digicert.com", "symantec.com", "geotrust.com", "rapidssl.com", "thawte.com", "digitalcertvalidation.com"}),
    (re.compile(r"sectigo|comodo|usertrust", re.I), {"sectigo.com", "comodoca.com", "comodo.com", "usertrust.com", "trust-provider.com"}),
    (re.compile(r"let'?s encrypt", re.I), {"letsencrypt.org"}),
    (re.compile(r"google trust services", re.I), {"pki.goog"}),
    (re.compile(r"\bamazon\b", re.I), {"amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com"}),
    (re.compile(r"globalsign", re.I), {"globalsign.com"}),
    (re.compile(r"entrust", re.I), {"entrust.net", "affirmtrust.com"}),
]

# Registries that publish EPP transfer statuses in RDAP. Every gTLD must; for ccTLDs only these were verified
# (Nominet and AFNIC show client/server transfer prohibited). DENIC (.de) publishes no lock status at all.
LOCK_CCTLDS = {"uk", "fr"}

# brand-protection registrars' DNS: a lookalike parked here is almost always a defensive registration
BRAND_PROTECTION_NS = re.compile(r"(markmonitor\.com|cscdns\.(net|uk)|safenames\.net|comlaude)", re.I)

CAA_MARGIN_H = 8
LOOKALIKE_TLDS = ["com", "net", "org", "co", "io"]
CC_TLD = {"GB": "co.uk", "UK": "co.uk"}


# ------------------------------------------------------------------ helpers
def _dt(s) -> datetime | None:
    if not s:
        return None
    t = str(s).strip().replace(" ", "T").replace("Z", "+00:00")
    for cand in (t, re.sub(r"\.\d+", "", t)):
        try:
            d = datetime.fromisoformat(cand)
            return d if d.tzinfo else d.replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def _iso(d: datetime | None) -> str | None:
    return d.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if d else None


def doh_url(name: str, rtype: str) -> str:
    return f"https://dns.google/resolve?name={name}&type={rtype}"


# ------------------------------------------------------------------ SPF
def spf_record(txts) -> str | None:
    return next((t.strip() for t in txts or [] if re.match(r"(?i)^v=spf1(\s|$)", t.strip())), None)


def spf_lookup_count(spf: str | None, resolver: Callable[[str], list[str]], *, domain: str | None = None,
                     max_depth: int = 10, stop_at: int = 40, trace: dict | None = None) -> int:
    """DNS-lookup terms in an SPF record, counted recursively through include: and redirect= (RFC 7208 §4.6.4).

    `resolver(name)` returns the TXT strings at `name` (raises on failure). Loop-safe: each domain is expanded once
    (a repeated include still counts, it is just not walked again), depth is capped and the walk stops once the count
    passes `stop_at`. Includes that could not be resolved or use macros are counted but not expanded, so the result is
    a lower bound. `trace` (optional dict) receives chain / unresolved / loops for the evidence text."""
    tr = trace if trace is not None else {}
    tr.update({"chain": [], "unresolved": [], "loops": [], "truncated": False})
    seen = {domain.lower().rstrip(".")} if domain else set()
    count = 0

    def walk(rec: str, depth: int) -> None:
        nonlocal count
        toks = [t.lower() for t in (rec or "").split()[1:]]
        has_all = any(t.lstrip("+-~?") == "all" for t in toks)
        for tok in toks:
            t = tok.lstrip("+-~?")
            if t.startswith("include:"):
                target = t[8:]
            elif t.startswith("redirect="):
                if has_all:  # RFC 7208 §6.1: redirect is ignored when an "all" mechanism is present
                    continue
                target = t[9:]
            elif re.match(r"^(a|mx|ptr)([:/]|$)|^exists:", t):
                count += 1
                continue
            else:
                continue
            count += 1
            if count > stop_at:
                tr["truncated"] = True
                return
            target = target.rstrip(".")
            if not target or "%{" in target:
                tr["unresolved"].append(target)
                continue
            if target in seen:
                tr["loops"].append(target)
                continue
            if depth >= max_depth:
                tr["truncated"] = True
                continue
            seen.add(target)
            try:
                sub = spf_record(resolver(target))
            except Exception:
                tr["unresolved"].append(target)
                continue
            if sub is None:
                tr["unresolved"].append(target)
                continue
            tr["chain"].append(target)
            walk(sub, depth + 1)

    walk(spf or "", 0)
    return count


def spf_sends_mail(spf: str | None) -> bool:
    """False for a "v=spf1 -all" style record (a domain that declares it sends no mail)."""
    if not spf:
        return False
    return any(t.lstrip("+-~?").lower() != "all" for t in spf.split()[1:])


# ------------------------------------------------------------------ DKIM / TLS-RPT
def dkim_record(txts) -> bool:
    return any("v=dkim1" in t.lower() or re.search(r"(^|;)\s*p=[A-Za-z0-9+/]", t) for t in txts or [])


def dkim_present(results_by_selector: dict) -> bool | None:
    """{selector: [TXT strings] | None (lookup failed)} → True if any selector publishes a key, False if every selector
    was answered and none does, None when a lookup failed and no key was found (not evaluable)."""
    if not results_by_selector:
        return None
    if any(dkim_record(v) for v in results_by_selector.values() if v):
        return True
    if any(v is None for v in results_by_selector.values()):
        return None
    return False


def tlsrpt_present(txt) -> bool:
    return any(re.sub(r"\s", "", t).lower().startswith("v=tlsrptv1") for t in txt or [])


# ------------------------------------------------------------------ nameservers
def ns_provider(host: str) -> str:
    h = (host or "").lower().rstrip(".")
    for rx, name in NS_PROVIDERS:
        if rx.search(h):
            return name
    return reg_domain(h)


def ns_providers(ns_hosts) -> list[str]:
    return sorted({ns_provider(h) for h in ns_hosts or [] if h})


def ns_single_provider(ns_hosts) -> bool | None:
    """True when every authoritative nameserver belongs to one provider; None when no nameservers are known."""
    provs = ns_providers(ns_hosts)
    return None if not provs else len(provs) == 1


# ------------------------------------------------------------------ RDAP
def rdap_domain_status(rdap_json: dict | None) -> dict:
    """→ {expires, locked, status}. locked: a client/server transfer prohibition is present (None if no status list)."""
    js = rdap_json or {}
    status = [str(s) for s in js.get("status") or []]
    flat = {re.sub(r"[\s_]", "", s).lower() for s in status}
    locked = bool(flat & {"clienttransferprohibited", "servertransferprohibited"}) if status else None
    exp = next((e.get("eventDate") for e in js.get("events") or [] if (e.get("eventAction") or "").lower() == "expiration"), None)
    return {"expires": exp, "locked": locked, "status": status}


def lock_evaluable(domain: str) -> bool:
    tld = (domain or "").lower().rstrip(".").rsplit(".", 1)[-1]
    return len(tld) > 2 or tld in LOCK_CCTLDS


# ------------------------------------------------------------------ RPKI
def rpki_findings(prefix_results: list[dict]) -> dict:
    """[{prefix, asn, status, roas}] (RIPEstat rpki-validation) → {invalid: [...], none: [...], valid: [...]}."""
    out = {"invalid": [], "none": [], "valid": []}
    for r in prefix_results or []:
        st = (r.get("status") or "").lower().replace("-", "_")
        if st.startswith("invalid"):
            out["invalid"].append(r)
        elif st in ("unknown", "not_found", "notfound"):
            out["none"].append(r)
        elif st == "valid":
            out["valid"].append(r)
    return out


def rpki_url(asn, prefix) -> str:
    return f"https://stat.ripe.net/data/rpki-validation/data.json?resource=AS{str(asn).upper().lstrip('AS')}&prefix={prefix}"


# ------------------------------------------------------------------ certificates (CT) and CAA
def ct_compact(row: dict) -> dict:
    """One crt.sh JSON row → the fields AEGIS keeps (no subject organisation / person data)."""
    return {"id": row.get("id"), "serial": row.get("serial_number"), "issuer": (row.get("issuer_name") or "")[:200],
            "not_before": row.get("not_before"), "not_after": row.get("not_after"),
            "names": sorted({n.strip().lower().rstrip(".") for n in (row.get("name_value") or "").split("\n") if n.strip()})}


def ct_recent(certs: list[dict], cap: int = 150, max_names: int = 25) -> list[dict]:
    """The most recently issued certificates (one per issuer + serial; the pre-certificate and leaf share it)."""
    uniq = {}
    for c in certs or []:
        k = (c.get("issuer"), c.get("serial") or c.get("id"))
        if k not in uniq or (c.get("id") or 0) < (uniq[k].get("id") or 0):
            uniq[k] = c
    rows = sorted(uniq.values(), key=lambda c: c.get("not_before") or "", reverse=True)[:cap]
    return [{k: (v[:max_names] if k == "names" else v) for k, v in c.items() if k != "serial"} for c in rows]


def ct_expiring(certs: list[dict], hosts=(), now: datetime | None = None, window_days: int = 30, cap: int = 150) -> dict:
    """Hostnames whose LATEST covering certificate ends within `window_days` → {host: {not_after, id, issuer}}.

    A host counts as covered by an exact SAN or a wildcard one label up; a renewed certificate therefore clears it.
    Wildcards are resolved against `hosts` (the names seen in CT). Apex names are skipped: the crt.sh query
    (%.domain) does not return apex-only certificates, so a renewal could be invisible."""
    now = now or datetime.now(UTC)
    best: dict[str, dict] = {}
    wild = defaultdict(list)

    def upd(h, c):
        cur = best.get(h)
        if cur is None or (c.get("not_after") or "") > (cur.get("not_after") or ""):
            best[h] = c
    for c in certs or []:
        for n in c.get("names") or []:
            if n.startswith("*."):
                wild[n[2:]].append(c)
            else:
                upd(n, c)
    for h in set(hosts or ()) | set(best):
        if h.startswith("*.") or "." not in h:
            continue
        for c in wild.get(h.split(".", 1)[1], []):
            upd(h, c)
    out = {}
    for h, c in best.items():
        na = _dt(c.get("not_after"))
        if not na or "." not in h or h == reg_domain(h):
            continue
        if now < na <= now + timedelta(days=window_days):
            out[h] = {"not_after": _iso(na), "id": c.get("id"), "issuer": c.get("issuer")}
    return dict(sorted(out.items(), key=lambda kv: kv[1]["not_after"])[:cap])


def caa_parse(records) -> list[tuple[int, str, str]]:
    """CAA RDATA strings → [(flags, tag, value)]. Accepts presentation format (with or without the closing quote the
    DoH helper trims) and the RFC 3597 generic form some resolvers return (\\# len hex…)."""
    out = []
    for r in records or []:
        s = str(r).strip()
        if s.startswith("\\#"):
            try:
                b = bytes.fromhex("".join(s.split()[2:]))
                tl = b[1]
                out.append((b[0], b[2:2 + tl].decode().lower(), b[2 + tl:].decode(errors="replace").strip()))
            except (ValueError, IndexError):
                pass
            continue
        m = re.match(r'^(\d+)\s+([A-Za-z0-9]+)\s+"?(.*?)"?\s*$', s)
        if m:
            out.append((int(m.group(1)), m.group(2).lower(), m.group(3).strip()))
    return out


def caa_policy(records) -> list[str]:
    """Normalised issue/issuewild properties (what the policy is; iodef contacts are not kept)."""
    return sorted({f"{t} {v.split(';')[0].strip().lower()}" for _, t, v in caa_parse(records) if t in ("issue", "issuewild")})


def caa_issuer_ids(issuer: str | None) -> set[str] | None:
    for rx, ids in CAA_ISSUERS:
        if rx.search(issuer or ""):
            return ids
    return None


def caa_chain(name: str) -> list[str]:
    """RFC 8659 §3 climb: the name itself, then each parent, stopping at the registrable domain (the public suffix
    above it, e.g. .com or .co.uk, is not queried)."""
    base = name.lower().rstrip(".")
    base = base[2:] if base.startswith("*.") else base
    stop = reg_domain(base)
    labels = base.split(".")
    chain = []
    for i in range(len(labels)):
        d = ".".join(labels[i:])
        chain.append(d)
        if d == stop or d.count(".") == 0:
            break
    return [d for d in chain if "." in d]


def _caa_name(name: str, cert: dict, caa_by_domain: dict, caa_first_seen: dict) -> dict:
    wildcard = name.startswith("*.")
    applied = None
    for d in caa_chain(name):
        if d not in caa_by_domain or caa_by_domain[d] is None:
            return {"name": name, "status": "not_evaluable", "why": f"CAA at {d} not observed"}
        if caa_parse(caa_by_domain[d]):
            applied = d
            break
    if applied is None:
        return {"name": name, "status": "unrestricted", "why": "no CAA record at the name or any parent"}
    props = caa_parse(caa_by_domain[applied])
    issue = [v for _, t, v in props if t == "issue"]
    wild = [v for _, t, v in props if t == "issuewild"]
    vals = wild if wildcard and wild else issue
    if not vals:
        return {"name": name, "status": "unrestricted", "domain": applied, "why": "CAA set has no issue property"}
    allowed = {v.split(";")[0].strip().lower() for v in vals} - {""}
    fs, nb = _dt(caa_first_seen.get(applied)), _dt(cert.get("not_before"))
    # a CA may rely on a CAA lookup made up to 8 hours before issuance (CA/B Forum BR §3.2.2.8), so allow that margin
    if not fs or not nb or nb <= fs + timedelta(hours=CAA_MARGIN_H):
        return {"name": name, "status": "not_evaluable", "domain": applied, "why": "issued before the current CAA policy was observed"}
    ids = caa_issuer_ids(cert.get("issuer"))
    if allowed and ids is None:
        return {"name": name, "status": "not_evaluable", "domain": applied, "why": "issuer not in the CAA identifier map"}
    if allowed & (ids or set()):
        return {"name": name, "status": "authorised", "domain": applied, "allowed": sorted(allowed)}
    return {"name": name, "status": "violation", "domain": applied, "allowed": sorted(allowed), "issuer": cert.get("issuer")}


def caa_evaluate(cert: dict, caa_by_domain: dict, caa_first_seen: dict) -> dict:
    """RFC 8659 check of one certificate {id, names, issuer, not_before} against observed CAA sets.

    caa_by_domain: {domain: [CAA strings]} as observed now ([] = queried, none; missing = not queried).
    caa_first_seen: {domain: ISO time the current CAA policy there was first observed}.
    Only a certificate issued AFTER the applicable policy was first observed can be a violation; anything we cannot
    establish (unqueried name, unknown issuer, older certificate) is "not_evaluable" and never a finding."""
    res = [_caa_name(n, cert, caa_by_domain or {}, caa_first_seen or {}) for n in cert.get("names") or []]
    for st in ("violation", "not_evaluable", "authorised", "unrestricted"):
        hit = [r for r in res if r["status"] == st]
        if hit:
            return {"status": st, **{k: v for k, v in hit[0].items() if k != "status"}, "names": res}
    return {"status": "not_evaluable", "why": "certificate has no names", "names": []}


# ------------------------------------------------------------------ lookalikes
def _valid_label(s: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", s)) and "--" not in s


def lookalike_permutations(domain: str, cc: str | None = None, cap: int = 60, exclude=()) -> list[str]:
    """Lookalike candidates of the registrable domain: homoglyphs (0/o, 1/l, rn/m, vv/w), omission, transposition,
    TLD swap (.com .net .org .co .io and the country's ccTLD), hyphenation and addition (doubled letter, trailing s).
    Interleaved by kind so the cap keeps variety. Never returns the organisation's own domain(s). Labels shorter
    than 4 characters are skipped: nearly every permutation of those is an unrelated, legitimately registered name."""
    reg = reg_domain(domain or "")
    if "." not in reg:
        return []
    label, suffix = reg.split(".", 1)
    if len(label) < 4:
        return []
    own = {reg, (domain or "").lower()} | {reg_domain(x) for x in exclude or () if x}
    homo, omit, trans, tlds, hyph, add = [], [], [], [], [], []
    for a, b in (("o", "0"), ("0", "o"), ("l", "1"), ("1", "l"), ("m", "rn"), ("rn", "m"), ("w", "vv"), ("vv", "w")):
        for m in re.finditer(re.escape(a), label):
            homo.append(label[:m.start()] + b + label[m.end():])
    for i in range(len(label)):
        omit.append(label[:i] + label[i + 1:])
        add.append(label[:i + 1] + label[i] + label[i + 1:])
    for i in range(len(label) - 1):
        if label[i] != label[i + 1]:
            trans.append(label[:i] + label[i + 1] + label[i] + label[i + 2:])
        if label[i] != "-" and label[i + 1] != "-":
            hyph.append(label[:i + 1] + "-" + label[i + 1:])
    add.append(label + "s")
    ccs = CC_TLD.get((cc or "").upper(), (cc or "").lower()) if cc else None
    for t in LOOKALIKE_TLDS + ([ccs] if ccs else []):
        if t and t != suffix:
            tlds.append(f"{label}.{t}")
    kinds = [[f"{x}.{suffix}" for x in homo], [f"{x}.{suffix}" for x in omit], [f"{x}.{suffix}" for x in trans], tlds,
             [f"{x}.{suffix}" for x in hyph], [f"{x}.{suffix}" for x in add]]
    out, seen = [], set()
    for i in range(max(len(k) for k in kinds)):
        for k in kinds:
            if i < len(k):
                c = k[i]
                lab = c.split(".", 1)[0]
                if c in seen or c in own or not _valid_label(lab) or len(lab) < 3:
                    continue
                seen.add(c)
                out.append(c)
                if len(out) >= cap:
                    return out
    return out


def lookalike_defensive(hit: dict, org_domain: str, org_ns=(), org_mx=(), org_ips=()) -> bool:
    """A lookalike served by the organisation's own nameservers / mail exchangers / web addresses, pointing mail at the
    organisation's domain, or parked with a brand-protection registrar is treated as a defensive registration."""
    d = (org_domain or "").lower()
    ns = {x.lower().rstrip(".") for x in hit.get("ns") or []}
    mx = {x.lower().rstrip(".") for x in hit.get("mx") or []}
    if ns & {x.lower() for x in org_ns or ()} or mx & {x.lower() for x in org_mx or ()}:
        return True
    if set(hit.get("a") or []) & set(org_ips or ()):
        return True
    if d and any(x == d or x.endswith("." + d) for x in ns | mx):
        return True
    return any(BRAND_PROTECTION_NS.search(x) for x in ns)


# ------------------------------------------------------------------ findings
def hardening_findings(org: dict, h: dict, now: datetime | None = None) -> list[dict]:
    """Stored hardening observations for one organisation → finding dicts (same fields build_findings writes, plus
    `key` for the stable id). Every finding links to the exact public record it rests on."""
    from aegis.intel.pipeline import rule_cat  # lazy: pipeline imports this module inside build_findings

    out: list[dict] = []
    h = h or {}
    d = h.get("domain") or org.get("domain")
    if not d:
        return out
    now = now or datetime.now(UTC)
    name = org.get("name") or d

    def add(rid, title, detail, url, observed, key, data=None):
        sev, _ = rule(rid)
        out.append({"org_id": org["id"], "rule_id": rid, "severity": sev, "category": rule_cat(rid), "title": title[:240],
                    "detail": (detail or "")[:600], "evidence_url": url, "source_id": "hardening",
                    "observed": observed or h.get("checked"), "key": key, "data": data or {}})

    # --- mail & DNS hygiene
    dns = h.get("dns") or {}
    if dns and not dns.get("error"):
        spf = dns.get("spf")
        receives = bool(dns.get("mx")) and not dns.get("null_mx")
        sends = spf_sends_mail(spf) or receives
        n = dns.get("spf_lookups")
        if spf and n is not None and n > SPF_LIMIT:
            tr = dns.get("spf_trace") or {}
            add("HYG-SPF-LOOKUPS", f"SPF on {d} needs {n}{'+' if tr.get('truncated') else ''} DNS lookups (limit {SPF_LIMIT})",
                f"Record: {spf[:200]}. Expanded includes: {', '.join((tr.get('chain') or [])[:10]) or '—'}. Flatten or remove unused includes.",
                doh_url(d, "TXT"), dns.get("checked"), "spf-lookups", {"lookups": n, "includes": (tr.get("chain") or [])[:30]})
        if dns.get("dkim_present") is False and sends:
            add("HYG-DKIM-NONE", f"No DKIM key on the common selectors of {d}",
                f"Selectors checked: {', '.join(DKIM_SELECTORS)}. Keys on custom selectors are not visible to passive DNS; "
                "confirm with the mail team.", doh_url(f"selector1._domainkey.{d}", "TXT"), dns.get("checked"), "dkim",
                {"selectors": DKIM_SELECTORS})
        ns = dns.get("ns") or []
        provs = dns.get("ns_providers") or ns_providers(ns)
        if ns and len(provs) == 1:
            add("HYG-NS-SINGLE", f"All {len(ns)} nameservers of {d} are with {provs[0]}", ", ".join(ns[:8]),
                doh_url(d, "NS"), dns.get("checked"), "ns-single", {"provider": provs[0], "ns": ns[:8]})
        if dns.get("tlsrpt") is False and receives:
            add("HYG-TLSRPT", f"No TLS-RPT record on {d}", "No v=TLSRPTv1 TXT record at _smtp._tls.",
                doh_url(f"_smtp._tls.{d}", "TXT"), dns.get("checked"), "tlsrpt")

    # --- registration (RDAP)
    rd = h.get("rdap") or {}
    if rd and not rd.get("error"):
        exp = _dt(rd.get("expires"))
        if exp:
            days = (exp - now).total_seconds() / 86400
            rid = "DOM-EXPIRY-30" if days <= 30 else "DOM-EXPIRY-90" if days <= 90 else None
            if rid:
                add(rid, f"{d} expires on {exp:%Y-%m-%d} ({max(0, int(days))} days)",
                    "Registry RDAP expiration date. Renew now and enable auto-renew and a registry lock with the registrar.",
                    rd.get("url"), rd.get("checked"), "dom-expiry", {"expires": _iso(exp), "days": int(days)})
        if rd.get("locked") is False and lock_evaluable(d):
            add("DOM-LOCK", f"{d} has no transfer lock at the registry",
                f"RDAP status: {', '.join(rd.get('status') or []) or '—'}. Ask the registrar to set clientTransferProhibited "
                "(or a registry lock).", rd.get("url"), rd.get("checked"), "dom-lock", {"status": rd.get("status")})

    # --- routing (RPKI)
    rp = h.get("rpki") or {}
    if rp.get("results") and not rp.get("error"):
        r = rpki_findings(rp["results"])
        if r["invalid"]:
            x = r["invalid"]
            def roas(p):
                return ", ".join(sorted({f"AS{o.get('origin')} {o.get('prefix')} max /{o.get('max_length')}" for o in p.get("roas") or []})) or "—"
            add("BGP-RPKI-INVALID", f"{len(x)} prefix{'es' if len(x) > 1 else ''} of {name} RPKI-invalid for its origin",
                "; ".join(f"{p['prefix']} from AS{p['asn']} (ROAs authorise: {roas(p)})" for p in x[:6]) +
                ". Fix the ROA or the announcement; check for a hijack.",
                rpki_url(x[0]["asn"], x[0]["prefix"]), rp.get("checked"), "rpki-invalid",
                {"prefixes": [{"prefix": p["prefix"], "asn": p["asn"], "status": p.get("status")} for p in x[:60]]})
        if r["none"]:
            x = r["none"]
            add("BGP-RPKI-NONE", f"{len(x)} of {len(rp['results'])} checked prefixes of {name} have no ROA",
                f"{', '.join(p['prefix'] + ' (AS' + str(p['asn']) + ')' for p in x[:10])}{' …' if len(x) > 10 else ''}. "
                "Create ROAs with the RIR for every announced prefix.", rpki_url(x[0]["asn"], x[0]["prefix"]), rp.get("checked"),
                "rpki-none", {"prefixes": [{"prefix": p["prefix"], "asn": p["asn"]} for p in x[:60]], "checked": len(rp["results"])})

    # --- certificates (CT) and CAA
    ct = h.get("certs") or {}
    soon = []
    for host, v in (ct.get("expiring_live") or {}).items():
        na = _dt(v.get("not_after"))
        if na and now < na <= now + timedelta(days=14):
            soon.append((na, host, v))
    if soon:
        soon.sort()
        add("CRT-EXPIRY-14", f"{len(soon)} live hostname{'s' if len(soon) > 1 else ''} of {d} with a certificate expiring within 14 days",
            "; ".join(f"{hst} — {na:%Y-%m-%d}" for na, hst, _ in soon[:8]) + ". No newer certificate for these names is in the CT logs.",
            f"https://crt.sh/?id={soon[0][2].get('id')}", ct.get("checked"), "crt-expiry",
            {"hosts": [{"host": hst, "not_after": _iso(na), "crtsh_id": v.get("id")} for na, hst, v in soon[:40]]})
    viol = []
    for c in ct.get("recent") or []:
        r = caa_evaluate(c, h.get("caa_by_domain") or {}, h.get("caa_first_seen") or {})
        if r["status"] == "violation":
            viol.append((c, r))
    if viol:
        c0, r0 = viol[0]
        add("CRT-CAA-VIOLATION", f"{len(viol)} certificate{'s' if len(viol) > 1 else ''} for {d} from a CA its CAA policy does not authorise",
            "; ".join(f"{r['name']} by {(c.get('issuer') or '')[:80]} on {(c.get('not_before') or '')[:10]} — CAA at {r['domain']} "
                      f"authorises {', '.join(r.get('allowed') or []) or 'no CA'}" for c, r in viol[:4]),
            f"https://crt.sh/?id={c0.get('id')}", ct.get("checked"), "caa-violation",
            {"certs": [{"crtsh_id": c.get("id"), "name": r["name"], "issuer": c.get("issuer"), "caa_domain": r["domain"],
                        "allowed": r.get("allowed")} for c, r in viol[:20]]})

    # --- lookalikes
    lk = h.get("lookalikes") or {}
    if lk and not lk.get("error"):
        hits = [x for x in lk.get("hits") or [] if not x.get("defensive")]
        mx_hits = [x for x in hits if x.get("mx")]
        live = [x for x in hits if not x.get("mx") and x.get("a")]
        if mx_hits:
            add("LOOK-MX", f"{len(mx_hits)} lookalike domain{'s' if len(mx_hits) > 1 else ''} of {d} accept mail",
                "; ".join(f"{x['domain']} (MX {', '.join(x['mx'][:2])})" for x in mx_hits[:6]) +
                ". Block them at the mail gateway and consider takedown or defensive registration.",
                doh_url(mx_hits[0]["domain"], "MX"), lk.get("checked"), "look-mx", {"domains": [x["domain"] for x in mx_hits[:40]]})
        if live:
            add("LOOK-LIVE", f"{len(live)} lookalike domain{'s' if len(live) > 1 else ''} of {d} resolve",
                "; ".join(f"{x['domain']} → {', '.join(x['a'][:2])}" for x in live[:6]) + ". Pre-block in web gateways and monitor.",
                doh_url(live[0]["domain"], "A"), lk.get("checked"), "look-live", {"domains": [x["domain"] for x in live[:40]]})
    return out
