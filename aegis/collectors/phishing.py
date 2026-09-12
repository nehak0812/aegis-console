"""Impersonation early warning and "your website used against you":

- Newly registered domains (WhoisDS daily list, ~70k gTLD domains/day) matched to monitored brands with lure words.
- Phishing feeds: OpenPhish, PhishTank (verified + online, with the targeted brand), URLhaus and ThreatFox exports
  (ClickFix / fake-CAPTCHA / ClearFake tags, compromised sites).
- Liveness: brand-matched domains are resolved through public DNS-over-HTTPS (never contacted directly).
Only matches are stored; the full lists are read and discarded.
"""
import base64
import csv
import io
import json
import re
import zipfile
from collections import Counter, defaultdict
from datetime import date, timedelta

from aegis import db, net
from aegis.collectors.reports import ioc_id, store_iocs
from aegis.intel.entities import matcher, norm, reg_domain
from aegis.intel.iocs import PLATFORM, BrandIndex, host_of
from aegis.registry import Source, collector

WHOISDS = "https://www.whoisds.com/whois-database/newly-registered-domains/{}/nrd"
NEWS_WORDS = {"news", "daily", "post", "times", "tribune", "voice", "voices", "herald", "gazette", "journal", "wire", "pulse",
              "insider", "observer", "chronicle", "report", "reporter", "press", "today", "digest", "bulletin", "dispatch", "telegraph"}
PLACES = {"british", "britain", "uk", "london", "america", "american", "us", "usa", "euro", "europe", "european", "german", "berlin",
          "france", "french", "paris", "ukraine", "ukrainian", "kyiv", "russia", "russian", "moscow", "israel", "gaza", "iran", "africa",
          "african", "naija", "nigeria", "kenya", "jambo", "axum", "ethiopia", "sahel", "mali", "india", "pakistan", "china", "taiwan",
          "japan", "korea", "canada", "australia", "commonwealth", "brussels", "poland", "polish", "moldova", "armenia", "georgia",
          "baltic", "latvia", "lithuania", "estonia", "serbia", "balkan", "arab", "gulf", "turkey", "malaysia", "philippines",
          "venezuela", "mexico", "brazil", "global", "world", "national", "civic", "liberty", "freedom", "patriot", "fiftystates"}


def _orgs() -> list[dict]:
    return db.q("SELECT id, name, domain, domains FROM org")


def _news_like(domain: str) -> bool:
    toks = set(re.findall(r"[a-z]+", domain.split(".")[0]))
    flat = domain.split(".")[0]
    return (bool(toks & NEWS_WORDS) or any(flat.endswith(w) or flat.startswith(w) for w in NEWS_WORDS if len(w) >= 5)) and \
        (bool(toks & PLACES) or any(flat.startswith(p) or flat.endswith(p) for p in PLACES if len(p) >= 5))


@collector(Source(
    id="nrd_whoisds", name="Newly registered domains (brand lookalikes)", category="Attack surface", publisher="WhoisDS (free daily list)",
    homepage="https://www.whoisds.com/newly-registered-domains", url="https://www.whoisds.com/newly-registered-domains", cadence_min=720,
    licence="Free public daily download (gTLDs, ~70k/day sample); attribute WhoisDS",
    notes="Each day's new domains are matched to monitored brands: a strong brand token, or a short/dictionary brand only next to a lure word "
          "(login, 365, us-east, …). Only matches are kept. News-style domain bursts are recorded as influence-operation context."))
def collect_nrd() -> int:
    done = set(db.kv_get("nrd_done", []) or [])
    bi = BrandIndex(_orgs())
    stats = db.kv_get("nrd_stats", {}) or {}
    news = db.kv_get("news_domains", {}) or {}
    n = 0
    for back in (1, 2, 3):
        d = (date.today() - timedelta(days=back)).isoformat()
        if d in done:
            continue
        try:
            raw = net.get(WHOISDS.format(base64.b64encode(f"{d}.zip".encode()).decode()), timeout=90).content
            z = zipfile.ZipFile(io.BytesIO(raw))
            domains = z.read(z.namelist()[0]).decode("utf-8", errors="replace").split()
        except Exception as e:
            print("[nrd]", d, e)
            continue
        rows = []
        for dom in domains:
            dom = dom.strip().lower()
            m = bi.match(dom)
            if m:
                rows.append({"id": ioc_id(dom, "domain", "nrd"), "value": dom, "type": "domain", "kind": "nrd", "source_id": "nrd_whoisds",
                             "publisher": "WhoisDS newly registered domains", "report_title": f"Registered {d}",
                             "report_url": "https://www.whoisds.com/newly-registered-domains", "published": f"{d}T00:00:00Z",
                             "context": m["how"], "tags": ["nrd"]})
        store_iocs(rows)
        nl = sorted(x for x in domains if _news_like(x))
        news[d] = {"count": len(nl), "sample": nl[:120]}
        stats[d] = {"total": len(domains), "matches": len(rows), "news_like": len(nl)}
        done.add(d)
        n += len(domains)
    keep = sorted(stats)[-30:]
    db.kv_set("nrd_stats", {k: stats[k] for k in keep})
    db.kv_set("news_domains", {k: news[k] for k in sorted(news)[-30:]})
    db.kv_set("nrd_done", sorted(done)[-40:])
    return n


# ------------------------------------------------------------------ phishing & malicious-URL feeds
OPENPHISH = "https://openphish.com/feed.txt"
PHISHTANK = "http://data.phishtank.com/data/online-valid.csv"
URLHAUS = "https://urlhaus.abuse.ch/downloads/csv_recent/"
THREATFOX = "https://threatfox.abuse.ch/export/json/recent/"
CLICKFIX = re.compile(r"clickfix|clearfake|fake-?captcha|fakecaptcha|iclickfix|kongtuke|smartapesg", re.I)
PT_ALIASES = {"amazon.com": "amazon.com", "facebook": "meta.com", "google": "abc.xyz", "microsoft": "microsoft.com", "apple": "apple.com",
              "hsbc group": "hsbc.com", "bank of america corporation": "bankofamerica.com", "at&t": "att.com", "at&amp;t": "att.com",
              "societe generale": "societegenerale.com", "société générale": "societegenerale.com", "american express": "americanexpress.com"}


@collector(Source(
    id="phish_feeds", name="Phishing & malicious-URL feeds", category="Attack surface",
    publisher="OpenPhish · PhishTank (Cisco Talos) · abuse.ch URLhaus & ThreatFox", homepage="https://phishtank.org/",
    url=OPENPHISH, cadence_min=360, licence="OpenPhish community · PhishTank free (attribution) · abuse.ch: non-commercial",
    feeds=[{"publisher": "PhishTank", "url": PHISHTANK}, {"publisher": "URLhaus", "url": URLHAUS}, {"publisher": "ThreatFox", "url": THREATFOX}],
    notes="Phishing URLs on lookalikes of monitored brands, PhishTank's targeted-brand label, and organisation-owned hostnames listed as "
          "serving malware or ClickFix / fake-CAPTCHA lures (a compromised website). Only matches are stored."))
def collect_phish() -> int:
    bi = BrandIndex(_orgs())
    by_dom = {reg_domain(o["domain"]): o["id"] for o in _orgs() if o.get("domain")}
    rows, phish_regs, errs = [], set(), []
    clickfix = Counter()
    now = db.now()

    def add(value, typ, host, source, publisher, url, tags, context, published=None):
        own = bi.owner(host)
        rd = reg_domain(host)
        if own and rd not in PLATFORM:
            tagset = tags + ["own-site"]
        else:
            m = bi.match(host)
            if not m:
                return
            tagset = tags + ["brand"]
            context = f"{context} · {m['how']}"
        rows.append({"id": ioc_id(value, typ, source), "value": value, "type": typ, "kind": "feed", "source_id": "phish_feeds",
                     "publisher": publisher, "report_title": publisher, "report_url": url, "published": published or now,
                     "context": context[:200], "tags": sorted(set(tagset))})

    try:
        for u in net.get_text(OPENPHISH, timeout=40).split():
            h = host_of(u)
            phish_regs.add(reg_domain(h))
            add(u, "url", h, "openphish", "OpenPhish", "https://openphish.com/", ["phishing"], "OpenPhish community feed")
    except Exception as e:
        errs.append(f"OpenPhish: {e}")
    targets = defaultdict(lambda: {"n": 0, "latest": "", "sample": None, "target": None})
    try:
        txt = net.cached(PHISHTANK, 5.5, timeout=180, headers={"User-Agent": "phishtank/aegis-console"})
        for r in csv.DictReader(io.StringIO(txt)):
            if r.get("verified") != "yes" or r.get("online") != "yes":
                continue
            h = host_of(r.get("url", ""))
            phish_regs.add(reg_domain(h))
            tgt = (r.get("target") or "").strip()
            if tgt and tgt != "Other":
                key = PT_ALIASES.get(tgt.lower())
                oid = by_dom.get(key) if key else matcher.name(tgt)
                if oid:
                    t = targets[oid]
                    t["n"] += 1
                    t["target"] = tgt
                    if (r.get("verification_time") or "") > t["latest"]:
                        t["latest"], t["sample"] = r.get("verification_time") or "", r.get("phish_detail_url")
            if (r.get("verification_time") or "")[:10] >= (date.today() - timedelta(days=14)).isoformat():
                add(r["url"], "url", h, "phishtank", "PhishTank", r.get("phish_detail_url") or "https://phishtank.org/", ["phishing"],
                    f"PhishTank verified phish (target: {tgt or 'n/a'})", (r.get("verification_time") or "")[:19] + "Z")
    except Exception as e:
        errs.append(f"PhishTank: {e}")
    try:
        lines = [l for l in net.cached(URLHAUS, 0.9, timeout=120).splitlines() if l and not l.startswith("#")]
        for r in csv.reader(lines):
            if len(r) < 8:
                continue
            _id, added, url, status, _last, threat, tags, link = r[:8]
            h = host_of(url)
            if CLICKFIX.search(tags):
                clickfix["URLhaus"] += 1
            tg = ["clickfix"] if CLICKFIX.search(tags) else ["malware"]
            add(url, "url", h, "urlhaus", "abuse.ch URLhaus", link, tg + [t for t in tags.split(",") if t and t != "None"][:5],
                f"URLhaus {threat} ({status}) tags: {tags}", added.replace(" ", "T") + "Z")
    except Exception as e:
        errs.append(f"URLhaus: {e}")
    try:
        js = net.cached_json(THREATFOX, 0.9, timeout=120)
        for _k, lst in (js or {}).items():
            for i in lst:
                v, t = i.get("ioc_value") or "", i.get("ioc_type") or ""
                if t not in ("domain", "url"):
                    continue
                h = host_of(v)
                tags = (i.get("tags") or "") + "," + (i.get("malware_printable") or "")
                cf = bool(CLICKFIX.search(tags))
                if cf:
                    clickfix["ThreatFox"] += 1
                add(v, "domain" if t == "domain" else "url", h, "threatfox", "abuse.ch ThreatFox", f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{h}",
                    (["clickfix"] if cf else ["malware"]) + (["compromised"] if i.get("is_compromised") else []),
                    f"ThreatFox {i.get('threat_type')} · {i.get('malware_printable')} · confidence {i.get('confidence_level')}",
                    (i.get("first_seen_utc") or "").replace(" ", "T") + "Z")
    except Exception as e:
        errs.append(f"ThreatFox: {e}")
    store_iocs(rows)
    db.kv_set("phishtank_targets", {k: v for k, v in targets.items()})
    db.kv_set("phish_regdomains", sorted(d for d in phish_regs if d)[:150000])
    db.kv_set("clickfix_stats", {"at": now, **clickfix})
    if errs:
        print("[phish_feeds]", "; ".join(errs)[:300])
        if len(errs) >= 4:
            raise RuntimeError("; ".join(errs)[:300])
    return len(rows) + sum(t["n"] for t in targets.values())


# ------------------------------------------------------------------ liveness of brand-matched domains
@collector(Source(
    id="ioc_liveness", name="Lookalike liveness (DNS-over-HTTPS)", category="Attack surface", publisher="Google & Cloudflare DNS-over-HTTPS",
    homepage="https://dns.google/", url="https://dns.google/resolve", cadence_min=60, licence="Free public resolvers",
    notes="Resolves brand-matched lookalike domains (A, MX, NS) through public resolvers — the domains themselves are never contacted. "
          "Up to 150 checks per run; each domain is re-checked daily. Same NS/MX as the brand's own domain = defensive registration."))
def collect_liveness() -> int:
    from aegis.collectors.surface import doh
    stale = db.now()[:10]
    rows = db.q("SELECT id, value, type, attrs FROM ioc WHERE org_id IS NOT NULL AND match IN ('brand','nrd','phish-brand') AND type IN ('domain','url') "
                "ORDER BY published DESC LIMIT 3000")
    todo = [r for r in rows if ((r.get("attrs") or {}).get("checked") or "")[:10] < stale][:150]
    c = db.conn()
    for r in todo:
        h = host_of(r["value"])
        a = [x for x in doh(h, "A")[0] if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", x)]
        mx = [m.split()[-1].rstrip(".").lower() for m in doh(reg_domain(h), "MX")[0] if m]
        ns = [x.rstrip(".").lower() for x in doh(reg_domain(h), "NS")[0]]
        at = {**(r.get("attrs") or {}), "a": a[:6], "mx": mx[:4], "ns": ns[:4], "checked": db.now()}
        c.execute("UPDATE ioc SET attrs=? WHERE id=?", (json.dumps(at), r["id"]))
    c.commit()
    return len(todo)
