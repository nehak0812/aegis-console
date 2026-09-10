"""Compromised / malicious IP feeds, intersected with each organisation's own IP footprint
(SPF-declared blocks, prefixes of ASNs registered to the org, and its resolved non-cloud IPs)."""
import bisect
import csv
import io
import ipaddress
import re

from aegis import db, net
from aegis.registry import Source, collector

FEEDS = [  # id, name, url, category, licence
    ("et_compromised", "Emerging Threats — compromised hosts", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "compromised", "ET Open (free)"),
    ("cins", "CINS Army — attacker IPs", "https://cinsscore.com/list/ci-badguys.txt", "attacker", "Free list"),
    ("blocklist_de", "blocklist.de — brute-force / attacks", "https://lists.blocklist.de/lists/all.txt", "attacker", "Free"),
    ("spamhaus_drop", "Spamhaus DROP — hijacked / criminal networks", "https://www.spamhaus.org/drop/drop_v4.json", "hijacked", "Free with attribution"),
    ("ipsum3", "IPsum (listed on ≥3 blocklists)", "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt", "attacker", "Unlicense"),
    ("feodo", "abuse.ch Feodo Tracker — botnet C2", "https://feodotracker.abuse.ch/downloads/ipblocklist.json", "c2", "abuse.ch: non-commercial"),
    ("threatfox", "abuse.ch ThreatFox — malware C2 (48h)", "https://threatfox.abuse.ch/export/csv/ip-port/recent/", "c2", "abuse.ch: non-commercial"),
    ("tor_exit", "Tor exit nodes (context)", "https://check.torproject.org/torbulkexitlist", "tor", "Public"),
]
IP_RX = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})(/\d{1,2})?$")


def _parse(fid: str, text: str) -> list[tuple[int, int]]:
    out = []

    def add(tok):
        tok = tok.strip()
        m = IP_RX.match(tok)
        if not m:
            return
        try:
            n = ipaddress.ip_network(tok, strict=False)
        except ValueError:
            return
        if n.is_private or n.is_reserved or n.prefixlen < 8:
            return
        out.append((int(n.network_address), int(n.broadcast_address)))
    if fid == "spamhaus_drop":
        for line in text.splitlines():
            m = re.search(r'"cidr"\s*:\s*"([^"]+)"', line)
            if m:
                add(m.group(1))
    elif fid == "feodo":
        for m in re.finditer(r'"ip_address"\s*:\s*"([\d.]+)"', text):
            add(m.group(1))
    elif fid == "threatfox":
        for row in csv.reader(io.StringIO("\n".join(l for l in text.splitlines() if not l.startswith("#")))):
            if len(row) > 2:
                add(row[2].strip().strip('"').split(":")[0])
    else:
        for line in text.splitlines():
            if line and not line.startswith("#"):
                add(line.split()[0])
    return out


@collector(Source(
    id="compromised_ips", name="Compromised & malicious IP feeds", category="Attack surface",
    publisher="Emerging Threats · CINS · blocklist.de · Spamhaus DROP · IPsum · abuse.ch · Tor Project", homepage="https://www.spamhaus.org/drop/",
    cadence_min=360, licence="Mixed — see each feed (abuse.ch non-commercial)",
    feeds=[{"publisher": f[1], "url": f[2]} for f in FEEDS],
    notes="Botnet C2, compromised hosts, attackers and hijacked networks. Matched only against IP space the organisation itself "
          "owns or declares — shared cloud / CDN addresses are excluded so a customer is never blamed for a neighbour."))
def collect_blocklists() -> int:
    feeds, stats = {}, {}
    for fid, name, url, cat, lic in FEEDS:
        try:
            txt = net.cached(url, 5.5, timeout=90)
            feeds[fid] = _parse(fid, txt)
            stats[fid] = {"name": name, "entries": len(feeds[fid]), "category": cat, "licence": lic, "url": url, "ok": True}
        except Exception as e:
            stats[fid] = {"name": name, "entries": 0, "category": cat, "licence": lic, "url": url, "ok": False, "error": str(e)[:160]}
    # organisation footprint intervals
    fp = []
    for a in db.q("SELECT org_id, kind, value, attrs FROM asset WHERE kind IN ('ip','prefix')"):
        at = a.get("attrs") or {}
        if a["kind"] == "ip" and (at.get("shared") and not at.get("owned")):
            continue
        try:
            n = ipaddress.ip_network(a["value"], strict=False)
        except ValueError:
            continue
        prov = at.get("provenance") or ("resolved IP (organisation ASN)" if at.get("owned") else "resolved IP (non-cloud)")
        fp.append((int(n.network_address), int(n.broadcast_address), a["org_id"], a["value"], prov))
    fp.sort()
    starts = [f[0] for f in fp]
    matches = []
    for fid, entries in feeds.items():
        for s, e in entries:
            # any footprint interval overlapping [s, e]
            i = bisect.bisect_right(starts, e)
            for j in range(i - 1, max(-1, i - 400), -1):
                fs, fe, org, val, prov = fp[j]
                if fe < s:
                    if fs < s - (1 << 24):
                        break
                    continue
                if fs <= e and s <= fe:
                    hit = str(ipaddress.ip_address(max(s, fs))) + (f"/{32 - (e - s + 1).bit_length() + 1}" if e > s else "")
                    matches.append({"org_id": org, "feed": fid, "feed_name": stats[fid]["name"], "category": stats[fid]["category"],
                                    "listed": hit, "footprint": val, "provenance": prov, "url": stats[fid]["url"]})
    counts = {}
    for f in fp:
        counts.setdefault(f[2], 0)
        counts[f[2]] += (f[1] - f[0] + 1)
    db.kv_set("blocklist_stats", stats)
    db.kv_set("compromised_matches", matches)
    db.kv_set("footprint_sizes", counts)
    db.kv_set("blocklist_checked", db.now())
    return sum(s["entries"] for s in stats.values())
