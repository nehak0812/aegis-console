"""Adversary knowledge base: MISP threat-actor galaxy (incl. CrowdStrike names) + MITRE ATT&CK groups
(tools, techniques) + CrowdStrike Adversary Universe (public targeting attributes). One alias index."""
import html
import json
import re

from aegis import db, net
from aegis.collectors.rss import strip_html
from aegis.registry import Source, collector

MISP_TA = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
ATTACK = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
CS_ADV = "https://www.crowdstrike.com/en-us/adversaries/"

# CrowdStrike naming convention → (origin ISO2, motivation)
CS_SUFFIX = {"BEAR": ("RU", "State-nexus"), "PANDA": ("CN", "State-nexus"), "KITTEN": ("IR", "State-nexus"),
             "CHOLLIMA": ("KP", "State-nexus"), "TIGER": ("IN", "State-nexus"), "LEOPARD": ("PK", "State-nexus"),
             "BUFFALO": ("VN", "State-nexus"), "CRANE": ("KR", "State-nexus"), "BOA": ("VE", "State-nexus"),
             "BISON": ("BY", "State-nexus"), "WOLF": ("TR", "State-nexus"), "OCELOT": ("CO", "State-nexus"),
             "SPHINX": ("EG", "State-nexus"), "HAWK": ("SY", "State-nexus"), "SAIGA": ("KZ", "State-nexus"),
             "LYNX": ("GE", "State-nexus"), "SPIDER": (None, "eCrime"), "JACKAL": (None, "Hacktivist")}
# Microsoft weather naming
MS_SUFFIX = {"Blizzard": ("RU", "State-nexus"), "Typhoon": ("CN", "State-nexus"), "Sandstorm": ("IR", "State-nexus"),
             "Sleet": ("KP", "State-nexus"), "Cyclone": ("VN", "State-nexus"), "Rain": ("LB", "State-nexus"),
             "Hail": ("KR", "State-nexus"), "Dust": ("TR", "State-nexus"), "Tempest": (None, "eCrime"),
             "Flood": (None, "Influence operations")}
CS_RX = re.compile(r"^([A-Za-z]+)\s+(" + "|".join(CS_SUFFIX) + r")$", re.I)
MS_RX = re.compile(r"^([A-Z][a-z]+)\s+(" + "|".join(MS_SUFFIX) + r")$")


def key(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _cs_rank(n: str) -> int:
    """Prefer state-nexus CrowdStrike names (e.g. APT41 → Wicked PANDA over its eCrime alias Wicked SPIDER)."""
    m = CS_RX.match(n.strip())
    return 9 if not m else (1 if m.group(2).upper() in ("SPIDER", "JACKAL") else 0)


def cs_name(names) -> str | None:
    c = sorted((n for n in names if CS_RX.match(n.strip())), key=_cs_rank)
    return c[0].strip().title() if c else None


def origin_from_names(names) -> tuple[str | None, str | None]:
    for n in sorted(names, key=_cs_rank):
        m = CS_RX.match(n.strip())
        if m:
            return CS_SUFFIX[m.group(2).upper()]
    for n in names:
        m = MS_RX.match(n.strip())
        if m:
            return MS_SUFFIX[m.group(2)]
    return None, None


CRIME_RX = re.compile(r"ransomware|extort|financially motivated|cybercrim|criminal|data theft|leak site|infostealer|carding|fraud|banking trojan|access broker|\bRaaS\b", re.I)
HACKTIVIST_RX = re.compile(r"hacktivis|\bDDoS\b|defac|pro-(russian|palestinian|iranian|ukrainian)", re.I)
STATE_RX = re.compile(r"espionage|state[- ](sponsored|backed)|nation[- ]state|government-sponsored|intelligence (service|agency)|\bAPT\b|military", re.I)


def classify(a: dict) -> str:
    """Kind from evidence, not from a default: naming convention first, then the description."""
    desc = a.get("description") or ""
    mot = a.get("motivation") or ""
    if mot == "Hacktivist" or (HACKTIVIST_RX.search(desc) and not STATE_RX.search(desc)):
        return "hacktivist"
    if mot == "eCrime":
        return "ecrime"
    if mot == "State-nexus" or STATE_RX.search(desc) or a.get("attack_id") and not CRIME_RX.search(desc):
        return "apt"
    if CRIME_RX.search(desc):
        return "ecrime"
    return "apt" if a.get("origin") else "unclassified"


@collector(Source(
    id="actors", name="Adversary knowledge base", category="Threat intel",
    publisher="MISP galaxy · MITRE ATT&CK · CrowdStrike Adversary Universe", homepage="https://attack.mitre.org/groups/",
    url=MISP_TA, cadence_min=1440, licence="MISP: CC0 · ATT&CK: MITRE terms (free, attribution) · CrowdStrike: public web page",
    feeds=[{"publisher": "MITRE ATT&CK STIX", "url": ATTACK}, {"publisher": "CrowdStrike Adversary Universe", "url": CS_ADV}],
    notes="1,000+ threat actors with aliases across vendor naming schemes (CrowdStrike animals, Microsoft weather, MITRE G-IDs), "
          "origin, targeted sectors/countries, tools and techniques."))
def collect_actors() -> int:
    actors: dict[str, dict] = {}
    alias: dict[str, str] = {}

    def index(aid, names):
        for n in names:
            k = key(n)
            if len(k) >= 3:
                alias.setdefault(k, aid)

    # 1. MISP threat actors
    misp = json.loads(net.cached(MISP_TA, 24))
    for v in misp.get("values", []):
        meta = v.get("meta") or {}
        names = [v["value"]] + list(meta.get("synonyms") or [])
        aid = "ta-" + (v.get("uuid") or key(v["value"]))[:12]
        o, mot = origin_from_names(names)
        incident = meta.get("cfr-type-of-incident") or []
        motivation = mot or ("Espionage" if any("spionage" in str(i) for i in incident) else (str(incident[0]) if incident else None))
        actors[aid] = {"id": aid, "name": v["value"], "aliases": sorted(set(names[1:]))[:40], "crowdstrike": cs_name(names),
                       "origin": (meta.get("country") or o), "motivation": motivation,
                       "sectors": sorted(set((meta.get("cfr-target-category") or []) + (meta.get("targeted-sector") or []))),
                       "countries": sorted(set(meta.get("cfr-suspected-victims") or [])),
                       "description": strip_html(v.get("description"), 900), "refs": (meta.get("refs") or [])[:8],
                       "kind": "hacktivist" if mot == "Hacktivist" else ("ecrime" if mot == "eCrime" else "apt"),
                       "misp_uuid": v.get("uuid"), "source_id": "actors"}
        index(aid, names)

    # 2. MITRE ATT&CK groups, tools, techniques
    bundle = json.loads(net.cached(ATTACK, 24 * 7, timeout=300))
    objs = {o["id"]: o for o in bundle["objects"] if not o.get("revoked") and not o.get("x_mitre_deprecated")}
    uses: dict[str, list] = {}
    for o in objs.values():
        if o.get("type") == "relationship" and o.get("relationship_type") == "uses" and o["source_ref"].startswith("intrusion-set"):
            uses.setdefault(o["source_ref"], []).append(o["target_ref"])
    for o in objs.values():
        if o.get("type") != "intrusion-set":
            continue
        ext = next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), {})
        names = [o["name"]] + list(o.get("aliases") or [])
        aid = next((alias[key(n)] for n in names if key(n) in alias), None)
        tools, techs = [], []
        for t in uses.get(o["id"], []):
            tgt = objs.get(t)
            if not tgt:
                continue
            if tgt["type"] in ("malware", "tool"):
                tools.append(tgt["name"])
            elif tgt["type"] == "attack-pattern":
                tid = next((r.get("external_id") for r in tgt.get("external_references", []) if r.get("source_name") == "mitre-attack"), "")
                techs.append(f"{tid} {tgt['name']}")
        rec = {"attack_id": ext.get("external_id"), "tools": sorted(set(tools))[:40], "techniques": sorted(set(techs))[:60]}
        if aid:
            a = actors[aid]
            a.update(rec)
            a["aliases"] = sorted(set(a["aliases"]) | set(n for n in names if n != a["name"]))[:40]
            a["crowdstrike"] = a["crowdstrike"] or cs_name(names)
            a["refs"] = [ext.get("url")] + [r for r in a["refs"] if r != ext.get("url")] if ext.get("url") else a["refs"]
        else:
            aid = "attack-" + (ext.get("external_id") or key(o["name"])).lower()
            orig, mot = origin_from_names(names)
            actors[aid] = {"id": aid, "name": o["name"], "aliases": sorted(set(names[1:])), "crowdstrike": cs_name(names),
                           "origin": orig, "motivation": mot, "sectors": [], "countries": [],
                           "description": strip_html(o.get("description"), 900), "refs": [ext.get("url")] if ext.get("url") else [],
                           "kind": "ecrime" if mot == "eCrime" else "apt", "source_id": "actors", **rec}
        index(aid, names)

    # 3. CrowdStrike Adversary Universe — public page, one request per day at most
    try:
        page = net.get_text(CS_ADV, timeout=60)
        for li in re.finditer(r"<li[^>]*class=\"[^\"]*adversary-item[^\"]*\"[^>]*>", page):
            tag = li.group(0)

            def attr(n):
                m = re.search(n + r"\s*=\s*(['\"])(.*?)\1", tag, re.S)
                return html.unescape(m.group(2)) if m else ""
            slug = attr("data-modal-path").strip("/").rsplit("/", 1)[-1]
            if not slug:
                continue
            name = slug.replace("-", " ").title()
            try:
                countries = json.loads(attr("data-target-countries") or "[]")
            except ValueError:
                countries = []
            inds = attr("data-target-industries")
            try:
                industries = json.loads(inds) if inds.startswith("[") else [i for i in re.split(r"[,\s]+", inds) if i]
            except ValueError:
                industries = []
            cs = {"countries": countries, "industries": [i.replace("-", " ") for i in industries]}
            url = f"https://www.crowdstrike.com/en-us/adversaries/{slug}/"
            aid = alias.get(key(name))
            if aid:
                actors[aid].update({"crowdstrike": name, "cs_targets": cs, "cs_url": url})
            else:
                orig, mot = origin_from_names([name])
                aid = "cs-" + slug
                actors[aid] = {"id": aid, "name": name, "aliases": [], "crowdstrike": name, "origin": orig, "motivation": mot,
                               "sectors": [], "countries": [], "description": "", "refs": [url], "cs_targets": cs, "cs_url": url,
                               "kind": "hacktivist" if mot == "Hacktivist" else ("ecrime" if mot == "eCrime" else "apt"),
                               "source_id": "actors"}
                index(aid, [name])
    except Exception as e:
        print("[actors] CrowdStrike Adversary Universe:", e)

    for a in actors.values():
        names = [a["name"]] + list(a.get("aliases") or [])
        o, m = origin_from_names(names)
        a["origin"] = a.get("origin") or o
        a["motivation"] = m or a.get("motivation")
        a["crowdstrike"] = a.get("crowdstrike") if a.get("cs_url") else cs_name(names) or a.get("crowdstrike")
        a["kind"] = classify(a)
    return db.upsert("actor", list(actors.values()))
