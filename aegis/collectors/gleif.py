"""Corporate group structure from GLEIF Level 2 (CC0): ultimate parent and direct subsidiaries per organisation.
Subsidiary names feed the matcher so a leak-site listing of a subsidiary links back to the group."""
from datetime import datetime, timedelta, timezone

from aegis import db, net
from aegis.registry import Source, collector

API = "https://api.gleif.org/api/v1/lei-records"


@collector(Source(
    id="gleif", name="GLEIF group structure (Level 2)", category="Registry", publisher="Global Legal Entity Identifier Foundation",
    homepage="https://search.gleif.org/", url=API, cadence_min=60, licence="CC0",
    notes="Direct subsidiaries and ultimate parent of every organisation with an LEI. 25 organisations per run, refreshed weekly."))
def collect_gleif() -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    done = db.kv_get("gleif_done", {}) or {}
    todo = [o for o in db.q("SELECT id, name, lei FROM org WHERE lei IS NOT NULL ORDER BY name") if done.get(o["id"], "") < cutoff][:25]
    n = 0
    for o in todo:
        rows = []
        try:
            js = net.get_json(f"{API}/{o['lei']}/direct-children", params={"page[size]": 200}, timeout=30, ok_404=True) or {}
            for c in js.get("data", []):
                ent = (c.get("attributes") or {}).get("entity") or {}
                addr = ent.get("headquartersAddress") or ent.get("legalAddress") or {}
                rows.append({"org_id": o["id"], "kind": "subsidiary", "value": c["id"], "source_id": "gleif",
                             "attrs": {"name": (ent.get("legalName") or {}).get("name"), "country": addr.get("country"),
                                       "city": addr.get("city"), "url": f"https://search.gleif.org/#/record/{c['id']}"},
                             "first_seen": db.now(), "last_seen": db.now()})
            total = ((js.get("meta") or {}).get("pagination") or {}).get("total", len(rows))
            p = net.get_json(f"{API}/{o['lei']}/ultimate-parent", timeout=30, ok_404=True)
            if p and p.get("data"):
                ent = (p["data"].get("attributes") or {}).get("entity") or {}
                rows.append({"org_id": o["id"], "kind": "parent", "value": p["data"]["id"], "source_id": "gleif",
                             "attrs": {"name": (ent.get("legalName") or {}).get("name"), "country": (ent.get("legalAddress") or {}).get("country"),
                                       "url": f"https://search.gleif.org/#/record/{p['data']['id']}"},
                             "first_seen": db.now(), "last_seen": db.now()})
            db.x("DELETE FROM asset WHERE org_id=? AND kind IN ('subsidiary','parent')", (o["id"],))
            db.upsert("asset", rows)
            db.upsert("asset", {"org_id": o["id"], "kind": "group", "value": o["lei"], "source_id": "gleif",
                                "attrs": {"direct_children": total, "url": f"https://search.gleif.org/#/record/{o['lei']}"},
                                "first_seen": db.now(), "last_seen": db.now()})
            done[o["id"]] = db.now()
            n += 1
        except Exception as e:
            print("[gleif]", o["name"], e)
    db.kv_set("gleif_done", done)
    return n
