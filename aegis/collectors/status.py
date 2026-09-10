"""Third-party provider service incidents (public status pages) — the 'shared provider' side of linkage."""
from datetime import datetime, timedelta, timezone

import feedparser

from aegis import db, net
from aegis.collectors.rss import entry_date, item_id, store_items, strip_html
from aegis.registry import Source, collector

STATUSPAGE = [  # vendor, Statuspage v2 base
    ("GitHub", "https://www.githubstatus.com"), ("Cloudflare", "https://www.cloudflarestatus.com"),
    ("Atlassian", "https://status.atlassian.com"), ("Zoom", "https://status.zoom.us"),
    ("Datadog", "https://status.datadoghq.com"), ("Twilio", "https://status.twilio.com"),
    ("Snowflake", "https://status.snowflake.com"), ("Dropbox", "https://status.dropbox.com"),
    ("Box", "https://status.box.com"), ("Akamai", "https://www.akamaistatus.com"),
    ("DigitalOcean", "https://status.digitalocean.com"), ("HubSpot", "https://status.hubspot.com"),
]
RSS = [("AWS", "https://status.aws.amazon.com/rss/all.rss"), ("Zscaler", "https://trust.zscaler.com/rss-feed")]
IMPACT = {"critical": "high", "major": "medium", "minor": "low", "none": "low", "maintenance": "low"}


@collector(Source(
    id="status_pages", name="Provider status pages", category="Service status",
    publisher="GitHub, Cloudflare, Atlassian, Zoom, Datadog, Twilio, Snowflake, Slack, Salesforce, Google Cloud, AWS, Zscaler, …",
    homepage="https://www.githubstatus.com", cadence_min=15, licence="Public status pages",
    feeds=[{"publisher": v, "url": u + "/api/v2/incidents.json"} for v, u in STATUSPAGE] + [{"publisher": v, "url": u} for v, u in RSS]
    + [{"publisher": "Slack", "url": "https://slack-status.com/api/v2.0.0/history"},
       {"publisher": "Salesforce", "url": "https://api.status.salesforce.com/v1/incidents"},
       {"publisher": "Google Cloud", "url": "https://status.cloud.google.com/incidents.json"}],
    notes="Outages and degradations at shared SaaS / cloud / CDN providers. Linked to organisations whose DNS shows they depend on the provider."))
def collect_status() -> int:
    since = datetime.now(timezone.utc) - timedelta(days=30)
    rows, errs = [], []

    def add(vendor, title, url, published, impact, summary=""):
        if not published or published < since.strftime("%Y-%m-%dT%H:%M:%SZ"):
            return
        rows.append({"id": item_id(url + title + published), "source_id": "status_pages", "kind": "status", "publisher": vendor,
                     "pub_type": "Service status", "title": f"{vendor}: {strip_html(title, 200)}", "summary": strip_html(summary, 400),
                     "url": url, "published": published, "fetched": db.now(), "themes": ["Resilience & outages"],
                     "entities": {"vendors": [vendor], "impact": impact}, "org_ids": [],
                     "severity": IMPACT.get(impact or "none", "low"), "severity_rule": "I-INFO"})

    def z(ts):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (AttributeError, ValueError):
            return None

    for vendor, base in STATUSPAGE:
        try:
            for i in (net.get_json(base + "/api/v2/incidents.json", timeout=20) or {}).get("incidents", [])[:25]:
                upd = (i.get("incident_updates") or [{}])[0].get("body", "")
                add(vendor, i.get("name", ""), i.get("shortlink") or base, z(i.get("created_at")), i.get("impact"), upd)
        except Exception as e:
            errs.append(f"{vendor}: {e}")
    for vendor, url in RSS:
        try:
            for e in feedparser.parse(net.get(url, timeout=20).content).entries[:25]:
                add(vendor, e.get("title", ""), e.get("link") or url, entry_date(e), "minor", e.get("summary", ""))
        except Exception as e:
            errs.append(f"{vendor}: {e}")
    try:
        js = net.get_json("https://slack-status.com/api/v2.0.0/history", timeout=20) or []
        for i in (js if isinstance(js, list) else [])[:25]:
            add("Slack", i.get("title", ""), i.get("url") or "https://slack-status.com", z(i.get("date_created")),
                "major" if i.get("type") == "outage" else "minor")
    except Exception as e:
        errs.append(f"Slack: {e}")
    try:
        for i in (net.get_json("https://api.status.salesforce.com/v1/incidents", params={"limit": 25}, timeout=20) or [])[:25]:
            msg = ((i.get("IncidentEvents") or [{}])[0] or {}).get("message", "")
            add("Salesforce", f"Incident {i.get('id')} ({', '.join(i.get('serviceKeys') or [])})",
                f"https://status.salesforce.com/incidents/{i.get('id')}", z(i.get("createdAt")),
                "major" if i.get("isCore") else "minor", msg)
    except Exception as e:
        errs.append(f"Salesforce: {e}")
    try:
        for i in (net.get_json("https://status.cloud.google.com/incidents.json", timeout=20) or [])[:25]:
            add("Google Cloud", i.get("external_desc", ""), "https://status.cloud.google.com/" + (i.get("uri") or ""),
                z(i.get("begin")), {"high": "major", "medium": "minor", "low": "minor"}.get(i.get("severity"), "minor"))
    except Exception as e:
        errs.append(f"GCP: {e}")
    if errs:
        print("[status_pages]", "; ".join(errs)[:400])
    return store_items(rows)
