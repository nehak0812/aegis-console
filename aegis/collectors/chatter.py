"""Open practitioner & social chatter. Aggregated to topic/organisation — author identities are never stored."""
import re

from aegis import db, net
from aegis.collectors.rss import enrich, ingest_feed, item_id, store_items, strip_html
from aegis.guard import redact
from aegis.registry import Source, collector

TOPICS = ["ransomware", "data breach", "cyberattack", "zero-day", "leaked database", "ddos attack", "infostealer", "initial access"]
SIGNAL = re.compile(r"ransom|breach|leak|hack|attack|exploit|cve-|zero-day|0day|vulnerab|stealer|ddos|phish|malware|compromis|outage|extort", re.I)


def _item(source_id, publisher, text, url, published):
    text = redact(strip_html(text, 600))
    if not text or not SIGNAL.search(text):
        return None
    title = text[:220] + ("…" if len(text) > 220 else "")
    return {"id": item_id(url), "source_id": source_id, "kind": "chatter", "publisher": publisher, "pub_type": "Community",
            "title": title, "summary": text, "url": url, "published": published, "fetched": db.now(), **enrich(title, text)}


@collector(Source(
    id="hn", name="Hacker News (Algolia search)", category="Chatter", publisher="Hacker News / Algolia",
    homepage="https://news.ycombinator.com", url="https://hn.algolia.com/api/v1/search_by_date", cadence_min=60,
    licence="Public API", notes="Practitioner discussion of breaches, exploits and outages."))
def collect_hn() -> int:
    rows = []
    for t in TOPICS[:6]:
        js = net.get_json("https://hn.algolia.com/api/v1/search_by_date", params={"query": t, "tags": "story", "hitsPerPage": 40}, timeout=30)
        for h in js.get("hits", []):
            url = f"https://news.ycombinator.com/item?id={h.get('objectID')}"
            r = _item("hn", "Hacker News", h.get("title") or "", url, h.get("created_at"))
            if r:
                r["summary"] = f"{h.get('points') or 0} points · {h.get('num_comments') or 0} comments · links to {h.get('url') or 'discussion'}"
                rows.append(r)
    return store_items(rows)


@collector(Source(
    id="bluesky", name="Bluesky public search", category="Chatter", publisher="Bluesky (AT Protocol AppView)",
    homepage="https://bsky.app", url="https://api.bsky.app/xrpc/app.bsky.feed.searchPosts", cadence_min=60,
    licence="Public API — posts are public",
    notes="Disabled: the public search endpoint returned HTTP 403 to unauthenticated clients on 2026-09-10. "
          "Re-enable once an app password is configured."), enabled=False)
def collect_bluesky() -> int:
    rows = []
    for t in TOPICS:
        js = net.get_json("https://api.bsky.app/xrpc/app.bsky.feed.searchPosts", params={"q": t, "sort": "latest", "limit": 50}, timeout=30)
        for p in js.get("posts", []):
            uri = p.get("uri", "")
            handle = (p.get("author") or {}).get("handle", "")
            rkey = uri.rsplit("/", 1)[-1]
            url = f"https://bsky.app/profile/{handle}/post/{rkey}" if handle else "https://bsky.app"
            r = _item("bluesky", "Bluesky", (p.get("record") or {}).get("text", ""), url, p.get("indexedAt"))
            if r:
                rows.append(r)
    return store_items(rows)


@collector(Source(
    id="mastodon", name="Mastodon security hashtags", category="Chatter", publisher="mastodon.social (federated)",
    homepage="https://mastodon.social", url="https://mastodon.social/api/v1/timelines/tag/ransomware", cadence_min=60,
    licence="Public API — posts are public", notes="#ransomware #databreach #cve #threatintel timelines (federated). Author handles are not stored."))
def collect_mastodon() -> int:
    rows = []
    for tag in ["ransomware", "databreach", "cve", "threatintel", "cybersecurity", "infosec"]:
        js = net.get_json(f"https://mastodon.social/api/v1/timelines/tag/{tag}", params={"limit": 40}, timeout=30)
        for p in js or []:
            r = _item("mastodon", "Mastodon", p.get("content", ""), p.get("url") or p.get("uri"), p.get("created_at"))
            if r:
                rows.append(r)
    return store_items(rows)


REDDIT = ["cybersecurity", "netsec", "sysadmin", "blueteamsec", "msp"]


@collector(Source(
    id="reddit", name="Reddit security communities (RSS)", category="Chatter", publisher="Reddit",
    homepage="https://www.reddit.com/r/cybersecurity", cadence_min=90, licence="Public RSS",
    feeds=[{"publisher": f"r/{s}", "url": f"https://www.reddit.com/r/{s}/new/.rss"} for s in REDDIT],
    notes="r/cybersecurity, r/netsec, r/sysadmin, r/blueteamsec, r/msp — incident chatter from defenders and MSPs."))
def collect_reddit() -> int:
    n = 0
    for s in REDDIT:
        try:
            n += ingest_feed("reddit", f"https://www.reddit.com/r/{s}/new/.rss", f"Reddit r/{s}", "Community", "chatter", 40, SIGNAL)
        except Exception as e:
            print("[reddit]", s, e)
    return n
