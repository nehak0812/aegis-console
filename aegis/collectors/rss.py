"""Generic RSS/Atom ingestion into the `item` table with deterministic enrichment (themes, CVEs, sectors, org mentions)."""
import calendar
import hashlib
import html
import re
from datetime import datetime, timezone

import feedparser

from aegis import db, net
from aegis.guard import redact
from aegis.intel.atlas import atlas_for
from aegis.intel.entities import matcher
from aegis.intel.themes import cves_for, sectors_for, themes_for

_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")


def strip_html(s: str | None, n: int = 700) -> str:
    s = html.unescape(_TAG.sub(" ", s or ""))
    s = _WS.sub(" ", s).strip()
    return s[:n] + ("…" if len(s) > n else "")


def iso(struct) -> str | None:
    if not struct:
        return None
    try:
        dt = datetime.fromtimestamp(calendar.timegm(struct), tz=timezone.utc)
    except (OverflowError, ValueError, TypeError):
        return None
    # some publishers stamp future dates — clamp to now so timelines stay honest
    return min(dt, datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")


def entry_date(e) -> str | None:
    d = iso(e.get("published_parsed") or e.get("updated_parsed"))
    if d:
        return d
    raw = (e.get("published") or e.get("updated") or "").strip()
    for fmt in ("%b %d, %Y %H:%M:%S%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%d %b %Y %H:%M:%S %z", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(raw, fmt)
            dt = dt.replace(tzinfo=dt.tzinfo or timezone.utc).astimezone(timezone.utc)
            return min(dt, datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    return None


def item_id(url: str, title: str = "") -> str:
    return hashlib.sha1((url or title).strip().encode()).hexdigest()[:24]


def enrich(title: str, summary: str) -> dict:
    text = f"{title}. {summary}"
    return {
        "themes": themes_for(text),
        "entities": {"cves": cves_for(text), "sectors": sectors_for(text), "atlas": atlas_for(text)},
        "org_ids": matcher.mentions(title) or matcher.mentions(summary[:400]),
    }


def store_items(rows: list[dict]) -> int:
    return db.upsert("item", rows, keep=("fetched", "incident_id", "severity", "severity_rule"))


def ingest_feed(source_id: str, url: str, publisher: str, pub_type: str, kind: str, limit: int = 60,
                filter_rx: re.Pattern | None = None, use_curl: bool = False) -> int:
    if use_curl:
        content = net.get_curl(url)
    else:
        content = net.get(url, headers={"Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.8"}, timeout=25).content
    feed = feedparser.parse(content)
    if feed.bozo and not feed.entries:
        raise ValueError(f"unparseable feed: {getattr(feed, 'bozo_exception', '')}")
    rows = []
    fetched = db.now()
    for e in feed.entries[:limit]:
        link = e.get("link") or ""
        title = strip_html(e.get("title"), 300)
        if not title or not link:
            continue
        summary = redact(strip_html(e.get("summary") or e.get("description") or (e.get("content") or [{}])[0].get("value", "")))
        if filter_rx and not filter_rx.search(f"{title} {summary}"):
            continue
        published = entry_date(e) or fetched
        rows.append({"id": item_id(link, title), "source_id": source_id, "kind": kind, "publisher": publisher,
                     "pub_type": pub_type, "title": title, "summary": summary, "url": link,
                     "published": published, "fetched": fetched, **enrich(title, summary)})
    return store_items(rows)
