"""Passive HTTP client: allow-list enforced, polite User-Agent, retries, and an on-disk cache for bulk files."""
import contextvars
import gzip
import hashlib
import json
import os
import threading
import time
from typing import Any

import httpx

from aegis import CACHE_DIR
from aegis.guard import check_url

# the host a collector asked for; redirect hops may stay on that site even when the exact host is not listed
_origin: contextvars.ContextVar[str | None] = contextvars.ContextVar("aegis_origin", default=None)


def _site(host: str) -> str:
    parts = (host or "").lower().rstrip(".").split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "gov", "ac", "org", "net") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _redirect_guard(request: httpx.Request) -> None:
    """Every outbound request — including each redirect hop — must be allow-listed, or stay on the same site as the URL
    the collector asked for. Without this, follow_redirects could reach a host the allow-list never approved."""
    try:
        check_url(str(request.url))
    except Exception:
        origin = _origin.get()
        if not origin or _site(request.url.host) != _site(origin):
            raise

CONTACT = os.environ.get("AEGIS_CONTACT", "aegis-console@localhost.localdomain")
UA = f"AEGIS-Console/2.0 (open-source cyber risk research; {CONTACT})"

_client_lock = threading.Lock()
_client: httpx.Client | None = None
_host_last: dict[str, float] = {}
_host_lock = threading.Lock()
# minimum seconds between requests to the same host (politeness / published limits)
HOST_INTERVAL = {"crt.sh": 3.0, "www.sec.gov": 0.15, "efts.sec.gov": 0.15, "data.sec.gov": 0.15,
                 "query.wikidata.org": 1.0, "api.gleif.org": 0.3, "internetdb.shodan.io": 0.25,
                 "stat.ripe.net": 0.2, "cavalier.hudsonrock.com": 1.5, "api.ransomware.live": 1.0,
                 "www.ransomlook.io": 1.0, "haveibeenpwned.com": 1.6, "www.reddit.com": 7.0,
                 "api.certspotter.com": 2.0}


def client() -> httpx.Client:
    global _client
    with _client_lock:
        if _client is None:
            _client = httpx.Client(timeout=httpx.Timeout(30.0, connect=10.0), follow_redirects=True,
                                   headers={"User-Agent": UA, "Accept-Encoding": "gzip, deflate"},
                                   limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
                                   event_hooks={"request": [_redirect_guard]})
        return _client


def _pace(host: str) -> None:
    gap = HOST_INTERVAL.get(host, 0.0)
    if not gap:
        return
    with _host_lock:
        last = _host_last.get(host, 0.0)
        wait = last + gap - time.time()
        _host_last[host] = max(time.time(), last + gap)
    if wait > 0:
        time.sleep(wait)


def get(url: str, *, params: dict | None = None, headers: dict | None = None, timeout: float | None = None,
        retries: int = 2, ok_404: bool = False) -> httpx.Response | None:
    check_url(url)
    host = httpx.URL(url).host
    err: Exception | None = None
    tok = _origin.set(host)
    try:
        for attempt in range(retries + 1):
            _pace(host)
            try:
                r = client().get(url, params=params, headers=headers, timeout=timeout or 30.0)
                if r.status_code == 404 and ok_404:
                    return None
                if r.status_code in (429, 502, 503, 504) and attempt < retries:
                    time.sleep(2 * (attempt + 1))
                    continue
                r.raise_for_status()
                return r
            except (httpx.HTTPError,) as e:
                err = e
                if attempt < retries:
                    time.sleep(1.5 * (attempt + 1))
    finally:
        _origin.reset(tok)
    raise err  # type: ignore[misc]


def post(url: str, *, data: dict | None = None, json_body: Any = None, headers: dict | None = None,
         timeout: float = 60.0) -> httpx.Response:
    """POST only for query endpoints of public data services (Wikidata SPARQL, USAspending) — never to monitored orgs."""
    check_url(url)
    _pace(httpx.URL(url).host)
    tok = _origin.set(httpx.URL(url).host)
    try:
        r = client().post(url, data=data, json=json_body, headers=headers, timeout=timeout)
    finally:
        _origin.reset(tok)
    r.raise_for_status()
    return r


def get_curl(url: str, timeout: int = 40) -> bytes:
    """Some government CDNs (CISA/Akamai) reject python TLS fingerprints; curl with a plain UA is accepted."""
    import subprocess
    check_url(url)
    out = subprocess.run(["curl", "-sSL", "--fail", "--max-time", str(timeout), "-A", "Mozilla/5.0 (AEGIS-Console)", url],
                         capture_output=True, timeout=timeout + 5)
    if out.returncode != 0:
        raise RuntimeError(f"curl exit {out.returncode}: {out.stderr.decode(errors='replace')[:200]}")
    return out.stdout


def get_json(url: str, **kw) -> Any:
    r = get(url, **kw)
    return None if r is None else r.json()


def get_text(url: str, **kw) -> str:
    r = get(url, **kw)
    return "" if r is None else r.text


def cached(url: str, max_age_h: float, *, binary: bool = False, headers: dict | None = None,
           timeout: float = 120.0) -> bytes | str:
    """Fetch a bulk file at most once per max_age_h; serve the previous copy if a refresh fails."""
    key = hashlib.sha1(url.encode()).hexdigest()[:20]
    path = os.path.join(CACHE_DIR, key)
    fresh = os.path.exists(path) and (time.time() - os.path.getmtime(path)) < max_age_h * 3600
    if not fresh:
        try:
            r = get(url, headers=headers, timeout=timeout)
            data = r.content
            if url.endswith(".gz") and data[:2] == b"\x1f\x8b":
                data = gzip.decompress(data)
            tmp = path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, path)
        except Exception:
            if not os.path.exists(path):
                raise
    with open(path, "rb") as f:
        raw = f.read()
    return raw if binary else raw.decode("utf-8", errors="replace")


def cached_json(url: str, max_age_h: float, **kw) -> Any:
    return json.loads(cached(url, max_age_h, **kw))
