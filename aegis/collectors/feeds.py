"""Publisher feeds — who is publishing what. Grouped by publisher type so the Analyst view can compare
vendor research, government/CERT, news, analyst houses and community. Per-feed health is recorded."""
from aegis import db
from aegis.collectors.rss import ingest_feed
from aegis.registry import Source, collector

VENDOR = [
    ("CrowdStrike", "https://www.crowdstrike.com/en-us/blog/feed/"),
    ("Google Threat Intelligence (Mandiant)", "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/"),
    ("Microsoft Threat Intelligence", "https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/"),
    ("Microsoft Security", "https://www.microsoft.com/en-us/security/blog/feed/"),
    ("Palo Alto Unit 42", "https://unit42.paloaltonetworks.com/feed/"),
    ("Cisco Talos", "https://blog.talosintelligence.com/rss/"),
    ("Kaspersky Securelist", "https://securelist.com/feed/"),
    ("ESET WeLiveSecurity", "https://feeds.feedburner.com/eset/blog"),
    ("Sophos X-Ops", "https://news.sophos.com/en-us/category/threat-research/feed/"),
    ("Check Point Research", "https://research.checkpoint.com/feed/"),
    ("SentinelLabs", "https://www.sentinelone.com/labs/feed/"),
    ("Proofpoint", "https://www.proofpoint.com/us/threat-insight-blog.xml"),
    ("Rapid7", "https://www.rapid7.com/blog/rss/"),
    ("Huntress", "https://www.huntress.com/blog/rss.xml"),
    ("Red Canary", "https://redcanary.com/blog/feed/"),
    ("The DFIR Report", "https://thedfirreport.com/feed/"),
    ("Recorded Future", "https://www.recordedfuture.com/feed"),
    ("Bitsight", "https://www.bitsight.com/rss.xml"),
    ("Tenable", "https://www.tenable.com/blog/feed"),
    ("Qualys Threat Research", "https://blog.qualys.com/vulnerabilities-threat-research/feed"),
    ("Zscaler ThreatLabz", "https://www.zscaler.com/blogs/feeds/security-research"),
    ("Arctic Wolf", "https://arcticwolf.com/feed/"),
    ("Akamai", "https://feeds.feedburner.com/akamai/blog"),
    ("Cloudflare", "https://blog.cloudflare.com/tag/security/rss/"),
    ("Google Project Zero", "https://googleprojectzero.blogspot.com/feeds/posts/default"),
    ("Wiz Research", "https://www.wiz.io/blog/rss.xml"),
    ("Elastic Security Labs", "https://www.elastic.co/security-labs/rss/feed.xml"),
    ("Volexity", "https://www.volexity.com/feed/"),
    ("Group-IB", "https://www.group-ib.com/feed/blogfeed/"),
    ("Flashpoint", "https://flashpoint.io/feed/"),
    ("Intel 471", "https://intel471.com/blog/feed"),
    ("Censys", "https://censys.com/feed/"),
    ("GreyNoise", "https://www.greynoise.io/blog/rss.xml"),
    ("ReversingLabs", "https://www.reversinglabs.com/blog/rss.xml"),
    ("Socket (supply chain)", "https://socket.dev/api/blog/feed.atom"),
    ("Hudson Rock (Infostealers)", "https://www.infostealers.com/feed/"),
]
GOV = [
    ("CISA", "https://www.cisa.gov/cybersecurity-advisories/all.xml", True),
    ("CISA News", "https://www.cisa.gov/news.xml", True),
    ("UK NCSC", "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml", False),
    ("CERT-EU (advisories)", "https://cert.europa.eu/publications/security-advisories-rss", False),
    ("CERT-EU (threat intelligence)", "https://cert.europa.eu/publications/threat-intelligence-rss", False),
    ("ANSSI CERT-FR (alerts)", "https://www.cert.ssi.gouv.fr/alerte/feed/", False),
    ("ANSSI CERT-FR (CTI)", "https://www.cert.ssi.gouv.fr/cti/feed/", False),
    ("NCSC-NL", "https://advisories.ncsc.nl/rss/advisories", False),
    ("ASD ACSC (alerts)", "https://www.cyber.gov.au/rss/alerts", False),
    ("ASD ACSC (advisories)", "https://www.cyber.gov.au/rss/advisories", False),
    ("Canadian Centre for Cyber Security", "https://cyber.gc.ca/webservice/en/rss/alerts", False),
    ("JPCERT/CC", "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf", False),
    ("CERT/CC", "https://www.kb.cert.org/vuls/atomfeed/", False),
    ("FBI IC3", "https://www.ic3.gov/PSA/RSS", False),
]
NEWS = [
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("The Record", "https://therecord.media/feed"),
    ("SecurityWeek", "https://www.securityweek.com/feed/"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml"),
    ("KrebsOnSecurity", "https://krebsonsecurity.com/feed/"),
    ("Help Net Security", "https://www.helpnetsecurity.com/feed/"),
    ("CyberScoop", "https://cyberscoop.com/feed/"),
    ("Infosecurity Magazine", "https://www.infosecurity-magazine.com/rss/news/"),
    ("The Register", "https://www.theregister.com/security/headlines.atom"),
    ("SC Media", "https://www.scworld.com/rss"),
    ("Security Affairs", "https://securityaffairs.com/feed"),
    ("Risky Bulletin", "https://news.risky.biz/rss/"),
    ("Graham Cluley", "https://grahamcluley.com/feed/"),
]
ANALYST = [
    ("Forrester (Security & Risk)", "https://www.forrester.com/blogs/category/security-risk/feed/"),
    ("SANS Internet Storm Center", "https://isc.sans.edu/rssfeed_full.xml"),
    ("Schneier on Security", "https://www.schneier.com/feed/atom/"),
]
PSIRT = [
    ("Fortinet PSIRT", "https://filestore.fortinet.com/fortiguard/rss/ir.xml"),
    ("Palo Alto Networks PSIRT", "https://security.paloaltonetworks.com/rss.xml"),
    ("Cisco PSIRT", "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"),
    ("Ivanti security advisories", "https://www.ivanti.com/blog/topics/security-advisory/rss"),
    ("Microsoft MSRC", "https://api.msrc.microsoft.com/update-guide/rss"),
    ("Tenable Research advisories", "https://www.tenable.com/security/research/feed"),
    ("JVN (Japan)", "https://jvn.jp/en/rss/jvn.rdf"),
]


def _run(source_id: str, feeds, pub_type: str, kind: str, limit: int = 40) -> int:
    health = db.kv_get("feed_health", {}) or {}
    total, errs = 0, []
    for f in feeds:
        pub, url = f[0], f[1]
        curl = len(f) > 2 and f[2]
        try:
            n = ingest_feed(source_id, url, pub, pub_type, kind, limit, use_curl=curl)
            health[url] = {"publisher": pub, "ok": True, "items": n, "at": db.now(), "source": source_id}
            total += n
        except Exception as e:
            health[url] = {"publisher": pub, "ok": False, "error": f"{type(e).__name__}: {e}"[:200], "at": db.now(), "source": source_id}
            errs.append(pub)
    db.kv_set("feed_health", health)
    if not total and errs:
        raise RuntimeError("all feeds failed: " + ", ".join(errs))
    return total


def _feeds(lst):
    return [{"publisher": f[0], "url": f[1]} for f in lst]


@collector(Source(id="pub_vendor", name=f"Vendor threat research ({len(VENDOR)} publishers)", category="Research",
                  publisher="CrowdStrike, Mandiant, Microsoft, Unit 42, Talos, Securelist, ESET, Sophos, Check Point, …",
                  homepage="https://www.crowdstrike.com/en-us/blog/", cadence_min=60, licence="RSS headline + summary + link",
                  feeds=_feeds(VENDOR), notes="Adversary, malware and campaign research from security vendors. Drives the Analyst view."))
def collect_vendor() -> int:
    return _run("pub_vendor", VENDOR, "Vendor research", "research", 25)


@collector(Source(id="pub_gov", name=f"Government & CERT advisories ({len(GOV)} feeds)", category="Government",
                  publisher="CISA, UK NCSC, CERT-EU, ANSSI, NCSC-NL, ASD ACSC, CCCS, JPCERT, CERT/CC, FBI IC3",
                  homepage="https://www.cisa.gov/news-events/cybersecurity-advisories", cadence_min=60,
                  licence="Government publications (public)", feeds=_feeds(GOV),
                  notes="Official alerts and advisories. CISA feeds are fetched with curl (its CDN rejects python TLS clients)."))
def collect_gov() -> int:
    return _run("pub_gov", GOV, "Government / CERT", "advisory", 30)


@collector(Source(id="pub_news", name=f"Security news ({len(NEWS)} outlets)", category="News",
                  publisher="BleepingComputer, The Record, SecurityWeek, The Hacker News, Dark Reading, Krebs, …",
                  homepage="https://www.bleepingcomputer.com", cadence_min=30, licence="RSS headline + summary + link",
                  feeds=_feeds(NEWS), notes="Incident reporting — the main input to incident clustering and victim naming."))
def collect_news() -> int:
    return _run("pub_news", NEWS, "News", "news", 40)


@collector(Source(id="pub_analyst", name="Analyst & community research", category="Research",
                  publisher="Forrester, SANS ISC, Schneier", homepage="https://www.forrester.com/blogs/category/security-risk/",
                  cadence_min=180, licence="RSS headline + summary + link", feeds=_feeds(ANALYST),
                  notes="Free analyst-house content. Gartner, IDC, WEF and IBM publish no machine-readable free feed (tested 2026-09-10)."))
def collect_analyst() -> int:
    return _run("pub_analyst", ANALYST, "Analyst / community", "research", 25)


@collector(Source(id="psirt", name=f"Vendor security advisories ({len(PSIRT)} PSIRTs)", category="Vulnerabilities",
                  publisher="Fortinet, Palo Alto, Cisco, Ivanti, Microsoft MSRC, Tenable, JVN",
                  homepage="https://www.fortiguard.com/psirt", cadence_min=120, licence="Vendor advisories (public)",
                  feeds=_feeds(PSIRT), notes="Edge-device and platform advisories; linked to CVEs and exposed products."))
def collect_psirt() -> int:
    return _run("psirt", PSIRT, "Vendor PSIRT", "advisory", 30)
