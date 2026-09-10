# AEGIS 2 — Cyber Risk Operations Center

An autonomous, open-source-only cyber-risk console. It monitors the organisation universe (S&P 500, FTSE 100,
DAX 40, CAC 40, EURO STOXX 50, plus organisations you add). It turns free public data into explainable findings,
incidents, and **incident → organisation impact links**. Every record links to its original source.

Rebuilt from the ground up on 2026-09-10. The v1 code (synthetic scores, fabricated DMARC/ASN values, fictional
graph nodes) is preserved untouched in `legacy_v1/`.

## Run

```powershell
.venv\Scripts\python run.py            # console + API on http://127.0.0.1:8000, collection starts automatically
.venv\Scripts\python -m pytest tests -q   # guardrail / rule tests
cd web; npm run build                   # only needed after changing the console source
```

**Deploying to Railway:** see [DEPLOY_RAILWAY.md](DEPLOY_RAILWAY.md). The repo includes a `Dockerfile` and `railway.json`.
Set `AEGIS_PASSWORD` to protect a hosted console, and attach a volume at `/data` to keep data across deploys.

**Themes:** Dark, Dim (softer slate) and Light, switchable from the top bar. The choice is remembered per browser,
and `?theme=light|dim|dark` in any URL sets it (useful for sharing a view). Each chart palette is validated for
colour-blind separation against its own background.

On start-up, a catch-up pass refreshes every stale source. After that, each source runs on its own cadence and
the intelligence pipeline re-runs every 15 minutes. No manual step is needed to keep data live.
Data lives in `data/aegis.sqlite`. Set `AEGIS_CONTACT` to put your contact address in the polite User-Agent
that SEC, Wikidata and RIPEstat ask for.

## What the console does

| Page | Purpose |
|---|---|
| **Situation** | SOC watch floor: live incident map, priority incidents, threat activity, "what changed", active groups, themes. |
| **Incidents & impact** | Incidents clustered from leak sites, 8-K filings, dark-web reporting, news, KEV and status pages. Each has a graph of the organisations it could reach, the reason for every link, a source trail and a provider-concentration treemap. |
| **Organisations → entity view** | 12 categories: assets & infrastructure, critical assets, cloud environments, software & third parties, open ports & exposed services, vulnerabilities & exploited software, compromised systems & IPs, dark web & credential exposure, threat chatter & targeting, email & domain security, incidents & disclosures, AI risk. |
| **Exposure & vulns** | Exploited software (KEV × EPSS × public exploits), watchlist exposure matrix, ports, edge products, cloud, compromised-IP feeds. |
| **Dark web & chatter** | Leak-site listings, forum/market claims (access, data, credentials), infostealer exposure, public breaches, hacktivist DDoS targets, community chatter, criminal-source catalogue. |
| **Adversaries** | 1,400+ actors in one alias index (CrowdStrike, Microsoft, MITRE, MISP names), ranked by live activity, with targets, victims, tools, techniques and who reports on them. |
| **Analyst view** | Key themes, recurring aspects (rank over 8 weeks), the publisher × theme matrix, consensus entities and theme co-occurrence. |
| **AI risk** | MIT AI Risk Repository taxonomy with live counts, AI incidents classified into MIT subdomains, and AIAAIC context. |
| **Sources & method** | Health, cadence, licence and per-feed status of every source, plus the rating rules, linkage rules, theme dictionary and Bitsight coverage map. |

## Rating: four levels, no scores

Every finding, vulnerability and incident gets **Critical / High / Medium / Low** from exactly one named rule
(`aegis/rating.py`, visible in the UI on hover and on the Sources & method page). An organisation's level is its
most severe active finding. Examples:

- `DW-LEAK-30` (Critical): named on a ransomware leak site in the last 30 days.
- `VUL-KEV-EXPOSED` (Critical): an owned internet-facing host reports a CISA-KEV CVE.
- `SURF-RISKY-PORT` (High): RDP, SMB, database or similar ports exposed.
- `HYG-DMARC-NONE` (Medium): no DMARC, or `p=none`.
- `V-KEV-RANSOM` / `V-KEV-NEW` / `V-KEV-TOOLED` (Critical vulnerabilities). These rules were calibrated on the live catalogue, and about 40% of KEV lands at Critical.

## Incident → organisation linkage

| Link | Evidence | Level |
|---|---|---|
| Named victim | Leak-site listing, SEC 8-K, forum claim, named in news | Critical |
| Corporate group | GLEIF Level 2 subsidiary of the victim | High |
| Exposed product | The CVE on the org's own host (Critical); product CPE or a hostname naming the product (High, "unconfirmed") | Critical / High |
| Provider dependency | Org's public DNS (MX, SPF, TXT verification, CNAME, NS) shows it uses the breached/disrupted provider | High (breach) / Medium (outage) |
| Sector targeting | Actor listed 3+ victims in the org's sector and country in 30 days | Low |

## Sources (all free; passive)

- **Registries:** S&P 500 list, Wikidata, SEC EDGAR (8-K Items 1.05/8.01), GLEIF Level 2.
- **Vulnerabilities:** CISA KEV, FIRST EPSS, CVE list V5, Metasploit, Nuclei, Exploit-DB, vendor PSIRTs (Fortinet, Palo Alto, Cisco, Ivanti, MSRC, Tenable, JVN).
- **Attack surface:** Google/Cloudflare DNS-over-HTTPS, crt.sh / Cert Spotter, Shodan InternetDB, Team Cymru, RIPEstat, and official AWS/Azure/GCP/Oracle/Cloudflare/Fastly/DigitalOcean IP ranges.
- **Compromised IPs:** Emerging Threats, CINS, blocklist.de, Spamhaus DROP, IPsum, abuse.ch Feodo & ThreatFox, Tor exits.
- **Dark web (metadata only):**
  - leak sites: RansomLook, ransomware.live;
  - forum and market claims: Dark Web Informer, Brinztech, SOCRadar, DataBreaches.net, The Cyber Express, DailyDarkWeb;
  - infostealers: Hudson Rock;
  - breaches: HIBP;
  - hacktivist DDoS targets: CIRCL witha.name;
  - source catalogue: deepdarkCTI.
- **Threat intel:** MITRE ATT&CK, the MISP galaxy (with CrowdStrike names), and CrowdStrike Adversary Universe targeting.
- **Publishers:** 36 vendor research blogs (incl. CrowdStrike, Mandiant, Microsoft, Unit 42, Talos, Bitsight), 14 government/CERT feeds, 14 news outlets, Forrester, SANS ISC, Schneier.
- **Chatter:** Hacker News, Mastodon, Reddit security communities. Bluesky is disabled because its public search now returns 403.
- **AI:** MIT AI Risk Repository, AI Incident Database, AIAAIC.
- **Service status:** 17 provider status pages.

## Guardrails (tested in `tests/test_aegis2.py`)

- **Passive only:** outbound requests go only to an allow-list of public data services. The organisation's hosts, `.onion` sites, Telegram and paste sites are never contacted.
- **Metadata only:** credential patterns and emails are redacted, and sensitive keys are dropped before storage. Infostealer data is stored as counts only.
- **No individuals:** victim extraction rejects person names, and chatter author handles are not stored.
- **No fabrication:** a failing source is marked Degraded, missing values stay blank, and trend "rising" flags wait for 28 days of self-collected baseline.

## Known limits

- **Licensing:** Shodan InternetDB, abuse.ch, SANS ISC and the free ransomware.live and Hudson Rock APIs are for non-commercial use. Get written permission, or switch those sources off, before any commercial use.
- **Surface-scan rotation:** each passive scan covers 12 organisations per 15 minutes, so the full universe takes about 14 hours. Until then, organisations show "Surface scan queued".
- **No free source:** Bitsight-style client-side botnet sinkhole telemetry, desktop/mobile software and file sharing have no free equivalent. They are stated as not assessed.
- **Name-based links:** CVEs from InternetDB are version-inferred, and hostname-based product links are marked "unconfirmed".
