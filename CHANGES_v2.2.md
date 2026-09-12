# AEGIS v2.2 — change manifest (v2.0 package → v2.2)

This manifest describes, file by file, what v2.2 changes and why. `tools/merge_v22.py` does the mechanical three-way merge; use this file to resolve conflicts with the right intent.

The v2.2 work has five parts:
- **A** — the Anthropic Sept 2026 report: AI stack, report indicators, lookalikes, phishing, ClickFix, DNS change;
- **B** — the provider catalogue and provider concentration;
- **C** — impersonation visuals and the per-organisation impersonation view;
- **D** — speed & spread: time to exploit, proliferation, act-by clocks;
- **E** — cross-section integration and fixes.

## New files (copy as-is)

| File | Part | Purpose |
|---|---|---|
| `aegis/intel/iocs.py` | A, C | Refang and extract indicators (defanged-only in prose, JSON-escape safe, file-name and platform filters). `BrandIndex` matching: distinctive vs weak tokens, lure words, glued compounds, one-letter variants, own-domain and platform exclusion. `lure_theme()`. |
| `aegis/intel/ai.py` | A | AI products: CPE, hostname and KEV mapping, AI ports, `assess_host()`. |
| `aegis/intel/atlas.py` | A | MITRE ATLAS phrase → technique tagging. |
| `aegis/intel/providers.py` | B | Provider catalogue: ~130 providers with aliases and DNS patterns, the `observable` flag, 41 tested `STATUS_FEEDS`, `sync_catalogue()`, and the `Catalogue` class (`match`, `canonical`, `mentioned`, `names_of`). |
| `aegis/intel/velocity.py` | D | `kev_lag`, `exploit_stats`, `spread`, `epss_surge`, and `deadline()` (the DL-* rules). |
| `aegis/collectors/reports.py` | A | Anthropic threat reports, MISP OSINT (CIRCL, botvrij), and the Talos / Unit 42 / Meta IOC repositories. |
| `aegis/collectors/phishing.py` | A | WhoisDS newly registered domains, OpenPhish / PhishTank / URLhaus / ThreatFox, and DoH liveness. |
| `aegis/collectors/ai_stack.py` | A | OSV AI-package advisories, NVD huntr CVEs, GitHub malware advisories, MITRE ATLAS, offensive AI frameworks. |
| `web/src/pages/Impersonation.tsx` | A, C | The `/impersonation` page. The Overview tab holds the ATT&CK chain, the Sankey (source → lure → brand), the brand × lure heatmap, the timeline, and the TLD / hosting / reporter charts. The other tabs are brand, reports, web & DNS, and context. |
| `web/src/pages/Speed.tsx` | D | The `/speed` page: time-to-exploit distribution and trend, **organisations in the path of fast-moving threats** (top 12, "show all"), spreading incidents with a plain-language spread timeline and the organisations each reaches, fastest vendors, fast-exploited CVEs and exposed orgs, rising EPSS, lookalike speed, extortion tempo, and action clocks. |
| `tests/test_aegis22.py` | all | Tests for extraction, brand matching (including false-positive regressions), AI rules, DNS drift, themes, ATLAS, rule → category mapping, the allow-list, catalogue patterns, lure themes, speed, and deadlines. |
| `tools/merge_v22.py` | — | The three-way merge helper. |

## Changed files (merge; do not overwrite)

| File | Part | What changed |
|---|---|---|
| `aegis/rating.py` | A–D | **New rules** by family:<br>• AI: `AI-KEV-EXPOSED`, `AI-KEV-PRODUCT`, `AI-EXPOSED-SERVICE`, `AI-EXPOSED-PORT`, `AI-PROVIDER-INC`, `AI-SERVICE-DNS`, `AI-HOST`<br>• Indicators & impersonation: `IOC-BRAND-LIVE`, `IOC-BRAND`, `IOC-OWN-DOMAIN`, `IOC-OWN-IP`, `NRD-PHISH`, `NRD-LIVE`, `NRD-MATCH`, `PHISH-BRAND`, `PHISH-TARGET`<br>• Websites: `WEB-CLICKFIX`, `WEB-MALWARE`, `WEB-CMS-KEV`<br>• DNS change: `DNS-NS-REPLACED`, `DNS-MX-MOVED`, `DNS-DNSSEC-LOST`, `DNS-CAA-REMOVED`<br>• Providers & speed: `TP-NAMED-CUSTOMER`, `VUL-EPSS-SURGE`<br>• Incident rule: `I-PROVIDER-REPORTED`<br>• Deadline rules (scope `deadline`): `DL-72H`, `DL-CISA`, `DL-7D-EXPLOITED`, `DL-7D`, `DL-30D`, `DL-90D` |
| `aegis/intel/pipeline.py` | A–D | **New stages:** `derive_dependencies` (before enrich) and `match_iocs` (before findings).<br>**enrich:** re-tags themes and ATLAS; AI-incident MIT themes; provider-canonical vendors.<br>**build_incidents:** provider recognition (`provider_is_victim`, `LAW_FOLLOWUP`, `MEGA_PLATFORMS`); status-incident titles; incident `velocity`.<br>**build_impacts:** canonical provider deps; the `NAMED_CUSTOMER` link; single-source provider reports become medium and are never escalated.<br>**build_findings:** AI / IOC / NRD / PHISH / WEB / DNS / `EPSS-SURGE` / `TP-NAMED` findings; grouped NRD and brand findings; `act_by` and `deadline_rule` on each finding.<br>**Constants:** `CATEGORIES` gains `impersonation`; `RULE_CAT` gains the new prefixes plus `CRT-`/`DOM-`/`BGP-`/`LOOK-`; `EDGE_VENDORS` gains N-able, JFrog, Langflow, BerriAI; `dns_drift()`; `CMS_CPE`. |
| `aegis/intel/themes.py` | A | Fixes the law-enforcement regex (`operation X` under `re.I`). Adds 11 themes: agentic intrusion, DNS hijacking, device-code & token theft, influence ops & FIMI, AI incidents & harms, offensive AI frameworks, AI supply chain & key theft, AI-enabled fraud, distillation & resellers, and export-control evasion. |
| `aegis/intel/fingerprints.py` | A, E | Citrix `receiver` → `citrix-?receiver`. Langflow, LiteLLM, N-central and Artifactory edge patterns. Azure OpenAI CNAME. |
| `aegis/collectors/feeds.py` | A | `AI_SEC` (13 feeds) and `INFLUENCE` (6 feeds) sources. Per-feed filter regex. |
| `aegis/collectors/status.py` | A, B | OpenAI and Anthropic status pages. Polls the catalogue's `STATUS_FEEDS` (statuspage JSON and RSS). |
| `aegis/collectors/surface.py` | A, B | Stores raw TXT in `hygiene.txt`. `write_snapshot()` after each scan. |
| `aegis/collectors/rss.py` | A | ATLAS tags in `entities.atlas`. |
| `aegis/collectors/vulns.py` | D | New collector `epss_trend`: two EPSS daily files give `epss_7d` and `epss_30d`. |
| `aegis/db.py` | A–D | **New tables:** `ioc`, `snapshot`, `provider`.<br>**MIGRATIONS:** `vuln.epss_7d/epss_30d`, `finding.act_by/deadline_rule`, `incident.velocity`.<br>**JSON_COLS** additions. |
| `aegis/guard.py` | A | New allow-list hosts. Hosts in collector `feeds` are added automatically. |
| `aegis/scheduler.py` | A, B, D | Imports the new collectors. Adds them to `CATCH_UP_ORDER`. Calls `sync_catalogue()` at start-up. |
| `aegis/api.py` | A–E | **New endpoints:** `/api/impersonation` (with `visuals`), `/api/iocs/export`, `/api/providers` (GET / POST / DELETE), `/api/speed`.<br>**Reworked:** `/api/linkage/providers`.<br>**Extended:**<br>• `/api/ai` → `stack`, and `?days=` now windows related reporting and themes (vendor reports use at least 90 days)<br>• `/api/overview` → `signals` (`new_lookalikes` windowed by `days`) and `speed` (`_speed_strip(days)`: `tte_window` = max(days, 30), `kev_window`, `kev_prev` = the prior window of equal length, `spreading` windowed)<br>• `/api/speed` → `in_path` (≤ 80 rows) + `in_path_total`: organisations reached (any non-TARGETING link) by an incident that is spreading or has `kev_lag` ≤ 7, with `worst`, `threats[{id,title,link,severity,why}]`, `act_72h`, `next_act_by`; `fast` and `spreading` rows gain `orgs`; `spreading` rows gain `kev_lag`, `first`<br>• `/api/orgs` → `?provider=` (catalogue-canonical dependency filter); rows gain `act_72h`, `next_act_by`, `lookalikes`<br>• `/api/orgs/{id}` → `identity`, `iocs`, `impersonation`, `inventory.ai`/`impersonation`; impacts gain `velocity` + `fast` and sort fast-first; `provider_issues` {vendor: {severity, id, title, kind}}<br>• `/api/incidents/{id}` → `spread`<br>• `/api/analyst` → `?family=`, AI incidents<br>• `/api/exposure` → `?category=`, `with_category`; `kev_recent` rows gain `published` and `lag` (days to exploit)<br>• search → indicators<br>**Also:** `VERSION` from `AEGIS_VERSION` in `/api/health` and `/api/status`. |
| `requirements.txt` | A | `pyyaml`. |
| `tests/test_aegis2.py` | D | Rule scope `deadline` is allowed. |
| `web/src/App.tsx` | A, D, E | Navigation adds Impersonation & IOCs and then **Speed & spread (after Impersonation)**, their routes, the 404 route and the version in the footer. The 7d/30d/90d selector has a tooltip saying what it windows (incidents, reporting, dark web, exploitation, impersonation, speed) and what it does not (levels, findings, deadlines = current state). |
| `web/src/components/ui.tsx` | D | `ActBy` clock component. |
| `web/src/components/charts.tsx` | D | `SpreadTimeline`: a plain-language headline ("N publishers, M within 72 hours, third after X hours") plus one bar per publisher = delay from the first report, with a dashed 72-hour line. It replaces the step chart in the UI; `SpreadCurve` is kept but unused. |
| `web/src/pages/AIRisk.tsx` | A, E | AI stack watch section (Medium+ exposure table, KEV, advisories, ATLAS, vendor reports, malware/huntr, offensive frameworks). It now passes the range (`/ai?days=`). |
| `web/src/pages/Analyst.tsx` | E | Family selector. Topic filter moved from `?theme=` to `?topic=` (it clashed with the colour theme). |
| `web/src/pages/Exposure.tsx` | E | Rank-by-category selector, a legend entry for "no finding", and a "Time to exploit" column (days from CVE publication to KEV; "zero-day"). |
| `web/src/pages/Incidents.tsx` | B, D, E | `NAMED_CUSTOMER` link type. Provider concentration rebuilt (KPIs, treemap with issue outline, providers with issues, reach, category, catalogue, add-provider form, `?view=providers`). Treemap clicks, the catalogue "Orgs in DNS" count and "see organisations" go to `/orgs?provider=`. Spread badge and `SpreadTimeline` on the incident. **Fix:** the list honours 7d (the forced 30-day minimum is removed). |
| `web/src/pages/OrgDetail.tsx` | C, D, E | Impersonation tab (`?tab=impersonation`). "Act first" card. Act-by clock on every finding. Identity-attack context card. Provider-incident card. Compromise findings. The incidents card is fast-first with "spreading" / "zero-day" / "exploited Nd after disclosure" badges and a link to Speed & spread. **Third-party tab:** the circle packing (overlapping labels) is replaced by a treemap grouped under category headers, with horizontal labels only where they fit and ⚠ + an ink outline for providers with an active issue. Clicking a tile opens the issue or `/orgs?provider=`. An "Active issues at this organisation's providers" list sits below. |
| `web/src/pages/Orgs.tsx` | E | `?provider=` filter chip ("Uses X ✕"); Next act-by, 72h actions and Lookalikes columns. |
| `web/src/pages/Overview.tsx` | C, D, E | Signals row (impersonation, lookalikes, AI exposure, providers) and speed strip. `?topic=` links. Every tile says whether it is "· now" (current state) or "· Nd" (follows the selector); it uses `signals.new_lookalikes` and `speed.kev_window` / `kev_prev` / `tte_window`. |
| `web/src/pages/Sources.tsx` | D | Rating-rules tab lists the `deadline` rules. The linkage card says six link types. |
| `web/src/pages/DarkWeb.tsx` | E | `?topic=` link. |
| `README.md`, `DEPLOY_RAILWAY.md` | — | New pages, sources and variables (`AEGIS_VERSION`, `GITHUB_TOKEN`), and limits. |

**Environment variables (all optional):**
- `AEGIS_VERSION`
- `GITHUB_TOKEN`
- `AEGIS_SLA_CRITICAL` / `AEGIS_SLA_HIGH` / `AEGIS_SLA_MEDIUM` (7 / 30 / 90 days)
- `AEGIS_SLA_EXPLOITED_EDGE_HOURS` (72)

## Round 5: Speed as a story, the range selector made honest, and map zoom

**The problem.** On Speed, every headline number used a fixed window: 90 days, 12 months, 30 days, or "now". The 7d/30d/90d selector therefore appeared broken. Several other tiles were fixed or mislabelled, and time to exploit disagreed between pages (10 days on Speed, 17 on Situation).

**Backend (`aegis/api.py`)**
- **`/api/speed`:** every headline follows `days`. New fields:
  - `win` and `prev`: time-to-exploit stats for the window and the window before it. They are widened to 30 days only when the window holds fewer than 10 KEV additions; `window` says which.
  - `race`: each CVE newly added to KEV in the window, with `lag` and the number of monitored organisations exposed.
  - `beaten`: the share of those CVEs exploited within each deadline rule's length of disclosure.
  - `sla`.
  - `calendar`: overdue plus the next 15 days, by level.
  - `later` buckets.
  - `board`: every organisation placed by its earliest act-by date: overdue / 72h / 7d / 30d / later. `fast` = in the path.
  - `threats`: fast incidents by distinct organisations reached.
  - `coverage`, `kev_window`, `kev_prev`.

  `spreading[].reach` now counts distinct organisations; `links` is the old link count. Lookalike speed is windowed. A local `_until()` computes days until an act-by date, because `pipeline.days_since` clamps future dates to zero.
- **`_speed_strip`:** applies the same time-to-exploit rule, so Situation and Speed agree.
- **`/api/overview`:** gains `coverage` (collection start, leak and lookalike start dates).

**Console**
- **`Speed.tsx`** is rebuilt as five chapters, opened by a four-number story strip:
  1. **The race.** A beeswarm of newly exploited CVEs by days to exploit (log scale), with the deadline rules as dashed lines. Blue dots run at a monitored organisation; each opens `/exposure?cve=`. Beside it, "How often attackers beat each deadline". Below, a quarterly trend and the fastest vendors (median, plus share within 7 days).
  2. **What is spreading.** Swimlanes: one dot per publisher over the first 120 hours, with the 72-hour window shaded.
  3. **Who is in the path.** Fast incidents ranked by organisations reached, and the deadline board: Overdue / Next 72 hours / This week / This month / Later, with ⚡ marking in-path organisations.
  4. **What is due, and when.** A clickable stacked bar per day by level, the rule counts, and the actions due (12 shown, "Show all").
  5. **Early warnings.** EPSS slope chart, lookalike go-live speed, and extortion tempo.

  Reference tables are tucked into a collapsible section.
- **`Overview.tsx`:**
  - a new **"Act now — who must act, on what, by when"** card: organisations due in 72 hours, incidents spreading, and newly exploited CVEs running at monitored organisations;
  - "data since …" on the leak and lookalike tiles;
  - the themes label follows the window (up to 14 days);
  - the time-to-exploit hint explains the widening.
- **`WorldMap.tsx`:** zoom and pan without new dependencies. Region buttons (World, North America, Europe, UK & Benelux, Asia-Pacific, Latin America) appear on maps at least 320px tall. Also: +/−/reset buttons, double-click (Shift to zoom out), Ctrl/⌘ + scroll or trackpad pinch, and drag to pan. On screen, markers grow by only a quarter per doubling of zoom, so clusters separate as you zoom. The hint shows markers in view. A plain scroll still scrolls the page.
- **`Orgs.tsx`:** the map card is no longer flush (its title was misaligned), is 480px tall, and has a level legend. The column is renamed "Incidents reaching it · 30d".
- **Range and labels**
  - The provider-concentration tab passes `days`, and its labels follow it.
  - Dark web tiles are suffixed "· Nd" or "· now".
  - "New lookalike domains · 30d".
  - The AI themes card says "selected window".
  - Adversaries mentions are "· all collected" (the old "120 days" was wrong).
  - The Exposure KEV total is "· all time", and Exposure's CVE columns open the internal CVE card.
  - Nav badges have tooltips giving their window.
  - The selector tooltip explains "· Nd" vs "· now", and that collection depth limits long windows.

## Round 6: one page shape everywhere (summary and visuals first, then details, then sources)

**Shared components**
- **`ui.tsx`** gains three components:
  - `StoryStrip`: the page in 3–4 numbers, each with one sentence, clickable;
  - `SectionLabel`: the divider between summary, details and sources;
  - `PageSources`: a footer listing the sources that feed the page (by source category), each with live status, last success and a link, plus "All sources & method →".
- **New `components/summaryviz.tsx`:**
  - `RaceChart`, moved out of Speed, with a `compact` mode;
  - `StackedBars`, a reusable per-day chart stacked by level;
  - `dueDays`;
  - `SpeedSummary`.

**Pages**
- **Situation:** the "Act now" lists are replaced by `SpeedSummary`, titled "Speed: from exploitation to action". It is a five-step flow: CVEs newly exploited → share within 7 days → running at monitored organisations → organisations in the path → must act within 72 hours. Each step links to its chapter on Speed (`/speed#race|path|due`). Beside the flow sit a compact race chart and the actions-due-per-day bars. A "Where, what and who" section follows, and every source is listed at the foot.
- **Incidents:** a summary band above the list.
  - Story strip: incidents in view (critical, spreading, new in 24 hours); monitored organisations reached, split into named victims / exploited product / provider; the most common type (click to filter); and the widest-reaching incident.
  - Heatmap: incident type × link rule, counting distinct organisations (click a row to filter).
  - New incidents per day, by level.

  Then "Every incident", then sources. Backend: `/api/incidents` returns a `summary` object: `reached`, `by_link`, `matrix`, `daily`, `new_24h`, `spreading`.
- **Speed:** uses the shared components, and opens the chapter named in the URL hash.
- **Adversaries:** story strip (tracked, active in 30 days, extortion groups listing victims, most active).
- **Sources footers:** Orgs, Exposure, Dark web, Impersonation, Analyst and AI risk gain `PageSources`. Orgs and Dark web also gain section labels.
- **Maps:** region buttons appear only on maps at least 320px tall.

## v2.3: production reconciled, Prevent, supply chain, a new landing page

This release replaces the colleague-merge route. Production's features are rebuilt here against its live API contract and pushed once. `RECONCILIATION_v2.3.md` has the side-by-side comparison and the push steps.

**Reconciled from production (v2.0.1 plus the backend part of v2.1)**
- **13 organisation rules**, with the same IDs, levels and wording:
  - DNS and certificates: `BGP-RPKI-INVALID/NONE`, `CRT-CAA-VIOLATION` (RFC 8659 climb, CA identifier map, only certificates issued after the policy was first seen), `CRT-EXPIRY-14`;
  - domain registration: `DOM-EXPIRY-30/90`, `DOM-LOCK`;
  - email: `HYG-DKIM-NONE`, `HYG-SPF-LOOKUPS`, `HYG-NS-SINGLE`, `HYG-TLSRPT`;
  - lookalikes: `LOOK-LIVE`, `LOOK-MX`.

  New files: `aegis/intel/hardening.py` (pure checks), `aegis/collectors/hardening.py` (daily, 40 organisations per run; results in `org.hardening`), `tests/test_hardening.py`.
- **Confidence on every finding** (`aegis/confidence.py`, `finding.confidence`): confirmed, likely or unconfirmed. Unconfirmed is capped at High, and the cap is recorded in `data.capped_from`.
- **Actions** (`aegis/actions.py`, tables `action` and `feedback`):
  - one action per Critical, High or Medium finding;
  - production's statuses, owner roles and history format;
  - the due date is the finding's act-by date;
  - verified closure when a later scan no longer sees the finding, and reopening when it returns;
  - false positive and accepted risk (with an expiry) suppress the finding.

  APIs: `/api/actions` and `POST /api/actions/{aid}/status`. Rejected transitions return a reason.
- **Playbooks** (`aegis/playbooks.py`): production's 58 verbatim (`aegis/playbooks_prod.json`) plus 20 for the v2.2 rules, covering all 78 organisation rules. `/api/method` gains playbooks, owners, effort, SLA and confidence definitions.
- **Preventive controls** (`aegis/prevent.py`, `/api/prevent`, per-organisation `prevent`): nine controls, with adoption across the estate and by sector as percentages.
- **`/api/orgs/export`:** the organisations table as .xlsx, honouring the filters.

**New in v2.3**
- **Prevent & actions page** (`/prevent`): a story strip, control adoption (weakest first), where the work sits by owner, a sector × control heatmap, then the action queue with inline status and an expandable playbook and history. Each organisation page gains a **Prevent & actions** tab: controls against sector and estate, "Re-check now", and its actions. The shared `components/actions.tsx` and the `Confidence` pill support both.
- **Supply chain page** (`/suppliers`, Exiger-inspired). New files: `aegis/intel/supplier.py` and `aegis/collectors/supplier_intel.py` (daily), stored in kv `supplier_intel`. `/api/suppliers` covers:
  - the providers' own **DNS (NS) and mail (MX) hosting**, i.e. fourth parties, with SPF sending services and TXT verification tokens excluded;
  - hidden concentration: organisations that depend on a fourth party directly vs only through a provider;
  - a provider → fourth-party flow;
  - ownership (GLEIF legal entity and ultimate parent);
  - CISA Secure by Design pledge signers;
  - exact-name screening against the US Consolidated Screening List and the UK Sanctions List. Entities only; individuals are never stored. Every match is labelled "for review", never a finding.
- **Situation, rebuilt** on `/api/landing`:
  - a linked brief;
  - the whole watchlist as one grid of squares by sector and level;
  - four "now" tiles;
  - four pressures: exploitation speed, spread, supply chain, impersonation and dark web;
  - "where the risk concentrates" (sector × risk domain);
  - deadlines ahead, and whether fixes are keeping pace;
  - the last 24 hours, and a map.
- **The 7/30/90 selector** now also drives Organisations, Adversaries, AI risk, Impersonation, Prevent (closures) and provider concentration. A browser test clicks it on every page.
- **Security:** `net.py` checks every redirect hop against the allow-list (off-site hops are refused). `tests/test_prevent.py` covers it.

**Tests:** 134 pass.

## v2.3, round 2: one risk chain through the whole console, an organisation brief, and mobile

**The framework.** The console now follows one chain of questions, modelled on the Diamond Model's adversary, capability, infrastructure and victim, plus the context around them:

**The threat:** where the issues are → who is hit and how → how fast they move → who is exposed next → who is behind it → what the dark web and forums discuss → what analysts say.
**The exposure:** exposed software → impersonation → supply-chain dependence → the AI stack.
**The response:** the risk for each organisation → what it must do, by when.

- **Situation** (`Overview.tsx`) is rebuilt as the ten questions:
  - a chain strip with one number per step, and the linked brief;
  - each step as a card with the question, a one-sentence answer, a visual, and a link to the page with the evidence;
  - step 10 is an organisation picker (most urgent first, or search) showing that organisation's risk brief, plus the deadline and fixes charts.
- **The chain across pages** (`components/chain.tsx`):
  - The nav is regrouped into *The threat*, *The exposure*, *The response* and *Method*.
  - Every chain page shows a breadcrumb at the top ("Situation › The threat › step 2 of 11 · How fast is it moving — and who is next?").
  - At the bottom, previous and next cards carry the data flow from page to page.
- **Who is exposed next** (`_line_of_fire(days)` in `api.py`): organisations exposed to what is happening now but not named as victims in the window. There are three explainable reasons, never a forecast:
  1. in the path of a spreading or fast-exploited incident: runs the product, uses the provider, named customer, or corporate group;
  2. its sector had 3+ leak-site victims and it has an exploitable Critical/High exposure: exploited CVE or edge product, C2, stealer, live phishing, or a risky port;
  3. a provider it uses has a High/Critical incident.
- **Organisation risk brief** (`/api/orgs/{id}/brief`, `components/brief.tsx`): the whole chain boiled down for one organisation:
  - a plain-language sentence;
  - what it must do (the open actions with their first playbook step);
  - what reaches it (fast-moving first) and its own exposures;
  - its providers, the incidents coming through them, and the providers' DNS and mail hosts;
  - extortion groups active against its sector, or its own leak-site listing;
  - mentions in reporting and chatter;
  - the reasons it is exposed to what is happening now.

  It appears on the landing page and at the top of every organisation's Overview tab.
- **Mobile** (`styles.css`, `App.tsx`):
  - a menu button opens the navigation as a slide-in drawer;
  - the top bar wraps, with search on its own row;
  - layouts stack to one column;
  - wide charts (heatmaps, flows, treemaps) keep a readable width and scroll sideways inside their card;
  - grid columns may shrink below their content, so no page overflows.
- **Robustness:** the pipeline used to empty the finding, incident and impact tables (and the catalogue dependencies) and then re-insert them. For a moment every organisation page read "not yet assessed". The new `db.replace_set()` writes the new set first, then removes only what is no longer present.

**Tests:** 135 pass.

## v2.3, round 3: a map you can see, shared providers as their own question, speed in bands, vendor fixes and their uptake, a glossary

- **Situation, question 1, "Where are the issues?"** now spans the full width:
  - a 440px zoomable world map (260px on phones);
  - severity counts under the map;
  - side panels for *what happened* (clickable) and *where* (victim country).
- **New question 4: "Which shared providers concentrate the risk?"** It sits after "How are they being impacted?" and before "How fast?".
  - Question 1 is where incidents land. Question 4 is where exposure is shared *before* anything happens: the providers seen in the public DNS of the most monitored organisations (from `/api/linkage/providers`, the data behind *Incidents & impact → provider concentration*).
  - It lists the shared providers with an issue now, those reaching monitored organisations first.
  - The old dependence step is now question 7, "What do those providers depend on?" (fourth parties).
  - There are now eleven questions.
- **Question 5, "How fast are the issues moving?"** is shown as classified bands, the same as Speed & spread:
  - disclosure → confirmed exploitation, in `velocity.LAG_BINS` bands from zero-day to over a year, with the number running at monitored organisations;
  - first report → 3 independent publishers, in bands: within 24h, 24–48h, 48–72h, slower, not yet at 3.
  - `/api/speed` now returns `spread_h3` (every incident, not just the top 25).
- **Vendor fixes: released, and applied?**
  - **Released** comes from the new collector `cve_fixes` (`collectors/vulns.py`, cvelistV5, every 3 hours). It looks at:
    - CNA and CISA-ADP references tagged *patch*, *vendor-advisory*, *mitigation* or *release-notes*;
    - affected ranges (`lessThan`, written as "ADC 14.1 before 66.59");
    - the vendor advisories CISA cites in KEV `notes` (now stored with `requiredAction` as `vuln.kev_notes` / `kev_action`).

    It re-checks every 14 days until a patch appears, or as soon as new KEV notes arrive.
  - **Applied** comes from the new `cve_exposure` table, filled by the pipeline stage `track_cve_exposure`. It keeps a history of (organisation, CVE) on the organisation's own non-shared hosts, from Shodan InternetDB.
    - A CVE counts as *fix observed* only when a newer scan no longer reports it.
    - It reopens if the CVE is reported again.
    - Wording is always "no longer observed (patched or host removed)", never "patched".
  - **API:** `/api/fixes?days=` returns the summary funnel and one row per exploited CVE: fix state and links, still exposed (organisations), fix observed, days observed exposed, past CISA's due date. `/api/vulns/{cve}` gains `fix_state` and `uptake`, and `/api/landing` gains `fixes`.
  - **Visuals** (`components/fixes.tsx`):
    - a funnel plus fixed-versus-still-exposed bars on the landing page (question 11);
    - a *Vendor fixes* section on Prevent & actions, with the funnel, a "how this is measured" card, and the full table (`/prevent#fixes`);
    - fix status, links, affected ranges, CISA's required action, and still-exposed versus fix-observed organisations on each CVE card in Exposure.
- **Glossary on hover** (`components/glossary.tsx`, mounted in `App.tsx`):
  - Abbreviations (KEV, EPSS, CVE, DMARC, DNS, CNA, NRD, C2 …) and rule IDs are underlined with the CSS Custom Highlight API. The DOM is not changed, so this is safe with React.
  - Hovering or tapping shows the meaning.
  - The full list is under *Sources & method → Glossary*.
- **Schema (additive only):**
  - new table `cve_exposure`;
  - new columns `vuln.fix`, `fix_checked`, `kev_action`, `kev_notes`.

**Tests:** 139 pass. New `tests/test_fixes.py` covers:
- fix evidence from a CVE record, including release-branch ranges;
- KEV note links (NVD excluded);
- fix observed only after a newer scan, and reopened when the CVE is reported again;
- shared infrastructure ignored.
