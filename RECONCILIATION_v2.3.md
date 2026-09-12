# AEGIS v2.3: one version, pushed once

This plan replaces the "colleague merges v2.2 into production" route. Our local build now contains everything production runs, plus v2.2. It is deployed once, following the steps in §5.

## 1. What production runs

Production is at `https://aegis-console-production.up.railway.app`. It reports **v2.0.1**. I read it without making changes on 11 Sept 2026 via `/openapi.json`, `/api/rules`, `/api/method`, `/api/actions`, `/api/prevent` and `/api/orgs/us-mu`.

| Production feature | Evidence | In v2.3 |
|---|---|---|
| **v2.0.1 fixes:** CAA precision, Citrix `receiver` fix, AI in heatmaps, 404 route, version reporting | health reports 2.0.1 | **Yes.** v2.2 already had the receiver fix, AI rules, 404 and version. CAA is in the new `CRT-CAA-VIOLATION` (§2). |
| **13 extra organisation rules:** `BGP-RPKI-INVALID/NONE`, `CRT-CAA-VIOLATION`, `CRT-EXPIRY-14`, `DOM-EXPIRY-30/90`, `DOM-LOCK`, `HYG-DKIM-NONE`, `HYG-NS-SINGLE`, `HYG-SPF-LOOKUPS`, `HYG-TLSRPT`, `LOOK-LIVE`, `LOOK-MX` | `/api/rules` | **Yes.** Same IDs, levels and texts. `aegis/intel/hardening.py` and the `hardening` collector store results in `org.hardening`. |
| **Confidence on every finding** (confirmed / likely / unconfirmed; unconfirmed capped at High) | `finding.confidence` | **Yes.** `aegis/confidence.py`, plus the migration `finding.confidence`. |
| **Actions:** lifecycle, owner roles, due dates, verified closure, reopening, history | `/api/actions`, `/api/actions/{aid}/status` | **Yes.** `aegis/actions.py` uses the same table name, column names, statuses, owner-role labels and history format. The due date comes from the finding's act-by deadline rule. |
| **Playbooks for all 58 production rules** | `/api/method` → `playbooks` | **Yes, verbatim** (`aegis/playbooks_prod.json`), plus playbooks for the 20 v2.2 rules. That covers all 78 organisation rules. |
| **Estate-wide preventive controls:** DMARC, SPF -all, DKIM, MTA-STS, TLS-RPT, DNSSEC, CAA, multi-provider DNS, transfer lock | `/api/prevent` | **Yes.** `aegis/prevent.py`. Estate figures match production to the percent (DMARC 87, SPF 52, DKIM 81, MTA-STS 9, TLS-RPT 10, DNSSEC 12, CAA 19). "Multi-provider DNS" counts AWS's several name-server domains as one provider, so it reads 20% rather than production's 43%. |
| **xlsx export of the organisations table** | `/api/orgs/export` | **Yes.** It honours the same filters, plus the time window. |
| **Per-organisation `actions` and `prevent`** | `/api/orgs/{id}` | **Yes.** |
| **UI** | production's bundle has no Prevent page | v2.3 adds `/prevent` and a "Prevent & actions" tab on each organisation page. |

Everything in v2.2 (`CHANGES_v2.2.md`, rounds 1–6) is also in v2.3.

**New in v2.3:**
- **Supplier intelligence (Exiger-inspired):** fourth parties, ownership, sanctions and export-control screening (entities only), and Secure by Design pledge signers.
- **A rebuilt Situation page.**
- **The 7 / 30 / 90-day selector works on every page.**

## 2. Database compatibility (additive only)

- **New tables:** `action` and `feedback`, created only if they do not exist. The `action` columns match production's API fields exactly.
- **New columns via `MIGRATIONS`:** `finding.confidence` and `org.hardening`, plus the v2.2 columns.

**Risk to check before the push.** Production has its own `action` table and probably a `feedback` table. Their column names must match ours:
- `feedback(source_key, org_id, rule_id, kind, reason, expires, by, at)`;
- `snapshot` (v2.2 adds `ns, mx, dnssec, caa`).

`CREATE TABLE IF NOT EXISTS` never alters an existing table. So if a column name differs, inserts will fail on production while the tests still pass locally.

**To check:** log in to Railway and run `railway ssh --service <production>`, then `sqlite3 /data/aegis.sqlite .schema`. Compare the output with `aegis/db.py`. Any extra production column is harmless. For any column we write that production lacks, add it to `MIGRATIONS`.

Two further details:
- **Status history carries over:** existing production actions keep their status and history, because `build_actions()` keys on `source_key`, the finding id.
- **Ids may differ:** the finding ids are hashes of org + rule + key. Where our title or key differs from production's for the same rule, an action is raised again under a new id and the old one closes as "verified closed". Spot-check this on staging (§5, step 3).

## 3. Known differences from production behaviour

- **Due dates follow the v2.2 deadline rules** (`DL-72H`, `DL-CISA`, `DL-7D-EXPLOITED`, `DL-7D/30D/90D`), not a flat 7/30/90-day SLA. For example, an exploited edge product is due in 72 hours, not 7 days.
- **Rules that production marked Critical are capped at High when the evidence is unconfirmed**, as specified. `DW-ACCESS-14` forum claims are the main case.
- **Lookalikes:** v2.2 has NRD-based lookalike rules (`NRD-*`). The permutation-based `LOOK-*` rules run alongside them.

## 4. Verification done locally

- `pytest`: all tests pass, including `tests/test_prevent.py`, `tests/test_hardening.py` and `tests/test_supplier.py`.
- `npm run build` is clean.
- A browser test clicks 7d / 30d / 90d on every page and diffs the numbers.
- Screenshots of the Situation, Prevent and organisation Prevent tab (dark and light).

## 5. Push once — steps (need the owner's go-ahead and `railway login`)

1. **Record:** `railway status`, `railway service`. Write the production service and domain into `VERSIONS.md`.
2. **Commit and tag:** `git init` if needed, commit, and tag `v2.3.0`.
3. **Staging first:** `railway up --service aegis-next` with `AEGIS_VERSION=2.3.0`.
   - Copy a **backup** of the production volume into staging, so the upgrade runs on real data. If that isn't possible, let staging collect for an hour.
   - Check: `/api/health`; `/api/actions` still returns production's existing actions with their history; `/api/prevent` matches; the Prevent page; the xlsx export; the 7/30/90 toggle.
4. **Back up the production volume** (Railway → service → Volume → Backups). If backups aren't available, stop.
5. **Promote:** `railway up --service <production>` with `AEGIS_VERSION=2.3.0`. Then re-check health, the Situation page, Prevent and the export.
6. **Rollback:** redeploy the previous production build, or restore the volume backup. The schema changes are additive, so v2.0.1 still runs on the upgraded database.

Never run a bare `railway up`, `railway redeploy` or `railway variables --set` against production. Do not set or change `AEGIS_PASSWORD`.
