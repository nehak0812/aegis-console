# Deploying AEGIS v2.3.0 on Railway

**Read this first.** This package is the complete AEGIS v2.3.0 application. It **replaces** the code that production runs today (v2.0.1). It already contains everything v2.0.1 does, carried over from production's own behaviour:
- the 58 playbooks;
- the action lifecycle and history;
- confidence levels;
- the preventive controls;
- the xlsx export;
- the hardening rules.

**Your data is kept.** The database lives on the `/data` volume, and v2.3 only ever *adds* tables and columns. On first start it upgrades the existing database in place, so no reset or manual migration is needed. Existing actions keep their status and history. v2.0.1 still runs on the upgraded database if you need to roll back.

- **Production today:** `https://aegis-console-production.up.railway.app`, reporting `"version": "2.0.1"` at `/api/health`.
- **After the upgrade:** the same URL, reporting `"version": "2.3.0"`.

---

## What you need

- The Railway CLI, logged in to the account that owns the AEGIS project. Install it with `npm i -g @railway/cli`, then run `railway login` in a normal terminal.
- This folder, unzipped.

Railway cannot upload a zip file through the dashboard. Deploy either from this folder with the CLI (below), or push the folder to a GitHub repository and connect that repository in Railway. The two routes give the same result.

---

## Step 1: Back up production's data (do not skip)

In the Railway dashboard, open the **AEGIS project → the production service → Volumes → `/data` → Backups → Create backup**.

If backups aren't available on your plan, **stop here** and ask. The upgrade is additive, but a backup is the only way back from an unexpected problem.

## Step 2: Try it on a staging service first (recommended, about 15 minutes)

```bash
cd AEGIS_v2.3.0            # the unzipped folder
railway link               # pick the AEGIS project
railway add --service aegis-next     # creates an empty staging service in the same project
railway up --service aegis-next      # uploads this folder; Railway builds the Dockerfile
railway domain --service aegis-next  # gives staging its own public URL
```

In the dashboard, open **aegis-next → Settings → Volumes → New volume** and mount it at **`/data`**.

Staging starts empty and fills itself from the public sources: most pages are populated within 10–20 minutes. Check:
- `https://<staging-url>/api/health` returns `{"ok": true, "version": "2.3.0", ...}`;
- the Situation page shows eleven numbered questions and a large world map;
- **Prevent & actions** shows the action queue and a **Vendor fixes** section;
- **Sources & method** shows the sources turning green;
- the 7d / 30d / 90d buttons change the numbers.

Optional, for a test on real data: restore production's backup into the staging volume before the checks.

## Step 3: Upgrade production

**Name the service explicitly.** Never run a bare `railway up` without `--service`, because the CLI may be linked to a different service. Check the name with `railway status`. The production service is the one whose domain is `aegis-console-production.up.railway.app`, usually `aegis-console`.

```bash
railway up --service aegis-console
```

**Variables:**
- If production has a variable **`AEGIS_VERSION`** set to `2.0.1`, change it to `2.3.0` or delete it; the code defaults to 2.3.0. Otherwise the console keeps showing 2.0.1.
- Leave every other variable as it is. In particular, do not add or change `AEGIS_PASSWORD`.

## Step 4: Check production

- `https://aegis-console-production.up.railway.app/api/health` returns `"version": "2.3.0"`.
- The deploy logs may show lines like `[db] upgraded: added action.xyz`. That is the in-place upgrade adding columns, and it is expected.
- `/api/actions` still lists the existing actions with their history.
- The Situation, Prevent & actions and Organisations pages work, and so does the **Export** (xlsx) on Organisations.
- New data appears over the next hour. In particular, the vendor-fix evidence and the "fix observed" history build up as organisations are re-scanned.

## Rollback

Two options:
- **Redeploy the previous build:** Railway → production service → Deployments → the last v2.0.1 deployment → **Redeploy**.
- **Restore the database:** restore the volume backup from Step 1.

The database changes are additive, so the previous version runs on the upgraded database as it is.

---

## What's new in v2.3 (summary)

- **Situation page:** now a chain of eleven questions. Where the issues are (a large zoomable map) → who is hit → how → which shared providers concentrate the risk → how fast (in day bands) → who is potentially next → what the providers depend on → who is behind it → dark web and forums → analysts → the risk for one organisation, what it must do, and whether vendor fixes are being applied.
- **Vendor fixes and uptake:** whether the vendor has published a patch or advisory (from CVE records and CISA's KEV notes), and whether each organisation's own internet-facing hosts still show the flaw on later scans.
- **Prevent & actions:** the action queue with production's lifecycle, owners, due dates, verified closure and 78 playbooks, plus estate-wide preventive controls.
- **Supply chain page:** fourth parties, ownership, sanctions and export-control screening (entities only), and Secure by Design signers.
- **Glossary on hover** for every abbreviation.
- **Works on phones.**
- **The 7/30/90-day selector** now drives every page.

The full detail is in `CHANGES_v2.2.md`, in the sections headed v2.3. `RECONCILIATION_v2.3.md` sets out how v2.3 matches what production runs. `DEPLOY_RAILWAY.md` is the general guide for a brand-new deployment.

## Run it locally (optional)

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt     # macOS/Linux: .venv/bin/pip
.venv/Scripts/python run.py                       # then open http://127.0.0.1:8000
```

The console is already built (`web/dist`), so Node.js is only needed to change the front end.
