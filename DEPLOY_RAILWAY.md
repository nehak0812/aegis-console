# Deploying AEGIS on Railway

AEGIS is one service: a Python API that also serves the console and runs the data collectors on a schedule.
It needs **no API keys and no database server** — it keeps its data in SQLite on a Railway volume.
The repository already contains a `Dockerfile` (builds the console, then the Python runtime) and a
`railway.json` (health check, single replica, restart policy), so Railway picks everything up automatically.

## 1. Deploy (choose one route)

**Route A — Railway CLI (from this unzipped folder)**
```bash
npm i -g @railway/cli        # or: brew install railway
railway login
railway init                 # create a new project
railway up                   # uploads this folder, builds the Dockerfile, deploys
railway domain               # generates a public https://<name>.up.railway.app URL
```

**Route B — GitHub**
1. Create a new (private) GitHub repository and push this folder to it.
2. In Railway: **New Project → Deploy from GitHub repo → select the repo**.
3. Service → **Settings → Networking → Generate Domain**.

## 2. Add a volume (keeps data across redeploys)
Service → **Settings → Volumes → New Volume**, mount path **`/data`**.
Without a volume the app still works, but every redeploy starts with an empty database and
re-collects from scratch (the console fills within ~10–20 minutes).

## 3. Set variables (Service → Variables)

| Variable | Required | Value / purpose |
|---|---|---|
| `AEGIS_PASSWORD` | **Strongly recommended** | Protects the console with a browser sign-in (user `aegis`). Without it anyone with the URL can use the console and trigger scans. |
| `AEGIS_USER` | optional | Change the sign-in user name (default `aegis`). |
| `AEGIS_CONTACT` | recommended | An email address for the polite User-Agent that SEC EDGAR, Wikidata and RIPEstat ask API users to send, e.g. `security-team@yourcompany.com`. |
| `AEGIS_DATA_DIR` | no | Already `/data` in the image. |
| `PORT` | no | Injected by Railway automatically. |

Redeploy after changing variables (Railway does this automatically).

## 4. First start — what to expect
- The health check (`/api/health`) passes within seconds; the console is reachable immediately.
- A catch-up pass then collects every source: registries and vulnerabilities in the first minutes,
  publisher feeds and dark-web trackers next, then the pipeline builds incidents and findings.
  Most pages are populated within **10–20 minutes**.
- The passive external-surface scan rotates through 12 organisations every 15 minutes, so the full
  universe (≈690 organisations) is covered in about **14 hours**; until then organisations show
  "Surface scan queued".
- **Sources & method** shows the live status of every source.

## 5. Check it works
- `https://<your-domain>/api/health` → `{"ok": true, ...}`
- Open `https://<your-domain>/` → sign in → Situation page.
- Deep links (e.g. `/incidents/…`, `/orgs/us-wmt`) work on refresh — the server returns the console for all non-API routes.
- Every item's "open source ↗" link goes to the original publisher, filing or record.

## Resources & limits
- Plan: Railway Hobby or above. Allow **1 GB RAM** (the MITRE ATT&CK bundle is parsed once a week) and ~1 GB volume.
- Keep **one replica** (set in `railway.json`): the scheduler and SQLite database live in the single process.
- Outbound traffic only goes to an allow-list of public data services (see `aegis/guard.py`); nothing is ever sent to the monitored organisations.

## Licensing before any commercial use
Shodan InternetDB, abuse.ch feeds, SANS ISC, and the free ransomware.live and Hudson Rock APIs are licensed
for non-commercial use. Obtain written permission or disable those sources (Sources & method page shows each
licence) before offering the service commercially.

## Run locally instead
```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt   # Windows: .venv\Scripts\pip
python run.py                                                        # http://127.0.0.1:8000
```
The package includes a pre-built console (`web/dist`), so Node.js is only needed to change the console source
(`cd web && npm ci && npm run build`).
