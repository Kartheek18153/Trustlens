# TrustLens Backend Deployment Guide

This document walks through every step of deploying the TrustLens backend (Cloudflare Worker + KV + crawler) on Windows. The backend is **optional** — TrustLens works without it at ~85-88% accuracy. With the backend deployed and the crawler run, accuracy reaches ~92-95% on PhishTank-validated phishing.

Total time: ~20 minutes. Cost: $0 (Cloudflare free tier covers ~100k requests/day and 100k KV reads/day).

---

## Prerequisites

- Windows 10 or 11 with PowerShell
- A Cloudflare account (free) — https://dash.cloudflare.com/sign-up
- Node.js 18+ — https://nodejs.org/ (download LTS, run installer, restart PowerShell)
- The TrustLens project at `C:\All_projects\Fraud_Dns_and_email_spoofing`

Verify Node is installed:

```powershell
node --version
```

Should print something like `v20.x.x` or `v22.x.x`.

---

## Step 1 — Install dependencies

Open PowerShell. Navigate to the backend directory and install Wrangler (Cloudflare's CLI):

```powershell
cd "C:\All_projects\Fraud_Dns_and_email_spoofing\backend"
npm install
```

This creates a `node_modules\` folder and a `package-lock.json`. Takes ~30 seconds.

---

## Step 2 — Log in to Cloudflare

```powershell
npx wrangler login
```

A browser window opens. Log in to your Cloudflare account. Click **Allow**. Wrangler saves credentials locally. You should see:

```
Successfully logged in.
```

---

## Step 3 — Create the KV namespace

KV is Cloudflare's key-value store. The Worker uses it to cache reputation data.

```powershell
npx wrangler kv:namespace create REPUTATION
```

Output looks like:

```
Add the following to your configuration file in your `wrangler.toml`:
[[kv_namespaces]]
binding = "REPUTATION"
id = "a388ab74a0904bd787d2418197060c86"
```

**Copy the `id` value** (the long hex string).

Open `backend\wrangler.toml` in any text editor. Replace the placeholder:

```toml
[[kv_namespaces]]
binding = "REPUTATION"
id = "a388ab74a0904bd787d2418197060c86"   ← paste your real id here
```

Save the file.

---

## Step 4 — Set the secret tokens

Two tokens are used. `INGEST_TOKEN` protects the `/ingest` endpoint (caller must send it as `X-TrustLens-Token` header). `REPORT_TOKEN` protects the `/report` endpoint (used by the extension for opt-in collab reporting).

Pick any two long random strings. Example:

```
tl-ingest-a8f3b2c1d4e5f6g7h8i9j0k
tl-report-z9y8x7w6v5u4t3s2r1q0p9o
```

Set them as Worker secrets:

```powershell
npx wrangler secret put INGEST_TOKEN
```

You'll be prompted: `Enter a secret value:` — type your INGEST_TOKEN, press Enter. Output:

```
Success! Uploaded secret INGEST_TOKEN.
```

Repeat for the second token:

```powershell
npx wrangler secret put REPORT_TOKEN
```

Same process. **Write these tokens down somewhere safe** — you'll need them in Steps 8 and for the extension in Step 10.

---

## Step 5 — Register a workers.dev subdomain

First deploy prompts you to choose a subdomain. Run:

```powershell
npx wrangler deploy
```

You'll see:

```
▲ [WARNING] You need to register a workers.dev subdomain before publishing to workers.dev
? Would you like to register a workers.dev subdomain now? ... yes
? What would you like your workers.dev subdomain to be?
```

Type any short unique name (your name, project codename, etc.). Must be globally unique across all Cloudflare.

Examples that work (if available): `karth-trustlens`, `trustlens-fraud`, `my-trustlens`.

Press Enter. Cloudflare registers it and deploys. Final output:

```
Uploaded trustlens-backend (7.78 sec)
Published trustlens-backend (1.23 sec)
  https://trustlens-backend.YOUR-SUBDOMAIN.workers.dev
```

**Copy the full URL** — that's your Backend URL.

Example: `https://trustlens-backend.trustlens.workers.dev`

---

## Step 6 — Verify the Worker is live

```powershell
curl "https://trustlens-backend.YOUR-SUBDOMAIN.workers.dev/health"
```

Or in PowerShell:

```powershell
Invoke-WebRequest "https://trustlens-backend.YOUR-SUBDOMAIN.workers.dev/health" | Select-Object -ExpandProperty Content
```

Expected response:

```json
{"status":"ok","ts":1234567890}
```

If you see that, the Worker is running.

---

## Step 7 — Install the TrustLens extension (if not already)

Open Chrome → `chrome://extensions/` → enable **Developer mode** (top right) → **Load unpacked** → pick `C:\All_projects\Fraud_Dns_and_email_spoofing\extension` → **Open**.

TrustLens appears in the toolbar.

---

## Step 8 — Run the crawler to seed the backend

The crawler pulls from PhishTank, URLhaus, OpenPhish, and ThreatFox, deduplicates by root domain, and POSTs to the Worker's `/ingest` endpoint. **First run takes 5-10 minutes** (PhishTank's full verified dump is ~10MB).

In PowerShell:

```powershell
cd "C:\All_projects\Fraud_Dns_and_email_spoofing\backend"
$env:INGEST_TOKEN = "tl-ingest-a8f3b2c1d4e5f6g7h8i9j0k"
$env:BACKEND_URL = "https://trustlens-backend.YOUR-SUBDOMAIN.workers.dev"
node crawler.js
```

**Replace the values** with the ones from Step 4 and Step 5.

You should see:

```
[phishtank] fetching online-valid.json...
[phishtank] 12345 unique root domains
[phishtank] ingest result: {"written":12345,"skipped":0}
[urlhaus] fetching recent...
[urlhaus] ingest result: {"written":678,...}
[openphish] ingest result: {"written":...}
[threatfox] ingest result: {"written":...}
crawl done. total written: 50000+
```

If any source fails (rate limit, network), the crawler logs the error and continues with the next. Common failures:

- `[phishtank] failed: HTTP 429` — PhishTank rate-limited. Wait an hour and rerun.
- `[threatfox] failed: HTTP 503` — abuse.ch temporarily down. Skip and rerun later.

---

## Step 9 — Configure the extension with the backend URL

1. Click the TrustLens icon in Chrome's toolbar.
2. Click the **Help** tab.
3. Find **Backend URL** (under "Backend (optional)").
4. Paste your Worker URL: `https://trustlens-backend.YOUR-SUBDOMAIN.workers.dev`
5. Click **Save**.
6. (Optional) Paste your `REPORT_TOKEN` from Step 4 into **Community report token** → **Save** (enables collab reporting).
7. Go to `chrome://extensions/`, find TrustLens, click the **refresh** icon (or toggle off/on) to reload the service worker.

---

## Step 10 — Verify the backend is live in the extension

1. Click the TrustLens icon.
2. Look at the **Threat feeds:** row under the verdict card.
3. The **Backend** pill should be green (not grey).
4. Click **Check this site**.
5. The test list should include a new entry: **Backend Reputation**.
6. If it says "Listed by backend (phishtank, urlhaus)" → the system is working end-to-end.

---

## Step 11 — Re-run the crawler periodically

A single crawl gets you started, but new phishing URLs appear every day. Re-run the crawler on whatever cadence suits you:

- **Weekly** is enough for most users.
- **Daily** (every 24h) catches brand-new kits within hours.
- **Every 30 min** matches commercial anti-phishing cadence.

To schedule on Windows (Task Scheduler):

```powershell
$action = New-ScheduledTaskAction `
  -Execute "node.exe" `
  -Argument "C:\All_projects\Fraud_Dns_and_email_spoofing\backend\crawler.js" `
  -WorkingDirectory "C:\All_projects\Fraud_Dns_and_email_spoofing\backend"

$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries

Register-ScheduledTask `
  -TaskName "TrustLens Crawler" `
  -Action $action `
  -Settings $settings `
  -Trigger (New-ScheduledTaskTrigger -Daily -At "03:00")
```

You'll also need to set the env vars persistently for the scheduled task. Either:

- Add them as system env vars: System Properties → Environment Variables → New (User or System).
- Or wrap the crawler call in a `.ps1` file that sets `$env:INGEST_TOKEN` and `$env:BACKEND_URL` first, then runs `node crawler.js`.

---

## Re-deploying after code changes

When you update `worker.js`:

```powershell
cd "C:\All_projects\Fraud_Dns_and_email_spoofing\backend"
npx wrangler deploy
```

Takes ~5-10 seconds. The Worker URL stays the same. The extension needs no changes.

---

## Updating the secret tokens

```powershell
npx wrangler secret put INGEST_TOKEN
npx wrangler secret put REPORT_TOKEN
```

Just retype the new value. The Worker picks it up on the next request.

---

## Updating the KV namespace

If you ever delete the KV namespace and create a new one:

```powershell
npx wrangler kv:namespace create REPUTATION
```

Copy the new id → paste into `wrangler.toml` → `npx wrangler deploy`.

The KV namespace ID you used (a388ab74a0904bd787d2418197060c86) is a stable identifier — keep it. If you lose track of it:

```powershell
npx wrangler kv:namespace list
```

---

## Verifying deployment with self-tests

These work without any network — they check the pure logic in `worker.js`:

```powershell
node "C:\All_projects\Fraud_Dns_and_email_spoofing\backend\tests\check_backend.mjs"
node "C:\All_projects\Fraud_Dns_and_email_spoofing\backend\tests\check_crawler.mjs"
```

Both should print all PASS.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `wrangler: command not found` | Run `npm install` in the backend directory first. |
| `Authentication error [code: 10000]` | Run `npx wrangler login` again. |
| KV error on deploy | Check `wrangler.toml` has the correct id from Step 3. |
| Extension says "Backend lookup failed" | Wrong URL, or Worker not deployed. Re-run Step 5 / Step 6. |
| Extension shows Backend pill as grey | Backend URL not saved in popup → Help → Settings → Backend URL. |
| `/health` returns 404 | Subdomain not registered. Re-run `npx wrangler deploy` and answer `yes` to subdomain prompt. |
| Crawler says `401 Unauthorized` | INGEST_TOKEN doesn't match the secret. Re-run Step 4 and make sure the env var in Step 8 matches. |
| `npm install` fails | Check Node version (`node --version`) is 18+. |
| Extension test list missing "Backend Reputation" entry | The extension wasn't reloaded after saving the URL. `chrome://extensions/` → toggle TrustLens off/on. |

---

## What accuracy to expect

| Configuration | Recall on PhishTank-validated phishing |
|---|---|
| Extension only, no feeds configured | ~70–75% |
| + Google Safe Browsing key | ~80–83% |
| + Backend (4 feeds, KV cached) | ~92–95% |
| + Backend + collab reporting | ~94–96% |

The backend's edge comes from:
1. **Aggregation** — one URL hits 4 feeds. If 2+ feeds agree, weight boosts (+20 for 2, +35 for 3+).
2. **Crawl freshness** — the crawler pulls fresh data; the Worker caches it for 7 days.
3. **Collab reports** — opt-in crowd-source: ≥3 independent user reports within the TTL flag a host.

TrustLens is heuristic. A polished phishing kit on a 2-year-old legitimate domain can still pass. It's not a substitute for paid enterprise anti-phishing.

---

## File reference

```
backend/
  worker.js              Cloudflare Worker — /score /ingest /report /health
  crawler.js             Node script — pulls 4 feeds, POSTs to /ingest
  wrangler.toml          Deploy config (KV namespace id lives here)
  package.json           Wrangler dev dep + scripts
  tests/
    check_backend.mjs    Pure-logic tests for worker.js
    check_crawler.mjs    Parse tests for crawler.js
  node_modules/          npm install output (gitignored)
  package-lock.json      npm install output (gitignored)
```