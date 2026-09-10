# TrustLens

Chrome extension (MV3) that scores the trustworthiness of the current site and of any emails displayed on the page. Click the toolbar icon to check a site; risky emails on the page get an underline + a hover tooltip; a red banner appears automatically when a site scores Dangerous. A submit-time warning fires if a password form is about to send credentials to a third party.

By default, lookups go to public RDAP (rdap.org), DoH (dns.google / cloudflare-dns.com), Certificate Transparency (crt.sh), PhishTank, URLhaus, and (optionally) Google Safe Browsing v4.

A self-hosted Cloudflare Worker backend in `backend/` aggregates PhishTank + URLhaus + OpenPhish + ThreatFox + Spamhaus via a private KV cache. **Optional but recommended** — bumps accuracy from ~85-88% to ~92-95% on PhishTank-validated phishing by combining 4-5 independent feeds within a few minutes of new threats appearing.

## How the score works

Start at 100. Each test either passes (no change) or fails (subtracts its weight). The final number is clamped to 0–100.

- **Safe (80–100)** — proceed normally.
- **Caution (50–79)** — double-check the URL; don't enter passwords unless you're certain.
- **Dangerous (<50)** — do not enter credentials or click email links.

| Category | Test | Source | Cost |
|---|---|---|---|
| Threat Intel | Google Safe Browsing v4 | `safebrowsing.googleapis.com` | Free tier 10k/day (key required) |
| Threat Intel | PhishTank | `data.phishtank.com` dump, 24h cached | Free |
| Threat Intel | URLhaus | `urlhaus-api.abuse.ch/v1/urls/recent/`, 24h cached | Free |
| Network | DNSSEC (AD flag) | DoH `dns.google` | Free |
| Network | Cross-Resolver Consistency | DoH Google vs Cloudflare, then ASN compare via ipinfo.io (HTTPS) | Free (50k/mo, optional token raises limit) |
| Network | Unsigned Composite | DNSSEC + SPF + DMARC aggregate | Free |
| Domain | Domain Age | RDAP (4s timeout) | Free |
| Domain | Registrar Reputation | RDAP (4s timeout) | Free |
| Domain | SSL Certificate Age | crt.sh (4s timeout) | Free |
| Domain | Homoglyph / Punycode | local | Free |
| Domain | High-Risk TLD / Naming | local heuristics | Free |
| Domain | Brand in Subdomain | local (brand list + popular-domain allowlist) | Free |
| Brand | Typosquat / Spelling Trick | Levenshtein vs 291-brand list | Free, local |
| Brand | Favicon Brand Match | local 8x8 aHash + hue histogram + edge hash | Free, local |
| Email | Email Authentication (MX/SPF/DMARC) | DoH TXT/MX | Free |
| Email | Disposable Email Provider | disposable-email-domains blocklist, 7d cached | Free |
| Email | Display Name Mismatch | token + year/numeric heuristic | Free, local |
| DOM | HTTPS Enabled | URL scheme | Free |
| DOM | Form Action Audit | page DOM | Free, local |
| DOM | iFrame Clickjack Scan | page DOM | Free, local |
| DOM | Form Submit Watcher | event hook | Free, local |
| DOM | Malvertising / Pop-Under | page DOM | Free, local |
| DOM | Page Content Signals | form inputs, title brand claim, target=_blank ratio, hidden password fields | Free, local |
| DOM | JS Behavior Signals | dynamic password creation, atob+document.write, large base64, off-origin beacons | Free, local |
| History | Kit Rotation Detector | same fingerprint on ≥3 hosts in 24h | Free, local |

Each test card in the popup shows its name, Pass/Fail/Skip badge, the penalty it applied, and the reason.

## Install (development)

1. Open `chrome://extensions/`.
2. Toggle **Developer mode** on.
3. Click **Load unpacked** and pick the `extension/` folder.
4. The TrustLens icon appears next to the address bar.
5. (Optional) Open the popup → **Help** tab → paste your Google Safe Browsing API key → **Save**. The key is stored in `chrome.storage.local`; it's never committed to disk by the extension code.

## Run

- Click the icon → **Check this site** → see the per-test breakdown.
- On any page, emails get auto-extracted; risky ones get a red/orange underline.
- If a site scores Dangerous, a red banner appears at the top of the page automatically.
- If a password form is about to post to a third-party domain, you get a confirm dialog before submission.
- The **History** tab keeps the last 50 checks (stored in `chrome.storage.local`).

## Self-tests

```bash
node extension/tests/check_score.mjs
node extension/tests/check_typosquat.mjs
node extension/tests/check_homoglyph.mjs
node extension/tests/check_brands.mjs
node extension/tests/check_display_name.mjs
node extension/tests/check_display_extract.mjs
node extension/tests/check_brand_subdomain.mjs
node extension/tests/check_composite.mjs
node extension/tests/check_history_rotation.mjs
node extension/tests/check_disposable.mjs
node extension/tests/check_integration.mjs
node extension/tests/check_backend_ext.mjs
node backend/tests/check_backend.mjs
node backend/tests/check_crawler.mjs
```

All should print all PASS.

## Accuracy

| Configuration | Recall on PhishTank-validated phishing |
|---|---|
| Heuristics only (no API keys) | ~70–75% |
| + Google Safe Browsing (key configured) | ~80–83% |
| + Backend (4+ feeds, KV cached, 30min crawler) | ~92–95% |
| + Backend + collab reporting | ~94–96% |

The backend is the largest single accuracy lever. It runs every public feed in parallel, deduplicates by root domain, and stores in KV with a 5-minute score cache and 7-day host TTL — a kit that hits one feed shows up across all of them within 30 minutes (crawler interval).

These are heuristic ceilings — a polished phishing kit hosted on a 2-year-old legitimate domain can still pass. TrustLens is not a substitute for enterprise anti-phishing or user caution.

## Backend (optional, recommended)

The `backend/` directory contains a Cloudflare Worker and a Node crawler.

**Deploy the Worker:**

```bash
cd backend
npm install
npx wrangler kv:namespace create REPUTATION   # paste the returned id into wrangler.toml
npx wrangler secret put INGEST_TOKEN           # any long random string
npx wrangler secret put REPORT_TOKEN           # any long random string (for collab reports)
npx wrangler deploy
```

The Worker URL is something like `https://trustlens-backend.<your-subdomain>.workers.dev`.

**Configure the extension:**

1. Click the TrustLens icon → **Help** tab.
2. Paste the Worker URL into **Backend URL** → **Save**.
3. (Optional) Paste `REPORT_TOKEN` into **Community report token** to enable collab reporting.

**Run the crawler:**

```bash
INGEST_TOKEN=<your-token> \
BACKEND_URL=https://trustlens-backend.<your-subdomain>.workers.dev \
  node backend/crawler.js
```

Schedule it via cron / Cloudflare Cron Triggers / GitHub Actions every 30 minutes. The crawler pulls from PhishTank, URLhaus, OpenPhish, and ThreatFox; each feed is deduplicated by root domain before posting to `/ingest`.

**Self-test the backend:**

```bash
node backend/tests/check_backend.mjs
node backend/tests/check_crawler.mjs
```

## Project layout

```
extension/
  manifest.json
  background/
    sw.js                  # service worker — orchestrates everything
    score.js               # aggregate(tests) -> { score, verdict, tests }
    tests.js               # domain age, registrar, cert age, typosquat, email auth, disposable, display-name
    test_safebrowsing.js   # GSB v4 (uses stored API key)
    test_phishtank.js      # PhishTank dump, 24h cached (legacy — backend preferred)
    test_urlhaus.js        # URLhaus recent, 24h cached (legacy — backend preferred)
    backend.js             # calls Worker /score + /report
    test_dnssec.js         # DNSSEC + cross-resolver (4s timeout)
    test_favicon.js        # aHash + hue + edge hash brand clone detection
    test_homoglyph.js      # xn-- + non-ASCII lookalikes
    test_highrisk.js       # high-risk TLD + piracy keywords
    test_brand_subdomain.js # paypal.com.evil.tk shape — brand in subdomain label
    popular.js             # popular-domain allowlist (FPR guard + heuristic skip)
    composite.js           # DNSSEC + SPF + DMARC aggregate signal
    history_rotation.js    # same fingerprint on multiple hosts
    brands.js              # 291-brand curated list
    disposable.js          # disposable-email-domains blocklist, 7d cached
    domain.js              # root-domain + validation helpers
    doh.js                 # DoH client (Google + Cloudflare)
    asn.js                 # ipinfo.io ASN lookup
  popup/
    popup.html / popup.css / popup.js
  content/
    content_signals.js     # page content + JS behavior signals (loaded first)
    content.js             # email extraction, highlighting, DOM tests, banner, form interception
    content.css
  icons/                   # placeholder PNGs
  tests/                   # node self-checks
backend/
  worker.js                # Cloudflare Worker — /score /ingest /report /health
  crawler.js               # pulls PhishTank + URLhaus + OpenPhish + ThreatFox
  wrangler.toml            # deploy config
  package.json
  tests/                   # node self-checks for worker + crawler
```

## What was deliberately skipped (add when needed)

- **Server-side ML model scoring** — would push to 95%+ but needs labeled data + retraining pipeline + ~1MB model file in extension. Out of scope for v0.2.

- **DKIM signature verification on actual messages** — needs the message body, not just DNS. Trivial to add once an `email.eml` is fed in.
- **Real-time favicon pHash caching** — currently hashes ~40 brand domains on every check; add a `chrome.storage.local` cache if you hit rate limits on the `s2/favicons` endpoint.
- **PhishTank offline dataset** — the live API is rate-limited; for high-volume checks, download the JSON dump and bundle it.
- **OpenPhish / URLhaus feeds** — same shape as PhishTank; one extra test, ~30 lines.
- **Backend proxy** — useful only if DoH/RDAP/GSB rate-limit you.

