// TrustLens backend. Cloudflare Worker.
// Endpoints:
//   POST /score        — extension sends {host, url}, gets a verdict
//   POST /ingest       — crawler submits batched {entries: [{host, source, firstSeen}]}
//   POST /report       — extension reports a confirmed-phish host (opt-in)
//   POST /asn          — extension sends {ips:[]}, gets {ip:{asn,org,country} | {error}}
//   POST /ct           — extension sends {domain}, gets {firstSeen, certCount} | {error}
//   GET  /health       — for monitoring
//
// KV layout:
//   bucket:<char>     -> packed map { <root>: { sources:[{name,firstSeen}],
//                                             reports?, lastSeen } }
//                        ~36 buckets (first char of the root). A 14k-host
//                        feed = ~36 writes/day instead of 14k — the free tier
//                        caps KV writes at 1,000/day, so per-host keys can
//                        never hold a full feed. No bucket TTL: staleness is
//                        per-entry — lastSeen older than 7 days is ignored at
//                        read time and pruned on the next rewrite.
//   score:<root>      -> cached /score response                              TTL 5m
//   asn:<ip>          -> { asn, org, country } | { error: "..." }           TTL 24h
//   ct:<rootDomain>   -> { firstSeen, certCount } | { error: "..." }        TTL 24h
//
// Privacy: backend never sees the full URL, just root domain or IPs (ASN lookup
// is naturally IP-shaped). /asn and /ct are read-only and require no token.

const KV_TTL_SECONDS = 7 * 24 * 60 * 60;
const SCORE_TTL_SECONDS = 5 * 60;
const ASN_TTL_SECONDS = 24 * 60 * 60;
const CT_TTL_SECONDS = 24 * 60 * 60;

// Per-entry staleness window (matches the old per-host KV TTL).
const STALE_MS = 7 * 24 * 60 * 60 * 1000;

// Rate limit for the tokenless public endpoints (/score /asn /ct).
// In-memory per-isolate: KV writes would cost more than the abuse they
// prevent, and per-isolate limiting stops the obvious quota-burner.
// ponytail: not global across isolates — add a KV/Durable Object counter
// if a single client still manages to burn the upstream quota.
const RL_WINDOW_MS = 60_000;
const RL_MAX = 30; // per IP per minute
const rlBuckets = new Map(); // ip -> { count, resetAt }

function rateLimited(request) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const now = Date.now();
  let b = rlBuckets.get(ip);
  if (!b || now > b.resetAt) {
    b = { count: 0, resetAt: now + RL_WINDOW_MS };
    rlBuckets.set(ip, b);
    // Bound the map: drop expired buckets when it grows.
    if (rlBuckets.size > 10_000) {
      for (const [k, v] of rlBuckets) if (now > v.resetAt) rlBuckets.delete(k);
    }
  }
  b.count++;
  return b.count > RL_MAX;
}

const SOURCES = {
  phishtank: { weight: 55, name: "PhishTank" },
  urlhaus:   { weight: 55, name: "URLhaus" },
  openphish: { weight: 55, name: "OpenPhish" },
  threatfox: { weight: 60, name: "ThreatFox" },
  spamhaus:  { weight: 60, name: "Spamhaus DBL" },
  collab:    { weight: 50, name: "Community Report" },
};

function rootDomainOf(host) {
  if (!host) return "";
  const h = host.toLowerCase().replace(/^www\./, "");
  const parts = h.split(".").filter(Boolean);
  if (parts.length <= 2) return h;
  const twoPart = new Set([
    "co.uk", "co.in", "co.jp", "co.kr", "co.nz", "co.za",
    "com.au", "com.br", "com.cn", "com.mx", "com.tr", "com.tw",
    "org.uk", "net.au", "ac.uk",
  ]);
  const last2 = parts.slice(-2).join(".");
  if (twoPart.has(last2)) return parts.slice(-3).join(".");
  return parts.slice(-2).join(".");
}

function isValidDomain(d) {
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d);
}

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-TrustLens-Token",
    "Content-Type": "application/json",
  };
}

function jsonResponse(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders(), ...extraHeaders },
  });
}

// --- bucketed host storage ---
// Buckets keyed by first char of the root domain (0-9a-z). Each bucket is one
// KV entry holding a packed map of root -> {sources, reports?, lastSeen}.
// One bucket write per ingest chunk beats the free tier's 1k writes/day cap.

const BUCKET_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz";

function bucketOf(root) {
  const c = (root[0] || "").toLowerCase();
  if (BUCKET_CHARS.includes(c)) return c;
  return "x"; // roots starting with anything else (shouldn't happen post-validation)
}

function bucketKey(root) {
  return `bucket:${bucketOf(root)}`;
}

async function readBucket(env, root) {
  const map = await env.REPUTATION.get(bucketKey(root), "json");
  return map && typeof map === "object" ? map : {};
}

// Prune stale entries before writing so buckets stay bounded: a bucket only
// shrinks when it's touched, which is fine — read path ignores stale anyway.
function pruneStale(map, now = Date.now()) {
  for (const [host, e] of Object.entries(map)) {
    if (!e || typeof e.lastSeen !== "number" || now - e.lastSeen > STALE_MS) {
      delete map[host];
    }
  }
  return map;
}

async function writeBucket(env, root, map) {
  await env.REPUTATION.put(bucketKey(root), JSON.stringify(map));
}

async function readHost(env, root) {
  const map = await readBucket(env, root);
  const entry = map[root];
  if (!entry || typeof entry.lastSeen !== "number") return null;
  if (Date.now() - entry.lastSeen > STALE_MS) return null;
  return entry;
}

async function writeHost(env, root, entry) {
  const map = await readBucket(env, root);
  map[root] = entry;
  pruneStale(map);
  await writeBucket(env, root, map);
}

async function mergeHost(env, root, source, firstSeen) {
  const map = await readBucket(env, root);
  const now = Date.now();
  const existing = map[root];
  const sources = existing && Array.isArray(existing.sources) ? [...existing.sources] : [];
  const alreadyListed = sources.find((s) => s.name === source);
  if (!alreadyListed) {
    sources.push({ name: source, firstSeen: firstSeen || now });
  }
  const merged = { sources, reports: existing && existing.reports, lastSeen: now };
  map[root] = merged;
  return { merged, map, changed: !alreadyListed };
}

// Aggregate across all stored sources → weight + verdict.
function aggregateFromSources(sources) {
  if (!Array.isArray(sources) || sources.length === 0) {
    return { listed: false, weight: 0, sources: [] };
  }
  const seen = new Set();
  let weight = 0;
  for (const s of sources) {
    const meta = SOURCES[s.name];
    if (!meta) continue;
    if (seen.has(s.name)) continue;
    seen.add(s.name);
    // Multiple sources boost: two = +20, three+ = +35.
    weight += meta.weight;
  }
  if (seen.size === 0) {
    return { listed: false, weight: 0, sources: [] };
  }
  if (seen.size >= 3) weight += 35;
  else if (seen.size >= 2) weight += 20;
  return { listed: true, weight, sources: [...seen] };
}

async function handleScore(request, env) {
  const body = await request.json().catch(() => null);
  if (!body || typeof body.host !== "string") {
    return jsonResponse({ error: "Missing host" }, 400);
  }
  const root = rootDomainOf(body.host);
  if (!isValidDomain(root)) {
    return jsonResponse({ error: "Invalid host" }, 400);
  }
  // Cache key includes source freshness window.
  const cacheKey = `score:${root}`;
  const cached = await env.REPUTATION.get(cacheKey);
  if (cached) {
    return jsonResponse(JSON.parse(cached), 200, { "X-Cache": "HIT" });
  }
  const entry = (await readHost(env, root))
    // Legacy pre-bucket key, still within its old 7d TTL during migration.
    || await env.REPUTATION.get(`host:${root}`, "json").catch(() => null);
  const agg = aggregateFromSources(entry && entry.sources);
  const out = {
    host: root,
    listed: agg.listed,
    weight: agg.weight,
    sources: agg.sources,
    timestamp: Date.now(),
  };
  // Cache is an optimization — a failed write (e.g. daily KV limit) must
  // never fail the lookup itself.
  await env.REPUTATION.put(cacheKey, JSON.stringify(out), {
    expirationTtl: SCORE_TTL_SECONDS,
  }).catch(() => {});
  return jsonResponse(out, 200, { "X-Cache": "MISS" });
}

async function handleIngest(request, env) {
  const auth = request.headers.get("X-TrustLens-Token");
  if (!env.INGEST_TOKEN || auth !== env.INGEST_TOKEN) {
    return jsonResponse({ error: "Unauthorized" }, 401);
  }
  const body = await request.json().catch(() => null);
  const entries = body && Array.isArray(body.entries) ? body.entries : null;
  if (!entries) {
    return jsonResponse({ error: "Missing entries[]" }, 400);
  }
  if (entries.length > 1000) {
    return jsonResponse({ error: "Too many entries (max 1000)" }, 400);
  }
  // Group by bucket: one read + at most one write per bucket. A full 14k-host
  // crawl is ~36 writes total, and a re-crawl that adds nothing new writes 0.
  let written = 0;
  let skipped = 0;
  const buckets = new Map(); // bucketChar -> { map, roots: Set, changed: bool }
  for (const e of entries) {
    if (!e || typeof e.host !== "string" || typeof e.source !== "string") { skipped++; continue; }
    const root = rootDomainOf(e.host);
    if (!isValidDomain(root)) { skipped++; continue; }
    if (!SOURCES[e.source]) { skipped++; continue; }
    const bc = bucketOf(root);
    let b = buckets.get(bc);
    if (!b) { b = { map: null, roots: new Set(), changed: false }; buckets.set(bc, b); }
    b.roots.add(root);
    b.pending = b.pending || [];
    b.pending.push({ root, source: e.source, firstSeen: e.firstSeen });
    written++;
  }
  const roots = new Set();
  for (const [bc, b] of buckets) {
    if (!b.map) b.map = await readBucketByKey(env, bc);
    for (const { root, source, firstSeen } of b.pending) {
      const now = Date.now();
      const existing = b.map[root];
      const sources = existing && Array.isArray(existing.sources) ? existing.sources : [];
      if (!sources.find((s) => s.name === source)) {
        sources.push({ name: source, firstSeen: firstSeen || now });
        b.changed = true;
      }
      b.map[root] = { sources, reports: existing && existing.reports, lastSeen: now };
      roots.add(root);
    }
    if (b.changed) {
      pruneStale(b.map);
      await env.REPUTATION.put(`bucket:${bc}`, JSON.stringify(b.map));
    }
  }
  // Invalidate score caches for touched hosts — otherwise /score serves
  // "not listed" for up to 5 minutes after the feed sees the host.
  // Only hosts whose bucket actually changed can differ, but deleting for
  // all touched roots is cheap and correct.
  await Promise.all([...roots].map((r) => env.REPUTATION.delete(`score:${r}`).catch(() => {})));
  return jsonResponse({ written, skipped, buckets: [...buckets.keys()] });
}

async function readBucketByKey(env, bc) {
  const map = await env.REPUTATION.get(`bucket:${bc}`, "json");
  return map && typeof map === "object" ? map : {};
}

async function handleReport(request, env) {
  // Opt-in crowd-source endpoint. Requires user token from popup settings.
  const auth = request.headers.get("X-TrustLens-Token");
  if (!env.REPORT_TOKEN || auth !== env.REPORT_TOKEN) {
    return jsonResponse({ error: "Unauthorized" }, 401);
  }
  const body = await request.json().catch(() => null);
  if (!body || typeof body.host !== "string") {
    return jsonResponse({ error: "Missing host" }, 400);
  }
  const root = rootDomainOf(body.host);
  if (!isValidDomain(root)) {
    return jsonResponse({ error: "Invalid host" }, 400);
  }
  // Merge collab source + increment report count in ONE bucket write.
  // (Legacy pre-bucket `host:` entries are folded in once, then left to
  // expire — every new write lands in the bucket.)
  const legacy = await env.REPUTATION.get(`host:${root}`, "json").catch(() => null);
  const map = await readBucket(env, root);
  const existing = map[root] || (legacy && { sources: legacy.sources, reports: legacy.reports }) || null;
  const sources = existing && Array.isArray(existing.sources) ? [...existing.sources] : [];
  if (!sources.find((s) => s.name === "collab")) {
    sources.push({ name: "collab", firstSeen: Date.now() });
  }
  const reports = ((existing && existing.reports) || 0) + 1;
  map[root] = { sources, reports, lastSeen: Date.now() };
  pruneStale(map);
  await writeBucket(env, root, map);
  // Mark collab listing only after ≥3 independent reports. Invalidate the
  // score cache so the next /score sees the new state.
  if (reports >= 3) {
    await env.REPUTATION.put(`score:${root}`, JSON.stringify({
      host: root, listed: true, weight: SOURCES.collab.weight + 20,
      sources: sources.map((s) => s.name), timestamp: Date.now(),
    }), { expirationTtl: SCORE_TTL_SECONDS }).catch(() => {});
  } else {
    await env.REPUTATION.delete(`score:${root}`).catch(() => {});
  }
  return jsonResponse({ ok: true, reports });
}

function handleHealth() {
  return jsonResponse({ status: "ok", ts: Date.now() });
}

// --- /asn — batch IP → ASN lookup via ipinfo.io ---
// ponytail: free tier blocks browser fetches but allows worker-to-worker without token.
// Cache per-IP for 24h. Cache misses in parallel.
async function handleAsn(request, env) {
  const body = await request.json().catch(() => null);
  const raw = body && Array.isArray(body.ips) ? body.ips : null;
  if (!raw || raw.length === 0) return jsonResponse({ error: "Missing or empty ips[]" }, 400);
  const ips = raw.filter((i) => typeof i === "string" && (/^\d+\.\d+\.\d+\.\d+$/.test(i) || /^\[?[0-9a-f:]+\]?$/i.test(i)));
  if (ips.length === 0) return jsonResponse({ error: "Missing or empty ips[]" }, 400);
  if (ips.length > 50) return jsonResponse({ error: "Too many IPs (max 50)" }, 400);

  const out = {};
  const misses = [];
  // Read cache in parallel; KV.get with "json" parses for us.
  await Promise.all(ips.map(async (ip) => {
    const cached = await env.REPUTATION.get(`asn:${ip}`, "json");
    if (cached) out[ip] = cached;
    else misses.push(ip);
  }));

  // Hit upstream for misses in parallel. ipinfo returns 404 for bogons and
  // 429 when rate-limited; we cache both as {error} so we don't retry for 24h.
  await Promise.all(misses.map(async (ip) => {
    try {
      const res = await fetch(`https://ipinfo.io/${ip}/json`);
      if (res.status === 429 || res.status === 403) {
        const rec = { error: `HTTP ${res.status}` };
        out[ip] = rec;
        await env.REPUTATION.put(`asn:${ip}`, JSON.stringify(rec), { expirationTtl: ASN_TTL_SECONDS }).catch(() => {});
        return;
      }
      if (!res.ok) { out[ip] = { error: `HTTP ${res.status}` }; return; }
      const data = await res.json();
      if (!data || data.bogon) { out[ip] = { error: "bogon" }; return; }
      const org = data.org || "";
      const m = org.match(/^AS(\d+)\s+(.*)$/);
      const rec = {
        asn: m ? `AS${m[1]}` : null,
        org: m ? m[2] : (data.org || null),
        country: data.country || null,
      };
      out[ip] = rec;
      await env.REPUTATION.put(`asn:${ip}`, JSON.stringify(rec), { expirationTtl: ASN_TTL_SECONDS }).catch(() => {});
    } catch (e) {
      out[ip] = { error: e.message };
    }
  }));

  return jsonResponse({ results: out });
}

// --- /ct — domain → cert age from crt.sh, falling back to Certspotter ---
// ponytail: crt.sh is overloaded; Certspotter (free, no auth) is the fallback.
// Cache per-domain for 24h. Transient errors get a 5-min cache.
async function handleCt(request, env) {
  const body = await request.json().catch(() => null);
  const domain = body && typeof body.domain === "string" ? rootDomainOf(body.domain) : "";
  if (!domain || !isValidDomain(domain)) {
    return jsonResponse({ error: "Missing or invalid domain" }, 400);
  }
  const cached = await env.REPUTATION.get(`ct:${domain}`, "json");
  if (cached) return jsonResponse(cached, 200, { "X-Cache": "HIT" });

  let out = await queryCrtSh(domain);
  if (!out) out = await queryCertspotter(domain);
  if (!out) {
    const err = { error: "all CT sources failed" };
    await env.REPUTATION.put(`ct:${domain}`, JSON.stringify(err), { expirationTtl: 5 * 60 }).catch(() => {});
    return jsonResponse(err, 200);
  }
  await env.REPUTATION.put(`ct:${domain}`, JSON.stringify(out), { expirationTtl: CT_TTL_SECONDS }).catch(() => {});
  return jsonResponse(out);
}

async function queryCrtSh(domain) {
  const url = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json&dedupe=Y`;
  try {
    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), 8000);
    let res;
    try { res = await fetch(url, { signal: controller.signal }); }
    finally { clearTimeout(tid); }
    if (!res.ok) return null;
    const text = await res.text();
    if (text.length > 2_000_000) return null;
    const arr = JSON.parse(text);
    if (!Array.isArray(arr) || arr.length === 0) return null;
    arr.sort((a, b) => new Date(a.not_before) - new Date(b.not_before));
    const first = new Date(arr[0].not_before);
    const days = Math.floor((Date.now() - first.getTime()) / 86400000);
    return { firstSeen: arr[0].not_before, certCount: arr.length, days };
  } catch (e) { return null; }
}

// ponytail: free, no auth, JSON list with not_before per cert.
async function queryCertspotter(domain) {
  const url = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&match_wildcards=true`;
  try {
    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), 8000);
    let res;
    try { res = await fetch(url, { signal: controller.signal }); }
    finally { clearTimeout(tid); }
    if (!res.ok) return null;
    const arr = await res.json();
    if (!Array.isArray(arr) || arr.length === 0) return null;
    const dates = arr
      .map((r) => r.not_before)
      .filter(Boolean)
      .map((d) => new Date(d))
      .filter((d) => !isNaN(d.getTime()))
      .sort((a, b) => a - b);
    if (dates.length === 0) return null;
    const first = dates[0];
    const days = Math.floor((Date.now() - first.getTime()) / 86400000);
    return { firstSeen: first.toISOString(), certCount: arr.length, days, source: "certspotter" };
  } catch (e) { return null; }
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }
    const url = new URL(request.url);
    try {
      if (url.pathname === "/health") return handleHealth();
      // Public endpoints are rate-limited; tokened ones (/ingest /report)
      // police themselves via their tokens.
      if (url.pathname === "/score" || url.pathname === "/asn" || url.pathname === "/ct") {
        if (rateLimited(request)) return jsonResponse({ error: "Rate limited" }, 429);
      }
      if (url.pathname === "/score" && request.method === "POST") return await handleScore(request, env);
      if (url.pathname === "/ingest" && request.method === "POST") return await handleIngest(request, env);
      if (url.pathname === "/report" && request.method === "POST") return await handleReport(request, env);
      if (url.pathname === "/asn" && request.method === "POST") return await handleAsn(request, env);
      if (url.pathname === "/ct" && request.method === "POST") return await handleCt(request, env);
      return jsonResponse({ error: "Not found" }, 404);
    } catch (e) {
      return jsonResponse({ error: e.message || "Internal error" }, 500);
    }
  },
};

// Exported for unit tests.
export { rootDomainOf, isValidDomain, aggregateFromSources, SOURCES, handleAsn, handleCt };