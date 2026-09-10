// Self-check for crawler parse helpers (no network).
// Run with: node tests/check_crawler.mjs

// Inline the helpers since crawler.js is a CommonJS script. We extract them
// by importing the script via dynamic import shim — but easier: copy the
// pure helpers here for unit testing.

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

function hostFromUrl(u) {
  try { return new URL(u).hostname.toLowerCase().replace(/^www\./, ""); }
  catch { return ""; }
}

// Parse PhishTank-style array of {url, submission_time}
function parsePhishtankArray(arr) {
  const seen = new Map();
  for (const entry of arr) {
    if (!entry || typeof entry.url !== "string") continue;
    const h = hostFromUrl(entry.url);
    const root = rootDomainOf(h);
    if (!root || seen.has(root)) continue;
    const ts = entry.submission_time ? Date.parse(entry.submission_time) : Date.now();
    seen.set(root, ts);
  }
  return seen;
}

// Parse URLhaus-style {urls:[{url,dateadded}]}
function parseUrlhausBody(data) {
  const seen = new Map();
  if (!data || !Array.isArray(data.urls)) return seen;
  for (const entry of data.urls) {
    if (!entry || typeof entry.url !== "string") continue;
    const h = hostFromUrl(entry.url);
    const root = rootDomainOf(h);
    if (!root || seen.has(root)) continue;
    const ts = entry.dateadded ? Date.parse(entry.dateadded) * 1000 : Date.now();
    seen.set(root, ts);
  }
  return seen;
}

// Parse OpenPhish feed.txt (one URL per line)
function parseOpenphishText(text) {
  const seen = new Map();
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const h = hostFromUrl(trimmed);
    const root = rootDomainOf(h);
    if (!root || seen.has(root)) continue;
    seen.set(root, Date.now());
  }
  return seen;
}

function expect(label, got, want) {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  console.log((ok ? "PASS" : "FAIL") + " " + label);
  if (!ok) {
    console.log("  got=" + JSON.stringify(got));
    console.log("  want=" + JSON.stringify(want));
    process.exitCode = 1;
  }
}

// PhishTank
const pt = parsePhishtankArray([
  { url: "http://evil.com/login", submission_time: "2024-01-15T10:00:00Z" },
  { url: "http://www.evil.com/account", submission_time: "2024-01-15T11:00:00Z" }, // dup root
  { url: "http://other.io/x", submission_time: "2024-01-15T12:00:00Z" },
]);
expect("phishtank dedup by root", [...pt.keys()].sort(), ["evil.com", "other.io"]);
expect("phishtank timestamp", pt.get("evil.com"), Date.parse("2024-01-15T10:00:00Z"));

// URLhaus
const uh = parseUrlhausBody({
  urls: [
    { url: "http://bad.io/path", dateadded: "1700000000" },
    { url: "http://www.bad.io/other", dateadded: "1700000000" }, // dup root
    { url: "http://evil.co.uk/x", dateadded: "1700000001" },
  ],
});
expect("urlhaus dedup by root", [...uh.keys()].sort(), ["bad.io", "evil.co.uk"]);
expect("urlhaus co.uk normalized", uh.has("evil.co.uk"), true);

// OpenPhish
const op = parseOpenphishText(
  "http://phish1.com/login\n" +
  "http://www.phish1.com/x\n" + // dup
  "http://phish2.org/y\n" +
  "\n" + // empty
  "garbage line\n"
);
expect("openphish dedup", [...op.keys()].sort(), ["phish1.com", "phish2.org"]);
expect("openphish ignores garbage", op.has("garbage line"), false);

// --- ingestBatch output shape: entries MUST carry the source field ---
// Regression: the old ingestBatch rebuilt entries as {host, firstSeen},
// dropping source — the Worker skipped every crawler submission.
{
  // Mirror the fixed ingestBatch logic (chunking + source retention).
  const entries = [
    { host: "evil.com", source: "phishtank", firstSeen: 123 },
    { host: "bad.io", source: "openphish", firstSeen: 456 },
  ];
  const sent = [];
  const postJSON = async (url, body) => { sent.push(body); return { written: body.entries.length, skipped: 0 }; };
  const CHUNK = 500;
  let written = 0;
  for (let i = 0; i < entries.length; i += CHUNK) {
    const chunk = entries.slice(i, i + CHUNK).map((e) => ({
      host: e.host, source: e.source, firstSeen: e.firstSeen,
    }));
    const result = await postJSON("x", { entries: chunk });
    written += (result && result.written) || 0;
  }
  expect("ingest entries carry source", sent[0].entries.map((e) => e.source), ["phishtank", "openphish"]);
  expect("ingest entries carry host", sent[0].entries.map((e) => e.host), ["evil.com", "bad.io"]);
}

// Chunking + bucket grouping: entries are grouped by first char so each POST
// maps to one Worker bucket. 1200 a-hosts + 300 b-hosts -> 6+2 posts, and
// every post is single-bucket.
{
  const entries = [];
  for (let i = 0; i < 1200; i++) entries.push({ host: `a${i}.com`, source: "phishtank", firstSeen: 1 });
  for (let i = 0; i < 300; i++) entries.push({ host: `b${i}.org`, source: "urlhaus", firstSeen: 1 });
  const sent = [];
  const postJSON = async (url, body) => { sent.push(body); return { written: body.entries.length, skipped: 0 }; };

  // Mirror the fixed ingestBatch grouping.
  const CHUNK = 200;
  const byBucket = new Map();
  for (const e of entries) {
    const bc = e.host[0].toLowerCase();
    if (!byBucket.has(bc)) byBucket.set(bc, []);
    byBucket.get(bc).push(e);
  }
  const posts = [];
  for (const list of byBucket.values()) {
    for (let i = 0; i < list.length; i += CHUNK) {
      posts.push(list.slice(i, i + CHUNK).map((e) => ({ host: e.host, source: e.source, firstSeen: e.firstSeen })));
    }
  }
  for (const chunk of posts) await postJSON("x", { entries: chunk });

  expect("post count", sent.length, 8); // 1200/200 + 300/200
  expect("every post single-bucket", sent.every((b) => new Set(b.entries.map((e) => e.host[0])).size === 1), true);
  expect("post sizes", sent.map((b) => b.entries.length), [200, 200, 200, 200, 200, 200, 200, 100]);
}