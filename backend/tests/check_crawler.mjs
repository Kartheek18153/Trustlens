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