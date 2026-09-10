// PhishTank lookup. Free API, no key required for read-only URL check.
// Endpoints:
//   - https://checkurl.phishtank.com/checkurl/   (POST form, returns HTML)
//   - https://data.phishtank.com/data/online-valid.json  (bulk JSON dump)
//
// For a per-URL check from the browser extension, the dump endpoint is the
// only practical shape — we download once and cache. The dump is ~10MB
// compressed; we filter to entries matching the host (or its root domain)
// to keep the work bounded.
//
// Cache: chrome.storage.local with 24h TTL.

import { getRootDomain } from "./domain.js";

const DUMP_URL = "https://data.phishtank.com/data/online-valid.json";
const CACHE_KEY = "trustlens.phishtankCache";
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_PAYLOAD_BYTES = 30 * 1024 * 1024; // 30MB safety cap

let memoryCache = null; // { fetchedAt, entries: Map<rootDomain, true> }

async function loadFromStorage() {
  try {
    if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) return null;
    const data = await chrome.storage.local.get(CACHE_KEY);
    const cached = data[CACHE_KEY];
    if (cached && Array.isArray(cached.entries) && typeof cached.fetchedAt === "number") {
      if (Date.now() - cached.fetchedAt < CACHE_TTL_MS) return cached;
    }
  } catch (e) { /* storage read failed */ }
  return null;
}

async function saveToStorage(cached) {
  try {
    if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) return;
    await chrome.storage.local.set({ [CACHE_KEY]: cached });
  } catch (e) { /* storage write failed */ }
}

async function fetchDump() {
  try {
    const res = await fetch(DUMP_URL, { redirect: "follow" });
    if (!res.ok) return null;
    const len = parseInt(res.headers.get("content-length") || "0", 10);
    if (len > MAX_PAYLOAD_BYTES) return null;
    const text = await res.text();
    if (text.length > MAX_PAYLOAD_BYTES) return null;
    let arr;
    try { arr = JSON.parse(text); } catch (e) { return null; }
    if (!Array.isArray(arr) || arr.length === 0) return null;
    // Build a Set of root domains for O(1) host match.
    const rootSet = new Map();
    for (const entry of arr) {
      const u = entry && entry.url;
      if (typeof u !== "string") continue;
      try {
        const host = new URL(u).hostname.toLowerCase().replace(/^www\./, "");
        const root = getRootDomain(host);
        if (root) rootSet.set(root, true);
      } catch (e) { /* skip malformed */ }
    }
    if (rootSet.size === 0) return null;
    return { entries: [...rootSet.keys()] };
  } catch (e) {
    return null;
  }
}

async function getEntries() {
  if (memoryCache && Date.now() - memoryCache.fetchedAt < CACHE_TTL_MS) {
    return memoryCache.entries;
  }
  const cached = await loadFromStorage();
  if (cached) {
    memoryCache = { fetchedAt: cached.fetchedAt, entries: cached.entries };
    return cached.entries;
  }
  const fresh = await fetchDump();
  if (fresh) {
    const fetchedAt = Date.now();
    memoryCache = { fetchedAt, entries: fresh.entries };
    await saveToStorage({ fetchedAt, entries: fresh.entries });
    return fresh.entries;
  }
  memoryCache = { fetchedAt: Date.now(), entries: [] };
  return memoryCache.entries;
}

export async function testPhishtank(host) {
  const name = "PhishTank";
  const domain = getRootDomain(host);
  try {
    const entries = await getEntries();
    if (entries.length === 0) {
      return { name, passed: true, weight: 0, reason: "PhishTank dump unavailable — skipped", evidence: domain, skipped: true };
    }
    if (entries.includes(domain)) {
      return { name, passed: false, weight: 55, reason: `Listed on PhishTank`, evidence: domain };
    }
    return { name, passed: true, weight: 0, reason: "Not on PhishTank", evidence: domain };
  } catch (e) {
    return { name, passed: true, weight: 0, reason: "PhishTank lookup failed", evidence: e.message, skipped: true };
  }
}

export function prewarm() { getEntries().catch(() => { /* swallow */ }); }