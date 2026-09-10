// URLhaus lookup. abuse.ch hosts a per-day text dump of malware URLs.
// Endpoints:
//   - https://urlhaus.abuse.ch/downloads/text/   (one URL per line)
//   - https://urlhaus-api.abuse.ch/v1/urls/recent/   (JSON, free, no key)
//
// We use the JSON endpoint — bounded size, gives us tags + status.
//
// Cache: chrome.storage.local with 24h TTL. We keep root-domain Set only.

import { getRootDomain } from "./domain.js";

const API_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/";
const CACHE_KEY = "trustlens.urlhausCache";
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

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

async function fetchRecent() {
  try {
    const res = await fetch(API_URL);
    if (!res.ok) return null;
    const data = await res.json();
    if (!data || !Array.isArray(data.urls)) return null;
    const rootSet = new Map();
    for (const entry of data.urls) {
      const u = entry && entry.url;
      if (typeof u !== "string") continue;
      try {
        const host = new URL(u).hostname.toLowerCase().replace(/^www\./, "");
        const root = getRootDomain(host);
        if (root) rootSet.set(root, true);
      } catch (e) { /* skip malformed */ }
    }
    return [...rootSet.keys()];
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
  const fresh = await fetchRecent();
  if (fresh) {
    const fetchedAt = Date.now();
    memoryCache = { fetchedAt, entries: fresh };
    await saveToStorage({ fetchedAt, entries: fresh });
    return fresh;
  }
  memoryCache = { fetchedAt: Date.now(), entries: [] };
  return memoryCache.entries;
}

export async function testUrlhaus(host) {
  const name = "URLhaus";
  const domain = getRootDomain(host);
  try {
    const entries = await getEntries();
    if (entries.length === 0) {
      return { name, passed: true, weight: 0, reason: "URLhaus feed unavailable — skipped", evidence: domain, skipped: true };
    }
    if (entries.includes(domain)) {
      return { name, passed: false, weight: 55, reason: `Listed on URLhaus (malware distribution)`, evidence: domain };
    }
    return { name, passed: true, weight: 0, reason: "Not on URLhaus", evidence: domain };
  } catch (e) {
    return { name, passed: true, weight: 0, reason: "URLhaus lookup failed", evidence: e.message, skipped: true };
  }
}

export function prewarm() { getEntries().catch(() => { /* swallow */ }); }