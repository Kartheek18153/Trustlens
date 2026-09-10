// Shared RDAP client. One fetch per domain per check (age + registrar tests
// used to each hit rdap.org separately) with a chrome.storage.local cache so
// re-checks and popup re-opens don't re-fetch.

const CACHE_KEY = "trustlens.rdapCache";
const CACHE_TTL_MS = 10 * 60 * 1000;
const TIMEOUT_MS = 4000;
const MAX_ENTRIES = 200; // storage.local is capped; keep the cache bounded

const memory = new Map(); // domain -> { data, at }

async function readStorageCache(domain) {
  try {
    if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) return null;
    const data = await chrome.storage.local.get(CACHE_KEY);
    const cache = data && data[CACHE_KEY];
    if (!cache || typeof cache !== "object") return null;
    const hit = cache[domain];
    if (hit && typeof hit.at === "number" && Date.now() - hit.at < CACHE_TTL_MS) {
      return hit.data;
    }
    return null;
  } catch (e) { return null; }
}

async function writeStorageCache(domain, data) {
  try {
    if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) return;
    const store = await chrome.storage.local.get(CACHE_KEY);
    const cache = (store && store[CACHE_KEY]) || {};
    cache[domain] = { data, at: Date.now() };
    // Bound the cache: drop the oldest entries beyond MAX_ENTRIES.
    const keys = Object.keys(cache);
    if (keys.length > MAX_ENTRIES) {
      keys.sort((a, b) => cache[a].at - cache[b].at);
      for (const k of keys.slice(0, keys.length - MAX_ENTRIES)) delete cache[k];
    }
    await chrome.storage.local.set({ [CACHE_KEY]: cache });
  } catch (e) { /* write failed — memory cache still serves */ }
}

// Returns parsed RDAP JSON, or { __error } on failure. Cached result includes
// errors so a failing domain doesn't get hammered either.
export async function fetchRdap(domain) {
  const now = Date.now();
  const mem = memory.get(domain);
  if (mem && now - mem.at < CACHE_TTL_MS) return mem.data;

  const stored = await readStorageCache(domain);
  if (stored) {
    memory.set(domain, { data: stored, at: now });
    return stored;
  }

  let data;
  try {
    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), TIMEOUT_MS);
    let res;
    try {
      res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { signal: controller.signal });
    } finally { clearTimeout(tid); }
    if (!res.ok) {
      data = { __error: `HTTP ${res.status}` };
    } else {
      data = await res.json();
    }
  } catch (e) {
    data = { __error: e.message || "RDAP fetch failed" };
  }
  memory.set(domain, { data, at: now });
  writeStorageCache(domain, data);
  return data;
}
