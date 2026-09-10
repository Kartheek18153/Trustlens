// Disposable / temporary email domain blocklist.
// Source: https://disposable.github.io/disposable-email-domains/domains.txt
// Plain text, ~3000 entries, free, no key. Cached in chrome.storage.local
// for 7 days so we don't fetch on every email check.
//
// If chrome.storage.local is unavailable (running under node for tests),
// we fall back to a small built-in list so tests don't need the network.

const CACHE_KEY = "trustlens.disposableCache";
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const SOURCE_URL = "https://disposable.github.io/disposable-email-domains/domains.txt";

const FALLBACK_LIST = [
  "mailinator.com", "guerrillamail.com", "tempmail.com", "10minutemail.com",
  "throwawaymail.com", "yopmail.com", "trashmail.com", "fakeinbox.com",
  "getnada.com", "dispostable.com", "maildrop.cc", "sharklasers.com",
  "trbvm.com", "mt2014.com", "mt2015.com",
];

let memorySet = null;
let memoryLoadedAt = 0;

function makeSet(arr) { return new Set(arr.map((d) => d.toLowerCase())); }

async function loadFromStorage() {
  try {
    if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) {
      return null;
    }
    const data = await chrome.storage.local.get(CACHE_KEY);
    const cached = data[CACHE_KEY];
    if (cached && Array.isArray(cached.domains) && typeof cached.fetchedAt === "number") {
      if (Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
        return cached.domains;
      }
    }
  } catch (e) { /* storage read failed */ }
  return null;
}

async function saveToStorage(domains) {
  try {
    if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) return;
    await chrome.storage.local.set({
      [CACHE_KEY]: { domains, fetchedAt: Date.now() },
    });
  } catch (e) { /* storage write failed — memory cache still serves */ }
}

async function fetchFresh() {
  try {
    const res = await fetch(SOURCE_URL);
    if (!res.ok) return null;
    const text = await res.text();
    const domains = text.split(/\r?\n/).map((s) => s.trim().toLowerCase()).filter(Boolean);
    if (domains.length < 100) return null; // sanity check — refuse tiny lists
    return domains;
  } catch (e) {
    return null;
  }
}

async function getSet() {
  const now = Date.now();
  if (memorySet && now - memoryLoadedAt < CACHE_TTL_MS) return memorySet;

  const cached = await loadFromStorage();
  if (cached) {
    memorySet = makeSet(cached);
    memoryLoadedAt = now;
    return memorySet;
  }

  const fresh = await fetchFresh();
  if (fresh) {
    await saveToStorage(fresh);
    memorySet = makeSet(fresh);
    memoryLoadedAt = now;
    return memorySet;
  }

  memorySet = makeSet(FALLBACK_LIST);
  memoryLoadedAt = now;
  return memorySet;
}

function isDisposableSync(domain) {
  if (!domain) return false;
  const d = domain.toLowerCase();
  if (!memorySet) {
    // sync fallback for tests / pre-warm path
    return FALLBACK_LIST.includes(d);
  }
  return memorySet.has(d);
}

async function isDisposable(domain) {
  if (!domain) return false;
  const set = await getSet();
  return set.has(domain.toLowerCase());
}

// Pre-warm cache at extension startup. Best-effort; if it fails the sync
// fallback still works.
function prewarm() {
  getSet().catch(() => { /* swallow */ });
}

export { isDisposable, isDisposableSync, prewarm, FALLBACK_LIST };