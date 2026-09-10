// History rotation detector. Stores recent check verdicts and flags a domain
// that has shown the same login form (or similar dangerous fingerprint)
// across multiple distinct hostnames in a short window.
//
// Storage: chrome.storage.local key "trustlens.rotation". Bounded to last
// 200 entries. Old entries pruned on write.

const KEY = "trustlens.rotation";
const MAX_ENTRIES = 200;
const WINDOW_MS = 24 * 60 * 60 * 1000;
const THRESHOLD_HOSTS = 3;

async function read() {
  try {
    if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) return [];
    const data = await chrome.storage.local.get(KEY);
    const entries = Array.isArray(data[KEY]) ? data[KEY] : [];
    // Drop junk fingerprints (empty "||||") — they match every site.
    return entries.filter((e) => e && e.fp && e.fp !== "||||");
  } catch (e) {
    return [];
  }
}

async function write(entries) {
  try {
    if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) return;
    await chrome.storage.local.set({ [KEY]: entries.slice(-MAX_ENTRIES) });
  } catch (e) { /* swallow */ }
}

// fingerprint: stable string that groups "same kit" detections
// (same form shape, same off-origin target, same brand-claim in title).
export function fingerprint(result) {
  const tests = Array.isArray(result && result.tests) ? result.tests : [];
  const formAction = tests.find((t) => t && t.name === "Form Action Audit");
  const pageContent = tests.find((t) => t && t.name === "Page Content Signals");
  const typosquat = tests.find((t) => t && t.name === "Typosquat / Spelling Trick");
  const fav = tests.find((t) => t && t.name === "Favicon Brand Match");
  return [
    (formAction && formAction.evidence) || "",
    (pageContent && pageContent.evidence) || "",
    (typosquat && typosquat.evidence) || "",
    (fav && fav.evidence) || "",
  ].join("|");
}

export async function recordVisit(host, fp) {
  const entries = await read();
  const cutoff = Date.now() - WINDOW_MS;
  const pruned = entries.filter((e) => e.t >= cutoff);
  pruned.push({ host, fp, t: Date.now() });
  await write(pruned);
  return pruned;
}

export async function testHistoryRotation(currentHost, currentFp) {
  const name = "History Rotation";
  try {
    const entries = await read();
    // Empty fingerprint means no distinguishing signal — don't rotate-match
    // every visited site that also lacks login forms.
    if (!currentFp || currentFp === "||||") {
      return { name, passed: true, weight: 0, reason: "No distinguishing fingerprint", skipped: true };
    }
    const cutoff = Date.now() - WINDOW_MS;
    const recent = entries.filter((e) => e.t >= cutoff && e.fp === currentFp);
    const distinctHosts = new Set(recent.map((e) => e.host));
    distinctHosts.add(currentHost);
    if (distinctHosts.size >= THRESHOLD_HOSTS) {
      return {
        name,
        passed: false,
        weight: 40,
        reason: `Same fingerprint seen on ${distinctHosts.size} distinct hosts in 24h (likely kit rotation)`,
        evidence: [...distinctHosts].slice(0, 5).join(", "),
      };
    }
    // Record for next visit.
    await recordVisit(currentHost, currentFp);
    return { name, passed: true, weight: 0, reason: `Rotation check: ${distinctHosts.size} host(s) with same fingerprint`, evidence: currentHost };
  } catch (e) {
    return { name, passed: true, weight: 0, reason: "History check failed", evidence: e.message, skipped: true };
  }
}