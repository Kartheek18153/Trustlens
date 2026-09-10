// Service worker. Glues popup click, content script, tests, and storage.

import { aggregate } from "./score.js";
import {
  testDomainAge,
  testRegistrarReputation,
  testCertAge,
  testTyposquat,
  testEmailAuth,
  testDisposableEmailDomain,
  testDisplayNameMismatch,
} from "./tests.js";
import { testSafeBrowsing } from "./test_safebrowsing.js";
import { testDnssec, testCrossResolver } from "./test_dnssec.js";
import { testFaviconPhash } from "./test_favicon.js";
import { testHomoglyph } from "./test_homoglyph.js";
import { testHighRiskDomain } from "./test_highrisk.js";
import { testBrandSubdomain } from "./test_brand_subdomain.js";
import { testPhishtank } from "./test_phishtank.js";
import { testUrlhaus } from "./test_urlhaus.js";
import { testBackend, prewarm as prewarmBackend } from "./backend.js";
import { compositeSignals } from "./composite.js";
import { testHistoryRotation, fingerprint } from "./history_rotation.js";
import { prewarm as prewarmDisposable } from "./disposable.js";
import { getRootDomain, isValidDomain, isCheckableHost } from "./domain.js";
import { isPopularRoot } from "./popular.js";
import { DEFAULT_GSB_KEY, DEFAULT_BACKEND_URL, DEFAULT_IPINFO_TOKEN, DEFAULT_REPORT_TOKEN } from "../config.js";

const HISTORY_KEY = "trustlens.history";
const HISTORY_MAX = 50;

// Pre-warm disposable / PhishTank / URLhaus / backend caches at SW startup.
// Wrap in async IIFE — top-level await is not allowed in service worker modules.
// Also re-seed any baked-in config.js defaults that are missing from
// storage — chrome.storage.local is cleared on "Remove" + fresh "Load
// unpacked", so without this the defaults would vanish every reload.
(async () => {
  try {
    const seeds = {
      trustlensGsbKey: DEFAULT_GSB_KEY,
      trustlensBackendUrl: DEFAULT_BACKEND_URL,
      trustlensIpinfoToken: DEFAULT_IPINFO_TOKEN,
      trustlensReportToken: DEFAULT_REPORT_TOKEN,
    };
    const current = await chrome.storage.local.get(Object.keys(seeds));
    for (const [key, def] of Object.entries(seeds)) {
      if (def && !current[key]) {
        await chrome.storage.local.set({ [key]: def });
      }
    }
  } catch (e) { /* seeding is best-effort */ }
  prewarmDisposable();
  prewarmBackend();
  try { (await import("./test_phishtank.js")).prewarm(); } catch (e) { /* */ }
  try { (await import("./test_urlhaus.js")).prewarm(); } catch (e) { /* */ }
})();

// Wrap fetch with an AbortSignal timeout so RDAP/crt.sh/etc. don't hang the
// popup forever. Default 4s.
async function fetchWithTimeout(url, opts = {}, ms = 4000) {
  const controller = new AbortController();
  const tid = setTimeout(() => controller.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: controller.signal });
  } finally {
    clearTimeout(tid);
  }
}

// Run all site-level tests for a given host. Returned object is what the popup renders.
async function scoreHost(host, url) {
  if (!host) {
    return { error: "No host in current tab" };
  }
  if (!isCheckableHost(host)) {
    return {
      error: "Not a checkable host (chrome://, new tab page, or internal URL)",
      host,
      verdict: "Skipped",
      score: null,
      tests: [],
    };
  }
  const root = getRootDomain(host);
  const httpsTest = url && url.startsWith("https://")
    ? { name: "HTTPS Enabled", passed: true, weight: 0, reason: "HTTPS detected", evidence: "scheme=https" }
    : { name: "HTTPS Enabled", passed: false, weight: 25, reason: "Site is not using HTTPS", evidence: url || host };
  // Run the age test first so the brand tests can use its result.
  const ageTest = await testDomainAge(root);
  // Popular domains skip the RDAP age lookup; feed downstream tests a
  // synthetic "old" so typosquat/highrisk take their aged-domain skip path.
  const domainAgeDays = parseAgeDays(ageTest) ?? (isPopularRoot(root) ? 400 : null);
  const network = await Promise.all([
    testSafeBrowsing(root),
    testDnssec(root),
    testCrossResolver(root),
    testHomoglyph(root),
    ageTest,
    testRegistrarReputation(root),
    testCertAge(root),
    testTyposquat(root, domainAgeDays),
    testFaviconPhash(root, domainAgeDays),
    testHighRiskDomain(root, domainAgeDays),
    testBrandSubdomain(host),
    testBackend(root),
    testEmailAuth(root, { domainAgeDays, hasLoginForms: false }),
    Promise.resolve(httpsTest),
  ]);
  const composites = compositeSignals(network);
  // History rotation needs the result fingerprint, so we skip it on the
  // initial popup click (no content signals yet). It runs in mergeDomTests.
  const result = aggregate([...network, ...composites]);
  result.host = root;
  result.url = url;
  result.timestamp = Date.now();
  return result;
}

// Score a single email address (called by content script).
async function scoreEmail({ displayName, address }) {
  const domain = (address.split("@")[1] || "").toLowerCase();
  if (!isValidDomain(domain)) {
    return { error: "Invalid email", address };
  }
  const tests = [
    await testEmailAuth(domain),
    await testDisposableEmailDomain(domain),
    testDisplayNameMismatch(displayName, address),
  ];
  const result = aggregate(tests);
  result.address = address;
  result.domain = domain;
  result.timestamp = Date.now();
  return result;
}

async function pushHistory(entry) {
  try {
    if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) return;
    const data = await chrome.storage.local.get(HISTORY_KEY);
    const arr = Array.isArray(data[HISTORY_KEY]) ? data[HISTORY_KEY] : [];
    arr.push({ ...entry, timestamp: Date.now() });
    await chrome.storage.local.set({ [HISTORY_KEY]: arr.slice(-HISTORY_MAX) });
  } catch (e) { /* swallow */ }
}

async function getHistory() {
  const data = await chrome.storage.local.get(HISTORY_KEY);
  return Array.isArray(data[HISTORY_KEY]) ? data[HISTORY_KEY] : [];
}

async function clearHistory() {
  await chrome.storage.local.remove(HISTORY_KEY);
}

// Extract the age-in-days from a Domain Age test result.
// Returns the number if known, otherwise null.
function parseAgeDays(ageTest) {
  if (!ageTest) return null;
  const m = (ageTest.reason || "").match(/(\d+)\s*days?\s*ago/);
  if (m) return parseInt(m[1], 10);
  if (ageTest.evidence) {
    const d = new Date(ageTest.evidence);
    if (!isNaN(d.getTime())) {
      return Math.floor((Date.now() - d.getTime()) / 86400000);
    }
  }
  return null;
}

// Combine network + DOM tests for a given host and return the final verdict.
async function mergeDomTests(host, domTests) {
  if (!host) return { error: "no host" };
  const root = getRootDomain(host);
  const ageTest = await testDomainAge(root);
  const domainAgeDays = parseAgeDays(ageTest) ?? (isPopularRoot(root) ? 400 : null);
  const hasLoginForms = Array.isArray(domTests)
    && domTests.some((t) => t && t.name === "Form Action Audit" && !t.skipped);
  const network = await Promise.all([
    testSafeBrowsing(root),
    testDnssec(root),
    testCrossResolver(root),
    testHomoglyph(root),
    ageTest,
    testRegistrarReputation(root),
    testCertAge(root),
    testTyposquat(root, domainAgeDays),
    testFaviconPhash(root, domainAgeDays),
    testHighRiskDomain(root, domainAgeDays),
    testBrandSubdomain(host),
    testBackend(root),
    testEmailAuth(root, { domainAgeDays, hasLoginForms }),
    Promise.resolve({ name: "HTTPS Enabled", passed: true, weight: 0, reason: "Page loaded over HTTPS", evidence: "scheme=https" }),
  ]);
  const composites = compositeSignals(network);
  const all = [...network, ...composites, ...(Array.isArray(domTests) ? domTests : [])];
  const result = aggregate(all);
  result.host = root;
  result.timestamp = Date.now();
  // Rotation check now that we have content signals.
  const fp = fingerprint(result);
  const rotationTest = await testHistoryRotation(root, fp);
  const finalResult = aggregate([...result.tests, rotationTest]);
  finalResult.host = root;
  finalResult.timestamp = Date.now();
  pushHistory({ host: root, verdict: finalResult.verdict, score: finalResult.score });
  return finalResult;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (msg.type === "scoreHost") {
        sendResponse(await scoreHost(msg.host, msg.url));
      } else if (msg.type === "scoreEmail") {
        sendResponse(await scoreEmail(msg.email));
      } else if (msg.type === "getHistory") {
        sendResponse(await getHistory());
      } else if (msg.type === "clearHistory") {
        await clearHistory();
        sendResponse({ ok: true });
      } else if (msg.type === "domTests") {
        sendResponse(await mergeDomTests(msg.host, msg.tests || []));
      } else if (msg.type === "saveGsbKey") {
        await chrome.storage.local.set({ trustlensGsbKey: msg.key || "" });
        sendResponse({ ok: true });
      } else if (msg.type === "getGsbKey") {
        const { trustlensGsbKey } = await chrome.storage.local.get("trustlensGsbKey");
        sendResponse({ key: trustlensGsbKey || DEFAULT_GSB_KEY });
      } else if (msg.type === "saveIpinfoToken") {
        await chrome.storage.local.set({ trustlensIpinfoToken: msg.token || "" });
        sendResponse({ ok: true });
      } else if (msg.type === "getIpinfoToken") {
        const { trustlensIpinfoToken } = await chrome.storage.local.get("trustlensIpinfoToken");
        sendResponse({ token: trustlensIpinfoToken || DEFAULT_IPINFO_TOKEN });
      } else if (msg.type === "saveBackendUrl") {
        await chrome.storage.local.set({ trustlensBackendUrl: msg.url || "" });
        sendResponse({ ok: true });
      } else if (msg.type === "getBackendUrl") {
        const { trustlensBackendUrl } = await chrome.storage.local.get("trustlensBackendUrl");
        sendResponse({ url: trustlensBackendUrl || DEFAULT_BACKEND_URL });
      } else if (msg.type === "saveReportToken") {
        await chrome.storage.local.set({ trustlensReportToken: msg.token || "" });
        sendResponse({ ok: true });
      } else if (msg.type === "getReportToken") {
        const { trustlensReportToken } = await chrome.storage.local.get("trustlensReportToken");
        sendResponse({ token: trustlensReportToken || DEFAULT_REPORT_TOKEN });
      } else {
        sendResponse({ error: "Unknown message type" });
      }
    } catch (e) {
      sendResponse({ error: e.message });
    }
  })();
  return true;
});

// Toolbar icon click — the popup handles the click-to-check flow,
// so this is just a fallback when popups are blocked.
chrome.action.onClicked.addListener(async (tab) => {
  if (!tab || !tab.id) return;
  try {
    const u = new URL(tab.url);
    const result = await scoreHost(u.hostname, tab.url);
    if (result.verdict === "Dangerous") {
      chrome.tabs.sendMessage(tab.id, { type: "showBanner", result });
    }
  } catch (e) { /* noop */ }
});