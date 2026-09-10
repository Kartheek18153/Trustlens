// Backend client. Calls the TrustLens Cloudflare Worker for cross-feed
// reputation. Replaces direct calls to PhishTank/URLhaus/OpenPhish/threatfox
// from the extension — the worker aggregates them in parallel + caches.
//
// Configuration: backend URL set in popup → Settings → Backend URL.
// Stored in chrome.storage.local key "trustlensBackendUrl".

import { getRootDomain } from "./domain.js";
import { DEFAULT_BACKEND_URL } from "../config.js";

const CACHE_KEY = "trustlensBackendUrl";
const CACHE_TTL_MS = 5 * 60 * 1000;
const TIMEOUT_MS = 3500;

let memoryUrl = null;
let memoryAt = 0;

export async function getBackendUrl() {
  const now = Date.now();
  if (memoryUrl && now - memoryAt < CACHE_TTL_MS) return memoryUrl;
  try {
    if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) return DEFAULT_BACKEND_URL;
    const data = await chrome.storage.local.get(CACHE_KEY);
    memoryUrl = (data && data[CACHE_KEY]) || DEFAULT_BACKEND_URL;
    memoryAt = now;
    return memoryUrl;
  } catch (e) {
    return memoryUrl || DEFAULT_BACKEND_URL;
  }
}

async function postJSON(url, body) {
  const controller = new AbortController();
  const tid = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(tid);
  }
}

export async function testBackend(host) {
  const name = "Backend Reputation";
  const domain = getRootDomain(host);
  try {
    const url = await getBackendUrl();
    if (!url) {
      return { name, passed: true, weight: 0, reason: "Backend not configured — skipped", evidence: domain, skipped: true };
    }
    const endpoint = url.replace(/\/+$/, "") + "/score";
    const data = await postJSON(endpoint, { host: domain });
    if (data && data.listed) {
      const sources = Array.isArray(data.sources) ? data.sources.join(", ") : "unknown";
      return {
        name,
        passed: false,
        weight: data.weight || 60,
        reason: `Listed by backend (${sources})`,
        evidence: `${domain} via ${sources}`,
      };
    }
    return { name, passed: true, weight: 0, reason: "Not listed by backend", evidence: domain };
  } catch (e) {
    return { name, passed: true, weight: 0, reason: "Backend lookup failed", evidence: e.message, skipped: true };
  }
}

export async function reportToBackend(host) {
  const url = await getBackendUrl();
  if (!url) return { ok: false, reason: "Backend not configured" };
  let trustlensReportToken = "";
  try {
    ({ trustlensReportToken = "" } = await chrome.storage.local.get("trustlensReportToken"));
  } catch (e) { /* fall through to default */ }
  const { DEFAULT_REPORT_TOKEN } = await import("../config.js");
  trustlensReportToken = trustlensReportToken || DEFAULT_REPORT_TOKEN;
  if (!trustlensReportToken) return { ok: false, reason: "Report token not set" };
  try {
    const endpoint = url.replace(/\/+$/, "") + "/report";
    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), TIMEOUT_MS);
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-TrustLens-Token": trustlensReportToken },
      body: JSON.stringify({ host }),
      signal: controller.signal,
    });
    clearTimeout(tid);
    return { ok: res.ok };
  } catch (e) {
    return { ok: false, reason: e.message };
  }
}

export function prewarm() { getBackendUrl().catch(() => { /* swallow */ }); }