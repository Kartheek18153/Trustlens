// ASN lookup via the TrustLens backend (/asn). The browser can't hit ipinfo.io
// directly on the free tier — workers can. Backend caches per-IP for 24h, so
// repeat visits across the user base don't re-hit ipinfo.
// Returns Map<ip, { asn, org, country }>. IPs with no upstream record are
// omitted from the map (callers already handle that as "ASN unknown").
//
// Fallback: if backend URL is not configured, no IP gets ASN data and the
// cross-resolver test will report a real result (not "skipped") — see test_dnssec.

import { getBackendUrl } from "./backend.js";

const TIMEOUT_MS = 3000;

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

export async function lookupAsns(ips) {
  const out = new Map();
  if (!ips || ips.length === 0) return out;
  const base = await getBackendUrl();
  if (!base) return out;
  try {
    const data = await postJSON(base.replace(/\/+$/, "") + "/asn", { ips });
    const results = data && data.results;
    if (!results || typeof results !== "object") return out;
    for (const [ip, rec] of Object.entries(results)) {
      if (rec && !rec.error && rec.asn) out.set(ip, rec);
    }
  } catch (e) { /* ponytail: backend down → cross-resolver reports no ASN data, not skipped */ }
  return out;
}

export function summarize(records) {
  const asns = new Set();
  const orgs = new Set();
  for (const r of records) {
    if (r && r.asn) asns.add(r.asn);
    if (r && r.org) orgs.add(r.org);
  }
  return {
    asns: [...asns].sort(),
    orgs: [...orgs].sort(),
  };
}