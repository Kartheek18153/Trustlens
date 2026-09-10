// Google Safe Browsing v4 lookup test.
// Reads the API key from chrome.storage.local (set via popup settings),
// falling back to the baked-in default from config.js so a fresh
// "Load unpacked" doesn't disable the check.
// Free tier: 10,000 requests/day. Docs: https://developers.google.com/safe-browsing/v4

import { getRootDomain } from "./domain.js";
import { DEFAULT_GSB_KEY } from "../config.js";

const GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find";
const PLATFORMS = ["ANY_PLATFORM"];
const THREAT_TYPES = [
  "MALWARE",
  "SOCIAL_ENGINEERING",
  "UNWANTED_SOFTWARE",
  "POTENTIALLY_HARMFUL_APPLICATION",
];

export async function testSafeBrowsing(host) {
  const name = "Google Safe Browsing";
  const domain = getRootDomain(host);
  let key = DEFAULT_GSB_KEY;
  try {
    const { trustlensGsbKey } = await chrome.storage.local.get("trustlensGsbKey");
    key = trustlensGsbKey || DEFAULT_GSB_KEY;
  } catch (e) { /* storage unavailable — default serves */ }
  if (!key) {
    return { name, passed: true, weight: 0, reason: "API key not set — skipped", evidence: "set in popup settings", skipped: true };
  }
  try {
    const url = `${GSB_ENDPOINT}?key=${encodeURIComponent(key)}`;
    const body = {
      client: { clientId: "trustlens", clientVersion: "0.2.0" },
      threatInfo: {
        platformTypes: PLATFORMS,
        threatEntryTypes: ["URL"],
        threatEntries: [{ url: `http://${domain}/` }, { url: `https://${domain}/` }],
        threatTypes: THREAT_TYPES,
      },
    };
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (res.status === 429) {
      return { name, passed: true, weight: 0, reason: "Rate limited (429) — skipped", evidence: "free tier exceeded", skipped: true };
    }
    if (!res.ok) {
      return { name, passed: true, weight: 0, reason: `GSB HTTP ${res.status} — skipped`, evidence: String(res.status), skipped: true };
    }
    const data = await res.json();
    if (data.matches && data.matches.length > 0) {
      const types = [...new Set(data.matches.map((m) => m.threatType))].join(", ");
      return { name, passed: false, weight: 60, reason: `Listed by Google Safe Browsing (${types})`, evidence: data.matches[0].threat?.url || domain };
    }
    return { name, passed: true, weight: 0, reason: "Not on GSB lists", evidence: domain };
  } catch (e) {
    return { name, passed: true, weight: 0, reason: "GSB lookup failed", evidence: e.message, skipped: true };
  }
}
