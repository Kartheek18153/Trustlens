// Individual trust tests. Each returns:
//   { name, passed, weight, reason, evidence, skipped? }
// The popup renders these directly so the user sees the per-test score.

import { getRootDomain, isValidDomain, isPrivateIp } from "./domain.js";
import { dohTxt, dohMx } from "./doh.js";
import { BRANDS as BIG_BRANDS } from "./brands.js";
import { isDisposable } from "./disposable.js";
import { getBackendUrl } from "./backend.js";
import { isPopularRoot } from "./popular.js";

// --- 1. Domain age (RDAP) ---
async function testDomainAge(host) {
  const name = "Domain Age";
  const domain = getRootDomain(host);
  if (!isValidDomain(domain)) {
    return { name, passed: false, weight: 30, reason: "Invalid domain", evidence: host };
  }
  // Popular domains skip the age penalty — a brand-new host on a known-big
  // domain (e.g. new google subdomain) was Safe yesterday too.
  if (isPopularRoot(domain)) {
    return { name, passed: true, weight: 0, reason: `Well-known domain — age check skipped`, evidence: domain, skipped: true };
  }
  try {
    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), 4000);
    let res;
    try {
      res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { signal: controller.signal });
    } finally { clearTimeout(tid); }
    if (!res.ok) {
      // Soft fail — lookup is unavailable, but it doesn't mean the site is safe.
      return { name, passed: false, weight: 8, reason: `RDAP lookup unavailable (HTTP ${res.status})`, evidence: String(res.status) };
    }
    const data = await res.json();
    const ev = data.events || [];
    const created = ev.find((e) => e.eventAction === "registration")?.eventDate
                 || ev.find((e) => e.eventAction === "creation")?.eventDate;
    if (!created) {
      return { name, passed: true, weight: 0, reason: "No creation date in RDAP", evidence: "", skipped: true };
    }
    const days = Math.floor((Date.now() - new Date(created).getTime()) / 86400000);
    if (days < 30)  return { name, passed: false, weight: 35, reason: `Registered ${days} days ago`, evidence: created };
    if (days < 180) return { name, passed: false, weight: 20, reason: `Registered ${days} days ago`, evidence: created };
    if (days < 365) return { name, passed: true,  weight: 0,  reason: `Registered ${days} days ago (young)`, evidence: created };
    return { name, passed: true, weight: 0, reason: `Registered ${days} days ago`, evidence: created };
  } catch (e) {
    return { name, passed: false, weight: 8, reason: "RDAP lookup failed", evidence: e.message };
  }
}

// --- 2. Registrar reputation ---
const ABUSED_REGISTRARS = new Set([
  "NameCheap, Inc.",
  "Porkbun LLC",
  "Namesilo LLC",
  "Alibaba Cloud Computing Ltd.",
  "Sav.com LLC",
  "Gname.com Pte. Ltd.",
  "Hostinger",
  "PDR Ltd.",
  "BigRock Solutions Ltd.",
  "Tucows Domains Inc.",
  "GoDaddy.com, LLC",
  "GMO Internet, Inc.",
  "eNom, LLC",
]);

const TRUSTED_REGISTRARS = new Set([
  "MarkMonitor Inc.",
  "CSC Corporate Domains, Inc.",
  "Com Laude",
  "Nom-IQ Limited",
  "SafeNames Ltd.",
  "Lexsynergy Limited",
  "Ascio Technologies, Inc.",
]);

async function testRegistrarReputation(host) {
  const name = "Registrar Reputation";
  const domain = getRootDomain(host);
  if (isPopularRoot(domain)) {
    return { name, passed: true, weight: 0, reason: `Well-known domain — registrar check skipped`, evidence: domain, skipped: true };
  }
  try {
    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), 4000);
    let res;
    try {
      res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { signal: controller.signal });
    } finally { clearTimeout(tid); }
    if (!res.ok) {
      return { name, passed: false, weight: 5, reason: `RDAP lookup unavailable (HTTP ${res.status})`, evidence: String(res.status) };
    }
    const data = await res.json();
    const registrar = data.entities?.find((e) => e.roles?.includes("registrar"))?.vcardArray?.[1]?.find((f) => f[0] === "fn")?.[3] || "Unknown";
    if (TRUSTED_REGISTRARS.has(registrar)) {
      return { name, passed: true, weight: 0, reason: `Trusted registrar: ${registrar}`, evidence: registrar };
    }
    if (ABUSED_REGISTRARS.has(registrar)) {
      return { name, passed: false, weight: 10, reason: `Registrar frequently abused: ${registrar}`, evidence: registrar };
    }
    return { name, passed: true, weight: 0, reason: `Registrar: ${registrar}`, evidence: registrar };
  } catch (e) {
    return { name, passed: false, weight: 5, reason: "RDAP lookup failed", evidence: e.message };
  }
}

// --- 3. SSL certificate age via backend /ct ---
// The backend hits crt.sh server-side and caches per-domain for 24h, so a 429
// only costs us once per day across all users. Browser-side crt.sh was always
// skipped because the browser is rate-limited faster than the worker.
async function testCertAge(host) {
  const name = "SSL Certificate Age";
  const domain = getRootDomain(host);
  const base = await getBackendUrl().catch(() => "");
  if (!base) {
    return { name, passed: true, weight: 0, reason: "Backend not configured — skipped", evidence: domain, skipped: true };
  }
  try {
    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), 4000);
    let res;
    try {
      res = await fetch(base.replace(/\/+$/, "") + "/ct", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
        signal: controller.signal,
      });
    } finally { clearTimeout(tid); }
    if (!res.ok) {
      return { name, passed: true, weight: 0, reason: `CT backend unavailable (HTTP ${res.status}) — skipped`, evidence: String(res.status), skipped: true };
    }
    const data = await res.json();
    if (data && data.error) {
      return { name, passed: true, weight: 0, reason: `CT lookup unavailable (${data.error}) — skipped`, evidence: data.error, skipped: true };
    }
    if (data && typeof data.days === "number") {
      const days = data.days;
      const firstSeen = data.firstSeen;
      if (days < 30)  return { name, passed: false, weight: 20, reason: `First cert only ${days} days old`, evidence: firstSeen };
      if (days < 180) return { name, passed: true,  weight: 0,  reason: `First cert ${days} days old (young)`, evidence: firstSeen };
      return { name, passed: true, weight: 0, reason: `First cert ${days} days old`, evidence: firstSeen };
    }
    return { name, passed: false, weight: 25, reason: "No certificate found in CT logs", evidence: "0 certs" };
  } catch (e) {
    return { name, passed: true, weight: 0, reason: "CT lookup failed — skipped", evidence: e.message, skipped: true };
  }
}

// --- 4. Typosquatting / spelling tricks ---
// Use the curated list from brands.js (~291 entries). Local copy retained
// for the dev-only inline cases below; main path imports BRANDS.
// (Inline list removed — see ./brands.js)
const BRANDS = BIG_BRANDS;

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  if (Math.abs(m - n) > 3) return Math.abs(m - n);
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const c = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + c);
    }
  }
  return dp[m][n];
}

async function testTyposquat(host, domainAgeDays) {
  const name = "Typosquat / Spelling Trick";
  const domain = getRootDomain(host);
  const labels = domain.split(".");
  if (labels.length < 2) {
    return { name, passed: true, weight: 0, reason: "Single-label domain (nothing to compare)" };
  }
  // Phishing sites almost never survive a year — skip the brand check on
  // established domains. We still return Pass so the test is recorded.
  if (typeof domainAgeDays === "number" && domainAgeDays > 365) {
    return { name, passed: true, weight: 0, reason: `Domain is ${domainAgeDays} days old — typosquat check skipped`, evidence: domain };
  }
  const sld = labels[labels.length - 2];
  const digitMap = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b" };
  const deobfuscated = sld.split("").map((c) => digitMap[c] || c).join("");
  // On young domains (<90d), use a tight edit distance (1) and require
  // exact-substitution matches. On older domains up to 365d, allow distance 2.
  const tight = typeof domainAgeDays === "number" && domainAgeDays < 90;
  const maxDist = tight ? 1 : 2;
  let closest = null;
  for (const brand of BRANDS) {
    if (sld === brand || deobfuscated === brand) {
      if (sld !== brand) {
        return { name, passed: false, weight: 40, reason: `Looks like ${brand} with substitutions (${sld})`, evidence: `${sld} -> ${brand}` };
      }
    }
    const d1 = levenshtein(sld, brand);
    const d2 = levenshtein(deobfuscated, brand);
    const d = Math.min(d1, d2);
    if (d > 0 && d <= maxDist && (closest === null || d < closest.d)) {
      closest = { brand, d, original: sld };
    }
  }
  if (closest) {
    const weight = tight ? 40 : 30;
    const reason = tight
      ? `Close to brand "${closest.brand}" (distance ${closest.d}, domain age ${domainAgeDays}d — tight rule)`
      : `Close to brand "${closest.brand}" (distance ${closest.d})`;
    return { name, passed: false, weight, reason, evidence: `${sld} ~ ${closest.brand}` };
  }
  return { name, passed: true, weight: 0, reason: "No known brand match", evidence: sld };
}

// --- 5. Email authentication (MX + SPF + DMARC) ---
// Two new rules:
//  1. If the site has no login forms AND the domain is > 365 days old,
//     email-auth issues are informational only (weight 0) — they affect
//     a separate "Email Spoofability Index" reported in evidence.
//  2. Even on a site with login forms, an old domain (>365d) missing only
//     DMARC carries 0 weight (don't drop Safe -> Caution just for that).
async function testEmailAuth(host, opts) {
  const name = "Email Authentication";
  const domain = getRootDomain(host);
  const domainAgeDays = opts && typeof opts.domainAgeDays === "number" ? opts.domainAgeDays : null;
  const hasLogin = !!(opts && opts.hasLoginForms);
  if (!isValidDomain(domain)) {
    return { name, passed: false, weight: 25, reason: "Invalid domain for email check", evidence: domain };
  }
  const results = { mx: null, spf: null, dmarc: null };
  try {
    const mx = await dohMx(domain);
    results.mx = mx;
  } catch { results.mx = []; }
  try {
    const txt = await dohTxt(domain);
    results.spf = txt.find((t) => t.toLowerCase().startsWith("v=spf1")) || null;
  } catch { results.spf = null; }
  try {
    const txt = await dohTxt(`_dmarc.${domain}`);
    results.dmarc = txt.find((t) => t.toLowerCase().startsWith("v=dmarc1")) || null;
  } catch { results.dmarc = null; }

  const issues = [];
  if (!results.mx || results.mx.length === 0) issues.push("no MX records");
  if (!results.spf) issues.push("no SPF");
  if (!results.dmarc) issues.push("no DMARC");

  if (issues.length === 0) {
    return { name, passed: true, weight: 0, reason: "MX + SPF + DMARC all present", evidence: `${results.mx.length} MX` };
  }

  // Context-aware gating:
  // - No login form on the page + old domain -> informational only.
  // - Old domain + only DMARC missing -> no penalty.
  // - Otherwise -> existing penalty weights.
  const oldDomain = typeof domainAgeDays === "number" && domainAgeDays > 365;
  const onlyDmarcMissing = issues.length === 1 && issues[0] === "no DMARC";
  const webOnlyNoLogin = !hasLogin && !results.mx.length; // not even an MX -> likely a pure web domain

  const emailSpoofIndex = computeSpoofIndex({ mx: !!results.mx?.length, spf: !!results.spf, dmarc: !!results.dmarc });

  if (webOnlyNoLogin || (oldDomain && onlyDmarcMissing)) {
    return {
      name,
      passed: true,
      weight: 0,
      reason: `Email issues noted but not penalized: ${issues.join(", ")} (no login form${oldDomain ? ", old domain" : ""})`,
      evidence: `Email Spoofability Index: ${emailSpoofIndex}/100`,
      spoofIndex: emailSpoofIndex,
    };
  }
  if (issues.length === 1 && issues[0] === "no DMARC") {
    return { name, passed: false, weight: 10, reason: "Missing DMARC (SPF + MX present)", evidence: `Email Spoofability Index: ${emailSpoofIndex}/100`, spoofIndex: emailSpoofIndex };
  }
  if (issues.length >= 2) {
    return { name, passed: false, weight: 25, reason: `Missing: ${issues.join(", ")}`, evidence: `Email Spoofability Index: ${emailSpoofIndex}/100`, spoofIndex: emailSpoofIndex };
  }
  return { name, passed: true, weight: 0, reason: "Critical auth present", evidence: `Email Spoofability Index: ${emailSpoofIndex}/100`, spoofIndex: emailSpoofIndex };
}

// Email Spoofability Index: 100 = fully protected, 0 = trivially spoofable.
// Separate from the web score; reported alongside it for context.
function computeSpoofIndex({ mx, spf, dmarc }) {
  let score = 0;
  if (mx)   score += 30;
  if (spf)  score += 30;
  if (dmarc) score += 40;
  return score;
}

// --- 6. HTTPS usage ---
// The popup / service worker knows the URL scheme directly, so the inline test
// in sw.js handles this. Kept here as a no-op for the export list only.

// --- 7. Disposable / free email domain (used when checking an email, not a site) ---
// List now lives in ./disposable.js (blocklist + chrome.storage.local cache).

async function testDisposableEmailDomain(emailDomain) {
  const name = "Disposable Email Provider";
  if (await isDisposable(emailDomain)) {
    return { name, passed: false, weight: 30, reason: `Disposable email provider: ${emailDomain}`, evidence: emailDomain };
  }
  return { name, passed: true, weight: 0, reason: "Not on disposable list", evidence: emailDomain };
}

// --- 8. Display name vs address mismatch (called with extracted emails) ---
// Token-based brand detection + year/numeric-run heuristics catch spoofs
// the old regex missed (e.g. PayPal.Support.2024@gmail.com).
const DISPLAY_CLAIM_WORDS = new Set([
  "paypal", "amazon", "apple", "google", "microsoft", "netflix", "facebook",
  "instagram", "wellsfargo", "chase", "bankofamerica", "coinbase", "binance",
  "fedex", "ups", "dhl", "usps", "irs", "hmrc", "dhl", "dhl",
  "support", "security", "team", "admin", "noreply", "no-reply", "service",
  "billing", "account", "verify", "verification", "helpdesk", "it",
]);
const YEAR_RE = /\b(19|20)\d{2}\b/;
const NUMERIC_RUN_RE = /\d{2,}/g;
const SEGMENT_RE = /[._-]/;

function displayNameSignals(displayName, address) {
  if (!displayName || !address) return null;
  const local = (address.split("@")[0] || "").toLowerCase();
  const display = displayName.toLowerCase();
  if (!local || !display) return null;

  // Strip separators from local part for token comparison
  const localTokens = local.split(SEGMENT_RE).filter(Boolean);
  const displayTokens = display.split(/[^a-z0-9]+/).filter(Boolean);

  // Signal A: display claims a brand/role word
  const claimsWord = displayTokens.some((t) => DISPLAY_CLAIM_WORDS.has(t));

  // Signal B: year token (2024 / 2025 / 2026) — legit corp emails don't carry these
  const hasYear = YEAR_RE.test(local) || YEAR_RE.test(display);

  // Signal C: numeric runs (2+ digits) in the local part
  const numericRuns = (local.match(NUMERIC_RUN_RE) || []).length;

  // Signal D: >2 segments in local part (looks like obfuscation)
  const manySegments = localTokens.length > 2;

  // Signal E: brand word in display but local part has zero brand-like tokens
  const localHasBrandToken = localTokens.some((t) => DISPLAY_CLAIM_WORDS.has(t));
  const brandWordWithoutLocalBrand = claimsWord && !localHasBrandToken;

  return { claimsWord, hasYear, numericRuns, manySegments, brandWordWithoutLocalBrand };
}

function testDisplayNameMismatch(displayName, address) {
  const name = "Display Name Mismatch";
  if (!displayName || !address) {
    return { name, passed: true, weight: 0, reason: "No display name", skipped: true };
  }
  const sig = displayNameSignals(displayName, address);
  if (!sig) {
    return { name, passed: true, weight: 0, reason: "No local part", skipped: true };
  }
  const triggers = [];
  if (sig.brandWordWithoutLocalBrand) triggers.push("display claims role/brand but local part doesn't");
  if (sig.hasYear) triggers.push("year token (e.g. 2024) in display/local");
  if (sig.numericRuns >= 2) triggers.push(`${sig.numericRuns} numeric runs in local part`);
  if (sig.manySegments) triggers.push(`${triggers.length > 0 ? "" : ">2 segments in local part"}`);

  if (triggers.length >= 2) {
    const weight = sig.brandWordWithoutLocalBrand && sig.hasYear ? 40 : 30;
    return {
      name,
      passed: false,
      weight,
      reason: `Spoof pattern: ${triggers.join("; ")}`,
      evidence: `${displayName} <${address}>`,
    };
  }
  return { name, passed: true, weight: 0, reason: "Looks consistent", evidence: `${displayName} <${address}>` };
}

export {
  testDomainAge,
  testRegistrarReputation,
  testCertAge,
  testTyposquat,
  testEmailAuth,
  testDisposableEmailDomain,
  testDisplayNameMismatch,
  displayNameSignals,
  computeSpoofIndex,
};
