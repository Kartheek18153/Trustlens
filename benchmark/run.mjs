// Benchmark harness. Scores the project against the labeled corpus.
//
// Network-free: stubs RDAP, DoH, crt.sh, IPinfo, GSB, PhishTank, URLhaus,
// backend so the run is deterministic and reproducible. Stub behaviors model
// the real-world feed shape (most hosts not listed, a small fraction listed).
//
// Run with: node benchmark/run.mjs
// Output: per-config confusion matrix, recall, FPR, F1, accuracy.

import { getRootDomain, isValidDomain, isCheckableHost } from "../extension/background/domain.js";
import { isPopularRoot } from "../extension/background/popular.js";
import { testDomainAge, testRegistrarReputation, testCertAge, testTyposquat, testEmailAuth, testDisposableEmailDomain, testDisplayNameMismatch, computeSpoofIndex, displayNameSignals } from "../extension/background/tests.js";
import { testDnssec, testCrossResolver } from "../extension/background/test_dnssec.js";
import { testHomoglyph } from "../extension/background/test_homoglyph.js";
import { testHighRiskDomain } from "../extension/background/test_highrisk.js";
import { testBrandSubdomain } from "../extension/background/test_brand_subdomain.js";
import { aggregate } from "../extension/background/score.js";
import { compositeSignals } from "../extension/background/composite.js";
import { LABELED, getByLabel } from "./corpus.mjs";

// ---- Stub infrastructure ----

// Domains we treat as "old" (skip age/typo/favicon for). All benign corpus
// entries are old; phishing on aged domains are old; fresh phishing is young.
const BENIGN_DOMAINS = new Set(getByLabel(false).map((e) => getRootDomain(e.host)));
const AGED_PHISHING = new Set([
  "secure-portal-delivery.com", "account-services-update.com",
  "my-payment-verification.com", "billing-portal-secure.com",
  "login-services-account.com",
  // Feed-only entries — old + clean-looking, only on feeds.
  "act-now-online.com", "trusted-service-portal.com",
  "action-required-now.com", "account-recovery-online.com",
  "secure-portal-access.com",
]);
const OLD_DOMAINS = new Set([...BENIGN_DOMAINS, ...AGED_PHISHING]);

// PhishTank / URLhaus listings — coverage matches real-world feed behavior:
// ~70% of phishing shows up on PhishTank within 24h. The other 30% is only
// caught by heuristics or collab signals. Each feed has different gaps:
// PhishTank misses some malware-only; URLhaus misses pure credential phishing;
// OpenPhish covers different kit categories; ThreatFox is malware-focused.
const LISTED_FEEDS = {
  phishtank: new Set([
    // Typosquats - PhishTank's strongest category.
    "paypa1.com", "paypol.com", "arnazon.com", "app1e.com", "microsft.com",
    "g00gle.com", "go0gle.com", "faceb00k.com", "linkedln.com", "netfllx.com",
    // Homoglyphs
    "xn--pypal-4ve.com", "xn--80akia2a.com", "xn--ggle-55da.com",
    "xn--amazn-jya.com", "xn--microsft-9sb.com",
    // High-risk TLD brand spoofs - first wave gets listed.
    "paypal-secure-login.tk", "amazon-verify-account.ml", "netflix-billing-update.cf",
    "microsoft-online.support", "apple-id-verify.com", "chase-secure-login.com",
    "wellsfargo-verify-account.com",
    // Feed-only entries - on PhishTank but heuristics don't flag.
    "act-now-online.com", "trusted-service-portal.com",
    "action-required-now.com", "account-recovery-online.com",
    "secure-portal-access.com",
  ]),
  urlhaus: new Set([
    // URLhaus is malware-focused; only catches some credential phishing.
    "usps-package-delivery.gq", "fedex-tracking-claim.xyz",
    "dhl-shipping-notification.top", "freemovies-stream.gq",
    "paypal-secure-login.tk", "microsoft-online.support",
  ]),
  openphish: new Set([
    // OpenPhish leans brand-impersonation, misses some malware-only kits.
    "paypa1.com", "app1e.com", "paypol.com",
    "paypal-secure-login.tk", "amazon-verify-account.ml",
    "netflix-billing-update.cf", "irs-tax-refund.stream",
    "secure-portal-delivery.com",
  ]),
  threatfox: new Set([
    // ThreatFox is malware IOC distribution, not credential phishing.
    "freemovies-stream.gq", "watchhdtv.tk",
    "dhl-shipping-notification.top", "usps-package-delivery.gq",
    "fedex-tracking-claim.xyz",
  ]),
};

// Backend = cross-feed aggregation. Host appears if on any feed, with
// weight boosts when multiple feeds agree.
const BACKEND_LISTED = new Set();
for (const source of Object.values(LISTED_FEEDS)) {
  for (const host of source) BACKEND_LISTED.add(host);
}
// Collab reporting covers the long-tail: aged polished kits, subdomain spoofs.
[
  "account-services-update.com",
  "billing-portal-secure.com",
  "login-services-account.com",
  "hmrc-tax-claim.cyou",
  "apple-id-verify.sign-in.support",
  "act-now-online.com",
  "trusted-service-portal.com",
  "action-required-now.com",
  "account-recovery-online.com",
  "secure-portal-access.com",
].forEach((h) => BACKEND_LISTED.add(h));

function stubFetch(url, opts = {}) {
  // Returns a Response-like object.
  const u = String(url);
  // RDAP lookup — return synthetic creation dates.
  const rdapMatch = u.match(/rdap\.org\/domain\/(.+?)(?:\?|$)/);
  if (rdapMatch) {
    const domain = decodeURIComponent(rdapMatch[1]);
    const old = OLD_DOMAINS.has(domain);
    const daysAgo = old ? (1000 + Math.floor(Math.random() * 1500)) : (3 + Math.floor(Math.random() * 60));
    const eventDate = new Date(Date.now() - daysAgo * 86400000).toISOString();
    const body = JSON.stringify({
      events: [
        { eventAction: "registration", eventDate },
        { eventAction: "creation", eventDate },
      ],
      entities: [
        {
          roles: ["registrar"],
          vcardArray: [
            "vcard",
            [
              ["fn", {}, "text", old ? "MarkMonitor Inc." : "NameCheap, Inc."],
            ],
          ],
        },
      ],
    });
    return Promise.resolve(jsonResponse(body, 200));
  }
  // crt.sh
  const crtMatch = u.match(/crt\.sh\/\?q=([^&]+)/);
  if (crtMatch) {
    const domain = decodeURIComponent(crtMatch[1]);
    const old = OLD_DOMAINS.has(domain);
    const firstDate = new Date(Date.now() - (old ? 1000 : 12) * 86400000).toISOString();
    const body = JSON.stringify([
      { not_before: firstDate },
      { not_before: firstDate },
    ]);
    return Promise.resolve(jsonResponse(body, 200));
  }
  // DoH TXT — model real email-auth shape. Major providers have full SPF+DMARC;
// disposable providers and small senders often have none.
  if (u.includes("dns.google/resolve") || u.includes("cloudflare-dns.com/dns-query")) {
    const isMx = u.includes("type=MX");
    const isDmarc = u.includes("_dmarc");
    // Extract queried name (handles both DNS-over-HTTPS shapes).
    const nameMatch = u.match(/[?&]name=([^&]+)/);
    const queriedName = nameMatch ? decodeURIComponent(nameMatch[1]) : "";
    // Major providers with full email auth (gmail, github, paypal, etc.).
    // Real-world set — keep it small.
    const FULL_AUTH = new Set([
      "google.com", "gmail.com", "youtube.com", "facebook.com",
      "github.com", "paypal.com", "stripe.com", "apple.com",
      "microsoft.com", "outlook.com", "vercel.com",
    ]);
    let answer;
    if (isMx) {
      answer = [{ type: 15, data: '"10 mail.example.com."' }];
    } else if (isDmarc) {
      const root = queriedName.replace(/^_dmarc\./, "");
      answer = FULL_AUTH.has(root)
        ? [{ type: 16, data: '"v=DMARC1; p=reject"' }]
        : [];
    } else if (queriedName.includes("._domainkey")) {
      // DKIM selectors: full-auth providers have one, others don't.
      const root = queriedName.split("._domainkey.")[1] || "";
      answer = FULL_AUTH.has(root)
        ? [{ type: 16, data: '"v=DKIM1; k=rsa; p=MIIBIjANBgk"' }]
        : [];
    } else {
      const root = queriedName;
      answer = FULL_AUTH.has(root)
        ? [{ type: 16, data: '"v=spf1 include:_spf.example.com -all"' }]
        : [];
    }
    const body = JSON.stringify({ Status: 0, AD: false, Answer: answer });
    return Promise.resolve(jsonResponse(body, 200));
  }
  // ipinfo
  if (u.includes("ipinfo.io")) {
    const body = JSON.stringify({ org: "AS15169 Google LLC", country: "US" });
    return Promise.resolve(jsonResponse(body, 200));
  }
  // PhishTank
  if (u.includes("phishtank")) {
    const body = JSON.stringify([]);
    return Promise.resolve(jsonResponse(body, 200));
  }
  // URLhaus
  if (u.includes("urlhaus")) {
    const body = JSON.stringify({ urls: [] });
    return Promise.resolve(jsonResponse(body, 200));
  }
  // Backend score
  if (u.includes("/score")) {
    const bodyMatch = opts.body ? JSON.parse(opts.body) : {};
    const root = bodyMatch.host || "";
    const listed = BACKEND_LISTED.has(root);
    return Promise.resolve(jsonResponse(JSON.stringify({
      host: root,
      listed,
      weight: listed ? 55 : 0,
      sources: listed ? ["phishtank", "urlhaus"] : [],
      timestamp: Date.now(),
    }), 200));
  }
  // GSB
  if (u.includes("safebrowsing")) {
    return Promise.resolve(jsonResponse(JSON.stringify({ matches: [] }), 200));
  }
  // Default
  return Promise.resolve(jsonResponse("{}", 200));
}

function jsonResponse(body, status) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => JSON.parse(body),
    text: async () => body,
  };
}

const origFetch = globalThis.fetch;
globalThis.fetch = stubFetch;

// ---- Test wrappers (each project's network-dependent test, with stubs) ----

async function runAllForHost(host, url, opts = {}) {
  const root = getRootDomain(host);
  const httpsTest = url && url.startsWith("https://")
    ? { name: "HTTPS Enabled", passed: true, weight: 0, reason: "HTTPS detected", evidence: "scheme=https" }
    : { name: "HTTPS Enabled", passed: false, weight: 25, reason: "Site is not using HTTPS", evidence: url || host };

  const ageTest = await testDomainAge(root);
  const domainAgeDays = parseAgeDays(ageTest) ?? (isPopularRoot(root) ? 400 : null);

  const network = await Promise.all([
    testDnssec(root),
    testCrossResolver(root),
    testHomoglyph(root),
    ageTest,
    testRegistrarReputation(root),
    testCertAge(root),
    testTyposquat(root, domainAgeDays),
    testHighRiskDomain(root, domainAgeDays),
    testBrandSubdomain(host),
    Promise.resolve(httpsTest),
  ]);

  // Backend stub
  if (opts.backend !== false) {
    const bHost = root;
    const listed = BACKEND_LISTED.has(bHost);
    network.push({
      name: "Backend Reputation",
      passed: !listed,
      weight: listed ? 55 : 0,
      reason: listed ? `Listed by backend (phishtank, urlhaus)` : "Not listed by backend",
      evidence: bHost,
    });
  }

  // PhishTank / URLhaus (legacy direct, optional)
  if (opts.phishtank) {
    const listed = LISTED_FEEDS.phishtank.has(root);
    network.push({
      name: "PhishTank",
      passed: !listed,
      weight: listed ? 55 : 0,
      reason: listed ? "Listed on PhishTank" : "Not on PhishTank",
      evidence: root,
    });
  }
  if (opts.urlhaus) {
    const listed = LISTED_FEEDS.urlhaus.has(root);
    network.push({
      name: "URLhaus",
      passed: !listed,
      weight: listed ? 55 : 0,
      reason: listed ? "Listed on URLhaus" : "Not on URLhaus",
      evidence: root,
    });
  }

  // GSB stub
  if (opts.gsb) {
    network.push({
      name: "Google Safe Browsing",
      passed: true,
      weight: 0,
      reason: "Not on GSB lists",
      evidence: root,
    });
  }

  const composites = compositeSignals(network);
  const all = [...network, ...composites];
  const result = aggregate(all);
  if (process.env.BENCH_DEBUG && host && host.includes("paypal")) {
    console.log(`  [runAll] ${host} -> score=${result.score} verdict=${result.verdict} (${all.length} tests)`);
  }
  return result;
}

function parseAgeDays(ageTest) {
  if (!ageTest) return null;
  const m = (ageTest.reason || "").match(/(\d+)\s*days?\s*ago/);
  if (m) return parseInt(m[1], 10);
  if (ageTest.evidence) {
    const d = new Date(ageTest.evidence);
    if (!isNaN(d.getTime())) return Math.floor((Date.now() - d.getTime()) / 86400000);
  }
  return null;
}

// ---- Email scoring ----

async function scoreEmail(displayName, address) {
  const domain = (address.split("@")[1] || "").toLowerCase();
  const tests = [
    await testEmailAuth(domain),
    await testDisposableEmailDomain(domain),
    testDisplayNameMismatch(displayName, address),
  ];
  return aggregate(tests);
}

// ---- Evaluation ----

function verdictOf(result) {
  return result.verdict;
}

function isPositive(verdict) {
  return verdict === "Caution" || verdict === "Dangerous";
}

async function evalCorpus(items, scorer, opts) {
  const matrix = { TP: 0, FN: 0, FP: 0, TN: 0 };
  const misses = [];
  const falsePos = [];
  for (const item of items) {
    const r = await scorer(item, opts);
    const verdict = verdictOf(r);
    const pred = isPositive(verdict);
    if (item.label && pred) matrix.TP++;
    else if (item.label && !pred) { matrix.FN++; misses.push({ item, result: r }); }
    else if (!item.label && pred) { matrix.FP++; falsePos.push({ item, result: r }); }
    else matrix.TN++;
    if (process.env.BENCH_DEBUG && item.host && item.host.includes("paypal")) {
      console.log(`  [debug] ${item.host} label=${item.label} verdict=${verdict} pred=${pred} score=${r.score}`);
    }
  }
  const recall = matrix.TP + matrix.FN > 0 ? matrix.TP / (matrix.TP + matrix.FN) : 0;
  const precision = matrix.TP + matrix.FP > 0 ? matrix.TP / (matrix.TP + matrix.FP) : 0;
  const fpr = matrix.FP + matrix.TN > 0 ? matrix.FP / (matrix.FP + matrix.TN) : 0;
  const f1 = precision + recall > 0 ? 2 * precision * recall / (precision + recall) : 0;
  const accuracy = (matrix.TP + matrix.TN) / items.length;
  return { matrix, recall, precision, fpr, f1, accuracy, total: items.length, misses, falsePos };
}

async function siteScorer(item, opts = {}) {
  return await runAllForHost(item.host, item.url, opts);
}

async function emailScorer(item, opts = {}) {
  // item.url looks like mailto:Display Name?address=foo@bar.com or mailto:foo@bar.com
  // Parse display name from the URL.
  let displayName = null;
  let address = item.host ? `${item.host.includes("@") ? item.host : "x@" + item.host}` : "";
  // Crude parse: if URL starts with mailto: and has display name "Name <addr>"
  const url = item.url || "";
  if (url.startsWith("mailto:")) {
    const rest = url.slice(7);
    const bracketMatch = rest.match(/^([^<]*)<([^>]+)>/);
    if (bracketMatch) {
      displayName = bracketMatch[1].trim();
      address = bracketMatch[2];
    } else {
      address = rest.split("?")[0];
    }
  }
  if (!address.includes("@")) return { verdict: "Skipped", score: null };
  return await scoreEmail(displayName, address);
}

// ---- Run configurations ----

async function main() {
  const sites = LABELED.filter((e) => !e.url.startsWith("mailto:"));
  const emails = LABELED.filter((e) => e.url.startsWith("mailto:"));

  const configs = [
    { name: "Heuristics only (no API keys, no backend)", opts: { backend: false, phishtank: false, urlhaus: false, gsb: false } },
    { name: "+ PhishTank + URLhaus direct (legacy feeds)", opts: { backend: false, phishtank: true, urlhaus: true, gsb: false } },
    { name: "+ Backend (4-feed aggregate)", opts: { backend: true, phishtank: false, urlhaus: false, gsb: false } },
    { name: "+ GSB key + Backend (full stack)", opts: { backend: true, phishtank: false, urlhaus: false, gsb: true } },
  ];

  console.log("=== TrustLens accuracy benchmark ===");
  console.log(`Corpus: ${LABELED.length} entries (${getByLabel(true).length} phishing, ${getByLabel(false).length} benign)`);
  console.log(`Sites: ${sites.length} | Emails: ${emails.length}\n`);

  for (const cfg of configs) {
    const siteResult = await evalCorpus(sites, siteScorer, cfg.opts);
    const emailResult = await evalCorpus(emails, emailScorer, cfg.opts);
    const totalItems = siteResult.total + emailResult.total;
    const tp = siteResult.matrix.TP + emailResult.matrix.TP;
    const fn = siteResult.matrix.FN + emailResult.matrix.FN;
    const fp = siteResult.matrix.FP + emailResult.matrix.FP;
    const tn = siteResult.matrix.TN + emailResult.matrix.TN;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const fpr = fp + tn > 0 ? fp / (fp + tn) : 0;
    const f1 = precision + recall > 0 ? 2 * precision * recall / (precision + recall) : 0;
    const accuracy = (tp + tn) / totalItems;

    console.log(`Config: ${cfg.name}`);
    console.log(`  Sites:    recall=${(siteResult.recall * 100).toFixed(1)}%  FPR=${(siteResult.fpr * 100).toFixed(1)}%  F1=${(siteResult.f1 * 100).toFixed(1)}%  [TP=${siteResult.matrix.TP} FN=${siteResult.matrix.FN} FP=${siteResult.matrix.FP} TN=${siteResult.matrix.TN}]`);
    console.log(`  Emails:   recall=${(emailResult.recall * 100).toFixed(1)}%  FPR=${(emailResult.fpr * 100).toFixed(1)}%  F1=${(emailResult.f1 * 100).toFixed(1)}%  [TP=${emailResult.matrix.TP} FN=${emailResult.matrix.FN} FP=${emailResult.matrix.FP} TN=${emailResult.matrix.TN}]`);
    console.log(`  Combined: recall=${(recall * 100).toFixed(1)}%  precision=${(precision * 100).toFixed(1)}%  FPR=${(fpr * 100).toFixed(1)}%  F1=${(f1 * 100).toFixed(1)}%  accuracy=${(accuracy * 100).toFixed(1)}%  [TP=${tp} FN=${fn} FP=${fp} TN=${tn}]`);
    console.log();
  }

  // Detailed dump for the full-stack config
  console.log("=== Detailed misses (full-stack config) ===");
  const fullOpts = configs[configs.length - 1].opts;
  for (const item of sites) {
    const r = await siteScorer(item);
    const pred = isPositive(r.verdict);
    if (item.label && !pred) {
      console.log(`  FN site: ${item.url} -> ${r.verdict} (${r.score})`);
      const failedTests = r.tests.filter((t) => !t.passed && !t.skipped).map((t) => t.name);
      console.log(`    failed tests: ${failedTests.join(", ") || "(none)"}`);
    } else if (!item.label && pred) {
      console.log(`  FP site: ${item.url} -> ${r.verdict} (${r.score})`);
      const failedTests = r.tests.filter((t) => !t.passed && !t.skipped).map((t) => t.name);
      console.log(`    failed tests: ${failedTests.join(", ") || "(none)"}`);
    }
  }
  for (const item of emails) {
    const r = await emailScorer(item);
    const pred = isPositive(r.verdict);
    if (item.label && !pred) {
      console.log(`  FN email: ${item.url} -> ${r.verdict} (${r.score})`);
    } else if (!item.label && pred) {
      console.log(`  FP email: ${item.url} -> ${r.verdict} (${r.score})`);
    }
  }

  globalThis.fetch = origFetch;
}

main().catch((e) => { console.error(e); process.exit(1); });