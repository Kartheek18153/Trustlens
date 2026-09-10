// Homoglyph / IDN / punycode detection.
// Flags domains that mix scripts, use unicode lookalikes, or use the punycode
// prefix (xn--) on the second-level label.
//
// Punycode labels are decoded first: a legit IDN site (münchen.de) passes,
// while a decoded label that confuses with a brand (xn--pypal-4ve.com →
// "pypal"~paypal) fails. Blanket-failing every xn-- domain would flag every
// non-English legitimate site.

import { getRootDomain } from "./domain.js";
import { isPopularRoot } from "./popular.js";
import { BRANDS } from "./brands.js";

const ASCII_LIKE = /^[a-z0-9.-]+$/;
const MIXED_SCRIPT_LABELS = /[^\u0000-\u007f]/;

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  if (Math.abs(m - n) > 3) return Math.abs(m - n);
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const c = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i][j - 1] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + c);
    }
  }
  return dp[m][n];
}

// Common Cyrillic / Greek lookalikes mapped to ASCII.
const GLYPHS = {
  "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0443": "y",
  "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u04bb": "h", "\u0455": "s",
  "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z", "\u0397": "H", "\u0399": "I",
  "\u039A": "K", "\u039C": "M", "\u039D": "N", "\u039F": "O", "\u03A1": "P", "\u03A4": "T",
  "\u03A5": "Y", "\u03A7": "X", "\u03BF": "o", "\u03C1": "p",
};

function deobfuscate(s) {
  return s.split("").map((c) => GLYPHS[c] || c).join("");
}

// Minimal punycode decoder (RFC 3492). Returns null when the label isn't
// valid punycode — callers treat that as its own red flag.
function decodePunycode(label) {
  if (!label.toLowerCase().startsWith("xn--")) return null;
  const base = 36, tmin = 1, tmax = 26, skew = 38, damp = 700, initialBias = 72, initialN = 128;
  const s = label.slice(4);
  // Find the last delimiter; everything before it is plain ASCII.
  const basicEnd = s.lastIndexOf("-");
  let output = [];
  let input = [];
  if (basicEnd > -1) {
    for (const ch of s.slice(0, basicEnd)) output.push(ch.codePointAt(0));
    for (const ch of s.slice(basicEnd + 1)) input.push(ch.codePointAt(0));
  } else {
    for (const ch of s) input.push(ch.codePointAt(0));
  }
  let n = initialN, i = 0, bias = initialBias;

  function adapt(delta, numpoints, first) {
    delta = first ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / numpoints);
    let k = 0;
    while (delta > ((base - tmin) * tmax) >> 1) {
      delta = Math.floor(delta / (base - tmin));
      k += base;
    }
    return k + Math.floor((delta + skew) / (base - tmin));
  }

  function digitOf(cp) {
    // RFC 3492 table: a-z=0..25, 0-9=26..35
    if (cp >= 97 && cp <= 122) return cp - 97;        // a-z
    if (cp >= 65 && cp <= 90)  return cp - 65;        // A-Z
    if (cp >= 48 && cp <= 57)  return cp - 48 + 26;   // 0-9
    return -1;
  }

  try {
    while (input.length > 0) {
      const oldi = i;
      let w = 1;
      for (let k = base; ; k += base) {
        if (input.length === 0) throw new Error("truncated");
        const digit = digitOf(input.shift());
        if (digit < 0) throw new Error("bad char");
        i += digit * w;
        const t = k <= bias ? tmin : (k >= bias + tmax ? tmax : k - bias);
        if (digit < t) break;
        w *= base - t;
      }
      const numpoints = output.length + 1;
      bias = adapt(i - oldi, numpoints, oldi === 0);
      n += Math.floor(i / numpoints);
      i %= numpoints;
      output.splice(i, 0, n);
      i++;
    }
    return output.map((cp) => String.fromCodePoint(cp)).join("");
  } catch (e) {
    return null;
  }
}

// Decoded label vs brand list — confusable if edit distance 1, or 2 with
// length >= 5 (long brands tolerate distance 2 without false positives).
function brandConfusable(decoded) {
  const d = decoded.toLowerCase();
  for (const brand of BRANDS) {
    if (brand.length < 4) continue;
    const dist = levenshtein(d, brand);
    if (dist === 0) return { brand, dist };
    if (dist === 1) return { brand, dist };
    if (dist === 2 && brand.length >= 5 && d.length >= 5) return { brand, dist };
  }
  return null;
}

// Check one label (used for root SLD and every subdomain label).
function checkLabel(sld) {
  if (sld.startsWith("xn--")) {
    const decoded = decodePunycode(sld);
    if (decoded === null) {
      return { weight: 30, reason: "Malformed punycode label (xn--)", evidence: sld };
    }
    // Brand check on the decoded form AND its homoglyph-mapped form —
    // "аоиие" isn't Levenshtein-close to any brand, but homoglyph-mapped
    // confusables of brand names are the whole point of IDN spoofs.
    const conf = brandConfusable(decoded) || brandConfusable(deobfuscate(decoded.toLowerCase()));
    if (conf) {
      return { weight: 40, reason: `Punycode label decodes to "${decoded}" — confusable with "${conf.brand}" (distance ${conf.dist})`, evidence: `${sld} -> ${decoded}` };
    }
    return null; // legit IDN
  }
  if (MIXED_SCRIPT_LABELS.test(sld)) {
    const deob = deobfuscate(sld.toLowerCase());
    return { weight: 25, reason: "Non-ASCII characters in domain", evidence: `${sld} -> ${deob}` };
  }
  return null;
}

export async function testHomoglyph(host) {
  const name = "Homoglyph / Punycode";
  const domain = getRootDomain(host);
  const labels = domain.split(".");
  if (labels.length < 2) {
    return { name, passed: true, weight: 0, reason: "Single-label (nothing to check)" };
  }

  // Popular roots (including IDN-heavy ccTLD sites we know are legit) pass.
  if (isPopularRoot(domain)) {
    return { name, passed: true, weight: 0, reason: "Well-known domain — homoglyph check skipped", evidence: domain, skipped: true };
  }

  // 1. Root SLD.
  const rootHit = checkLabel(labels[labels.length - 2]);
  if (rootHit) {
    return { name, passed: false, weight: rootHit.weight, reason: rootHit.reason, evidence: rootHit.evidence };
  }

  // 2. Subdomain labels — pаypal.evil.com must not slip past the root check.
  const full = (host || "").toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
  if (full.length > labels.length) {
    const rootLabels = domain.split(".");
    for (const sub of full.slice(0, full.length - rootLabels.length)) {
      const hit = checkLabel(sub);
      if (hit) {
        return { name, passed: false, weight: Math.max(25, hit.weight), reason: `${hit.reason} (in subdomain "${sub}")`, evidence: hit.evidence };
      }
    }
  }
  return { name, passed: true, weight: 0, reason: "ASCII domain, no punycode", evidence: labels[labels.length - 2] };
}

export { decodePunycode, brandConfusable };
