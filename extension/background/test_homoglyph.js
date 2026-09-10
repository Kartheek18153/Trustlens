// Homoglyph / IDN / punycode detection.
// Flags domains that mix scripts, use unicode lookalikes, or use the punycode
// prefix (xn--) on the second-level label.

import { getRootDomain } from "./domain.js";

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
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + c);
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

export async function testHomoglyph(host) {
  const name = "Homoglyph / Punycode";
  const domain = getRootDomain(host);
  const labels = domain.split(".");
  if (labels.length < 2) {
    return { name, passed: true, weight: 0, reason: "Single-label (nothing to check)" };
  }
  const sld = labels[labels.length - 2];

  if (sld.startsWith("xn--")) {
    return { name, passed: false, weight: 30, reason: "Punycode second-level label (xn--)", evidence: sld };
  }
  if (MIXED_SCRIPT_LABELS.test(sld)) {
    const deob = deobfuscate(sld.toLowerCase());
    return { name, passed: false, weight: 25, reason: "Non-ASCII characters in domain", evidence: `${sld} -> ${deob}` };
  }
  return { name, passed: true, weight: 0, reason: "ASCII domain, no punycode", evidence: sld };
}
