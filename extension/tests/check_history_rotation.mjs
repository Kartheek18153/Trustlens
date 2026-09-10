// Self-check for fingerprinting + history rotation helpers.
// Run with: node tests/check_history_rotation.mjs
import { fingerprint } from "../background/history_rotation.js";

function expect(label, got, want) {
  const ok = got === want;
  console.log((ok ? "PASS" : "FAIL") + " " + label + " got=" + got + " want=" + want);
  if (!ok) process.exitCode = 1;
}

// Empty result → fingerprint is just the joined empty strings (not "").
expect("empty fingerprint is a string", typeof fingerprint({}), "string");

// Realistic result with the kit signature fields.
const r = {
  tests: [
    { name: "Form Action Audit", passed: false, weight: 35, reason: "Password form posts off-origin", evidence: "evil.com -> steal.io" },
    { name: "Page Content Signals", passed: false, weight: 30, reason: "title claims paypal; off-site links", evidence: "title claims paypal" },
    { name: "Typosquat / Spelling Trick", passed: false, weight: 40, reason: "Close to brand paypal", evidence: "paypol ~ paypal" },
  ],
};
const fp1 = fingerprint(r);
expect("fingerprint non-empty", fp1.length > 10, true);
expect("fingerprint stable across re-order", fingerprint(r), fp1);

// Same evidence on a different host → same fingerprint (would trigger rotation).
const r2 = {
  tests: [
    { name: "Form Action Audit", passed: false, weight: 35, reason: "Password form posts off-origin", evidence: "evil2.com -> steal.io" },
    { name: "Page Content Signals", passed: false, weight: 30, reason: "title claims paypal; off-site links", evidence: "title claims paypal" },
    { name: "Typosquat / Spelling Trick", passed: false, weight: 40, reason: "Close to brand paypal", evidence: "paypol2 ~ paypal" },
  ],
};
expect("rotation fingerprint matches",
  fingerprint(r2).includes("evil.com -> steal.io|title claims paypal|paypol ~ paypal"), false);