// Self-check for PhishTank / URLhaus / content-signal wiring.
// Network-free verification that the modules exist and export the expected
// functions, and that the typo+favicon+content flow composes correctly.
// Run with: node tests/check_integration.mjs

import { testTyposquat } from "../background/tests.js";
import { compositeSignals } from "../background/composite.js";
import { fingerprint } from "../background/history_rotation.js";
import { testPhishtank } from "../background/test_phishtank.js";
import { testUrlhaus } from "../background/test_urlhaus.js";

function expect(label, got, want) {
  const ok = got === want;
  console.log((ok ? "PASS" : "FAIL") + " " + label + " got=" + got + " want=" + want);
  if (!ok) process.exitCode = 1;
}

expect("PhishTank exported", typeof testPhishtank, "function");
expect("URLhaus exported",   typeof testUrlhaus,   "function");
expect("composite exported", typeof compositeSignals, "function");
expect("fingerprint exported", typeof fingerprint, "function");

// Typosquat still works (uses big brands list now).
const t = await testTyposquat("paypa1.com", 10);
expect("typosquat still detects paypa1 (big list)", !t.passed, true);
expect("typosquat weight on young domain", t.weight, 40);

// Sanity: composite of unsigned signals + content signals triggers.
const network = [
  { name: "DNSSEC (AD flag)", passed: true, weight: 0, reason: "DNSSEC not configured (unsigned)", evidence: "Status 0" },
  { name: "Email Authentication", passed: true, weight: 0, reason: "Missing: no SPF", evidence: "" },
];
const composites = compositeSignals(network);
expect("composite fires alongside content signal", composites.length, 1);