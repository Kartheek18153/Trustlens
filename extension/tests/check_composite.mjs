// Self-check for composite trust signals.
// Run with: node tests/check_composite.mjs
import { compositeSignals } from "../background/composite.js";

function expect(label, got, want) {
  const ok = got === want;
  console.log((ok ? "PASS" : "FAIL") + " " + label + " got=" + got + " want=" + want);
  if (!ok) process.exitCode = 1;
}

// No tests → no composites.
expect("empty input no composite", compositeSignals([]).length, 0);

// All signed/authed → no composite.
const allGood = [
  { name: "DNSSEC (AD flag)", passed: true, weight: 0, reason: "DNSSEC chain valid", evidence: "example.com" },
  { name: "Email Authentication", passed: true, weight: 0, reason: "MX + SPF + DMARC all present", evidence: "" },
];
expect("all good no composite", compositeSignals(allGood).length, 0);

// Two of three unsigned → composite.
const twoUnsigned = [
  { name: "DNSSEC (AD flag)", passed: true, weight: 0, reason: "DNSSEC not configured (unsigned)", evidence: "Status 0" },
  { name: "Email Authentication", passed: true, weight: 0, reason: "Missing: no SPF", evidence: "" },
];
const c2 = compositeSignals(twoUnsigned);
expect("two unsigned composite fires", c2.length, 1);
expect("two unsigned weight=15", c2[0].weight, 15);
expect("two unsigned fails", c2[0].passed, false);

// One unsigned only → no composite.
const oneUnsigned = [
  { name: "DNSSEC (AD flag)", passed: true, weight: 0, reason: "DNSSEC not configured (unsigned)", evidence: "Status 0" },
  { name: "Email Authentication", passed: true, weight: 0, reason: "MX + SPF + DMARC all present", evidence: "" },
];
expect("one unsigned no composite", compositeSignals(oneUnsigned).length, 0);