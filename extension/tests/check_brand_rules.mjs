// Self-check for the new multi-factor brand rules.
// Run with: node tests/check_brand_rules.mjs
import { testTyposquat } from "../background/tests.js";
import { testFaviconPhash } from "../background/test_favicon.js";

function expect(label, got, want) {
  const ok = got === want;
  console.log((ok ? "PASS" : "FAIL") + " " + label + " got=" + got + " want=" + want);
  if (!ok) process.exitCode = 1;
}

// --- Typosquat: tight on young domains, loose up to 365, skip after ---
// paypa1 hits the substitution early-return (weight 40), not the distance path.
const t1 = await testTyposquat("paypa1.com", 10);
expect("young + substitution (paypa1, 10d) -> fail", !t1.passed, true);
expect("young + substitution (paypa1, 10d) weight=40", t1.weight, 40);

const t2 = await testTyposquat("paypa1.com", 200);
expect("medium + substitution (paypa1, 200d) -> fail", !t2.passed, true);
expect("medium + substitution (paypa1, 200d) weight=40 (substitution path)", t2.weight, 40);

const t3 = await testTyposquat("paypa1.com", 800);
expect("old + substitution (paypa1, 800d) -> pass (skipped)", t3.passed, true);
expect("old skipped mention", t3.reason.includes("skipped"), true);

// Pure edit-distance path (no digit substitution): paypol is distance 1 from paypal.
const t4 = await testTyposquat("paypol.com", 30);
expect("young distance 1 fail", !t4.passed, true);
expect("young distance 1 weight=40 (tight)", t4.weight, 40);

const t4b = await testTyposquat("paypol.com", 200);
expect("medium distance 1 fail", !t4b.passed, true);
expect("medium distance 1 weight=30", t4b.weight, 30);

// Distance 2: paypalll vs paypal = 2 (two extra l's).
const t5 = await testTyposquat("paypalll.com", 30);
expect("young distance 2 pass (tight)", t5.passed, true);

const t6 = await testTyposquat("paypalll.com", 200);
expect("medium distance 2 fail", !t6.passed, true);

// --- Favicon: hamming threshold now 2, plus age rule ---
// We can't easily test the favicon pHash without network, but we can test
// the age-based skip path.
const f1 = await testFaviconPhash("paypal.com", 1000);
expect("old favicon skipped", f1.passed, true);
expect("old favicon mention", f1.reason.includes("skipped"), true);

const f2 = await testFaviconPhash("paypal.com", 30);
expect("young favicon tested (no error)", f2 !== undefined, true);
