// Self-check for homoglyph test. Run with: node tests/check_homoglyph.mjs
import { testHomoglyph } from "../background/test_homoglyph.js";

function expect(label, got, want) {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  console.log((ok ? "PASS" : "FAIL") + " " + label + " got=" + JSON.stringify(got) + " want=" + JSON.stringify(want));
  if (!ok) process.exitCode = 1;
}

// has to await because we made it async for symmetry
const t1 = await testHomoglyph("xn--pypal-4ve.com");
expect("punycode fail", !t1.passed, true);

const t2 = await testHomoglyph("paypal.com");
expect("ascii pass", t2.passed, true);

// Cyrillic 'a' in second-level label
const t3 = await testHomoglyph("\u0440aypal.com");
expect("cyrillic fail", !t3.passed, true);
