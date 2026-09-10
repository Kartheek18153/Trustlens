// Self-check for typosquat test. Run with: node tests/check_typosquat.mjs
import { testTyposquat } from "../background/tests.js";

function expect(label, gotVerdict, want) {
  const ok = gotVerdict === want;
  console.log((ok ? "PASS" : "FAIL") + " " + label + " got=" + gotVerdict + " want=" + want);
  if (!ok) process.exitCode = 1;
}

const t1 = await testTyposquat("paypa1.com");
expect("paypa1 -> paypal fail", !t1.passed, true);

const t2 = await testTyposquat("paypal.com");
expect("paypal exact pass", t2.passed, true);

const t3 = await testTyposquat("go0gle.com");
expect("go0gle -> google fail", !t3.passed, true);

const t4 = await testTyposquat("myblog.example.com");
expect("random domain pass", t4.passed, true);
