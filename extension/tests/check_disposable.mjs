// Self-check for disposable list fallback (no network).
// Run with: node tests/check_disposable.mjs
import { isDisposableSync, FALLBACK_LIST } from "../background/disposable.js";

function expect(label, got, want) {
  const ok = got === want;
  console.log((ok ? "PASS" : "FAIL") + " " + label + " got=" + got + " want=" + want);
  if (!ok) process.exitCode = 1;
}

expect("fallback list non-empty", FALLBACK_LIST.length > 10, true);
expect("mailinator disposable", isDisposableSync("mailinator.com"), true);
expect("gmail NOT disposable", isDisposableSync("gmail.com"), false);
expect("empty domain not disposable", isDisposableSync(""), false);
expect("case insensitive", isDisposableSync("MAILINATOR.COM"), true);