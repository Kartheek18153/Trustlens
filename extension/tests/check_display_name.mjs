// Self-check for display-name mismatch heuristic.
// Run with: node tests/check_display_name.mjs
import { displayNameSignals, testDisplayNameMismatch } from "../background/tests.js";

function expect(label, got, want) {
  const ok = got === want;
  console.log((ok ? "PASS" : "FAIL") + " " + label + " got=" + got + " want=" + want);
  if (!ok) process.exitCode = 1;
}

// Old-style personal address with no display name: skipped.
expect("no display name skipped",
  testDisplayNameMismatch(null, "user@gmail.com").skipped, true);

// Personal-looking from normal gmail: pass.
expect("personal from gmail passes",
  testDisplayNameMismatch("Alice", "alice@gmail.com").passed, true);

// The headline spoof case.
expect("PayPal.Support.2024@gmail.com fails",
  testDisplayNameMismatch("PayPal Support", "paypal.support.2024@gmail.com").passed, false);

// Brand claim in display, random local part, plus year — 2 triggers.
expect("'Microsoft Security Team' <random123.2024@outlook.com> fails",
  testDisplayNameMismatch("Microsoft Security Team", "random123.2024@outlook.com").passed, false);

// Many segments + year.
expect("'Amazon Billing' <accounts.billing.invoices.2025@gmail.com> fails",
  testDisplayNameMismatch("Amazon Billing", "accounts.billing.invoices.2025@gmail.com").passed, false);

// Brand in display AND in local part — legit corp address shape, pass.
expect("'GitHub' <noreply@github.com> passes",
  testDisplayNameMismatch("GitHub", "noreply@github.com").passed, true);

// Year in display but no brand claim.
expect("'Year 2024 newsletter' <news@example.com> passes (no brand)",
  testDisplayNameMismatch("Year 2024 newsletter", "news@example.com").passed, true);

// Sign helper exports the function.
expect("signals helper exported", typeof displayNameSignals, "function");