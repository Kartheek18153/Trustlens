// Self-check for context-aware email auth rules + policy-strength parsing.
// Run with: node tests/check_email_rules.mjs
import { testEmailAuth, computeSpoofIndex, dmarcStrength, spfStrength } from "../background/tests.js";

function expect(label, got, want) {
  const ok = got === want;
  console.log((ok ? "PASS" : "FAIL") + " " + label + " got=" + got + " want=" + want);
  if (!ok) process.exitCode = 1;
}

// --- DMARC policy strength ---
expect("dmarc reject=3",     dmarcStrength("v=DMARC1; p=reject; rua=mailto:x@y"), 3);
expect("dmarc quarantine=2", dmarcStrength("v=DMARC1; p=quarantine"), 2);
expect("dmarc none=1",       dmarcStrength("v=DMARC1; p=none"), 1);
expect("dmarc missing=0",    dmarcStrength(null), 0);
expect("dmarc malformed=0",  dmarcStrength("v=DMARC1"), 0);

// --- SPF policy strength ---
expect("spf -all=3",    spfStrength("v=spf1 include:_spf.google.com -all"), 3);
expect("spf ~all=2",    spfStrength("v=spf1 a ~all"), 2);
expect("spf ?all=1",    spfStrength("v=spf1 a ?all"), 1);
expect("spf +all=0",    spfStrength("v=spf1 +all"), 0);
expect("spf missing=0", spfStrength(null), 0);
expect("spf no-mech=0", spfStrength("v=spf1 include:x"), 0);

// --- Spoof index: strength-weighted, not presence-weighted ---
expect("full protection",
  computeSpoofIndex({ mx: true, spfRecord: "v=spf1 -all", dmarcRecord: "v=DMARC1; p=reject", dkim: "default._domainkey" }), 100);
expect("cosmetic protection (p=none, +all) scores low",
  computeSpoofIndex({ mx: true, spfRecord: "v=spf1 +all", dmarcRecord: "v=DMARC1; p=none", dkim: null }) < 50, true);
expect("no records at all",
  computeSpoofIndex({ mx: false, spfRecord: null, dmarcRecord: null, dkim: null }), 0);
// Back-compat: booleans still accepted (old signature)
expect("old boolean signature still works",
  computeSpoofIndex({ mx: true, spf: true, dmarc: true }) >= 25, true);

expect("spoof index exported", typeof computeSpoofIndex, "function");
expect("email auth exported",  typeof testEmailAuth,     "function");
