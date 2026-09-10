// Composite trust signal for sites that fail multiple "unsigned / no auth" checks.
// Most of the web is unsigned + no SPF/DMARC; alone those are noisy. Three of
// them firing together is a much stronger signal.
//
// Used by score.js via a separate aggregator pass over already-collected
// network tests. Returns a synthetic test result.

const UNSIGNED_DNSSEC = "DNSSEC (AD flag)";
const UNSIGNED_SPF = "Email Authentication";

function reasonIncludes(test, needle) {
  if (!test || !test.reason) return false;
  return test.reason.includes(needle);
}

export function compositeSignals(tests) {
  const out = [];
  if (!Array.isArray(tests) || tests.length === 0) return out;

  const dnssec = tests.find((t) => t.name === UNSIGNED_DNSSEC);
  const email = tests.find((t) => t.name === UNSIGNED_SPF);
  const certAge = tests.find((t) => t.name === "SSL Certificate Age");

  let unsignedCount = 0;
  if (dnssec && (dnssec.evidence === "Status 0" || reasonIncludes(dnssec, "unsigned"))) unsignedCount++;
  if (email && reasonIncludes(email, "no SPF")) unsignedCount++;
  if (email && reasonIncludes(email, "no DMARC")) unsignedCount++;

  if (unsignedCount >= 2) {
    out.push({
      name: "Unsigned Composite",
      passed: false,
      weight: 15,
      reason: `Multiple unsigned indicators (${unsignedCount}/3: DNSSEC, SPF, DMARC)`,
      evidence: unsignedCount >= 3 ? "all unsigned" : "2 of 3 unsigned",
    });
  }

  return out;
}