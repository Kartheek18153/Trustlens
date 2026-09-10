// Self-check for punycode-aware homoglyph detection + RDAP cache.
import { testHomoglyph, decodePunycode, brandConfusable } from "../background/test_homoglyph.js";
import { fetchRdap } from "../background/rdap.js";

function expect(label, got, want) {
  const ok = got === want;
  console.log((ok ? "PASS" : "FAIL") + " " + label + " got=" + got + " want=" + want);
  if (!ok) process.exitCode = 1;
}

// --- Punycode decode (verified against node:url domainToUnicode) ---
expect("decode xn--pypal-4ve", decodePunycode("xn--pypal-4ve"), "p\u0430ypal");
expect("decode xn--mnchen-3ya (münchen)", decodePunycode("xn--mnchen-3ya"), "m\u00fcnchen");
expect("decode xn--ggle-55da", decodePunycode("xn--ggle-55da"), "g\u043e\u043egle");
expect("decode non-punycode is null", decodePunycode("paypal"), null);

// --- Brand confusables on decoded labels ---
expect("pаypal confuses with paypal", brandConfusable("p\u0430ypal")?.brand, "paypal");
expect("münchen does not confuse", brandConfusable("m\u00fcnchen"), null);

// --- Test verdicts ---
expect("legit IDN münchen.de passes", (await testHomoglyph("xn--mnchen-3ya.de")).passed, true);
expect("xn--pypal-4ve.com fails", (await testHomoglyph("xn--pypal-4ve.com")).passed, false);
// The real-world Cyrillic apple.com attack label.
expect("xn--80ak6aa92e.com (Cyrillic аррӏе) fails", (await testHomoglyph("xn--80ak6aa92e.com")).passed, false);
expect("cyrillic in subdomain fails", (await testHomoglyph("p\u0430ypal.evil.com")).passed, false);
expect("plain paypal root passes (brand's own domain)", (await testHomoglyph("paypal.com")).passed, true);

// Weight: punycode-brand confusable is heavier than raw non-ASCII.
const conf = await testHomoglyph("xn--pypal-4ve.com");
expect("confusable weight 40", conf.weight, 40);

// --- RDAP cache: same-domain lookups return the identical object (1 fetch) ---
globalThis.fetch = (url) => {
  if (String(url).includes("rdap.org")) {
    return Promise.resolve({
      ok: true,
      json: async () => ({ events: [{ eventAction: "registration", eventDate: "2020-01-01" }], entities: [] }),
    });
  }
  return Promise.resolve({ ok: false, status: 404, json: async () => ({}) });
};
const a = await fetchRdap("cache-test.example");
const b = await fetchRdap("cache-test.example");
expect("rdap cache returns same object", a === b, true);
expect("rdap cache parsed", Array.isArray(a.events), true);
