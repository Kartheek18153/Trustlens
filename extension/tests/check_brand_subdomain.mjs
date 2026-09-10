// Self-check for brand-in-subdomain spoof detection.
import { testBrandSubdomain } from "../background/test_brand_subdomain.js";
import { POPULAR_ROOTS, isPopularRoot } from "../background/popular.js";

function expect(label, got, want) {
  const ok = got === want;
  console.log((ok ? "PASS" : "FAIL") + " " + label + " got=" + got + " want=" + want);
  if (!ok) process.exitCode = 1;
}

// The classic spoof shapes from the corpus — all must FAIL.
const spoofs = [
  ["paypal.com.malicious-domain.tk", "paypal.com.malicious-domain.tk"],
  ["login.microsoftonline.update-required.gq", "login.microsoftonline.update-required.gq"],
  ["secure-chase.banking-update.loan", "secure-chase.banking-update.loan"],
  ["accounts.google.verify-signin.account-security.kitchen", "accounts.google.verify-signin.account-security.kitchen"],
  ["netflix-login.payment-update.science", "netflix-login.payment-update.science"],
  ["apple-id-verify.sign-in.support", "apple-id-verify.sign-in.support"],
];
for (const [host] of spoofs) {
  const r = await testBrandSubdomain(host);
  expect(`spoof ${host} fails`, r.passed, false);
}

// Legit popular parents must PASS.
for (const host of ["accounts.google.com", "login.microsoftonline.com", "outlook.live.com", "mail.google.com", "cdn.cloudflare.com"]) {
  const r = await testBrandSubdomain(host);
  expect(`legit ${host} passes`, r.passed, true);
}

// Brand's own domain passes (no subdomains or with them).
expect("paypal.com passes", (await testBrandSubdomain("paypal.com")).passed, true);
expect("www.paypal.com passes", (await testBrandSubdomain("www.paypal.com")).passed, true);
expect("secure.paypal.com passes", (await testBrandSubdomain("secure.paypal.com")).passed, true);

// Non-brand subdomains pass.
expect("random subdomain passes", (await testBrandSubdomain("blog.example.com")).passed, true);
expect("apex domain passes", (await testBrandSubdomain("example.com")).passed, true);

// Weight check — spoof must cost 40.
const spoofResult = await testBrandSubdomain("paypal.com.malicious-domain.tk");
expect("spoof weight is 40", spoofResult.weight, 40);

// Popular list sanity.
expect("isPopularRoot google.com", isPopularRoot("google.com"), true);
expect("isPopularRoot unknown", isPopularRoot("totally-unknown-site-123.com"), false);
expect("popular list is non-trivial", POPULAR_ROOTS.size > 50, true);

// Substring match in a subdomain label under unknown parent IS a spoof shape — flag it.
// (The aggressive match is gated to subdomain labels of non-popular domains.)
expect("substring match flags", (await testBrandSubdomain("paypalicious.evil.com")).passed, false);

// A short brand token like "x" in a subdomain must not match (min length 4).
expect("short token x.evil.com passes", (await testBrandSubdomain("x.evil.com")).passed, true);
