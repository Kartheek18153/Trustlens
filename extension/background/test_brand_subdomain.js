// Brand-in-subdomain spoof detection — the classic "paypal.com.evil.tk" shape.
// A hostname label containing a known brand (e.g. "paypal", "accounts.google")
// that is NOT part of a popular parent domain is the #1 phishing URL pattern.
//
// We check every label of the full hostname (not just the eTLD+1's SLD) for
// brand tokens, and fail when a brand appears in a label owned by an
// unpopular domain.

import { BRANDS } from "./brands.js";
import { POPULAR_ROOTS, isPopularRoot } from "./popular.js";
import { getRootDomain } from "./domain.js";

// Short strings that collide with brand tokens ("x", "me", "hm", "mac", "via",
// "box", "fly", "ing") are excluded by the length>=4 rule below; keep BRANDS
// untouched for typosquat use.
const MIN_TOKEN_LEN = 4;

function labels(host) {
  return (host || "").toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
}

function brandInLabel(label) {
  // brand as a whole label ("paypal.com") or a token inside a compound
  // label ("paypal-secure", "accounts-google-login") — but not a substring of
  // a longer word ("paypalicious" is not a match; typosquat handles those).
  for (const brand of BRANDS) {
    if (brand.length < MIN_TOKEN_LEN) continue;
    const tokenized = label.split(/[^a-z0-9]+/).filter(Boolean);
    for (const t of tokenized) {
      if (t === brand) return brand;
    }
  }
  // Compound brand words ("microsoftonline", "appleidverify") — substring
  // match for brands >= 5 chars, still gated behind the non-popular-parent
  // check that runs before this is consulted.
  for (const brand of BRANDS) {
    if (brand.length < 5) continue;
    if (label.includes(brand)) return brand;
  }
  return null;
}

export async function testBrandSubdomain(host) {
  const name = "Brand in Subdomain";
  const root = getRootDomain(host);
  if (!root) {
    return { name, passed: true, weight: 0, reason: "No domain", skipped: true };
  }
  // Popular parents legitimately carry brand subdomains:
  //   accounts.google.com, login.microsoftonline.com, mail.paypal.com
  if (isPopularRoot(root)) {
    return { name, passed: true, weight: 0, reason: `Popular parent domain (${root})`, evidence: root };
  }
  // If the site's own root domain IS a brand root (paypal.com itself),
  // its subdomains are fine too.
  const sldTokens = root.split(/[^a-z0-9]+/).filter(Boolean);
  for (const brand of BRANDS) {
    if (brand.length >= MIN_TOKEN_LEN && sldTokens.includes(brand)) {
      return { name, passed: true, weight: 0, reason: `Brand's own domain (${root})`, evidence: root };
    }
  }

  const all = labels(host);
  if (all.length <= 2) {
    return { name, passed: true, weight: 0, reason: "No subdomain labels", evidence: root };
  }
  // Only labels BELOW the eTLD+1 carry the spoof signal.
  const rootLabels = root.split(".");
  const subLabels = all.slice(0, all.length - rootLabels.length);
  if (subLabels.length === 0) {
    return { name, passed: true, weight: 0, reason: "No subdomain labels", evidence: root };
  }
  for (const label of subLabels) {
    const brand = brandInLabel(label);
    if (brand) {
      return {
        name,
        passed: false,
        weight: 40,
        reason: `Subdomain label "${label}" contains brand "${brand}" under non-brand domain ${root}`,
        evidence: `${host} (${brand})`,
      };
    }
  }
  return { name, passed: true, weight: 0, reason: "No brand in subdomain labels", evidence: root };
}
