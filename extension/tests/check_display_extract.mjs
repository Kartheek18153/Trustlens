// Self-check for the display-name extraction logic in content.js.
// The regex/DOM-shape logic is mirrored here; content.js can't be imported
// under node (chrome APIs), so this validates the *pattern rules*.

function expect(label, got, want) {
  const ok = got === want;
  console.log((ok ? "PASS" : "FAIL") + " " + label + " got=" + got + " want=" + want);
  if (!ok) process.exitCode = 1;
}

// Mirrors content.js: given text nodes and mailto anchors, produce the map.
function extractDisplayNames(textNodes, mailtoAnchors) {
  const displayNames = new Map();
  for (const a of mailtoAnchors) {
    const address = a.href.slice(7).split("?")[0];
    const dn = (a.text || "").trim() || (a.title || "").trim();
    if (dn && dn !== address && !displayNames.has(address)) displayNames.set(address, dn);
  }
  for (const value of textNodes) {
    const EMAIL_RE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
    const matches = value.match(EMAIL_RE);
    if (!matches) continue;
    for (const m of matches) {
      const before = value.slice(0, value.indexOf(m)).trim();
      const dnMatch = before.match(/([A-Za-z][A-Za-z0-9.'-]*(?:\s+[A-Za-z][A-Za-z0-9.'-]*)*)\s*<$/);
      if (dnMatch && !displayNames.has(m)) {
        const words = dnMatch[1].trim().split(/\s+/);
        displayNames.set(m, words.slice(-3).join(" "));
      }
    }
  }
  return displayNames;
}

// mailto anchor with text content
const dn = extractDisplayNames(
  [],
  [{ href: "mailto:paypal.support.2024@gmail.com", text: "PayPal Support", title: "" }]
);
expect("mailto text becomes display name", dn.get("paypal.support.2024@gmail.com"), "PayPal Support");

// mailto anchor with title fallback
const dn2 = extractDisplayNames(
  [],
  [{ href: "mailto:x@gmail.com", text: "  ", title: "Microsoft Security" }]
);
expect("mailto title fallback", dn2.get("x@gmail.com"), "Microsoft Security");

// bare mailto, no text — no display name
const dn3 = extractDisplayNames([], [{ href: "mailto:y@gmail.com", text: "y@gmail.com", title: "" }]);
expect("bare mailto no display name", dn3.has("y@gmail.com"), false);

// "Display Name <addr>" in visible text. Trailing-3-words keeps the full
// prefix "Contact PayPal Support" — that's fine: the display-name heuristic
// is token-based (paypal + support tokens), so extra leading words don't
// weaken the spoof signal.
const dn4 = extractDisplayNames(["Contact PayPal Support <paypal.support.2024@gmail.com> now"], []);
expect("bracketed text keeps trailing words", dn4.get("paypal.support.2024@gmail.com"), "Contact PayPal Support");
expect("bracketed text still triggers brand tokens",
  /paypal/i.test(dn4.get("paypal.support.2024@gmail.com")), true);

// A 2-word spoof display name is preserved exactly.
const dn6 = extractDisplayNames(["PayPal Support <x.evil@attacker.com>"], []);
expect("short display name exact", dn6.get("x.evil@attacker.com"), "PayPal Support");

// plain email in text, no display name
const dn5 = extractDisplayNames(["reach us at someone@gmail.com today"], []);
expect("plain text no display name", dn5.has("someone@gmail.com"), false);
