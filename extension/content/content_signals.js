// Page-content + JS-behavior signals. Runs in the content script.
// Returns an array of test objects that sw.js aggregates alongside network tests.

(function () {
"use:strict"; // intentional no-op to fail fast on sloppy minification

const BRAND_HINT_WORDS = [
  "paypal", "amazon", "apple", "google", "microsoft", "outlook", "office365",
  "facebook", "instagram", "wellsfargo", "chase", "bankofamerica", "coinbase",
  "binance", "fedex", "ups", "dhl", "usps", "irs", "hmrc", "netflix", "spotify",
  "linkedin", "github", "dropbox", "icloud", "gmail", "yahoo",
];

const LOGIN_INPUT_NAMES = [
  "password", "passwd", "pass", "pwd", "secret",
  "login", "email", "username", "user", "account",
  "otp", "2fa", "token", "pin", "security",
];

const OFFORIGIN_BEACON_RE = /beacon|fetch\(|navigator\.sendbeacon|xmlhttprequest|new\s+image\s*\(/i;

function safeHost(url) {
  try { return new URL(url, location.href).hostname.toLowerCase(); } catch { return ""; }
}

function pageContentSignals() {
  const signals = [];
  try {
    // 1. Form input name analysis — login forms with brand-name inputs on a
    //    non-matching domain is the classic credential-harvesting fingerprint.
    const inputs = Array.from(document.querySelectorAll("form input, form button"));
    let loginLikeCount = 0;
    let offOriginFormCount = 0;
    let passwordInputCount = 0;
    const forms = Array.from(document.querySelectorAll("form"));
    for (const f of forms) {
      const inputs = Array.from(f.querySelectorAll("input, button"));
      let loginLike = false;
      for (const inp of inputs) {
        const n = ((inp.name || "") + " " + (inp.id || "") + " " + (inp.placeholder || "")).toLowerCase();
        if (!n) continue;
        if (LOGIN_INPUT_NAMES.some((w) => n.includes(w))) { loginLike = true; break; }
        if ((inp.type || "").toLowerCase() === "password") { loginLike = true; passwordInputCount++; break; }
      }
      if (loginLike) loginLikeCount++;
      const action = f.getAttribute("action");
      if (action) {
        const host = safeHost(action);
        if (host && host !== location.hostname.toLowerCase()) offOriginFormCount++;
      }
    }
    if (loginLikeCount > 0) signals.push(`${loginLikeCount} login-like form(s)`);
    if (offOriginFormCount > 0) signals.push(`${offOriginFormCount} form(s) post off-origin`);

    // 2. Title / brand-claim mismatch — page title references a brand not
    //    present in the domain. Strongest single signal for novel phishing.
    const title = (document.title || "").toLowerCase();
    const ogTitle = ((document.querySelector('meta[property="og:title"]') || {}).content || "").toLowerCase();
    const titleText = title + " " + ogTitle;
    const claimedBrand = BRAND_HINT_WORDS.find((b) => titleText.includes(b));
    if (claimedBrand) {
      const host = location.hostname.toLowerCase().replace(/^www\./, "");
      const hostHasBrand = BRAND_HINT_WORDS.some((b) => host.includes(b));
      if (!hostHasBrand) {
        signals.push(`title claims "${claimedBrand}" but domain is ${host}`);
      }
    }

    // 3. target=_blank ratio — phishing pages open dozens of off-site links.
    const anchors = Array.from(document.querySelectorAll("a[href]"));
    let externalCount = 0;
    for (const a of anchors) {
      const h = safeHost(a.getAttribute("href") || "");
      if (h && h !== location.hostname.toLowerCase()) externalCount++;
    }
    const externalRatio = anchors.length > 0 ? externalCount / anchors.length : 0;
    if (anchors.length >= 5 && externalRatio > 0.85) {
      signals.push(`${externalCount}/${anchors.length} links go off-site`);
    }

    // 4. Hidden password fields — `display:none` or `visibility:hidden` on a
    //    password input is a known skimmer pattern (e.g. KryptoCibule).
    const hiddenPasswords = Array.from(document.querySelectorAll('input[type="password"]')).filter((inp) => {
      const cs = window.getComputedStyle(inp);
      return cs.display === "none" || cs.visibility === "hidden" || (inp.offsetWidth === 0 && inp.offsetHeight === 0);
    });
    if (hiddenPasswords.length > 0) signals.push(`${hiddenPasswords.length} hidden password field(s)`);
  } catch (e) { /* ignore */ }

  if (signals.length === 0) return [];
  return [{
    name: "Page Content Signals",
    passed: signals.length < 2,
    weight: signals.length >= 2 ? 30 : 10,
    reason: signals.join("; "),
    evidence: signals.join("; "),
  }];
}

function jsBehaviorSignals() {
  const signals = [];
  try {
    // 1. Post-load dynamic password input creation. Legit sites have these
    //    in the initial DOM; injected ones are skimmers.
    //    (best-effort heuristic — we can't observe post-load creation here,
    //    so we flag inline scripts that *try* to create them.)
    const inlineScripts = Array.from(document.querySelectorAll("script:not([src])"));
    let dynamicPwHits = 0;
    for (const s of inlineScripts) {
      const t = (s.textContent || "").toLowerCase();
      if (/createelement\s*\(\s*['"]input['"]\s*\)/.test(t) && /type\s*=\s*['"]password['"]/.test(t)) dynamicPwHits++;
      if (/type\s*=\s*['"]password['"]/.test(t) && /appendchild|insertbefore|body\.append/.test(t)) dynamicPwHits++;
    }
    if (dynamicPwHits > 0) signals.push(`${dynamicPwHits} script(s) dynamically create password fields`);

    // 2. Obfuscation unpack — atob() + document.write on the same script
    //    body. Legitimate analytics don't combine these.
    let atobWriteHits = 0;
    for (const s of inlineScripts) {
      const t = s.textContent || "";
      if (/atob\s*\(/.test(t) && /document\.write|innerhtml/.test(t)) atobWriteHits++;
    }
    if (atobWriteHits > 0) signals.push(`${atobWriteHits} script(s) decode+inject obfuscated payload`);

    // 3. Large base64 blobs — heuristic for packed/encoded payloads.
    let largeBlobHits = 0;
    for (const s of inlineScripts) {
      const t = s.textContent || "";
      const m = t.match(/[A-Za-z0-9+/]{1500,}={0,2}/);
      if (m && m[0].length > 1500) largeBlobHits++;
    }
    if (largeBlobHits > 0) signals.push(`${largeBlobHits} large base64 blob(s) in inline scripts`);

    // 4. Off-origin network beacons in inline scripts — not declared in
    //    <script src> or <form action>, but a script fetches another host.
    const declaredHosts = new Set([location.hostname.toLowerCase()]);
    Array.from(document.querySelectorAll("script[src]")).forEach((s) => {
      const h = safeHost(s.getAttribute("src") || "");
      if (h) declaredHosts.add(h);
    });
    let beaconHits = 0;
    for (const s of inlineScripts) {
      const t = s.textContent || "";
      const matches = t.match(/https?:\/\/[^\s'")]+/g) || [];
      for (const url of matches) {
        try {
          const h = new URL(url).hostname.toLowerCase();
          if (!declaredHosts.has(h) && OFFORIGIN_BEACON_RE.test(t)) beaconHits++;
        } catch (e) { /* skip */ }
      }
    }
    if (beaconHits > 0) signals.push(`${beaconHits} off-origin beacon(s) in inline scripts`);
  } catch (e) { /* ignore */ }

  if (signals.length === 0) return [];
  return [{
    name: "JS Behavior Signals",
    passed: signals.length < 2,
    weight: signals.length >= 2 ? 30 : 10,
    reason: signals.join("; "),
    evidence: signals.join("; "),
  }];
}

function runContentSignalTests() {
  return [...pageContentSignals(), ...jsBehaviorSignals()];
}

if (typeof window !== "undefined") {
  window.__trustlensContentSignals = runContentSignalTests;
}

})();