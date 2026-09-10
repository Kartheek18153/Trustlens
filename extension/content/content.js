// Content script. Runs DOM-based trust tests, shows a banner when the site
// is Dangerous, and warns the user when a password form is about to post
// off-origin. Wrapped in IIFE so any throw can't take the whole script down.

(function () {
"use strict";

window.addEventListener("error", (e) => { /* swallow content-script errors so the page still works */ e.preventDefault(); return true; }, true);

try {

const EMAIL_RE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const SCANNED = new Set();
const DISMISSED_HOSTS = new Set();
let bannerEl = null;
let interceptionInstalled = false;

function safeHost(url) {
  try { return new URL(url, location.href).hostname.toLowerCase(); } catch { return ""; }
}

function rootDomain(host) {
  const h = (host || "").replace(/^www\./, "");
  const parts = h.split(".").filter(Boolean);
  if (parts.length <= 2) return h;
  const twoPartTlds = new Set(["co.uk", "co.in", "co.jp", "co.kr", "com.au", "com.br", "com.cn"]);
  const last2 = parts.slice(-2).join(".");
  if (parts.length >= 3 && twoPartTlds.has(last2)) return parts.slice(-3).join(".");
  return parts.slice(-2).join(".");
}

const PAGE_HOST = rootDomain(location.hostname);
const isCheckable = PAGE_HOST && /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(PAGE_HOST);

function showBanner(result) {
  if (!result || result.verdict !== "Dangerous") return;
  const host = result.host || "";
  if (host && DISMISSED_HOSTS.has(host)) return;
  if (bannerEl) bannerEl.remove();
  const el = document.createElement("div");
  el.className = "trustlens-banner";
  el.innerHTML = `
    <div class="trustlens-banner-inner">
      <div class="trustlens-banner-title">TrustLens: Dangerous site</div>
      <div class="trustlens-banner-body">
        Score <b>${typeof result.score === "number" ? result.score : "—"}/100</b> — ${escapeHtml(host)}
      </div>
      <div class="trustlens-banner-actions">
        <button class="trustlens-banner-close" type="button">Dismiss</button>
      </div>
    </div>`;
  document.documentElement.appendChild(el);
  el.querySelector(".trustlens-banner-close").addEventListener("click", () => {
    if (host) DISMISSED_HOSTS.add(host);
    el.remove();
  });
  bannerEl = el;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function extractEmails() {
  const found = new Set();
  if (!document.body) return [];
  try {
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null);
    let node;
    while ((node = walker.nextNode())) {
      const matches = node.nodeValue && node.nodeValue.match(EMAIL_RE);
      if (matches) matches.forEach((m) => found.add(m));
    }
  } catch (e) { /* ignore */ }
  try {
    document.querySelectorAll('a[href^="mailto:"]').forEach((a) => {
      const m = a.getAttribute("href").slice(7).split("?")[0];
      if (m) found.add(m);
    });
  } catch (e) { /* ignore */ }
  return [...found];
}

async function scanEmails() {
  if (!isCheckable) return;
  const emails = extractEmails();
  for (const address of emails) {
    if (SCANNED.has(address)) continue;
    SCANNED.add(address);
    try {
      const res = await chrome.runtime.sendMessage({
        type: "scoreEmail",
        email: { displayName: null, address },
      });
      if (res && (res.verdict === "Dangerous" || res.verdict === "Caution")) {
        highlightEmails(address, res.verdict);
      }
    } catch (e) { /* ignore */ }
  }
}

function highlightEmails(address, verdict) {
  if (!document.body) return;
  const color = verdict === "Dangerous" ? "#dc2626" : "#d97706";
  try {
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null);
    const re = new RegExp(address.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
    const toReplace = [];
    let node;
    while ((node = walker.nextNode())) {
      if (!re.test(node.nodeValue || "")) continue;
      re.lastIndex = 0;
      toReplace.push(node);
    }
    for (const n of toReplace) {
      const frag = document.createDocumentFragment();
      let last = 0;
      const text = n.nodeValue || "";
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) !== null) {
        if (m.index > last) frag.appendChild(document.createTextNode(text.slice(last, m.index)));
        const span = document.createElement("span");
        span.className = "trustlens-email " + verdict.toLowerCase();
        span.style.borderBottom = `2px dotted ${color}`;
        span.style.cursor = "help";
        span.title = `TrustLens: ${verdict}`;
        span.textContent = m[0];
        frag.appendChild(span);
        last = m.index + m[0].length;
      }
      if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
      n.parentNode.replaceChild(frag, n);
    }
  } catch (e) { /* ignore */ }
  try {
    document.querySelectorAll(`a[href^="mailto:${address}"]`).forEach((a) => {
      a.classList.add("trustlens-email", verdict.toLowerCase());
      a.style.borderBottom = `2px dotted ${color}`;
      a.title = `TrustLens: ${verdict}`;
    });
  } catch (e) { /* ignore */ }
}

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "showBanner") {
    showBanner(msg.result);
  }
});

// --- DOM/behavioral tests ---

function runDomTests() {
  const out = [];

  // Page content + JS behavior signals (loaded via content_signals.js)
  try {
    if (typeof window.__trustlensContentSignals === "function") {
      const sig = window.__trustlensContentSignals();
      if (Array.isArray(sig)) out.push(...sig);
    }
  } catch (e) { /* ignore */ }

  // Form action audit
  let passwordFields = [];
  try { passwordFields = document.querySelectorAll('input[type="password"]'); } catch (e) {}
  if (passwordFields.length === 0) {
    out.push({ name: "Form Action Audit", passed: true, weight: 0, reason: "No password fields on page", skipped: true });
  } else {
    const offending = [];
    try {
      for (const form of document.querySelectorAll("form")) {
        const action = form.getAttribute("action");
        if (!action || action === "" || action.startsWith("#")) continue;
        const host = safeHost(action);
        if (host && host !== PAGE_HOST) offending.push(`${PAGE_HOST} -> ${host}`);
      }
    } catch (e) { /* ignore */ }
    if (offending.length === 0) {
      out.push({ name: "Form Action Audit", passed: true, weight: 0, reason: "Password forms post to same origin", evidence: PAGE_HOST });
    } else {
      out.push({ name: "Form Action Audit", passed: false, weight: 35, reason: "Password form posts off-origin", evidence: offending[0] });
    }
  }

  // iFrame clickjack scan
  if (window.top === window) {
    out.push({ name: "iFrame Clickjack Scan", passed: true, weight: 0, reason: "Top frame", evidence: location.hostname, skipped: true });
  } else {
    const parentHost = safeHost(document.referrer) || "(unknown referrer)";
    if (passwordFields.length > 0 && parentHost && parentHost !== PAGE_HOST) {
      out.push({ name: "iFrame Clickjack Scan", passed: false, weight: 30, reason: "Login page framed by third party", evidence: `${parentHost} -> ${PAGE_HOST}` });
    } else {
      out.push({ name: "iFrame Clickjack Scan", passed: true, weight: 0, reason: "Framed, no password fields", evidence: parentHost });
    }
  }

  // Form submit interception (install once)
  if (interceptionInstalled) {
    out.push({ name: "Form Submit Watcher", passed: true, weight: 0, reason: "Interception active", evidence: "active" });
  } else {
    try {
      document.addEventListener("submit", (e) => {
        const form = e.target;
        if (!form || !form.querySelector('input[type="password"]')) return;
        const action = form.getAttribute("action") || location.href;
        const actionHost = safeHost(action);
        if (actionHost && actionHost !== PAGE_HOST) {
          const ok = window.confirm(
            `TrustLens warning\n\nThis form will send your password to:\n${actionHost}\n\nThe page you're on is ${PAGE_HOST}.\n\nProceed?`
          );
          if (!ok) {
            e.preventDefault();
            e.stopImmediatePropagation();
          }
        }
      }, true);
      const origSubmit = HTMLFormElement.prototype.submit;
      HTMLFormElement.prototype.submit = function () {
        if (this.querySelector && this.querySelector('input[type="password"]')) {
          const action = this.getAttribute("action") || location.href;
          const actionHost = safeHost(action);
          if (actionHost && actionHost !== PAGE_HOST) {
            const ok = window.confirm(
              `TrustLens warning\n\nThis form will send your password to:\n${actionHost}\n\nThe page you're on is ${PAGE_HOST}.\n\nProceed?`
            );
            if (!ok) return;
          }
        }
        return origSubmit.apply(this, arguments);
      };
      interceptionInstalled = true;
    } catch (e) { /* ignore */ }
    out.push({ name: "Form Submit Watcher", passed: true, weight: 0, reason: "Interception active", evidence: "active" });
  }

  // Malvertising / pop-under detector.
  // Three signals; each one alone is suspicious, two together is a red flag.
  out.push(detectMalvertising());

  return out;
}

// Ad-network script src patterns (kept in sync with test_highrisk.js).
// Inlined here because the content script can't import from the service worker.
const AD_SCRIPT_PATTERNS = [
  /popads\.net/i, /popcash\.net/i, /propellerads\.com/i, /exoclick\.com/i,
  /juicyads\.com/i, /trafficjunky\.net/i, /mondiad\.com/i, /clickadu\.com/i,
  /adsterra\.com/i, /hilltopads\.com/i, /revcontent\.com/i, /taboola\.com/i,
  /outbrain\.com/i, /mgid\.com/i, /zedo\.com/i, /adservice\.google/i,
];

function detectMalvertising() {
  const name = "Malvertising / Pop-Under";
  const signals = [];
  try {
    // Signal 1: known ad-network script tags.
    const adScripts = Array.from(document.querySelectorAll("script[src]"))
      .map((s) => s.src)
      .filter((src) => AD_SCRIPT_PATTERNS.some((re) => re.test(src)));
    if (adScripts.length > 0) signals.push(`${adScripts.length} ad-network script(s)`);

    // Signal 2: a body-wide click listener is a classic pop-under trigger.
    // document.onclick is a settable property; if it's not null, something
    // wired a handler at the document level.
    const docHasOnclick = !!document.onclick;
    const bodyHasOnclick = document.body && !!document.body.onclick;
    if (docHasOnclick || bodyHasOnclick) signals.push("document/body onclick handler set");

    // Signal 3: inline scripts that call window.open or create <a target=_blank>
    // with a fake URL are pop-unders. We look for the pattern conservatively.
    const inlineScripts = Array.from(document.querySelectorAll("script:not([src])"));
    let popUnderHits = 0;
    for (const s of inlineScripts) {
      const t = s.textContent || "";
      if (/window\.open\s*\(\s*["']https?:\/\//.test(t)) popUnderHits++;
      if (/\.click\s*\(\s*\)\s*;?\s*$/m.test(t) && /target=["']_blank["']/i.test(t)) popUnderHits++;
    }
    if (popUnderHits > 0) signals.push(`${popUnderHits} suspicious window.open/auto-click pattern(s)`);
  } catch (e) { /* ignore */ }

  if (signals.length === 0) {
    return { name, passed: true, weight: 0, reason: "No ad-network or pop-under signals" };
  }
  if (signals.length === 1) {
    return { name, passed: true, weight: 5, reason: `One malvertising signal: ${signals[0]}`, evidence: signals.join("; ") };
  }
  return { name, passed: false, weight: 20, reason: `Multiple malvertising signals: ${signals.join("; ")}`, evidence: signals.join("; ") };
}

// Send DOM tests to the background for aggregation, then update the banner.
async function runAndReport() {
  if (!isCheckable) return;
  const domTests = runDomTests();
  try {
    const result = await chrome.runtime.sendMessage({ type: "domTests", tests: domTests, host: location.hostname });
    if (result && result.verdict === "Dangerous") {
      showBanner(result);
    }
  } catch (e) { /* noop */ }
  // Also scan emails on real sites.
  scanEmails();
}

// First DOM pass after the page settles.
setTimeout(runAndReport, 600);
// Re-run on DOM mutations, throttled.
let pending = false;
const mo = new MutationObserver(() => {
  if (pending) return;
  pending = true;
  setTimeout(() => { pending = false; runAndReport(); }, 1500);
});
mo.observe(document.documentElement, { childList: true, subtree: true });

} catch (e) { /* fatal script error — bail silently */ }
})();
