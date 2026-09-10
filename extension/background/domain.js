// Domain utilities shared by all tests.

function getRootDomain(host) {
  if (!host) return "";
  const h = host.toLowerCase().replace(/^www\./, "").split("/")[0].split("?")[0];
  const parts = h.split(".").filter(Boolean);
  if (parts.length <= 2) return h;
  // crude eTLD+1 — good enough for the common cases; the public suffix list
  // is overkill for a first cut. Handles .co.uk, .com.au, .co.in style 2-part TLDs.
  const twoPartTlds = new Set([
    "co.uk", "co.in", "co.jp", "co.kr", "co.nz", "co.za", "co.id",
    "com.au", "com.br", "com.cn", "com.mx", "com.tr", "com.tw", "com.sg",
    "org.uk", "net.au", "ac.uk", "gov.uk", "or.jp",
  ]);
  const last2 = parts.slice(-2).join(".");
  if (parts.length >= 3 && twoPartTlds.has(last2)) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

function isValidDomain(d) {
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d);
}

function isCheckableHost(host) {
  if (!host) return false;
  const h = host.toLowerCase();
  if (h.startsWith("chrome://") || h.startsWith("chrome-extension://") ||
      h.startsWith("chrome-search://") || h.startsWith("edge://") ||
      h.startsWith("about:") || h === "localhost" || h.endsWith(".localhost") ||
      h === "newtab" || h === "devtools" || /^\d+(\.\d+){3}$/.test(h) ||
      h.includes(":")) {  // IPv6 literal
    return false;
  }
  return isValidDomain(getRootDomain(h));
}

function isPrivateIp(ip) {
  if (!ip) return false;
  if (ip.startsWith("127.") || ip === "::1") return true;
  if (/^10\./.test(ip)) return true;
  if (/^192\.168\./.test(ip)) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[01])\./.test(ip)) return true;
  return false;
}

export { getRootDomain, isValidDomain, isPrivateIp, isCheckableHost };
