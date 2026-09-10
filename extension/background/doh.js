// DoH (DNS over HTTPS) client. Uses Google + Cloudflare as fallbacks.
// Public endpoints, no API key, CORS-friendly for extensions.

const DOH_ENDPOINTS = [
  (name) => `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${name === "_dmarc" || name.startsWith("_dmarc.") ? 16 : 1}`,
  (name) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TXT`,
];

async function dohTxt(name) {
  const errors = [];
  for (const make of DOH_ENDPOINTS) {
    const url = make(name);
    try {
      const headers = url.includes("dns.google")
        ? { Accept: "application/dns-json" }
        : { Accept: "application/dns-json" };
      const res = await fetch(url, { headers });
      if (!res.ok) { errors.push(`${url} -> ${res.status}`); continue; }
      const data = await res.json();
      if (data.Answer) {
        return data.Answer.filter((a) => a.type === 16).map((a) => a.data.replace(/^"|"$/g, ""));
      }
      return [];
    } catch (e) {
      errors.push(`${url} -> ${e.message}`);
    }
  }
  throw new Error(`DoH TXT failed for ${name}: ${errors.join("; ")}`);
}

async function dohMx(name) {
  // Google supports type=MX via /resolve too. Cloudflare /dns-query supports it.
  const urls = [
    `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=MX`,
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=MX`,
  ];
  for (const url of urls) {
    try {
      const res = await fetch(url, { headers: { Accept: "application/dns-json" } });
      if (!res.ok) continue;
      const data = await res.json();
      if (data.Answer) {
        return data.Answer
          .filter((a) => a.type === 15)
          .map((a) => a.data.replace(/^"|"$/g, ""))
          .sort((a, b) => parseInt(a.split(" ")[0]) - parseInt(b.split(" ")[0]));
      }
      return [];
    } catch (e) { /* try next */ }
  }
  return [];
}

export { dohTxt, dohMx };
