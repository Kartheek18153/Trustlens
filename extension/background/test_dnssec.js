// DNSSEC + cross-resolver tests.
// AD flag from a DoH response indicates the chain validated.
// Cross-resolver comparison is a softer spoofing signal that works even on
// unsigned domains — answers that diverge between two trusted resolvers
// usually mean someone in the path is tampering with responses.
//
// We compare ASNs, not exact IPs. Big sites use CDNs and return different IPs
// from every resolver on purpose. What matters is whether the IPs are owned
// by the same organization.

import { getRootDomain } from "./domain.js";
import { lookupAsns, summarize } from "./asn.js";

const DOH_RESOLVERS = [
  { name: "google", url: (n) => `https://dns.google/resolve?name=${encodeURIComponent(n)}&type=A` },
  { name: "cloudflare", url: (n) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=A` },
];

async function query(resolver, name) {
  const controller = new AbortController();
  const tid = setTimeout(() => controller.abort(), 4000);
  try {
    const res = await fetch(resolver.url(name), { headers: { Accept: "application/dns-json" }, signal: controller.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  } finally { clearTimeout(tid); }
}

export async function testDnssec(host) {
  const name = "DNSSEC (AD flag)";
  const domain = getRootDomain(host);
  try {
    // Google sets `AD` true when the chain validated.
    const data = await query(DOH_RESOLVERS[0], domain);
    if (data.AD === true) {
      return { name, passed: true, weight: 0, reason: "DNSSEC chain valid (AD=1)", evidence: domain };
    }
    if (data.AD === false) {
      // AD not set could mean "unsigned" or "bogus". dns.google returns Status.
      if (data.Status === 3) {
        return { name, passed: false, weight: 35, reason: "DNSSEC bogus (chain failed)", evidence: `Status ${data.Status}` };
      }
      return { name, passed: true, weight: 0, reason: "DNSSEC not configured (unsigned)", evidence: `Status ${data.Status || 0}` };
    }
    return { name, passed: true, weight: 0, reason: "DNSSEC status unknown (no AD flag)", evidence: "no AD flag" };
  } catch (e) {
    return { name, passed: true, weight: 0, reason: "DNSSEC lookup failed", evidence: e.message, skipped: true };
  }
}

export async function testCrossResolver(host) {
  const name = "Cross-Resolver Consistency";
  const domain = getRootDomain(host);
  try {
    const results = await Promise.all(DOH_RESOLVERS.map((r) => query(r, domain).then((d) => ({ resolver: r.name, ips: (d.Answer || []).filter((a) => a.type === 1).map((a) => a.data) })).catch((e) => ({ resolver: r.name, error: e.message }))));
    const good = results.filter((r) => !r.error && r.ips.length > 0);
    if (good.length < 2) {
      return { name, passed: true, weight: 0, reason: `Only one resolver responded (${good[0]?.resolver || "none"})`, evidence: good.map((r) => r.resolver).join(",") };
    }

    // Different IPs from the same CDN are normal — compare ASNs.
    const allIps = [...new Set(good.flatMap((r) => r.ips))];
    const asnMap = await lookupAsns(allIps);
    const perResolver = good.map((r) => ({
      resolver: r.resolver,
      ...summarize(r.ips.map((ip) => asnMap.get(ip) || {})),
    }));

    const allAsns = new Set(perResolver.flatMap((r) => r.asns));
    if (allAsns.size === 0) {
      return { name, passed: true, weight: 0, reason: "Could not resolve ASNs", evidence: allIps.join(","), skipped: true };
    }
    if (allAsns.size === 1) {
      const org = perResolver[0].orgs[0] || perResolver[0].asns[0];
      return { name, passed: true, weight: 0, reason: `Same owner on both resolvers (${org})`, evidence: perResolver.map((r) => `${r.resolver}=${r.asns.join("|")}`).join(" ") };
    }
    return {
      name,
      passed: false,
      weight: 30,
      reason: `Resolvers return different owners: ${perResolver.map((r) => `${r.resolver} -> ${r.asns.join("|") || "?"}`).join(" vs ")}`,
      evidence: "possible DNS spoofing",
    };
  } catch (e) {
    return { name, passed: true, weight: 0, reason: "Cross-resolver lookup failed", evidence: e.message, skipped: true };
  }
}
