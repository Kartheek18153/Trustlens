import { getRootDomain } from "./domain.js";

// High-risk TLDs and piracy-adjacent naming patterns.
// These are heuristics, not verdicts. They apply only with low weight and
// can be overridden by the explicit checks (GSB, typosquat, etc.).
//
// Sources: Spamhaus DBL, abuse.ch, public TLD abuse reports. Updated by hand.

export const HIGH_RISK_TLDS = new Set([
  // ccTLDs that Spamhaus / abuse.ch flag as heavily abused
  "tk", "ml", "ga", "cf", "gq",         // Freenom's free batch
  "xyz", "top", "click", "loan", "work", "review", "download",
  "stream", "kitchen", "cyou", "mom", "rest", "monster", "buzz",
  "fit", "rest", "country", "science", "party", "gdn", "win",
  "bid", "racing", "accountant", "men", "date", "faith",
  // cheap / unregulated
  "ru", "su", "cn", "icu", "rest",
]);

// Media/piracy-adjacent keywords that frequently appear in pirate-streaming
// or warez domain names. Matched against the SLD.
export const PIRACY_KEYWORDS = [
  "stream", "streaming", "watch", "live", "tv", "movie", "movies", "film",
  "free", "download", "mp3", "mp4", "torrent", "torrents", "warez", "crack",
  "premium", "unlock", "mod", "apk", "hack", "cheat", "cracked", "leak",
  "leaked", "freeshare", "fshare", "ddl", "rapidgator", "uploaded",
  "putlocker", "solarmovie", "123movies", "gomovies", "fmovies",
  "hdmovie", "hdtv", "hdstream", "4kstream", "animestream",
  "pirate", "piratebay", "thepiratebay", "1337x", "rarbg",
];

// Ad-network / pop-under script patterns. Loaded from the DOM side.
export const AD_SCRIPT_PATTERNS = [
  /popads\.net/i,
  /popcash\.net/i,
  /propellerads\.com/i,
  /exoclick\.com/i,
  /juicyads\.com/i,
  /trafficjunky\.net/i,
  /mondiad\.com/i,
  /clickadu\.com/i,
  /adsterra\.com/i,
  /hilltopads\.com/i,
  /revcontent\.com/i,
  /taboola\.com/i,
  /outbrain\.com/i,
  /mgid\.com/i,
  /zedo\.com/i,
];

// Compute a suspicion score for a domain based on TLD + SLD keywords.
// Returns { score, reasons[] } — score is 0..100, reasons list of evidence.
export function scoreDomainRisk(domain) {
  const reasons = [];
  let score = 0;
  const labels = domain.toLowerCase().split(".");
  const tld = labels[labels.length - 1];
  const sld = labels.length >= 2 ? labels[labels.length - 2] : "";

  if (HIGH_RISK_TLDS.has(tld)) {
    score += 40;
    reasons.push(`high-risk TLD .${tld}`);
  }

  let hits = 0;
  for (const kw of PIRACY_KEYWORDS) {
    if (sld.includes(kw)) { hits++; }
  }
  if (hits > 0) {
    score += Math.min(40, hits * 20);
    reasons.push(`${hits} piracy/stream keyword(s) in domain`);
  }

  // Two-signal boost: high-risk TLD + media keyword -> almost always bad.
  if (HIGH_RISK_TLDS.has(tld) && hits > 0) {
    score += 20;
    reasons.push("high-risk TLD combined with media/piracy keyword");
  }

  return { score: Math.min(100, score), reasons };
}

export async function testHighRiskDomain(host, domainAgeDays) {
  const name = "High-Risk TLD / Naming";
  const domain = getRootDomain(host);
  // Established domains get a pass — old pirate sites do exist, but the
  // heuristic is most useful for new ones.
  if (typeof domainAgeDays === "number" && domainAgeDays > 365) {
    return { name, passed: true, weight: 0, reason: `Domain is ${domainAgeDays} days old — high-risk naming skipped`, evidence: domain };
  }
  const { score, reasons } = scoreDomainRisk(domain);
  if (score === 0) {
    return { name, passed: true, weight: 0, reason: "No high-risk TLD or piracy keywords", evidence: domain };
  }
  // TLD-only signal is too weak on its own (lots of legit .xyz blogs).
  // It's an informational penalty, not a fail.
  if (score < 60) {
    return { name, passed: true, weight: 10, reason: `Mild risk signals: ${reasons.join(", ")}`, evidence: `risk=${score}/100` };
  }
  if (score < 80) {
    return { name, passed: false, weight: 15, reason: `Suspicious naming: ${reasons.join(", ")}`, evidence: `risk=${score}/100` };
  }
  return { name, passed: false, weight: 25, reason: `Strong risk signals: ${reasons.join(", ")}`, evidence: `risk=${score}/100` };
}
