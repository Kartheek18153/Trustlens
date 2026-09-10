// Self-check for the high-risk domain heuristic. Run with:
//   node tests/check_highrisk.mjs
import { scoreDomainRisk, testHighRiskDomain } from "../background/test_highrisk.js";

function expect(label, got, want) {
  const ok = got === want;
  console.log((ok ? "PASS" : "FAIL") + " " + label + " got=" + got + " want=" + want);
  if (!ok) process.exitCode = 1;
}

// --- scoreDomainRisk ---
const r1 = scoreDomainRisk("freemovies.stream");
expect("freemovies.stream strong", r1.score >= 80, true);
expect("freemovies.stream has piracy keyword", r1.reasons.some((x) => x.includes("piracy/stream")), true);

const r2 = scoreDomainRisk("news.com");
expect("news.com no risk", r2.score, 0);

const r3 = scoreDomainRisk("watch.tk");
expect("watch.tk medium", r3.score >= 40, true);

const r4 = scoreDomainRisk("blog.xyz");
expect("blog.xyz mild (TLD only)", r4.score, 40);

// --- testHighRiskDomain wrappers ---
const t1 = await testHighRiskDomain("freemovies.stream", 10);
expect("young strong -> fail", !t1.passed, true);
expect("young strong weight=25", t1.weight, 25);

const t2 = await testHighRiskDomain("blog.xyz", 10);
// blog.xyz -> .xyz is high-risk TLD (score 40). TLD-only is informational: pass, weight 10.
expect("young TLD-only -> pass with weight=10", t2.passed && t2.weight === 10, true);

const t3 = await testHighRiskDomain("freemovies.stream", 800);
expect("old -> skip (weight 0, pass)", t3.passed && t3.weight === 0, true);
expect("old skip reason mentions age", t3.reason.includes("days old"), true);

const t4 = await testHighRiskDomain("news.com", 30);
expect("clean -> pass weight 0", t4.passed && t4.weight === 0, true);
