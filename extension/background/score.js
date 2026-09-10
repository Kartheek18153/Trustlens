// Trust score engine.
// Each test returns { name, passed, score, weight, reason, evidence }.
// Final score starts at 100 and is reduced by failing tests (weight-capped).
// Bounded 0..100. Verdict bands: >=80 Safe, >=50 Caution, <50 Dangerous.

const SCORE = {
  startAt: 100,
  bands: { safe: 80, caution: 50 },
};

function verdictFor(score) {
  if (score >= SCORE.bands.safe) return "Safe";
  if (score >= SCORE.bands.caution) return "Caution";
  return "Dangerous";
}

function colorFor(verdict) {
  if (verdict === "Safe") return "#16a34a";
  if (verdict === "Caution") return "#d97706";
  return "#dc2626";
}

// Apply test results to a base score. Each test's penalty is its weight
// (capped at weight) when failed, 0 when passed. Untaken tests are ignored.
function aggregate(tests) {
  let score = SCORE.startAt;
  const applied = [];
  for (const t of tests) {
    if (t.skipped) {
      applied.push({ ...t, delta: 0, applied: false });
      continue;
    }
    const delta = t.passed ? 0 : -Math.min(Math.abs(t.weight), t.weight);
    score += delta;
    applied.push({ ...t, delta, applied: true });
  }
  score = Math.max(0, Math.min(100, Math.round(score)));
  return { score, verdict: verdictFor(score), tests: applied };
}

export { aggregate, verdictFor, colorFor, SCORE };
