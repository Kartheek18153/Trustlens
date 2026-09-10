// Minimal self-check for the score engine. Run with: node tests/check_score.mjs
import { aggregate, verdictFor } from "../background/score.js";

function expect(label, got, want) {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  console.log((ok ? "PASS" : "FAIL") + " " + label + " got=" + JSON.stringify(got) + " want=" + JSON.stringify(want));
  if (!ok) process.exitCode = 1;
}

// all pass -> 100, Safe
expect("all pass", aggregate([
  { name: "a", passed: true, weight: 10, reason: "" },
  { name: "b", passed: true, weight: 5,  reason: "" },
]).score, 100);

// one fail by full weight
expect("one fail by weight", aggregate([
  { name: "a", passed: true,  weight: 10, reason: "" },
  { name: "b", passed: false, weight: 20, reason: "" },
]).score, 80);

// skipped does nothing
expect("skipped no-op", aggregate([
  { name: "a", passed: true,  weight: 10, reason: "" },
  { name: "b", passed: false, weight: 30, reason: "", skipped: true },
]).score, 100);

// clamp at 0
expect("clamp 0", aggregate([
  { name: "a", passed: false, weight: 999, reason: "" },
]).score, 0);

// verdict bands
expect("safe band",    verdictFor(80),  "Safe");
expect("caution band", verdictFor(50),  "Caution");
expect("danger band",   verdictFor(49),  "Dangerous");
