// Self-check for ASN summarize() — pure, no network.
import { summarize } from "../background/asn.js";

function expect(label, got, want) {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  console.log((ok ? "PASS" : "FAIL") + " " + label + " got=" + JSON.stringify(got) + " want=" + JSON.stringify(want));
  if (!ok) process.exitCode = 1;
}

const s1 = summarize([
  { asn: "AS15169", org: "Google LLC" },
  { asn: "AS15169", org: "Google LLC" },
]);
expect("google deduped", s1, { asns: ["AS15169"], orgs: ["Google LLC"] });

const s2 = summarize([
  { asn: "AS16509", org: "Amazon.com, Inc." },
  { asn: "AS15169", org: "Google LLC" },
]);
expect("different orgs", s2, { asns: ["AS15169", "AS16509"], orgs: ["Amazon.com, Inc.", "Google LLC"] });

const s3 = summarize([{}]);
expect("empty record", s3, { asns: [], orgs: [] });
