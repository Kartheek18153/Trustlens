// Self-check for backend domain normalization + aggregator + new /asn /ct routes.
// Run with: node tests/check_backend.mjs
import { rootDomainOf, isValidDomain, aggregateFromSources, SOURCES, handleAsn, handleCt } from "../worker.js";
import worker from "../worker.js";

function expect(label, got, want) {
  const ok = got === want;
  console.log((ok ? "PASS" : "FAIL") + " " + label + " got=" + JSON.stringify(got) + " want=" + JSON.stringify(want));
  if (!ok) process.exitCode = 1;
}

// --- rootDomainOf ---
expect("plain 2-part", rootDomainOf("evil.com"), "evil.com");
expect("strips www", rootDomainOf("www.evil.com"), "evil.com");
expect("3-part normalizes", rootDomainOf("a.b.evil.com"), "evil.com");
expect("4-part normalizes", rootDomainOf("login.a.b.evil.com"), "evil.com");
expect("co.uk 3-part", rootDomainOf("login.bank.co.uk"), "bank.co.uk");
expect("empty", rootDomainOf(""), "");
expect("lowercase", rootDomainOf("EVIL.COM"), "evil.com");

// --- isValidDomain ---
expect("valid", isValidDomain("evil.com"), true);
expect("invalid single label", isValidDomain("evil"), false);
expect("invalid with scheme", isValidDomain("https://evil.com"), false);

// --- aggregateFromSources ---
expect("empty sources", aggregateFromSources([]).listed, false);
expect("single source weight = base", aggregateFromSources([{ name: "phishtank" }]).weight, SOURCES.phishtank.weight);
expect("two sources get +20", aggregateFromSources([{ name: "phishtank" }, { name: "urlhaus" }]).weight, SOURCES.phishtank.weight + SOURCES.urlhaus.weight + 20);
expect("three sources get +35", aggregateFromSources([{ name: "phishtank" }, { name: "urlhaus" }, { name: "openphish" }]).weight, SOURCES.phishtank.weight + SOURCES.urlhaus.weight + SOURCES.openphish.weight + 35);
expect("duplicate source counted once", aggregateFromSources([{ name: "phishtank" }, { name: "phishtank" }]).weight, SOURCES.phishtank.weight);
expect("unknown source ignored", aggregateFromSources([{ name: "madeup" }]).listed, false);
expect("sources list deduplicated", aggregateFromSources([{ name: "phishtank" }, { name: "phishtank" }]).sources.length, 1);

// --- handleAsn / handleCt: input validation (no upstream, no KV) ---
function makeEnv() {
  const store = new Map();
  return {
    REPUTATION: {
      // Honor the KV "json" read type like real KV does.
      async get(key, type) {
        if (!store.has(key)) return null;
        const v = store.get(key);
        return type === "json" ? JSON.parse(v) : v;
      },
      async put(key, value) { store.set(key, value); },
      async delete(key) { store.delete(key); },
    },
    _store: store,
  };
}

async function asnReq(body) {
  return new Request("https://x/asn", { method: "POST", body: JSON.stringify(body) });
}
async function ctReq(body) {
  return new Request("https://x/ct", { method: "POST", body: JSON.stringify(body) });
}

// --- /asn validation ---
{
  const env = makeEnv();
  const res = await handleAsn(await asnReq({}), env);
  expect("/asn missing ips → 400", res.status, 400);
}
{
  const env = makeEnv();
  const res = await handleAsn(await asnReq({ ips: [] }), env);
  expect("/asn empty ips → 400", res.status, 400);
}
{
  const env = makeEnv();
  const big = Array.from({ length: 51 }, (_, i) => `1.1.1.${i}`);
  const res = await handleAsn(await asnReq({ ips: big }), env);
  expect("/asn >50 ips → 400", res.status, 400);
}

// --- /ct validation ---
{
  const env = makeEnv();
  const res = await handleCt(await ctReq({}), env);
  expect("/ct missing domain → 400", res.status, 400);
}
{
  const env = makeEnv();
  const res = await handleCt(await ctReq({ domain: "not a domain" }), env);
  expect("/ct invalid domain → 400", res.status, 400);
}

// --- /ct transient (502) vs permanent (400) → fallback path ---
// Ponytail: crt.sh errors fall through to "all CT sources failed" when no
// fallback is configured. Once crt.sh returns data, we don't hit Censys.
async function withStubbedFetch(statusCode, run) {
  const orig = globalThis.fetch;
  globalThis.fetch = async () => new Response("upstream", { status: statusCode });
  try { await run(); }
  finally { globalThis.fetch = orig; }
}
{
  // crt.sh 502, no Censys → "all CT sources failed" cached 5 min
  const env = makeEnv();
  await withStubbedFetch(502, async () => {
    const res = await handleCt(await ctReq({ domain: "transient.example" }), env);
    expect("/ct 502 returns body", res.status, 200);
    const body = await res.json();
    expect("/ct 502 falls through to all-failed", body.error, "all CT sources failed");
  });
  expect("/ct 502 cached as all-failed", JSON.parse(env._store.get("ct:transient.example")).error, "all CT sources failed");
}
{
  // crt.sh 200 with valid JSON → success path
  const orig = globalThis.fetch;
  const oldDate = new Date(Date.now() - 365 * 86400000).toISOString();
  globalThis.fetch = async () => new Response(JSON.stringify([{ not_before: oldDate }]), {
    status: 200, headers: { "Content-Type": "application/json" },
  });
  try {
    const env = makeEnv();
    const res = await handleCt(await ctReq({ domain: "happy.example" }), env);
    expect("/ct 200 returns body", res.status, 200);
    const body = await res.json();
    expect("/ct 200 has days", typeof body.days, "number");
    expect("/ct 200 days ~365", body.days >= 360 && body.days <= 370, true);
  } finally { globalThis.fetch = orig; }
}
{
  // crt.sh 502, Certspotter returns data → success, no auth needed
  const orig = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (url.toString().includes("crt.sh")) return new Response("", { status: 502 });
    const oldDate = new Date(Date.now() - 400 * 86400000).toISOString();
    return new Response(JSON.stringify([{ not_before: oldDate }]), {
      status: 200, headers: { "Content-Type": "application/json" },
    });
  };
  try {
    const env = makeEnv();
    const res = await handleCt(await ctReq({ domain: "fallback.example" }), env);
    const body = await res.json();
    expect("/ct fallback to certspotter works", body.source, "certspotter");
    expect("/ct fallback days ~400", body.days >= 395 && body.days <= 405, true);
  } finally { globalThis.fetch = orig; }
}
{
  // Certspotter sends no Authorization header
  const orig = globalThis.fetch;
  let sentAuth = false;
  globalThis.fetch = async (url, opts) => {
    if (url.toString().includes("certspotter")) {
      if (opts && opts.headers && opts.headers.Authorization) sentAuth = true;
      return new Response("[]", { status: 200 });
    }
    return new Response("", { status: 502 });
  };
  try {
    const env = makeEnv();
    await handleCt(await ctReq({ domain: "noauth.example" }), env);
    expect("/ct certspotter uses no auth", sentAuth, false);
  } finally { globalThis.fetch = orig; }
}

// --- /report: collab entry must survive its own write (lost-update race) ---
// The old implementation merged "collab" then wrote back the STALE sources
// array — the collab entry vanished. Reproduce with a plain in-memory KV.
{
  const store = new Map();
  const env = {
    REPUTATION: {
      async get(key, type) {
        if (!store.has(key)) return null;
        const v = store.get(key);
        return type === "json" ? JSON.parse(v) : v;
      },
      async put(key, value) { store.set(key, value); },
      async delete(key) { store.delete(key); },
    },
    REPORT_TOKEN: "tok",
    _store: store,
  };
  const req = (host = "race.example") => new Request("https://x/report", {
    method: "POST",
    headers: { "X-TrustLens-Token": "tok" },
    body: JSON.stringify({ host }),
  });
  // Seed: host already listed by phishtank.
  store.set("host:race.example", JSON.stringify({
    sources: [{ name: "phishtank", firstSeen: 1 }], lastSeen: 1,
  }));
  const res = await worker.fetch(req("race.example"), env, {});
  expect("/report returns 200", res.status, 200);
  const body = await res.json();
  expect("/report reports=1", body.reports, 1);
  const stored = JSON.parse(store.get("host:race.example"));
  const names = (stored.sources || []).map((s) => s.name);
  expect("/report collab survives write", names.includes("collab"), true);
  expect("/report phishtank survives too", names.includes("phishtank"), true);
  expect("/report reports persisted", stored.reports, 1);

  // Three reports → collab listing lands in the score cache.
  await worker.fetch(req("race.example"), env, {});
  await worker.fetch(req("race.example"), env, {});
  const score = JSON.parse(store.get("score:race.example"));
  expect("/report 3 reports marks listed", score.listed, true);
  expect("/report listed weight boosted", score.weight, SOURCES.collab.weight + 20);
}

// --- rate limit: 30th request in a minute from one IP passes, 31st 429s ---
{
  const env = makeEnv();
  const req = () => new Request("https://x/score", {
    method: "POST",
    body: JSON.stringify({ host: "rl.example" }),
    headers: { "CF-Connecting-IP": "9.9.9.9" },
  });
  let saw429 = false;
  let lastStatus = null;
  for (let i = 0; i < 35; i++) {
    const res = await worker.fetch(req(), env, {});
    lastStatus = res.status;
    if (res.status === 429) { saw429 = true; break; }
  }
  expect("rate limit fires by 31st call", saw429, true);
  expect("rate limited status 429", lastStatus, 429);
}