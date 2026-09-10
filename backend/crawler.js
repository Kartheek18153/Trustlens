#!/usr/bin/env node
// TrustLens crawler. Pulls from public phishing feeds and POSTs to the
// backend's /ingest endpoint. Runs as a cron job (every 30 min) or on demand.
//
// Sources:
//   - PhishTank verified (data.phishtank.com/data/online-valid.json)
//   - URLhaus recent (urlhaus-api.abuse.ch/v1/urls/recent/)
//   - OpenPhish feed (openphish.com/feed.txt)
//   - ThreatFox (threatfox.abuse.ch/api/v1/)
//   - Spamhaus DBL zone (not directly accessible; we proxy via a daily
//     aggregator or skip if unavailable)
//
// Usage:
//   INGEST_TOKEN=xxx BACKEND_URL=https://trustlens-backend.example.workers.dev \
//     node crawler.js [--source=phishtank,urlhaus,...]
//
// Env:
//   BACKEND_URL   — required, e.g. https://trustlens-backend.example.workers.dev
//   INGEST_TOKEN  — required, must match wrangler secret INGEST_TOKEN
//   CRAWL_SOURCES — optional comma-list override

import https from "node:https";
import http from "node:http";
import { URL } from "node:url";
import zlib from "node:zlib";

const BACKEND_URL = process.env.BACKEND_URL || "";
const INGEST_TOKEN = process.env.INGEST_TOKEN || "";
const SOURCES = (process.argv.find((a) => a.startsWith("--source="))?.split("=")[1] ||
  process.env.CRAWL_SOURCES ||
  "phishtank,urlhaus,openphish,threatfox").split(",").map((s) => s.trim()).filter(Boolean);

if (!BACKEND_URL || !INGEST_TOKEN) {
  console.error("BACKEND_URL and INGEST_TOKEN required");
  process.exit(1);
}

// Native fetch (undici) — handles PhishTank's short-lived signed CDN redirect
// in one shot; the hand-rolled https.get re-request tripped 403/404 on the
// already-expired signature.
async function fetchText(url, timeoutMs = 30000) {
  const controller = new AbortController();
  const tid = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      headers: { "User-Agent": "TrustLens-Crawler/0.1" },
      signal: controller.signal,
      redirect: "follow",
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
    return await res.text();
  } finally {
    clearTimeout(tid);
  }
}

function postJSON(url, body, token) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const data = Buffer.from(JSON.stringify(body), "utf8");
    const lib = u.protocol === "https:" ? https : http;
    const req = lib.request({
      hostname: u.hostname,
      port: u.port || (u.protocol === "https:" ? 443 : 80),
      path: u.pathname + u.search,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": data.length,
        "X-TrustLens-Token": token,
      },
      timeout: 30000,
    }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        if (res.statusCode !== 200) {
          return reject(new Error(`HTTP ${res.statusCode}: ${text}`));
        }
        try { resolve(JSON.parse(text)); } catch (e) { reject(new Error("invalid JSON: " + text.slice(0, 100))); }
      });
    });
    req.on("error", reject);
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.write(data);
    req.end();
  });
}

function rootDomainOf(host) {
  if (!host) return "";
  const h = host.toLowerCase().replace(/^www\./, "");
  const parts = h.split(".").filter(Boolean);
  if (parts.length <= 2) return h;
  const twoPart = new Set([
    "co.uk", "co.in", "co.jp", "co.kr", "co.nz", "co.za",
    "com.au", "com.br", "com.cn", "com.mx", "com.tr", "com.tw",
    "org.uk", "net.au", "ac.uk",
  ]);
  const last2 = parts.slice(-2).join(".");
  if (twoPart.has(last2)) return parts.slice(-3).join(".");
  return parts.slice(-2).join(".");
}

function hostFromUrl(u) {
  try { return new URL(u).hostname.toLowerCase().replace(/^www\./, ""); }
  catch { return ""; }
}

// --- Source parsers. Each returns [{host, firstSeen}] ---

async function fetchPhishtank() {
  console.log("[phishtank] fetching online-valid.json.gz...");
  // ponytail: the .json dump 404s on their CDN (serves a JPEG with a 404
  // status); the .gz dump is the working endpoint as of 2026-09.
  const res = await fetch("https://data.phishtank.com/data/online-valid.json.gz");
  if (!res.ok) throw new Error(`phishtank dump HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  if (!(buf[0] === 0x1f && buf[1] === 0x8b)) throw new Error("phishtank: not gzip");
  const text = zlib.gunzipSync(buf).toString("utf8");
  let arr;
  try { arr = JSON.parse(text); } catch (e) { throw new Error("phishtank parse: " + e.message); }
  if (!Array.isArray(arr)) throw new Error("phishtank: not an array");
  const seen = new Map();
  for (const entry of arr) {
    if (!entry || typeof entry.url !== "string") continue;
    const h = hostFromUrl(entry.url);
    const root = rootDomainOf(h);
    if (!root || seen.has(root)) continue;
    const ts = entry.submission_time ? Date.parse(entry.submission_time) : Date.now();
    seen.set(root, ts);
  }
  console.log(`[phishtank] ${seen.size} unique root domains`);
  return { source: "phishtank", entries: [...seen.entries()].map(([host, firstSeen]) => ({ host, firstSeen })) };
}

async function fetchUrlhaus() {
  console.log("[urlhaus] fetching text_recent...");
  // ponytail: urlhaus-api.abuse.ch/v1/urls/recent/ started 401ing without an
  // Auth-Key; the plaintext dump works keyless. Switch to
  // urlhaus.abuse.ch/downloads/text_recent if the API is needed again.
  const text = await fetchText("https://urlhaus.abuse.ch/downloads/text_recent/");
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const seen = new Map();
  for (const line of lines) {
    if (!line || line.startsWith("#")) continue;
    const h = hostFromUrl(line);
    const root = rootDomainOf(h);
    if (!root || seen.has(root)) continue;
    seen.set(root, Date.now());
  }
  console.log(`[urlhaus] ${seen.size} unique root domains`);
  return { source: "urlhaus", entries: [...seen.entries()].map(([host, firstSeen]) => ({ host, firstSeen })) };
}

async function fetchOpenphish() {
  console.log("[openphish] fetching feed.txt...");
  const text = await fetchText("https://www.openphish.com/feed.txt");
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const seen = new Map();
  for (const line of lines) {
    const h = hostFromUrl(line);
    const root = rootDomainOf(h);
    if (!root || seen.has(root)) continue;
    seen.set(root, Date.now());
  }
  console.log(`[openphish] ${seen.size} unique root domains`);
  return { source: "openphish", entries: [...seen.entries()].map(([host, firstSeen]) => ({ host, firstSeen })) };
}

async function fetchThreatfox() {
  console.log("[threatfox] fetching recent...");
  // ThreatFox returns a CSV-style text body when querying recent payloads.
  const text = await fetchText("https://threatfox.abuse.ch/export/csv/recent/");
  const lines = text.split(/\r?\n/);
  const seen = new Map();
  for (const line of lines) {
    if (!line || line.startsWith("#")) continue;
    const cols = line.split(",");
    if (cols.length < 5) continue;
    const ioc = cols[5]; // ioc value column
    const ts = cols[1] ? Date.parse(cols[1]) : Date.now();
    if (!ioc || !ioc.startsWith("http")) continue;
    const h = hostFromUrl(ioc);
    const root = rootDomainOf(h);
    if (!root || seen.has(root)) continue;
    seen.set(root, isNaN(ts) ? Date.now() : ts);
  }
  console.log(`[threatfox] ${seen.size} unique root domains`);
  return { source: "threatfox", entries: [...seen.entries()].map(([host, firstSeen]) => ({ host, firstSeen })) };
}

const FETCHERS = {
  phishtank: fetchPhishtank,
  urlhaus: fetchUrlhaus,
  openphish: fetchOpenphish,
  threatfox: fetchThreatfox,
};

async function ingestBatch(entries) {
  // Worker expects {entries:[{host, source, firstSeen}]}. Post in chunks of
  // 200 with a pause between posts — one 14k-entry PhishTank dump both
  // exceeds the request-size limit and, posted back-to-back, trips the
  // Worker free-tier subrequest/conn limits (503 error 1102).
  const CHUNK = 200;
  const PAUSE_MS = 350;
  let written = 0;
  let skipped = 0;
  for (let i = 0; i < entries.length; i += CHUNK) {
    const chunk = entries.slice(i, i + CHUNK).map((e) => ({
      host: e.host,
      source: e.source,
      firstSeen: e.firstSeen,
    }));
    let result;
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        result = await postJSON(`${BACKEND_URL}/ingest`, { entries: chunk }, INGEST_TOKEN);
        break;
      } catch (e) {
        if (attempt === 3) throw e;
        await new Promise((r) => setTimeout(r, 1000 * attempt)); // backoff and retry
      }
    }
    written += (result && result.written) || 0;
    skipped += (result && result.skipped) || 0;
    await new Promise((r) => setTimeout(r, PAUSE_MS));
  }
  return { written, skipped };
}

async function main() {
  let totalWritten = 0;
  for (const src of SOURCES) {
    const fetcher = FETCHERS[src];
    if (!fetcher) {
      console.warn(`unknown source: ${src}`);
      continue;
    }
    try {
      const batch = await fetcher();
      const tagged = batch.entries.map((e) => ({ ...e, source: batch.source }));
      const result = await ingestBatch(tagged);
      console.log(`[${src}] ingest result: ${JSON.stringify(result)}`);
      totalWritten += (result && result.written) || 0;
    } catch (e) {
      console.error(`[${src}] failed: ${e.message}`);
    }
  }
  console.log(`crawl done. total written: ${totalWritten}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});