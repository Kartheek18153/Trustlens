// Favicon perceptual hash. Compares the current site's favicon against
// the favicon of each brand's canonical domain.
//
// Three hashes, any pair within threshold = match:
//   - aHash: 8x8 grayscale average compare (existing, catches grayscale clones)
//   - hue:   12-bin hue histogram chi-square (catches color-shifted clones)
//   - edge:  8x8 Sobel gradient binarized (catches stylized clones)
//
// Hue and edge hash are weighted to favor strict comparison; we dark/light
// bucket to reduce false positives on legit dark-mode brand logos.

import { BRANDS } from "./brands.js";
import { getRootDomain } from "./domain.js";

const FAVICON_URLS = [
  (host) => `https://www.google.com/s2/favicons?sz=64&domain=${encodeURIComponent(host)}`,
];

const BRAND_DOMAINS = {
  google: "google.com",
  youtube: "youtube.com",
  gmail: "mail.google.com",
  facebook: "facebook.com",
  instagram: "instagram.com",
  whatsapp: "whatsapp.com",
  microsoft: "microsoft.com",
  outlook: "outlook.com",
  apple: "apple.com",
  icloud: "icloud.com",
  amazon: "amazon.com",
  netflix: "netflix.com",
  paypal: "paypal.com",
  stripe: "stripe.com",
  github: "github.com",
  twitter: "twitter.com",
  x: "x.com",
  reddit: "reddit.com",
  linkedin: "linkedin.com",
  discord: "discord.com",
  spotify: "spotify.com",
  dropbox: "dropbox.com",
  zoom: "zoom.us",
  slack: "slack.com",
  shopify: "shopify.com",
  coinbase: "coinbase.com",
  binance: "binance.com",
  wellsfargo: "wellsfargo.com",
  chase: "chase.com",
  bankofamerica: "bankofamerica.com",
};

function aHashFromImageData(imgData) {
  const w = imgData.width, h = imgData.height;
  const data = imgData.data;
  const tile = 8;
  const tw = Math.floor(w / tile);
  const th = Math.floor(h / tile);
  const grays = [];
  for (let ty = 0; ty < tile; ty++) {
    for (let tx = 0; tx < tile; tx++) {
      let sum = 0, n = 0;
      for (let y = ty * th; y < (ty + 1) * th; y += 2) {
        for (let x = tx * tw; x < (tx + 1) * tw; x += 2) {
          const i = (y * w + x) * 4;
          const g = 0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2];
          sum += g; n++;
        }
      }
      grays.push(sum / Math.max(1, n));
    }
  }
  const avg = grays.reduce((a, b) => a + b, 0) / grays.length;
  return { bits: grays.map((g) => g >= avg ? 1 : 0).join(""), avg };
}

function hueHistogram(imgData) {
  const data = imgData.data;
  const bins = new Array(12).fill(0);
  let counted = 0;
  for (let i = 0; i < data.length; i += 4) {
    const r = data[i], g = data[i + 1], b = data[i + 2];
    const max = Math.max(r, g, b);
    const min = Math.min(r, g, b);
    const d = max - min;
    if (max < 30) continue; // skip near-black (logos often have transparent bg)
    if (d < 20) continue;  // skip near-gray
    let h;
    if (max === r) h = ((g - b) / d) % 6;
    else if (max === g) h = (b - r) / d + 2;
    else h = (r - g) / d + 4;
    h = h * 60;
    if (h < 0) h += 360;
    const bin = Math.min(11, Math.floor(h / 30));
    bins[bin]++;
    counted++;
  }
  if (counted === 0) return null;
  return bins.map((b) => b / counted);
}

function chiSquare(a, b) {
  if (!a || !b || a.length !== b.length) return 1;
  let s = 0;
  for (let i = 0; i < a.length; i++) {
    const denom = a[i] + b[i];
    if (denom === 0) continue;
    s += Math.pow(a[i] - b[i], 2) / denom;
  }
  return s;
}

function edgeHash(imgData) {
  // 8x8 Sobel gradient, binarized against gradient magnitude median.
  const w = imgData.width, h = imgData.height;
  const data = imgData.data;
  function gray(x, y) {
    const i = (y * w + x) * 4;
    return 0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2];
  }
  const tile = 8;
  const tw = Math.max(1, Math.floor(w / tile));
  const th = Math.max(1, Math.floor(h / tile));
  const mags = [];
  const tiles = [];
  for (let ty = 0; ty < tile; ty++) {
    for (let tx = 0; tx < tile; tx++) {
      let sum = 0, n = 0;
      for (let y = ty * th; y < (ty + 1) * th && y < h - 1; y++) {
        for (let x = tx * tw; x < (tx + 1) * tw && x < w - 1; x++) {
          const gx = -gray(x - 1, y - 1) - 2 * gray(x - 1, y) - gray(x - 1, y + 1)
                    + gray(x + 1, y - 1) + 2 * gray(x + 1, y) + gray(x + 1, y + 1);
          const gy = -gray(x - 1, y - 1) - 2 * gray(x, y - 1) - gray(x + 1, y - 1)
                    + gray(x - 1, y + 1) + 2 * gray(x, y + 1) + gray(x + 1, y + 1);
          sum += Math.sqrt(gx * gx + gy * gy);
          n++;
        }
      }
      const mag = sum / Math.max(1, n);
      tiles.push(mag);
      mags.push(mag);
    }
  }
  const sorted = [...mags].sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)];
  return { bits: tiles.map((m) => (m >= median ? 1 : 0)).join("") };
}

function hamming(a, b) {
  let d = 0;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) d++;
  return d;
}

async function hashFavicon(host) {
  for (const make of FAVICON_URLS) {
    try {
      const res = await fetch(make(host));
      if (!res.ok) continue;
      const blob = await res.blob();
      const bmp = await createImageBitmap(blob);
      const canvas = new OffscreenCanvas(64, 64);
      const ctx = canvas.getContext("2d");
      ctx.drawImage(bmp, 0, 0, 64, 64);
      const data = ctx.getImageData(0, 0, 64, 64);
      return {
        a: aHashFromImageData(data),
        h: hueHistogram(data),
        e: edgeHash(data),
      };
    } catch (e) { /* try next */ }
  }
  return null;
}

function isDark(hash) {
  return hash && hash.a && typeof hash.a.avg === "number" && hash.a.avg < 128;
}

export async function testFaviconPhash(host, domainAgeDays) {
  const name = "Favicon Brand Match";
  const domain = getRootDomain(host);
  try {
    if (typeof domainAgeDays === "number" && domainAgeDays > 365) {
      return { name, passed: true, weight: 0, reason: `Domain is ${domainAgeDays} days old — favicon brand match skipped`, evidence: domain };
    }
    const target = await hashFavicon(domain);
    if (!target) {
      return { name, passed: true, weight: 0, reason: "No favicon to compare", evidence: domain };
    }
    const candidates = Object.entries(BRAND_DOMAINS).filter(([_, d]) => d !== domain).slice(0, 40);
    const targetDark = isDark(target);
    let closest = null;
    for (const [brand, brandDomain] of candidates) {
      const h = await hashFavicon(brandDomain);
      if (!h) continue;
      // Skip cross-bucket comparison to avoid dark/light false positives.
      if (isDark(h) !== targetDark) continue;
      const ah = hamming(target.a.bits, h.a.bits);
      const hueD = target.h && h.h ? chiSquare(target.h, h.h) : null;
      const eh = hamming(target.e.bits, h.e.bits);
      // Match rule: at least TWO of three hashes within threshold.
      // This catches recolored clones (aHash passes, hue close) and stylized
      // clones (aHash fails, edge close) without false-positiving legitimate
      // same-brand sites with minor palette tweaks.
      const close = [];
      if (ah <= 2) close.push("aHash");
      if (hueD !== null && hueD <= 0.15) close.push("hue");
      if (eh <= 3) close.push("edge");
      if (close.length >= 2) {
        return {
          name,
          passed: false,
          weight: 35,
          reason: `Favicon matches "${brand}" via ${close.join("+")} (aHash=${ah}/64, hue=${hueD?.toFixed(2) ?? "?"}, edge=${eh}/64)`,
          evidence: `${domain} ~ ${brandDomain}`,
        };
      }
      const score = ah + (hueD ?? 1) * 10 + eh;
      if (!closest || score < closest.score) closest = { brand, brandDomain, ah, hueD, eh, score };
    }
    if (closest) {
      return { name, passed: true, weight: 0, reason: `Closest: ${closest.brand} (aHash=${closest.ah}, hue=${closest.hueD?.toFixed(2) ?? "?"}, edge=${closest.eh})`, evidence: domain };
    }
    return { name, passed: true, weight: 0, reason: "No brand match", evidence: domain };
  } catch (e) {
    return { name, passed: true, weight: 0, reason: "Favicon scan failed", evidence: e.message, skipped: true };
  }
}