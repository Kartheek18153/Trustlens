// Popup controller. Pure ES module — no build step.

const els = {
  currentUrl: document.getElementById("currentUrl"),
  score: document.getElementById("score"),
  verdict: document.getElementById("verdict"),
  checkBtn: document.getElementById("checkBtn"),
  tests: document.getElementById("tests"),
  history: document.getElementById("history"),
  clearHistory: document.getElementById("clearHistory"),
};

let activeTab = { id: null, url: null, host: null };

// --- Tabs ---
document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.add("hidden"));
    document.getElementById(`tab-${btn.dataset.tab}`).classList.remove("hidden");
    if (btn.dataset.tab === "history") loadHistory();
  });
});

// --- Load active tab info ---
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const tab = tabs[0];
  if (!tab) { els.currentUrl.textContent = "No active tab"; return; }
  activeTab = { id: tab.id, url: tab.url, host: safeHost(tab.url) };
  els.currentUrl.textContent = tab.url || "(no URL)";
});

// --- Coverage pill (GSB indicator) ---
async function refreshCoverage() {
  const gsbPill = document.getElementById("covGsb");
  const backendPill = document.getElementById("covBackend");
  try {
    const { key } = await chrome.runtime.sendMessage({ type: "getGsbKey" });
    if (gsbPill) {
      gsbPill.dataset.on = key ? "true" : "false";
      gsbPill.title = key ? "GSB key configured" : "GSB skipped — set key in Help tab";
    }
  } catch (e) { /* ignore */ }
  try {
    const { url } = await chrome.runtime.sendMessage({ type: "getBackendUrl" });
    if (backendPill) {
      backendPill.dataset.on = url ? "true" : "false";
      backendPill.title = url ? `Backend: ${url}` : "Backend not configured";
    }
  } catch (e) { /* ignore */ }
}
refreshCoverage();

function safeHost(url) {
  try { return new URL(url).hostname; } catch { return ""; }
}

// --- Run check ---
els.checkBtn.addEventListener("click", async () => {
  if (!activeTab.host) return;
  els.checkBtn.disabled = true;
  els.checkBtn.textContent = "Checking…";
  els.tests.innerHTML = "";
  els.score.textContent = "…";
  els.verdict.textContent = "";
  els.verdict.className = "verdict";
  try {
    const result = await chrome.runtime.sendMessage({
      type: "scoreHost",
      host: activeTab.host,
      url: activeTab.url,
    });
    renderResult(result);
  } catch (e) {
    els.verdict.textContent = "Error: " + e.message;
    els.verdict.className = "verdict dangerous";
  } finally {
    els.checkBtn.disabled = false;
    els.checkBtn.textContent = "Check this site";
  }
});

function renderResult(result) {
  if (!result || result.error) {
    els.score.textContent = result && result.score === null ? "—" : "—";
    els.verdict.textContent = (result && result.verdict === "Skipped") ? "Skipped" : (result?.error || "Unknown error");
    els.verdict.className = "verdict caution";
    if (result && result.error) {
      const note = document.createElement("div");
      note.className = "muted";
      note.style.marginTop = "8px";
      note.textContent = "TrustLens runs only on normal websites (http/https).";
      els.tests.appendChild(note);
    }
    return;
  }
  els.score.textContent = typeof result.score === "number" ? result.score : "—";
  els.verdict.textContent = result.verdict;
  els.verdict.className = "verdict " + result.verdict.toLowerCase();
  els.tests.innerHTML = "";
  for (const t of result.tests) {
    const card = document.createElement("div");
    card.className = "test " + (t.skipped ? "skip" : t.passed ? "pass" : "fail");
    const row = document.createElement("div");
    row.className = "row";
    const left = document.createElement("div");
    left.innerHTML = `<span class="name"></span><span class="score-pill"></span>`;
    left.querySelector(".name").textContent = t.name;
    left.querySelector(".score-pill").textContent = t.skipped ? "(skipped)" : (t.passed ? "+0" : `-${t.weight}`);
    const badge = document.createElement("span");
    badge.className = "badge";
    badge.textContent = t.skipped ? "Skip" : t.passed ? "Pass" : "Fail";
    row.appendChild(left);
    row.appendChild(badge);
    const reason = document.createElement("div");
    reason.className = "reason";
    reason.textContent = t.reason;
    card.appendChild(row);
    card.appendChild(reason);
    els.tests.appendChild(card);
  }
}

// --- History ---
async function loadHistory() {
  const list = await chrome.runtime.sendMessage({ type: "getHistory" });
  els.history.innerHTML = "";
  if (!list || list.length === 0) {
    els.history.innerHTML = '<div class="muted">No checks yet.</div>';
    return;
  }
  for (const h of list) {
    const div = document.createElement("div");
    div.className = "item";
    const host = document.createElement("div");
    host.innerHTML = `<div class="host"></div><div class="when"></div>`;
    host.querySelector(".host").textContent = h.host || h.address || "(unknown)";
    host.querySelector(".when").textContent = `${h.score} · ${h.verdict || ""} · ${timeAgo(h.timestamp)}`;
    div.appendChild(host);
    els.history.appendChild(div);
  }
}

function timeAgo(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return s + "s ago";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
}

els.clearHistory.addEventListener("click", async () => {
  await chrome.runtime.sendMessage({ type: "clearHistory" });
  loadHistory();
});

// --- GSB key ---
const gsbInput = document.getElementById("gsbKey");
const gsbSave = document.getElementById("saveGsbKey");
const gsbStatus = document.getElementById("gsbStatus");

(async () => {
  try {
    const resp = await chrome.runtime.sendMessage({ type: "getGsbKey" });
    const key = resp && resp.key ? resp.key : "";
    gsbInput.value = key;
    gsbStatus.textContent = key ? "Key saved locally — never sent except to Google." : "No key set — Safe Browsing check will be skipped.";
  } catch (e) {
    gsbStatus.textContent = `Load failed: ${e.message}`;
  }
})();

gsbSave.addEventListener("click", async () => {
  const v = gsbInput.value.trim();
  try {
    const resp = await chrome.runtime.sendMessage({ type: "saveGsbKey", key: v });
    if (!resp || !resp.ok) {
      gsbStatus.textContent = `Save failed: ${JSON.stringify(resp)}`;
      return;
    }
    const verify = await chrome.runtime.sendMessage({ type: "getGsbKey" });
    const stored = verify && verify.key ? "set" : "";
    gsbStatus.textContent = stored ? "Key saved." : "Save returned OK but readback empty.";
    refreshCoverage();
  } catch (e) {
    gsbStatus.textContent = `Save error: ${e.message}`;
  }
});

// --- ipinfo token ---
const ipinfoInput = document.getElementById("ipinfoToken");
const ipinfoSave = document.getElementById("saveIpinfoToken");
const ipinfoStatus = document.getElementById("ipinfoStatus");

(async () => {
  const { token } = await chrome.runtime.sendMessage({ type: "getIpinfoToken" });
  ipinfoInput.value = token || "";
  ipinfoStatus.textContent = token ? "Token saved locally." : "No token — using free tier (50k/mo).";
})();

ipinfoSave.addEventListener("click", async () => {
  const v = ipinfoInput.value.trim();
  await chrome.runtime.sendMessage({ type: "saveIpinfoToken", token: v });
  ipinfoStatus.textContent = v ? "Token saved." : "Token cleared.";
});

// --- Backend URL ---
const backendUrlInput = document.getElementById("backendUrl");
const backendUrlSave = document.getElementById("saveBackendUrl");
const backendUrlStatus = document.getElementById("backendStatus");

(async () => {
  try {
    const resp = await chrome.runtime.sendMessage({ type: "getBackendUrl" });
    const url = resp && resp.url ? resp.url : "";
    backendUrlInput.value = url;
    backendUrlStatus.textContent = url ? `Backend configured: ${url}` : "No backend — accuracy capped at ~88% on validated phishing.";
  } catch (e) {
    backendUrlStatus.textContent = `Load failed: ${e.message}`;
  }
})();

backendUrlSave.addEventListener("click", async () => {
  const v = backendUrlInput.value.trim();
  try {
    const resp = await chrome.runtime.sendMessage({ type: "saveBackendUrl", url: v });
    if (!resp || !resp.ok) {
      backendUrlStatus.textContent = `Save failed: ${JSON.stringify(resp)}`;
      return;
    }
    const verify = await chrome.runtime.sendMessage({ type: "getBackendUrl" });
    const stored = verify && verify.url ? verify.url : "";
    backendUrlStatus.textContent = stored ? `Saved: ${stored}` : "Saved empty.";
    refreshCoverage();
  } catch (e) {
    backendUrlStatus.textContent = `Save error: ${e.message}`;
  }
});

// --- Report token ---
const reportTokenInput = document.getElementById("reportToken");
const reportTokenSave = document.getElementById("saveReportToken");
const reportTokenStatus = document.getElementById("reportStatus");

(async () => {
  const { token } = await chrome.runtime.sendMessage({ type: "getReportToken" });
  reportTokenInput.value = token || "";
  reportTokenStatus.textContent = token ? "Report token saved." : "No report token — collab reporting disabled.";
})();

reportTokenSave.addEventListener("click", async () => {
  const v = reportTokenInput.value.trim();
  await chrome.runtime.sendMessage({ type: "saveReportToken", token: v });
  reportTokenStatus.textContent = v ? "Token saved." : "Token cleared.";
});
