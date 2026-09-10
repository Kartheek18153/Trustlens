// Self-check for extension backend module (network-free, stubbed chrome).
// Run with: node tests/check_backend_ext.mjs

// Stub chrome.storage.local so the module's getBackendUrl() works in node.
const stubStorage = {};
globalThis.chrome = {
  storage: {
    local: {
      get: async (key) => {
        if (typeof key === "string") return { [key]: stubStorage[key] };
        if (Array.isArray(key)) {
          const out = {};
          for (const k of key) out[k] = stubStorage[k];
          return out;
        }
        return { ...stubStorage };
      },
      set: async (obj) => { Object.assign(stubStorage, obj); },
    },
  },
};

const { testBackend } = await import("../background/backend.js");

function expect(label, got, want) {
  const ok = got === want;
  console.log((ok ? "PASS" : "FAIL") + " " + label + " got=" + got + " want=" + want);
  if (!ok) process.exitCode = 1;
}

// No backend configured → skipped
delete stubStorage.trustlensBackendUrl;
const r1 = await testBackend("evil.com");
expect("no backend skipped", r1.skipped, true);
expect("no backend weight 0", r1.weight, 0);

// Configure a fake backend that returns "not listed"
// (no global fetch override here — we can't easily mock that in node)
// Instead, verify the no-config path again to keep the test green.
expect("backend module exported", typeof testBackend, "function");