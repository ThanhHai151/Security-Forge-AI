/**
 * Thin fetch wrappers for the SecForge backend (Hermes agent + native AI router). All calls go
 * through the Vite dev proxy: `/api/*` → the Python backend's `/*` (see vite.config.js), so the
 * frontend never hard-codes the backend host/port.
 */
const BASE = "/api";

async function jsonOrThrow(res) {
  if (!res.ok) {
    let detail;
    try {
      detail = (await res.json())?.error;
    } catch {
      /* non-JSON error body */
    }
    throw new Error(detail || `HTTP ${res.status}`);
  }
  return res.json();
}

const get = (p) => fetch(`${BASE}${p}`).then(jsonOrThrow);
const send = (method, p, body) =>
  fetch(`${BASE}${p}`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  }).then(jsonOrThrow);

// ── Runs (the agent loop) ──
export const startRun = (body) => send("POST", "/runs", body);
export const getRun = (id) => get(`/runs/${encodeURIComponent(id)}`);

// ── AI router: accounts + rotation policy ──
export const getProviderTypes = () => get("/provider-types");
export const getAccounts = () => get("/accounts"); // -> { policy, accounts: [...] }
export const addAccount = (body) => send("POST", "/accounts", body);
export const updateAccount = (id, body) => send("PATCH", `/accounts/${encodeURIComponent(id)}`, body);
export const deleteAccount = (id) => send("DELETE", `/accounts/${encodeURIComponent(id)}`);
export const getAccountModels = (id) => get(`/accounts/${encodeURIComponent(id)}/models`);
export const probeModels = (body) => send("POST", "/probe-models", body); // {base_url, api_key?}
export const setPolicy = (policy) => send("POST", "/router/policy", { policy });

// Live connection tests -> { ok, status, error? }
export const testConnection = (body) => send("POST", "/test-connection", body); // {base_url, api_key?, model?}
export const testAccount = (id) => send("POST", `/accounts/${encodeURIComponent(id)}/test`);

// ── Memory (Hermes) ──
export const getMemory = (target = "") =>
  get(`/memory${target ? `?target=${encodeURIComponent(target)}` : ""}`);

// ── Vuln search (catalog + opt-in CVE lookup) ──
export const vulnSearch = (q, { online = false, locale = "en" } = {}) =>
  get(`/vuln-search?q=${encodeURIComponent(q)}&online=${online ? 1 : 0}&locale=${locale}`);

// ── Defense (codebase review) ──
export const reviewDefense = (path) => send("POST", "/defense/review", { path });

// ── Labs (sandboxed practice targets; metadata only) ──
export const getLabs = () => get("/labs");
