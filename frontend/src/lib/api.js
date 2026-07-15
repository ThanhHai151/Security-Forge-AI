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
// X-SecForge-Client is a non-simple header the backend requires on state-changing requests: a
// cross-origin drive-by page cannot set it without a CORS preflight it will fail, so it blocks
// CSRF against the local control plane (see backend/app.py _csrf_ok).
const send = (method, p, body) =>
  fetch(`${BASE}${p}`, {
    method,
    headers: { "Content-Type": "application/json", "X-SecForge-Client": "secforge-console" },
    body: body === undefined ? undefined : JSON.stringify(body),
  }).then(jsonOrThrow);

// ── Runs (the agent loop) ──
export const startRun = (body) => send("POST", "/runs", body);
export const getRun = (id) => get(`/runs/${encodeURIComponent(id)}`);
export const listRuns = () => get("/runs"); // -> { runs: [{id, goal, target, backend, outcome, turns}] }
export const stopRun = (id) => send("POST", `/runs/${encodeURIComponent(id)}/stop`); // -> {ok}

// ── Campaigns (the continuous "infinite" engagement) ──
export const startCampaign = (body) => send("POST", "/campaigns", body); // {domain, backend?, ...}
// One-shot autonomous pentest: just an address. Autopilot is forced on server-side, so the run
// drives every phase itself to a stop state. -> { id } (poll with getCampaign).
export const startPentest = (body) => send("POST", "/pentest", body); // {target|domain, backend?, ...}
export const listCampaigns = () => get("/campaigns");
export const getCampaign = (id) => get(`/campaigns/${encodeURIComponent(id)}`);
const campaignAction = (id, action, body) =>
  send("POST", `/campaigns/${encodeURIComponent(id)}/${action}`, body);
export const continueCampaign = (id) => campaignAction(id, "continue");
export const stopCampaign = (id) => campaignAction(id, "stop");
export const approveAction = (id, approvalId) =>
  campaignAction(id, "approve", { approval_id: approvalId });
export const rejectAction = (id, approvalId) =>
  campaignAction(id, "reject", { approval_id: approvalId });

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
export const testConnection = (body) => send("POST", "/test-connection", body); // {base_url, api_key?, model?, api_style?}
export const testAccount = (id) => send("POST", `/accounts/${encodeURIComponent(id)}/test`);

// ── Settings menu: quota tracker, models overview, import/export ──
// Per-account usage + daily limits + live health. -> { accounts: [{id,label,limits,total,today,health}] }
export const getUsage = () => get("/usage");
// Clear recorded usage for one account, or the whole pool when no id is given.
export const resetUsage = (accountId) =>
  send("POST", "/usage/reset", accountId ? { account_id: accountId } : {});
// Pool-wide model overview (network-free). -> { accounts:[...], catalog:[{provider,label,models}] }
export const getModelsOverview = () => get("/models");
// Backup excludes secrets. Credentials remain encrypted locally and are never exported.
export const exportAccounts = () => get("/accounts/export");
// Restore: add accounts from an uploaded export. mode: "merge" (dedupe) | "replace" (clear first).
export const importAccounts = (accounts, mode = "merge") =>
  send("POST", "/accounts/import", { accounts, mode });

// ── OAuth sign-in flows (device-code + browser PKCE) ──
export const getOAuthProviders = () => get("/oauth/providers"); // -> { id: {flow, supported, reason} }
export const oauthStart = (provider, model = "") => send("POST", "/oauth/start", { provider, model });
// device: -> {status:"pending"} | {status:"done", account}; pass a label to name the connection.
export const oauthPoll = (session_id, label = "") => send("POST", "/oauth/poll", { session_id, label });
export const oauthComplete = (session_id, code, label = "") =>
  send("POST", "/oauth/complete", { session_id, code, label });

// ── Memory (Hermes) ──
export const getMemory = (target = "") =>
  get(`/memory${target ? `?target=${encodeURIComponent(target)}` : ""}`);

// ── Expert Supervisor + Hermes notebook (the default advisory flow) ──
// Never calls an AI provider and never touches the target itself — it hands a ranked
// strategy + skill(s) to whichever coding agent (e.g. Claude Code) the operator drives.
// -> { domain, archetype, plan, skills, questions, harness, context_block }
export const advise = ({
  domain,
  question,
  mode = "blackbox",
  projectPath,
  scanMode = "standard",
  vendor = "generic",
  rulesOfEngagement,
} = {}) =>
  send("POST", "/supervisor/advise", {
    domain,
    question,
    mode,
    project_path: projectPath || undefined,
    scan_mode: scanMode,
    vendor,
    rules_of_engagement: rulesOfEngagement,
  });
// Shared category -> technique tree (the same vocabulary the notebook and skills use).
export const getTaxonomy = () => get("/taxonomy"); // -> { tree: [{id, label, children}] }
export const getArchetypes = () => get("/archetypes"); // -> { archetypes: [...] }
export const listNotebooks = () => get("/notebooks"); // -> { notebooks: [{domain, parent_domain, archetype, confirmed, total, updated_at}] }
// Nested root domain -> discovered-subdomain tree, for the sidebar.
export const getNotebookTreeRoots = () => get("/notebooks/tree"); // -> { roots: [{domain, confirmed, total, children: [...]}] }
export const getNotebook = (domain) => get(`/notebook/${encodeURIComponent(domain)}`);
// Taxonomy tree merged with this domain's per-node confirmed/unconfirmed/untested status
// (plus in_progress/justification, and a synthetic "others" category for custom findings).
export const getNotebookTree = (domain) => get(`/notebook/${encodeURIComponent(domain)}/tree`);
// SARIF 2.1.0 export of a domain's confirmed/unconfirmed findings, for CI code-scanning upload.
export const notebookSarif = (domain) => get(`/notebook/${encodeURIComponent(domain)}/sarif`);
export const updateNotebookNode = (domain, nodeId, status, extra = {}) =>
  send("PATCH", `/notebook/${encodeURIComponent(domain)}`, { node_id: nodeId, status, ...extra });
// Manually flag a node as "being tested right now" (normally set automatically by advise()).
export const markNotebookInProgress = (domain, nodeId) =>
  send("PATCH", `/notebook/${encodeURIComponent(domain)}`, { node_id: nodeId, in_progress: true });
export const setNotebookArchetype = (domain, archetype) =>
  send("PATCH", `/notebook/${encodeURIComponent(domain)}/archetype`, { archetype });
// Paste an external coding agent's raw output; stored verbatim, then parsed for CONFIRMED /
// NEW_FINDING_TYPE markers (falls back to a keyword match if no markers are present).
export const ingestNotebookOutput = (domain, text) =>
  send("POST", `/notebook/${encodeURIComponent(domain)}/ingest`, { text });
// Attach a discovered subdomain under its parent in the sidebar tree.
export const addNotebookChild = (domain, child) =>
  send("POST", `/notebook/${encodeURIComponent(domain)}/children`, { child });
// Permanently remove a domain's notebook. Does not cascade — any of its subdomains simply
// resurface as their own root in the sidebar tree (see NotebookStore.delete).
export const deleteNotebookDomain = (domain) => send("DELETE", `/notebook/${encodeURIComponent(domain)}`);
// Record a manually-noted exploit-chain step from one node to another, for the mind-map.
export const addNotebookChain = (domain, fromNode, toNode, note = "") =>
  send("POST", `/notebook/${encodeURIComponent(domain)}/chains`, {
    from_node: fromNode,
    to_node: toNode,
    note,
  });

// ── Vuln search (catalog + opt-in CVE lookup) ──
export const vulnSearch = (q, { online = false, locale = "en" } = {}) =>
  get(`/vuln-search?q=${encodeURIComponent(q)}&online=${online ? 1 : 0}&locale=${locale}`);

// ── Defense (codebase review) ──
export const reviewDefense = (path) => send("POST", "/defense/review", { path });
// Combined assessment: code signatures + dependency (SCA) inventory, plus an optional live attack
// of the running app when `serve_url` is set. -> { code_review, dependencies, campaign_id }
export const scanDefense = (body) => send("POST", "/defense/scan", body); // {path, deps_online?, serve_url?}
