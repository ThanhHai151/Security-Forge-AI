# `ai_framework/tools/` — Runnable Action Catalog

The agent's hands. A categorised catalog of tools the [`agent`](../agent/README.md) can
invoke, each with a clear name, description, and typed inputs — so a run can be gated,
logged, and reasoned about.

## Tool categories (planned)

- **recon** — fingerprinting, endpoint mapping, header inspection.
- **http** — send crafted requests, compare responses, follow redirects.
- **injection** — helpers for SQLi / XSS / SSTI / command-injection probing.
- **auth** — token/cookie inspection, brute-force helpers (rate-limited).
- **decode/encode** — the obfuscation/encoding helpers the KB already documents.

(These mirror the repo's existing helper scripts so they can be adopted directly.)

## What each tool defines

- `name`, human-readable `description`.
- A JSON-schema for its inputs (so the model calls it correctly and the backend can
  validate).
- A `run(input)` contract that returns a structured result + the **logs** the
  [`agent`](../agent/README.md) feeds into its log-driven planner.

## Connects to

- [`../agent/`](../agent/README.md) — invokes tools and reads their logs.
- [`../skills/`](../skills/README.md) — skills recommend which tools to use.

## Safety

- Safe-by-default; destructive or noisy actions require explicit confirmation.
- Any tool that hits a real target must require the target to be authorized first.

## Inspired by

Z4nzu / **hackingtool** — a menu/catalog of security tools organized by category.

Every network tool declares two flags the loop reads: `touches_network` (so `opsec.py` paces
it) and `mutating` (so `guardrails.py` gives state-changing calls a tighter leash). All network
tools pass through `base.require_authorized` — the single scope choke point.

**Status:** implemented — `base.py` (`Tool`, `ToolRegistry`, `require_authorized` gate),
`builtin.py` (`http_get`, `note_finding` with severity/evidence), and `security.py` (recon &
transform catalog: `http_request`, `inspect_headers`, `fetch_robots_sitemap`, `decode_encode`).
Add more tools by dropping a class in `security.py` and registering it in `default_registry`.
