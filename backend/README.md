# `backend/` — HTTP API & Orchestration

The server that ties everything together. It serves the [`frontend/`](../frontend/README.md),
exposes each pillar over a JSON API, and owns cross-cutting concerns (config, the KB index
lifecycle, language selection).

## Responsibilities

- **Serve the console** and static assets.
- **Expose the pillars** as API endpoints:
  - Knowledge Base — list categories, fetch a rendered document, search.
  - Vuln Search — query techniques + trigger CVE lookups.
  - Agent — start a run, stream steps, submit step logs back for next-step planning.
  - Defense — submit a target web project, return findings + hardening.
  - Labs — list/launch/reset sandboxed targets (proxied to the labs host).
- **Hold configuration** — the single source of truth for the knowledge-base root path,
  ports, the selected model backend, and feature flags.
- **Apply localization** — resolve the requested language for both UI strings and content.

## Planned contents

- An HTTP server entry point.
- An `api/` area with one route module per pillar.
- A small `core/` area for shared services (config loader, KB index lifecycle).

## Connects to

- Up to [`../frontend/`](../frontend/README.md) over HTTP/JSON.
- Down to every pillar: [`knowledge_base`](../knowledge_base/README.md),
  [`ai_framework`](../ai_framework/README.md), [`vuln_search`](../vuln_search/README.md),
  [`defense`](../defense/README.md), [`labs`](../labs/README.md).
- [`../i18n/`](../i18n/README.md) for language resolution.

## Design notes

- Prefer the Python standard library so it runs with zero install friction (matches the
  repo's existing scripts and `.venv`). Optional extras stay optional.
- The labs host runs as a **separate** server on its own localhost port; the backend only
  proxies/links to it, keeping intentionally vulnerable code isolated from the console.
- No secrets in code — the model API key is read from an environment variable.

**Status:** skeleton — directory purpose only.
