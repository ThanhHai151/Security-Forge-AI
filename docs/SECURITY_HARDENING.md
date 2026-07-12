# SecForge Security Hardening

## Safe operating defaults

SecForge is an authorized-assessment control plane. Its autonomous engine is disabled by default
and, when explicitly enabled, requires an active Rules of Engagement (RoE) unless an offline test
environment deliberately sets `SECFORGE_REQUIRE_ROE=0`.

- The API binds to `127.0.0.1` by default. A non-loopback bind refuses to start unless
  `SECFORGE_API_TOKEN` is configured.
- Requests to a token-protected API require `Authorization: Bearer <token>`.
- Do not put that bearer token in the static frontend. A remote UI must sit behind an
  authentication-aware TLS reverse proxy (or use a dedicated authenticated client).
- Loopback mode rejects hostile Host and cross-origin headers to reduce accidental exposure and
  DNS-rebinding risk.
- Provider secrets are encrypted in the local account store. Set `SECFORGE_MASTER_KEY` from a
  secret manager for managed deployments; otherwise a local mode-0600 key is generated.
- Account export never returns raw provider credentials.

## Tool execution

External scanners and Playwright are not safe to execute directly on an operator workstation.
SecForge therefore blocks host execution by default.

Provide a `ToolContext.runner` or `ToolContext.renderer` backed by a disposable worker with:

- a non-root user, read-only root filesystem, memory/PID/CPU limits, and no ambient credentials;
- a workspace mount restricted to engagement artifacts;
- an egress proxy that enforces the RoE destination set after DNS resolution;
- pinned tool/image versions and an auditable image digest.

`SECFORGE_ALLOW_HOST_TOOLS=1` and `SECFORGE_ALLOW_HOST_BROWSER=1` are development-only escape
hatches. Do not set them for client engagements.

## Evidence and data handling

Run transcripts, findings, memory, campaigns, assets, and external-agent logs pass through
deterministic credential redaction before persistence. Tool results are also written to a
mode-0600, SHA-256 hash-chained evidence ledger. Check integrity through:

```text
GET /api/evidence/verify
```

The ledger is tamper-evident, not a replacement for a centralized immutable evidence store.
Production use still needs encrypted backups, retention/deletion policy, access controls, and
external audit retention.

## Remaining boundary

The RoE currently controls application-level tool calls and pacing. It cannot by itself control
the internal concurrency, redirects, callbacks, or DNS behavior of third-party binaries. That is
why the mandatory next deployment step is an isolated worker plus a policy-enforcing egress proxy.
