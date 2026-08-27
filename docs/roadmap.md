# Roadmap

## Current release status

The `v0.1.0` sandbox release completes the executable semantics and local
single-tenant gateway slices, and implements selected ecosystem features such as
MCP enforcement, RFC 8693 token exchange, OPA boundaries, DPoP hooks, and
mechanically attenuated delegation. Its providers and payment API remain local
sandboxes.

The v0.2 implementation candidate now contains the narrow GitHub issue profile,
persisted approval flow, product-only MCP/REST listener, safe multi-client CLI,
Compose profile, and receipt-verifying live proof runner. The next milestone is
to execute that candidate against a real provider-owned sandbox and produce
candidate-bound interoperability, performance, outage, and security evidence.
None of this changes the frozen `am.action.v1` contract silently.

## Phase 0 — semantics (implemented)

- Executable mandate model with task/audience/action/resource binding
- Deterministic equality, numeric ceiling, expiry, approval, use-limit, revocation, and audit behavior
- Threat model and standards mapping

Exit: contributors can debate a running contract instead of a slide deck.

## Phase 1 — usable local gateway (core local slice implemented)

- Implemented: PostgreSQL storage with atomic consumption and tenant isolation.
- Implemented: canonical, versioned action envelopes and idempotent execution
  receipts.
- Implemented: OIDC principal authentication and a separate workload identity
  adapter.
- Implemented: deterministic local constraints and an optional fail-closed OPA
  data adapter.
- Implemented: HTTP and MCP enforcement points, OpenAPI, Docker Compose, and
  telemetry/redaction defaults.
- Implemented in the v0.2 candidate: a real GitHub App issue provider with
  one-repository credential attenuation and bounded reconciliation.
- Remaining: Cedar, reverse-proxy, and TypeScript SDK adapters.

Remaining exit work: validate the exact candidate in a real GitHub
provider-owned sandbox without exposing its credential to the agent.

## Phase 2 — agent ecosystem adapters (partially implemented)

- Implemented: typed MCP middleware on the shared execution path with exact
  step-up approval.
- Implemented: generic HTTP execution, RFC 8707 audience binding, RFC 8693
  token exchange, a DPoP proof hook, and mechanically attenuated parent/child
  delegation.
- Implemented in the v0.2 candidate: four narrow first-party MCP tools, remote
  HTTP and stdio transports, OAuth protected-resource metadata, and safe
  installers for Codex, Claude Code, Cursor, VS Code, and Gemini CLI.
- Remaining: direct LangGraph and OpenAI Agents SDK adapters, an RFC 9396
  authorization-detail profile, and mTLS support.

Remaining exit work: two independent integrations and a public
interop/conformance suite.

## Phase 3 — enterprise hardening

- HA control plane and regional data plane
- KMS-backed signing, rotation, revocation propagation, WORM audit export
- SCIM/admin/RBAC, policy bundles, break-glass workflow, SIEM integrations
- Formal schema and policy-invariant testing; external security audit

Exit: production pilots with measured credential-exposure reduction and incident reconstruction.

## Open-source traction strategy

The hero demo should show a prompt-injected coding agent trying to delete a repository after being approved only to open one issue. The request is visibly denied, while the approved issue creation succeeds once and produces a receipt. Ship this as a copy-paste Docker Compose example, then publish adapters and conformance tests. The durable moat is ecosystem compatibility and high-quality authorization semantics, not a proprietary proxy.
