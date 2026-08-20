# Roadmap

## Phase 0 — semantics (current)

- Executable mandate model with task/audience/action/resource binding
- Deterministic equality, numeric ceiling, expiry, approval, use-limit, revocation, and audit behavior
- Threat model and standards mapping

Exit: contributors can debate a running contract instead of a slide deck.

## Phase 1 — usable local gateway

- PostgreSQL storage with atomic consumption and tenant isolation
- Signed, versioned action envelopes and idempotent execution receipts
- OIDC principal authentication and workload identity adapter
- Cedar and OPA policy adapters; no home-grown policy language
- Reverse-proxy and TypeScript SDK enforcement points
- OpenAPI contract, Docker Compose demo, telemetry/redaction defaults

Exit: secure a real GitHub or cloud read/write workflow without exposing its credential to the agent.

## Phase 2 — agent ecosystem adapters

- MCP middleware with per-tool action schemas and step-up approval
- LangGraph, OpenAI Agents SDK, and generic HTTP adapters
- OAuth protected-resource metadata, RFC 8707 audience binding, RFC 8693 token exchange, and RFC 9396 authorization-detail profile
- DPoP/mTLS proof-of-possession option
- Parent/child delegation with mechanically tested attenuation

Exit: two independent integrations and a public interop/conformance suite.

## Phase 3 — enterprise hardening

- HA control plane and regional data plane
- KMS-backed signing, rotation, revocation propagation, WORM audit export
- SCIM/admin/RBAC, policy bundles, break-glass workflow, SIEM integrations
- Formal schema and policy-invariant testing; external security audit

Exit: production pilots with measured credential-exposure reduction and incident reconstruction.

## Open-source traction strategy

The hero demo should show a prompt-injected coding agent trying to delete a repository after being approved only to open one issue. The request is visibly denied, while the approved issue creation succeeds once and produces a receipt. Ship this as a copy-paste Docker Compose example, then publish adapters and conformance tests. The durable moat is ecosystem compatibility and high-quality authorization semantics, not a proprietary proxy.
