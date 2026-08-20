# Architecture

## Components

- **Identity adapters:** validate user OIDC identity, OAuth client identity, cloud workload identity, or SPIFFE SVID. Identity is evidence, not authority.
- **Mandate service:** validates requested delegation, records approval, issues a short-lived opaque or proof-of-possession-bound grant, and manages revocation/consumption.
- **Policy decision point:** evaluates principal, agent, task, action, resource, environment, and mandate constraints. Begin with Cedar or OPA adapters.
- **Policy enforcement point:** SDK, reverse proxy, sidecar, MCP middleware, or API gateway hook that canonicalizes an attempted action and blocks it before side effects.
- **Credential broker:** obtains a separate downstream token via OAuth token exchange, workload federation, or vault dynamic secret. It never returns that credential to the model.
- **Receipt service:** links mandate, decision, approval envelope, idempotency key, downstream result hash, and timestamps in an append-only store.

## Request lifecycle

1. An agent proposes an action with structured parameters.
2. The gateway resolves authenticated principal, agent/workload identity, task lineage, tool identity, and target audience.
3. The policy layer calculates the least authority required and whether fresh approval is needed.
4. The user approves a canonical, human-readable envelope. Material mutation creates a new envelope and requires reapproval.
5. The broker issues a short-lived grant bound to the envelope and enforcement point.
6. At execution, the gateway revalidates resource state, policy, expiry, revocation, call/idempotency limits, and exact parameter binding.
7. The credential broker obtains downstream authority without exposing secrets to the model.
8. The executor commits the action and records a receipt. Ambiguous timeouts enter reconciliation; they are not blindly retried.

## Production protocol direction

The reference profile should reuse:

- OAuth 2.0/2.1 authorization server metadata and protected-resource metadata
- RFC 8707 resource indicators for audience restriction
- RFC 8693 token exchange for delegation to downstream audiences
- RFC 9396 authorization details for typed action constraints
- DPoP or mTLS sender-constrained tokens where the ecosystem permits
- OIDC for principals and SPIFFE for workloads
- W3C Trace Context/OpenTelemetry for correlation, without placing secrets in spans

The mandate schema should have canonical JSON encoding, versioned action types, extension namespaces, explicit attenuation rules, and conformance tests. Do not seek a standards process before two independent real integrations expose the right abstraction.

## Data plane safety invariants

- Deny on missing or ambiguous identity/context.
- Never accept token passthrough to a different audience.
- Never let the model choose trusted identity attributes or policy outcomes.
- A child mandate can only attenuate parent authority.
- Approval binds the exact normalized parameters executed.
- Revocation and usage counters are checked atomically.
- Side effects use idempotency keys and record an execution receipt.
- Logs redact grants, downstream tokens, personal data, and tool outputs by default.
