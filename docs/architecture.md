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

## Frozen pilot contract (`am.action.v1`)

The pilot uses one concrete profile so independently implemented components do not
reinterpret authority:

- Tenant: `pilot`; every persisted mandate, audit event, idempotency record, and
  receipt carries `tenantId`, and every query is tenant-scoped.
- Principal identity: an OIDC JWT validated for configured issuer and audience.
  `tenantId`, `principalId`, and approval identity are derived from validated
  claims, never from a request body.
- Workload identity: a separately validated JWT with configured issuer and
  audience. `tenantId`, `agentId`, and `workloadId` are derived from its claims.
- Pilot action: `payment.create` against a `payment:<id>` resource, restricted to
  an exact `recipient` and `currency` and a maximum `amount`. This is the sole
  high-risk demo action.
- Downstream: a local payment sandbox reached through an RFC 8693-compatible
  token-exchange adapter. The exchanged credential is audience-bound to
  `https://payments.sandbox` and exists only inside the gateway executor.
- Envelope: `am.action.v1` with the exact fields defined in `src/types.ts`.
  Canonical serialization recursively sorts object keys, rejects non-JSON values,
  and hashes UTF-8 bytes with SHA-256. Material field or parameter changes alter
  the hash and invalidate approval.
- Grants: opaque `mandate-id.secret` values. Only a SHA-256 secret hash is stored.
  All grant, revocation, expiry, tenant, binding, and use-limit checks happen in a
  single database transaction before an execution is reserved.
- Idempotency: unique within `(tenantId, mandateId, idempotencyKey)`. Reuse with a
  different envelope is denied. Retry with the same envelope returns the existing
  receipt and never repeats a completed or ambiguous side effect.
- Receipts: append-only identity/action fields plus mutable reconciliation state,
  linked by `previousReceiptHash`; `receiptHash` is SHA-256 over the canonical
  receipt payload. Secrets and raw sensitive downstream bodies are excluded.
- Policy: deterministic local constraints are always evaluated. An optional OPA
  adapter may add a denial; timeout, outage, malformed response, or indeterminate
  result fails closed.

Stable public denial codes are exported as `ERROR_CODES` from `src/types.ts`.
Changing envelope fields, their meaning, a denial code, or a receipt integrity
field requires a new version and updated conformance fixtures.

## Pilot threat assumptions and rollback

- One process region and one PostgreSQL primary are trusted; host compromise,
  database superuser compromise, and IdP signing-key compromise are outside this
  pilot's protection boundary.
- TLS terminates at trusted infrastructure. Clock skew is bounded by 60 seconds.
  Secrets arrive through environment or container secrets and are never checked
  into source control.
- The payment sandbox honors idempotency keys. An unconfirmed network timeout is
  marked `ambiguous` and requires reconciliation; the gateway never blindly
  retries it.
- Rollback stops gateway traffic, deploys the previous image, and runs only the
  documented down migration after a verified backup. Evidence tables are retained;
  rollback must never delete audit events or receipts.
