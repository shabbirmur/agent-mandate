# Threat model

## Protected assets

Downstream credentials, user data, mutation authority, approval integrity, policy configuration, audit evidence, and the identities/lineage attached to an action.

## Primary threats and controls

| Threat | Required control |
|---|---|
| Prompt injection causes tool drift | Deterministic allow-list and exact action/resource constraints; model never makes authorization decisions |
| Stolen bearer grant | Very short TTL, audience binding, one/few-use limits, DPoP or mTLS in production |
| Confused deputy/token passthrough | Validate audience; exchange for a distinct downstream token; never forward inbound tokens |
| Agent or task spoofing | Derive identity from authenticated runtime/session and attested workload, never request-body assertions |
| Approval bait-and-switch | Canonical envelope hash; reapproval after material changes; execute the approved representation |
| Replay/double execution | Atomic consumption, idempotency key, downstream reconciliation and receipt |
| Delegation amplification | Formal attenuation: child expiry/actions/resources/constraints must be a subset of parent |
| Malicious tool metadata | Admin-trusted tool registry, signed/versioned schemas, runtime parameter validation |
| Audit tampering or secret leakage | Append-only/WORM export, chained hashes or signed receipts, strict redaction and access control |
| Policy outage or indeterminate decision | Fail closed for consequential actions; explicit, narrow emergency policy outside the agent path |

## Honest boundary

Authorization cannot determine whether an allowed action is wise or whether source data is true. It reduces blast radius and preserves intent. Sandboxing, content provenance, transaction validation, monitoring, recovery, and human operations remain necessary.

The production server path uses PostgreSQL, hashed opaque bearer grants, atomic
consumption, and immutable hash-linked evidence events. `src/broker.ts` remains
only as a fast in-memory conformance implementation. Bearer theft, host/database
administrator compromise, and signing-key compromise remain outside the pilot's
full protection boundary; use the DPoP hook where the downstream ecosystem
supports sender-constrained credentials and complete an external security review
before production use.
