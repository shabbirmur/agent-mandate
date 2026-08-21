# Local pilot evidence — 2026-08-21

This report records observed local evidence for the accelerated implementation.
It is not production approval or pilot-owner acceptance.

- Source base: `549112502f7468d92106338657e0a0c78f7f1a67` plus the reviewed working-tree implementation in this delivery.
- Release tag: pending; no tag or commit was created without explicit publication authorization.
- Gateway image: `sha256:92532b05875ae3bbd297270123b23a335486311cceed16dac348fbcaf6fe3aa8` (`linux/arm64`, local Docker build).
- Runtime: Node 22 Alpine images; PostgreSQL 17 Alpine; Docker Compose on a single local region/host.
- Providers: checked-in sandbox OIDC/workload issuer and payment token-exchange/API only.

## Observed gates

| Gate | Observed result |
|---|---|
| Strict compile and production build | Passed: `npm run typecheck`, `npm run build`, and Docker multi-stage build. |
| Unit/contract/adversarial suite | Passed all 49 discovered tests when run with PostgreSQL; no failures or skips. |
| Live PostgreSQL suite | The same 49/49 run passed migration, tenant, concurrency, replay, revocation, hash-chain tamper, and sibling-delegation cases against PostgreSQL 17. |
| Fresh Compose health | PostgreSQL, issuer, payment sandbox, and gateway all reached healthy state. |
| Allow path | `payment.create` completed through OIDC/workload validation, mandate grant, policy, atomic reservation, RFC 8693 exchange, downstream sandbox, receipt, and audit. |
| Prompt/task drift | Denied before side effect with `task_mismatch`. |
| Approval mutation | Denied before side effect with `approval_mismatch`. |
| Invalid workload audience | Rejected with `invalid_workload_identity`. |
| Concurrent one-use race | Exactly one `allowed`; the competing request returned `call_limit_exceeded`. |
| Ambiguous downstream timeout | First request returned `downstream_ambiguous`; retry returned the same receipt and attempt count without repeating the mutation. |
| Downstream outage | Token-exchange outage produced a persisted `failed` receipt; retry after recovery returned the same receipt without executing. |
| Gateway restart | Container restart returned to healthy and the full E2E suite passed against persisted database state. |
| PostgreSQL outage/recovery | Initial drill exposed an unhandled pool error and was fixed. Re-run kept the gateway alive with `readyz` HTTP 503; PostgreSQL restart restored healthy state and the full E2E path passed. |
| Migration rollback | Empty-schema down migration passed; populated audit/receipt evidence made destructive rollback fail closed. |
| Bounded load | 100 approved actions at concurrency 10: 160.10 actions/s, p50 51.19 ms, p95 145.17 ms, max 165.88 ms on this local host. |
| Redaction | Unit tests passed; sampled gateway logs contained request ID, method, path, status, and duration only—no grants, JWTs, exchanged tokens, parameters, or downstream bodies. |

## Residual gates

- A reviewed release commit/tag and immutable registry image do not yet exist.
- The Compose identity and payment providers are test sandboxes; a real provider
  integration and provider-owned sandbox acceptance remain external work.
- Managed PostgreSQL backup/restore and platform database failover were not
  exercised locally; only process/container restart and database outage/recovery
  were observed.
- No multi-hour soak, external penetration test, formal certification, WORM
  evidence export, KMS signature, or production deployment was performed.
- The pilot owner has not signed the operating envelope. Acceptance must name the
  tenant, region, identity/workload issuers, payment audience, action schema,
  expected rate, support window, and residual risks.
