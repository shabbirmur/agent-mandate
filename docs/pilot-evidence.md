# Local pilot evidence — 2026-08-21

This report records observed local evidence for the accelerated implementation.
It is not production approval or pilot-owner acceptance.

- Source base: merged confidence-window base `eeb12d3693cf2b1b75a42df597d240ba535ddaf1` plus the database-timeout fix in this evidence commit.
- Release tag: pending; no release tag has been created for this phase.
- Gateway image: `sha256:ec557484494a8372f2f7fd574da8ad7fa9c6179c51229ec35b94eed6fcfbb8dc` (`linux/arm64`, local Docker build from the database-timeout change set).
- Runtime: Node 22 Alpine images; PostgreSQL 17 Alpine; Docker Compose on a single local region/host.
- Providers: checked-in sandbox OIDC/workload issuer and payment token-exchange/API only.

## Observed gates

| Gate | Observed result |
|---|---|
| Strict compile and production build | Passed: `npm run typecheck`, `npm run build`, and Docker multi-stage build. |
| Unit/contract/adversarial suite | Passed all 52 discovered tests when run with PostgreSQL; no failures or skips. This includes bounded-pool configuration and failed-transaction client-disposal coverage. |
| Live PostgreSQL suite | The same 52/52 run passed migration, tenant, concurrency, replay, revocation, hash-chain tamper, and sibling-delegation cases against PostgreSQL 17. |
| Fresh Compose health | PostgreSQL, issuer, payment sandbox, and gateway all reached healthy state. |
| Allow path | `payment.create` completed through OIDC/workload validation, mandate grant, policy, atomic reservation, RFC 8693 exchange, downstream sandbox, receipt, and audit. |
| Prompt/task drift | Denied before side effect with `task_mismatch`. |
| Approval mutation | Denied before side effect with `approval_mismatch`. |
| Invalid workload audience | Rejected with `invalid_workload_identity`. |
| Concurrent one-use race | Exactly one `allowed`; the competing request returned `call_limit_exceeded`. |
| Ambiguous downstream timeout | First request returned `downstream_ambiguous`; retry returned the same receipt and attempt count without repeating the mutation. |
| Downstream outage | Token-exchange outage produced a persisted `failed` receipt; retry after recovery returned the same receipt without executing. |
| Gateway restart | Container restart returned to healthy and the full E2E suite passed against persisted database state. |
| PostgreSQL outage/recovery | Initial drill exposed an unhandled idle-pool error and was fixed. The first hosted CI confidence run then exposed unbounded PostgreSQL waits under repeated aborted readiness probes. Explicit acquisition, query, and statement timeouts fixed that source path; the local re-run kept the gateway alive with `readyz` HTTP 503, and PostgreSQL recovery restored healthy state and the full E2E path passed. Hosted confirmation is represented by this revision's GitHub commit check, not claimed by this local report. |
| Stateful confidence drill | Hardened re-run passed: while PostgreSQL was paused, a saturated burst of 20 concurrent `/readyz` requests all returned 503 in 621 ms. Over the following five-second window, seven consecutive probe pairs observed `/healthz` 200 and bounded `/readyz` 503 responses; container ID/start time/PID/restart count stayed unchanged, and a consequential action failed closed with `policy_indeterminate`. Successful replay, pre-outage one-use consumption, and revocation survived gateway restart and database recovery; fresh execution and one-use enforcement succeeded after recovery. |
| Migration rollback | Empty-schema down migration passed; populated audit/receipt evidence made destructive rollback fail closed. |
| Bounded load | 100 approved actions at concurrency 10: 160.10 actions/s, p50 51.19 ms, p95 145.17 ms, max 165.88 ms on this local host. |
| Confidence smoke-soak | CI-sized 10-second run passed 20/20 actions at target and observed 2 actions/s, concurrency 3, zero errors, two token renewals after initial acquisition, p50 118.34 ms, p95 200.06 ms, max 211.09 ms, scheduler-lag p95 1.20 ms, and no deadline violation. This validates the runner, not the outstanding multi-hour soak gate. |
| Redaction | Unit tests passed; sampled gateway logs contained request ID, method, path, status, and duration only—no grants, JWTs, exchanged tokens, parameters, or downstream bodies. |

## Residual gates

- A reviewed release commit/tag and immutable registry image do not yet exist.
- The Compose identity and payment providers are test sandboxes; a real provider
  integration and provider-owned sandbox acceptance remain external work.
- Managed PostgreSQL backup/restore and platform database failover were not
  exercised locally; only process/container restart and database outage/recovery
  were observed.
- The confidence runner passed a CI-sized 10-second smoke-soak after independent
  review. No multi-hour soak,
  external penetration test, formal certification, WORM
  evidence export, KMS signature, or production deployment was performed.
- The pilot owner has not signed the operating envelope. Acceptance must name the
  tenant, region, identity/workload issuers, payment audience, action schema,
  expected rate, support window, and residual risks.
