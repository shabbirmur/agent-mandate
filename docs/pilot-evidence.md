# v0.1.0 sandbox release evidence — 2026-08-24

This report records observed local and hosted evidence for the accelerated implementation.
It is not production approval or pilot-owner acceptance.

- Original authorization implementation baseline: `abfa608e8394b52c5824fe68466ed31920049602`.
- Validated cumulative protected-main base: `66bfe31443e0af2555554df39e5909712e21c366`, including Node 26, `@types/node` 26, TypeScript 7, and `setup-node` 7.
- Release integration and local-image revision: `c5901de20933238f2f264d26eed231a1c8fb4878`.
- Release tag: `v0.1.0`; publication and independent archive verification will be recorded in `release-checklist.md` after the immutable tag and GitHub release exist.
- Gateway image: `sha256:6786252c04899c52f603121057bf90d582835bb9dd105bbfdf81964ae083fa92` (`linux/arm64`, local Node 26 Docker build with OCI revision `c5901de20933238f2f264d26eed231a1c8fb4878`).
- Runtime: Node 26 Alpine images; PostgreSQL 17 Alpine; Docker Compose on a single local region/host.
- Providers: checked-in sandbox OIDC/workload issuer and payment token-exchange/API only.

## Observed gates

| Gate | Observed result |
|---|---|
| Strict compile and production build | Passed: `npm run typecheck`, `npm run build`, and Docker multi-stage build. |
| Hosted implementation CI | Passed on cumulative protected-main base `66bfe31443e0af2555554df39e5909712e21c366`: [CI run 32756329592](https://github.com/shabbirmur/agent-mandate/actions/runs/32756329592) and [CodeQL run 32756329584](https://github.com/shabbirmur/agent-mandate/actions/runs/32756329584). |
| Supply-chain checks | Implementation CI passed `npm audit --omit=dev`, full-history Gitleaks, and Trivy high/critical image scanning. The 2026-08-24 local dependency recheck reported zero vulnerabilities; distributed dependency licenses are Apache-2.0, ISC, or MIT. |
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
| PostgreSQL outage/recovery | Initial drill exposed an unhandled idle-pool error and was fixed. The first hosted CI confidence run then exposed unbounded PostgreSQL waits under repeated aborted readiness probes. Explicit acquisition, query, and statement timeouts fixed that source path; the local re-run kept the gateway alive with `readyz` HTTP 503, and PostgreSQL recovery restored healthy state and the full E2E path passed. Hosted confirmation is in cumulative-base [CI run 32756329592](https://github.com/shabbirmur/agent-mandate/actions/runs/32756329592). |
| Stateful confidence drill | Hardened re-run passed: while PostgreSQL was paused, a saturated burst of 20 concurrent `/readyz` requests all returned 503 in 621 ms. Over the following five-second window, seven consecutive probe pairs observed `/healthz` 200 and bounded `/readyz` 503 responses; container ID/start time/PID/restart count stayed unchanged, and a consequential action failed closed with `policy_indeterminate`. Successful replay, pre-outage one-use consumption, and revocation survived gateway restart and database recovery; fresh execution and one-use enforcement succeeded after recovery. |
| Migration rollback | Empty-schema down migration passed; populated audit/receipt evidence made destructive rollback fail closed. |
| Bounded load | Final Node 26 re-run passed 100 approved actions at concurrency 10: 190.49 actions/s, p50 48.19 ms, p95 98.79 ms, max 120.98 ms on this local host. |
| Confidence smoke-soak | Final Node 26 CI-sized re-run passed 20/20 actions at target and observed 2 actions/s, concurrency 3, zero errors, two token renewals after initial acquisition, p50 27.63 ms, p95 37.87 ms, max 64.56 ms, scheduler-lag p95 0.98 ms, and no deadline violation. This validates the runner, not the outstanding multi-hour soak gate. |
| Redaction | Unit tests passed; sampled gateway logs contained request ID, method, path, status, and duration only—no grants, JWTs, exchanged tokens, parameters, or downstream bodies. |

## Residual gates

- No immutable registry image is published; `v0.1.0` distributes source and local
  container definitions only.
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
