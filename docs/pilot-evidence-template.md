# Pilot evidence report

- Release tag:
- Commit and image digest:
- UTC window:
- Operator/reviewer:
- PostgreSQL version and migration:
- Identity issuer and workload adapter:
- Downstream sandbox/provider:

## Required observations

| Gate | Command/evidence | Result |
|---|---|---|
| Unit, contract, and adversarial tests | `npm test` | Pending |
| Type safety and build | `npm run typecheck && npm run build` | Pending |
| Fresh Compose deployment | `docker compose up -d --wait` | Pending |
| Allow + prompt-drift denial | `node test/docker-e2e.mjs` | Pending |
| Concurrent one-use consumption | PostgreSQL integration test | Pending |
| Replay and timeout reconciliation | Gateway integration test | Pending |
| Migration rollback/reapply | migration verification | Pending |
| Secret/PII redaction | redaction tests and sampled logs | Pending |
| Restart/revocation persistence | Compose recovery test | Pending |
| PostgreSQL outage liveness/readiness and recovery | `npm run test:confidence` | Pending |
| Pilot-rate load/soak | load command and summary | Pending |
| Soak duration, rate, error, p95, scheduler lag, deadline, and token refresh | `npm run test:soak` JSON thresholds/summary | Pending |

## Residual risks and acceptance

List unresolved risks without expanding the operating envelope. The pilot owner
must sign the exact tenant, region, identity provider, workload adapter,
downstream audience, action schema, request rate, and operational support window.

- Accepted by:
- Date:
- Operating-envelope exceptions: none / list
