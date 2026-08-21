# Agent Mandate

Task-bound authorization infrastructure for AI agents. This repository contains
a deployable, single-tenant pilot showing that an agent can perform one
consequential action without receiving a standing downstream credential.

The gateway binds a validated human principal and workload identity to one task,
audience, action, resource, canonical parameter envelope, expiry, approval, and
use budget. PostgreSQL atomically enforces use/revocation/idempotency and stores
redacted audit events plus an immutable hash-linked receipt-state chain.

> Pilot status: suitable for a controlled sandbox evaluation, not production.
> The checked-in identity and payment services are local test providers. A real
> pilot still requires reviewed provider configuration, managed PostgreSQL/TLS,
> secret management, deployment approval, and an external security review.

## Run the complete pilot

Requirements: Docker Compose v2. The images use Node 22 and PostgreSQL 17.

```bash
docker compose build
docker compose up -d --wait
npm run test:docker
```

The live test obtains separately signed principal and workload tokens, issues an
exactly approved `payment.create` mandate, denies prompt-injected task drift and
parameter mutation, executes through token exchange and the payment sandbox,
verifies idempotent replay, races a one-use mandate concurrently, and proves an
unresolved downstream timeout is `ambiguous` rather than blindly repeated.

Run every PostgreSQL concurrency/migration test against the Compose database:

```bash
TEST_DATABASE_URL=postgres://mandate:local-postgres-only@127.0.0.1:55432/agent_mandate npm test
```

Run the bounded local load check (defaults to 50 actions at concurrency 5):

```bash
npm run test:load
LOAD_REQUESTS=500 LOAD_CONCURRENCY=10 npm run test:load
```

Run the stateful confidence drill. It verifies revocation and successful-receipt
replay before and after a gateway restart, then stops PostgreSQL long enough to
observe liveness 200 and readiness 503 repeatedly, verify the gateway container
did not restart, require a consequential action to fail closed, restore
PostgreSQL, and verify persisted and fresh-write behavior:

```bash
npm run test:confidence
```

Run the rate-controlled soak gate (defaults to 60 seconds at 2 actions/second,
zero tolerated errors, a 2-second p95 ceiling, minimum sustained throughput,
and bounded scheduler lag):

```bash
npm run test:soak
SOAK_DURATION_SECONDS=3600 SOAK_ACTIONS_PER_SECOND=2 \
  SOAK_CONCURRENCY=5 SOAK_MAX_ERROR_RATE=0.001 SOAK_MAX_P95_MS=500 \
  npm run test:soak
```

The confidence drill intentionally restarts local Compose services and performs
a graceful stop/start of one PostgreSQL container. It does not claim crash or
managed-database failover: run abrupt-failure, provider-owned failover, and
backup/restore exercises before a real pilot.

Stop the stack with `docker compose down`. Add `-v` only when intentionally
discarding the local database; pilot evidence must not be deleted.

## Implemented pilot contract

- OIDC JWT validation for the principal: signature, issuer, audience, expiry,
  exact nonce, bounded clock tolerance, and rotating remote JWKS.
- Separately validated workload JWT deriving tenant, agent, and workload fields;
  request bodies cannot assert trusted identity.
- Opaque grants stored only as SHA-256 hashes, one-hour maximum TTL, immediate
  tenant-scoped revocation, and mechanically attenuated child grants.
- Atomic parent/child call-budget allocation and one-use consumption under
  PostgreSQL row locks.
- Canonical `am.action.v1` envelopes and mandatory exact step-up approval for the
  pilot's high-risk `payment.create` action.
- Always-on deterministic policy plus an optional fail-closed OPA data adapter.
- Shared HTTP and typed MCP enforcement pipeline.
- RFC 8693 token-exchange adapter with RFC 8707 target/returned-audience checks;
  exchanged credentials stay inside the executor.
- Optional DPoP execution hook that fails closed if a DPoP credential has no
  proof generator.
- Idempotent execution receipts for success, failure, pending recovery, and
  ambiguous timeout states; replay never repeats a completed or uncertain side
  effect.
- Redacted structured request telemetry, tenant-scoped audits, immutable evidence
  guards, and hash-linked receipt-state events covering outcomes and result hashes.
- Health/readiness probes, guarded reversible migrations, non-root read-only
  containers, OpenAPI, CI, deployment/rollback/incident instructions, and live
  adversarial/load tests.

## Request boundary

`POST /v1/mandates` requires the principal JWT in `Authorization: Bearer`, the
workload JWT in `x-workload-authorization: Bearer`, and the login nonce in
`x-oidc-nonce`. The server validates the target agent/workload against the token.

`POST /v1/execute` requires the short-lived mandate grant in
`Authorization: Bearer` and the workload JWT in `x-workload-authorization`.
Identity fields in a JSON body are ignored; the gateway constructs them from the
validated workload context. See [openapi.yaml](openapi.yaml) for the exact API.

## Local development

```bash
npm ci
npm run typecheck
npm test
npm run build
```

For a non-Compose server, set every variable validated by `src/config.ts`, run
`npm run build && npm run migrate`, then `npm start`. The gateway fails startup on
missing configuration and fails readiness while PostgreSQL is unavailable.

## Explicit pilot limits

- Exactly one configured tenant (`pilot` by default), environment, region,
  principal issuer, workload issuer/adapter, and PostgreSQL primary.
- Exactly one approved high-risk action profile and payment downstream audience;
  the Compose issuer/token exchange/payment API are sandboxes, not production
  providers.
- No active-active failover, general policy-authoring UI, provider catalog,
  automatic ambiguous-action retry, secrets vault, WORM export, SCIM/admin RBAC,
  formal certification, or external penetration test.
- The local issuer exposes a test-only client-credentials minting endpoint and
  regenerates its key on restart. Never deploy it as an identity provider.
- Receipt hashes make database tampering detectable during verification; a
  production pilot should export evidence to separately controlled immutable
  storage or sign it with KMS-backed keys.

Authorization preserves the approved operating envelope; it cannot decide
whether an allowed payment is wise or its source data is true.

## Operations and design

- [Architecture and frozen contract](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Deployment, rotation, rollback, recovery, and incidents](docs/deployment-runbook.md)
- [Pilot evidence template](docs/pilot-evidence-template.md)
- [Accelerated delivery plan](docs/accelerated-pilot-plan.md)

## License

Apache-2.0
