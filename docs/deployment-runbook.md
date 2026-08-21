# Pilot deployment and recovery runbook

This runbook applies only to the single-tenant, single-region pilot described in
`docs/architecture.md`. Commands assume Docker Compose v2 and a release tag whose
source has passed CI.

## Configuration gate

Set secrets outside source control and replace every `local-*` Compose value for
a shared environment. Required settings are:

- PostgreSQL `DATABASE_URL` with TLS enforced by the platform.
- PostgreSQL `DATABASE_TIMEOUT_MS` (100-1500 ms), a total readiness budget split
  between pool acquisition and query execution so their sequential worst case
  remains below the external probe timeout.
- OIDC and workload issuer, audience, and JWKS URLs.
- Token-exchange endpoint, client ID, and client secret.
- Exact downstream audience and API base URL.
- Request timeout and allowed clock tolerance.

The gateway refuses readiness until PostgreSQL is reachable. Authentication and
policy errors fail closed; there is no emergency bypass in the agent path.

## Fresh deployment

```bash
git fetch --tags --force
git checkout <reviewed-release-tag>
npm ci
npm test
npm run build
docker compose build --pull
docker compose up -d --wait
node test/docker-e2e.mjs
```

Record the tag, image digest, migration version, test output, UTC time, and
operator in the evidence report. The local issuer and payment API in Compose are
sandboxes; a pilot deployment must configure the approved provider endpoints.

## Migration and rollback

Before every migration, take and verify a PostgreSQL snapshot. Apply migrations
as a distinct deployment step before sending traffic to new gateway instances.

Rollback procedure:

1. Stop new gateway traffic while leaving PostgreSQL and the downstream service
   available for reconciliation.
2. Export unresolved `pending` or `ambiguous` receipt IDs and reconcile them.
3. Deploy the previous image digest.
4. Run the down migration only when its header declares it evidence-preserving
   and the snapshot has been verified. Never drop receipt or audit data merely to
   make an old binary start.
5. Run readiness, denial, replay, and receipt-chain checks before restoring
   traffic.

## Incident response

### Suspected grant or client-secret exposure

1. Revoke the affected mandate(s) by tenant and stop the workload identity.
2. Rotate the token-exchange client secret and invalidate downstream tokens.
3. Search audit events by principal, agent, workload, task, mandate, and audience.
4. Reconcile every `pending` or `ambiguous` receipt before retrying an action.
5. Preserve database and structured-log evidence; do not paste tokens into the
   incident channel or ticket.

### Policy or identity provider outage

Consequential actions remain denied. Restore the provider, verify issuer,
audience, key ID, clock, and policy response shape, then run the adversarial suite.
Do not weaken validation or enable a permissive fallback.

### Downstream timeout

The gateway marks the receipt `ambiguous` and does not repeat the side effect.
Query the downstream system by the same idempotency key. Update reconciliation
state only from an authenticated downstream response and retain the original
receipt hash as evidence.

## Signing-key rotation

Publish the new verification key before issuing tokens under its `kid`; retain
the previous public key for at least the maximum token TTL plus clock tolerance.
After the overlap, stop issuing with the old key, verify traffic, then remove the
old public key. Private keys never enter gateway configuration or telemetry.

## Recovery validation

After process restart, database restore, or failover, verify:

- a previously revoked grant remains revoked;
- a consumed one-use grant cannot be consumed again;
- the same idempotency key returns its existing receipt;
- receipt-chain verification succeeds;
- tenant-scoped audit queries do not return another tenant's records.

For the local Compose environment, run the automated stateful drill:

```bash
npm run test:confidence
```

It restarts the gateway, pauses and unpauses PostgreSQL without deleting the
named volume, repeatedly checks liveness/readiness against established
connections, verifies no hidden gateway restart, requires consequential
authorization to fail closed during the pause, and verifies persisted replay,
revocation, and fresh writes after recovery. A passing local drill is not
evidence of PostgreSQL process restart, abrupt process failure, managed-primary
promotion, connection-string rotation, DNS convergence, or provider backup
restoration; exercise those separately in the chosen platform.

## Confidence-window soak

Choose thresholds from the signed pilot operating envelope, then run a soak at
the expected action rate. For example:

```bash
SOAK_DURATION_SECONDS=14400 SOAK_ACTIONS_PER_SECOND=2 \
  SOAK_CONCURRENCY=5 SOAK_MAX_ERROR_RATE=0.001 SOAK_MAX_P95_MS=500 \
  npm run test:soak
```

Record the JSON summary, gateway image digest, database version, start/end UTC
times, and sampled redacted logs. A valid confidence window has no unexplained
failed actions, remains within the accepted error, latency, sustained-rate, and
scheduler-lag budgets, exercises token refresh, and is followed by receipt-chain
verification. Do not raise thresholds after a failed run without pilot-owner
review.
