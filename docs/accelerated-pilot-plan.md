# Accelerated pilot delivery plan

This plan targets a code-complete, deployable single-tenant pilot in 5–10 days, with the first complete vertical slice running on day 1. It assumes a coordinated agent team, stable interfaces, one primary identity provider, managed PostgreSQL, one region, and one or two downstream APIs.

This is intentionally narrower than a general enterprise authorization platform. The goal is to prove that an agent can perform a consequential action without receiving standing credentials, while policy, approval, revocation, replay protection, and evidence remain deterministic.

## Pilot contract

### In scope

- One tenant and one deployment environment; tenant identifiers are present in every persisted object so widening does not require a data-model rewrite.
- OIDC for the human principal and one workload identity adapter.
- PostgreSQL-backed mandates, atomic use limits, revocation, expiry, and idempotency.
- Versioned canonical action envelopes with exact parameter binding.
- One HTTP gateway and one MCP middleware adapter.
- One downstream OAuth integration using a separate exchanged credential.
- Step-up approval for high-risk actions.
- Redacted audit events and signed or hash-linked execution receipts.
- Docker Compose deployment, migration checks, API contract, and adversarial integration tests.

### Explicitly deferred

- Multi-region active-active operation
- Multiple IdPs and cloud workload providers
- General-purpose policy authoring UI
- Custom cryptography or a secrets vault
- Formal certification or external penetration testing
- Broad downstream connector coverage

## Team split

Agents work in parallel only after the shared contract in `docs/architecture.md` and `src/types.ts` is frozen.

| Workstream | Ownership | Deliverable |
|---|---|---|
| Persistence | Agent A | PostgreSQL schema, migrations, atomic consume/revoke, repository tests |
| Identity and grants | Agent B | OIDC validation, workload identity adapter, token/grant lifecycle |
| Policy and gateway | Agent C | Canonical envelope, Cedar/OPA adapter boundary, HTTP/MCP enforcement |
| Credential and receipts | Agent D | Downstream token exchange, redaction, idempotency, receipt chain |
| Integration and operations | Lead agent | Docker, API contract, CI, attack tests, load tests, deployment and evidence |

No workstream may silently redefine identity claims, action names, resource selectors, error codes, or receipt fields. Contract changes require a documented version bump and updates to conformance fixtures.

## Day-by-day execution

### Day 0 — contract freeze (2–4 hours)

- Select the pilot downstream API and identity provider.
- Freeze mandate, action envelope, decision, receipt, and error schemas.
- Define the one high-risk demo action and its exact constraints.
- Add contract fixtures for allow, task drift, audience drift, replay, expiry, revocation, parameter mutation, and downstream timeout.
- Create the deployment threat assumptions and rollback procedure.

**Gate:** all agents can compile against the same schemas; no open ownership ambiguity.

### Day 1 — vertical slice

- Replace the in-memory broker with PostgreSQL persistence.
- Issue a mandate through authenticated principal context.
- Enforce one action through the HTTP gateway.
- Exchange for a downstream credential without returning it to the agent.
- Persist an idempotent execution receipt and redacted audit event.
- Demonstrate a prompt-injected drift attempt being denied.

**Gate:** one clean end-to-end success and one denied drift attempt in Docker Compose.

### Days 2–3 — correctness and integrations

- Add atomic compare-and-consume and revocation checks under concurrency.
- Add OIDC issuer/audience/nonce validation and workload identity binding.
- Add RFC 8707 audience restriction and RFC 8693 token-exchange adapter boundaries.
- Add MCP tool middleware with typed action metadata.
- Bind approval to a canonical envelope hash; require reapproval after material changes.
- Add downstream retry classification and reconciliation for ambiguous timeouts.

**Gate:** integration suite passes with concurrent requests, crash/retry simulation, and mutated approval payloads.

### Days 4–5 — hardening and operations

- Add key rotation configuration and sender-constrained token option where supported.
- Add tenant columns and authorization checks throughout storage and audit queries.
- Add health/readiness probes, structured telemetry, secret/PII redaction tests, and migration rollback checks.
- Run negative tests for confused deputy, token passthrough, delegation amplification, replay, clock skew, and policy indeterminacy.
- Produce a deployment runbook, incident response steps, and a reproducible evidence report.

**Gate:** clean deployment from a tagged commit; rollback and recovery are demonstrated; no known high-severity test failure.

### Days 6–10 — pilot confidence window

- Run soak and load tests at the expected pilot rate.
- Exercise revocation propagation, process restart, database failover, and downstream outage behavior.
- Fix defects found by evidence, not by expanding scope.
- Record unresolved risks and explicit pilot limits.

**Gate:** pilot owner signs the narrow operating envelope and accepts the residual risks.

## Test matrix

### Unit and contract tests

- Schema validation and canonical serialization
- Grant attenuation and expiry calculation
- Exact action/resource/parameter matching
- Policy adapter decisions and fail-closed behavior
- Redaction and receipt integrity

### Integration tests

- OIDC login and invalid issuer/audience/token cases
- PostgreSQL concurrent consumption and revocation race
- MCP and HTTP gateway parity
- Downstream token exchange and audience mismatch
- Idempotent retry after success, failure, and timeout

### Adversarial tests

- Prompt injection requests an unapproved tool/action
- Agent changes task, audience, resource, recipient, amount, or currency
- Stolen or replayed grant
- Parent attempts to create a broader child grant
- Inbound token is presented to the wrong downstream audience
- Policy engine unavailable or returns an indeterminate result
- Logs and traces contain secrets or sensitive parameters

## Definition of done

The pilot is done when all of the following are true:

1. A fresh deployment can be created from a tagged commit using documented commands.
2. The complete allow path works through the real gateway and downstream sandbox.
3. Every listed negative path is denied before the side effect.
4. Two concurrent requests cannot consume one-use authority twice.
5. A downstream timeout is reconciled or explicitly surfaced as ambiguous; it is never blindly duplicated.
6. The model, logs, traces, and receipts do not contain downstream credentials.
7. Every decision and execution is correlated to principal, agent, task, mandate, action, resource, and envelope version.
8. Revocation, restart, migration, rollback, and recovery procedures have observed evidence.
9. The README states the exact single-tenant/provider limits and deferred enterprise features.

## Schedule interpretation

Agents can generate most implementation code in a few days. The 5–10 day window includes integration, concurrency testing, failure injection, deployment, and evidence collection. External security review, vendor onboarding, and production approval remain separate gates; they are not hidden inside the coding estimate.
