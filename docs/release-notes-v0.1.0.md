# Agent Mandate v0.1.0 release notes

Status: release candidate; tag and GitHub release pending.

`v0.1.0` is the first public sandbox release of Agent Mandate, a task-bound
authorization gateway for consequential AI-agent actions. It demonstrates that
an agent can complete one exactly approved action without receiving a standing
downstream credential.

## What the release proves

- Human and workload identities are validated under separate JWT trust
  configurations and cannot be asserted by request bodies.
- A canonical `am.action.v1` envelope binds task, audience, action, resource,
  and exact parameters to approval.
- PostgreSQL atomically enforces expiry, revocation, one-use limits,
  idempotency, and delegation budgets.
- HTTP and MCP calls share the same enforcement path.
- Downstream credentials are obtained through RFC 8693 token exchange, remain
  internal to the executor, and are audience restricted.
- Uncertain downstream mutations are recorded as ambiguous and reconciled
  without blind retry.
- Redacted audit events and append-only hash-linked receipt events preserve
  deterministic local evidence.

## Release evidence

- The pre-candidate `main` baseline passed hosted CI with typecheck, 52 tests
  against PostgreSQL 17 with no skips,
  production build, Compose deployment, adversarial E2E, downstream outage,
  database-pause confidence, load, and soak gates. Candidate-specific hosted CI
  and CodeQL are still required before tagging.

See [pilot-evidence.md](pilot-evidence.md) for the machine-observed local details
and their explicit limits. The exact candidate SHA, hosted run URLs, scan
results, and artifact digests must be recorded in the release checklist before
the release status changes from candidate to published.

## Deliberate limits

This release is a local single-tenant sandbox, not a production security
boundary. It does not include a production identity provider, real payment
provider, managed PostgreSQL failover, KMS-backed signing, immutable external
evidence export, a secrets vault, multi-region operation, external penetration
testing, or pilot-owner acceptance.

The release is appropriate for local evaluation, protocol and threat-model
review, adapter experimentation, and contributions. Do not describe it as
production-ready or deploy the checked-in issuer/payment sandboxes as providers.
It is a source release; the npm package remains intentionally private.

## Upgrade and compatibility

This is the first tagged contract candidate. Future incompatible changes to
mandates, action envelopes, decisions, or receipts require an explicit contract
version change and updated conformance fixtures. Database migrations must retain
receipt and audit evidence as described in the deployment runbook.
