# Agent Mandate v0.1.0 release notes

Status: approved open-source sandbox release.

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

- Cumulative protected-main implementation base
  `66bfe31443e0af2555554df39e5909712e21c366` passed
  [hosted CI](https://github.com/shabbirmur/agent-mandate/actions/runs/32756329592)
  and [CodeQL](https://github.com/shabbirmur/agent-mandate/actions/runs/32756329584).
  CI passed typecheck, 52 PostgreSQL-backed tests with no skips, production
  build, full-history secret scanning, high/critical image scanning, Compose
  deployment, adversarial E2E, downstream outage, database-pause confidence,
  bounded load, and the CI-sized soak gate.

See [pilot-evidence.md](pilot-evidence.md) for the machine-observed local details
and their explicit limits. The exact implementation SHA, hosted run URLs, scan
results, and artifact digests are recorded in the release checklist.

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

This is the first tagged contract release. Future incompatible changes to
mandates, action envelopes, decisions, or receipts require an explicit contract
version change and updated conformance fixtures. Database migrations must retain
receipt and audit evidence as described in the deployment runbook.

- Breaking changes: none; this is the first public release.
- Migration: a fresh sandbox deployment runs the documented up migration. There
  is no prior public release to upgrade from.
