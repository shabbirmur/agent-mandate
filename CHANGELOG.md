# Changelog

All notable changes to Agent Mandate will be documented in this file. The
project follows semantic versioning for tagged public releases; the
authorization envelope carries its own explicit contract version.

## Unreleased

No unreleased changes.

## 0.1.0 - 2026-08-24

### Added

- PostgreSQL-backed mandates, revocation, idempotency, delegation budgets,
  tenant isolation, redacted audit, and hash-linked receipt-state evidence.
- Separate OIDC principal and workload JWT validation with exact high-risk
  approval-envelope binding.
- Shared HTTP and MCP enforcement, RFC 8693 token exchange, RFC 8707 audience
  restriction, an optional DPoP hook, and a fail-closed OPA boundary.
- Ambiguous-timeout reconciliation that never blindly repeats an uncertain
  side effect.
- Hardened Docker Compose, migrations, OpenAPI, CI, adversarial tests, load and
  soak runners, dependency-outage drills, and operational runbooks.
- Bounded PostgreSQL acquisition/query behavior under saturated readiness
  probes and safe disposal of failed transaction clients.
- Apache-2.0 governance files, contribution and security guidance, structured
  issue forms, a release checklist, Dependabot, CodeQL, history secret scanning,
  and high/critical container-CVE scanning.
- Node 26 Alpine runtime images, `@types/node` 26, TypeScript 7, and the pinned
  `setup-node` 7 GitHub Action.

### Security

- Downstream credentials remain inside the executor and are excluded from
  model-visible responses, receipts, audit records, and structured request logs.
- One-use authority, revocation, idempotency, and parent delegation budgets are
  enforced atomically with PostgreSQL row locking.
- CI actions and container bases are immutable-digest pinned. Runtime images
  omit npm, Corepack, and Yarn, include license notices and OCI provenance
  labels, and run as the unprivileged `node` user.

### Release status

- `v0.1.0` is the first open-source sandbox release.
- The checked-in providers are local test sandboxes; production and managed
  database acceptance gates remain open.
