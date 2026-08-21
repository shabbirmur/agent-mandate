# Contributing to Agent Mandate

Agent Mandate is a single-tenant sandbox pilot for task-bound authorization of
AI-agent actions. Contributions should preserve its fail-closed authorization,
atomic budget, idempotency, tenant-isolation, and receipt-evidence guarantees.
This repository is not a production payment service or identity provider.

## Before you start

- Use Node.js 22 or newer, npm, and a Docker daemon with Docker Compose v2.
- Open an issue before proposing a new action type, changing the frozen action
  envelope, or making a substantial architecture or security-boundary change.
- Never commit real credentials, personal data, payment data, or production
  provider configuration. The checked-in identity and payment services are
  local test providers only.
- Keep pull requests focused and explain any security or compatibility tradeoff.

## Local checks

Install dependencies and run the checks that do not require the Compose stack:

```bash
npm ci
npm run typecheck
npm test
npm run build
```

For the full PostgreSQL and sandbox-provider path:

```bash
docker compose build
docker compose up -d --wait
TEST_DATABASE_URL=postgres://mandate:local-postgres-only@127.0.0.1:55432/agent_mandate npm test
npm run test:docker
npm run test:downstream-outage
npm run test:confidence
npm run test:load
npm run test:soak
docker compose down
```

Run the full sequence for changes to authorization, persistence, identity,
execution, migrations, Compose, or outage behavior. For narrower changes, run
the relevant checks and state exactly what you ran in the pull request.

## Pull requests

Describe the behavior changed, its pilot scope, tests performed, and any open
operational or security gate. Add or update tests for behavioral changes. Do not
claim production readiness from local or CI evidence: real-provider integration,
managed-database failover, deployment approval, and external security review
remain outside this sandbox.

By submitting a contribution, you agree that it is provided under the
[Apache License 2.0](LICENSE), as described by that license's contribution terms.

Security vulnerabilities must be reported privately as described in
[SECURITY.md](SECURITY.md), not in a public issue.
