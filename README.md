# Agent Mandate

[![CI](https://github.com/shabbirmur/agent-mandate/actions/workflows/ci.yml/badge.svg)](https://github.com/shabbirmur/agent-mandate/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/shabbirmur/agent-mandate?label=release)](https://github.com/shabbirmur/agent-mandate/releases/tag/v0.1.0)

## Give agents a mandate, not a master key

Task-bound authorization for AI agents: exact approvals, atomic limits,
credential isolation, and execution receipts. Agent Mandate lets an agent
perform one consequential action without receiving a standing downstream
credential.

**[Run the demo](#protect-a-real-github-action)** · **[Become a design partner](docs/design-partners.md)**

### See the authorization boundary in action

```text
Agent proposes: create issue #1 in owner/sandbox with this exact title and body
User approves:  immutable action envelope in a separate browser session
Agent resumes:  GitHub App token minted for one repository, Issues:write only
Exact action:   succeeds once and returns a hash-linked execution receipt
Injected drift: repository-delete fields are rejected before an approval exists
Replay:         returns the recorded outcome without repeating the side effect
```

Agent Mandate does not claim to detect or eliminate prompt injection. It makes
post-injection authority drift deterministic: an agent can only execute the
stored action a separately authenticated user approved.

The gateway binds a validated human principal and workload identity to one task,
audience, action, resource, canonical parameter envelope, expiry, approval, and
use budget. PostgreSQL atomically enforces use/revocation/idempotency and stores
redacted audit events plus an immutable hash-linked receipt-state chain.

> Product status: `v0.2` is an unreleased implementation candidate for controlled
> GitHub sandbox evaluations, not a production claim. Live GitHub evidence,
> hosted deployment, managed PostgreSQL/failover testing, client interoperability,
> external security review, and pilot-owner acceptance remain release gates.

`v0.1.0` remains the released local payment sandbox. The v0.2 product listener
is deliberately separate: it exposes four narrow MCP tools and no generic
downstream proxy or raw mandate-issuance route.

## Why this exists

Agents are often given credentials that are broader and longer-lived than the
task they are performing. Agent Mandate turns authority into an explicit,
revocable object bound to a principal, workload, task, audience, action,
resource, parameters, expiry, approval, and use budget. The downstream
credential is exchanged inside the gateway and never returned to the agent.

The `v0.1.0` sandbox demonstrates the authorization core and its failure modes.
The v0.2 candidate adds the first real provider profile: one exact GitHub issue,
one separately authenticated approval, one selected repository, one atomic use,
and one verifiable receipt chain.

## Protect a real GitHub action

The release target is one client-side command:

```bash
npx -y @agent-mandate/cli@0.2.0 protect github \
  --endpoint https://mandate.example.com/mcp
```

The package and hosted endpoint are not published yet. From this branch, build
the exact same CLI locally and point it at a configured product service:

```bash
npm ci
npm run build:cli
node packages/cli/dist/main.js protect github \
  --endpoint https://mandate.example.com/mcp
```

The installer auto-detects Codex, Claude Code, Cursor, VS Code, and Gemini CLI,
adds only the secret-free MCP URL, and starts browser OAuth where the client
supports it. Select clients explicitly with `--clients`; inspect changes first
with `--dry-run`; use `am doctor` to distinguish a mediated route from a
deployment where direct GitHub credentials and egress have actually been
removed.

For the self-hosted product service, GitHub App, OIDC claim contract, and live
proof command, follow [the v0.2 quickstart](docs/product-quickstart.md). The live
script first proves an injected repository-delete request is denied, then waits
for approval, executes the exact issue creation once, and verifies its receipt
chain:

```bash
AGENT_MANDATE_URL=http://127.0.0.1:8787 \
AGENT_MANDATE_ACCESS_TOKEN='short-lived-oauth-access-token' \
GITHUB_REPOSITORY=owner/sandbox npm run demo:github
```

The access token is read from the environment for this operator-run proof and is
never printed. Agent clients use OAuth discovery at `/mcp`; do not put bearer or
GitHub tokens in MCP configuration.

## Run the v0.1 sandbox demo

Requirements: Docker Compose v2. The images use Node 26 and PostgreSQL 17.

```bash
docker compose build
docker compose up -d --wait
npm run test:docker
```

On success, the final JSON summary reports `"ok": true`, the allowed receipt
ID, denial codes for task and approval drift, the ambiguous-timeout outcome,
one allowed result in the concurrent one-use race, and the recorded audit-event
count.

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
replay before and after a gateway restart, then pauses PostgreSQL long enough to
hold established connections open while observing liveness 200 and bounded
readiness 503 responses repeatedly. It verifies the gateway container did not
restart, requires a consequential action to fail closed, unpauses PostgreSQL,
and verifies persisted and fresh-write behavior:

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

The confidence drill intentionally restarts the local gateway and pauses then
unpauses one PostgreSQL container to freeze established connections. It does not
claim PostgreSQL process restart, crash, or managed-database failover: run those
and provider-owned backup/restore exercises before a real pilot.

Stop the stack with `docker compose down`. Add `-v` only when intentionally
discarding the local database; pilot evidence must not be deleted.

## Implemented pilot contract

- OIDC JWT validation for the principal: signature, issuer, audience, expiry,
  bounded clock tolerance, rotating remote JWKS, and an exact sandbox
  token/header nonce equality check.
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
`x-oidc-nonce`. In this local profile the header must equal the token claim; the
header is caller supplied and is not server-side login-session or replay
protection. A real relying-party integration must supply the expected nonce from
trusted session state. The server validates the target agent/workload against
the token.

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
- The HTTP pilot's nonce header only exercises exact claim comparison. It is not
  a one-time, server-bound OIDC login nonce and must be replaced by trusted
  relying-party session state in a real integration.
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
- [v0.2 product contract](docs/v0.2-product-contract.md)
- [v0.2 self-hosted quickstart](docs/product-quickstart.md)
- [v0.2 product REST contract](openapi-product.yaml)
- [Why OAuth identity is not enough to authorize agent intent](docs/why-oauth-identity-is-not-agent-intent.md)
- [Design-partner program](docs/design-partners.md)
- [Threat model](docs/threat-model.md)
- [Deployment, rotation, rollback, recovery, and incidents](docs/deployment-runbook.md)
- [Pilot evidence template](docs/pilot-evidence-template.md)
- [Accelerated delivery plan](docs/accelerated-pilot-plan.md)
- [Roadmap](docs/roadmap.md)
- [Launch and design-partner plan](docs/launch-plan.md)
- [v0.1.0 release notes](docs/release-notes-v0.1.0.md)
- [Changelog](CHANGELOG.md)

## Contributing and security

- Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing contracts or behavior.
- [Become a design partner](docs/design-partners.md)
  by describing one consequential agent action you want to protect. Do not
  include credentials, customer data, or confidential system details.
- Use [GitHub Discussions](https://github.com/shabbirmur/agent-mandate/discussions)
  for integration questions, ideas, and implementation feedback.
- Report vulnerabilities using the private process in [SECURITY.md](SECURITY.md),
  not a public issue.
- Community participation follows [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

Apache-2.0

`v0.1.0` is distributed as source and local container definitions. The root
service package remains private. `@agent-mandate/cli` is staged separately for a
future v0.2 npm publication only after the candidate gates are complete.
