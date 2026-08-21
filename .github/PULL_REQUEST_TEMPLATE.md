## Summary

Describe the problem, the bounded change, and any intentionally deferred work.

Closes #

## Contract and security

Select one contract statement:

- [ ] This change preserves identity claims, action names, resource selectors, canonical envelopes, error codes, and receipt fields.
- [ ] Contract changes are explicitly versioned and include updated conformance fixtures, API/docs, compatibility behavior, and migration/rollback notes.

For applicable execution paths:

- [ ] Authority remains task-, audience-, action-, resource-, parameter-, expiry-, approval-, and budget-bound; delegation cannot amplify it.
- [ ] Identity is derived from validated principal/workload credentials, downstream credentials never reach the agent, and consequential failures remain fail-closed.
- [ ] Tenant isolation, atomic use/revocation, idempotency, ambiguous-outcome handling, redaction, and receipt integrity are preserved.
- [ ] No secrets, JWTs, grants, personal data, or sensitive downstream payloads appear in code, fixtures, logs, screenshots, or review text.

## Evidence

- [ ] Focused tests cover the allow and relevant deny/failure paths.
- [ ] `npm run typecheck`, `npm test`, and `npm run build` pass, or exceptions are explained below.
- [ ] Runtime/infrastructure changes include applicable PostgreSQL, HTTP/MCP parity, concurrency, migration, outage/recovery, load, or soak evidence.
- [ ] OpenAPI, runbooks, threat model, and evidence records are updated when their contracts or claims change.
- [ ] Results distinguish local/CI sandbox evidence from hosted deployment, real-provider, production, and pilot-owner acceptance.

Evidence commands, results, CI run, and sanitized artifacts:

<!-- Include exact source SHA and test counts. Use N/A only with a brief reason. -->

## Operational notes

Migration/rollback impact, configuration changes, residual risks, and release-note text:
