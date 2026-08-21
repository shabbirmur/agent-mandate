# v0.1.0 release checklist

This checklist has two independent decisions:

1. **Open-source sandbox release** — publishing the Apache-2.0 source, documentation, and local Docker Compose demonstration as `v0.1.0`.
2. **Production or pilot acceptance** — authorizing a particular hosted deployment, real identity/payment providers, operating envelope, and accountable owners.

Completing the open-source checklist does not satisfy, waive, or imply any production/pilot gate. The repository currently describes a controlled sandbox evaluation, not production software.

## A. Open-source sandbox release

### Scope and community safety

- [ ] `LICENSE` is present, correct for Apache-2.0, and compatible with all distributed source and assets.
- [ ] `SECURITY.md` is published with a private reporting channel, supported-version policy, response expectations, and safe-disclosure guidance; the repository security-policy link is tested from a signed-in non-collaborator account.
- [ ] Blank issues are disabled, security reports route to `SECURITY.md`, and the structured bug/feature forms and pull-request template render correctly on GitHub.
- [ ] The README and release notes clearly say that the bundled identity and payment services are test providers and that v0.1.0 is for local/non-production sandbox evaluation.
- [ ] Repository history, current files, fixtures, logs, and release artifacts have been scanned for credentials, JWTs, grants, personal data, private endpoints, and sensitive downstream payloads; any scanner ignores identify exact reviewed test fixtures.
- [ ] Runtime and development dependencies, license notices, and `npm audit --omit=dev` results have been reviewed; accepted findings are documented.

### Candidate integrity and evidence

- [ ] `package.json` reports `0.1.0`, the release candidate is a clean reviewed commit, and its full SHA is recorded below.
- [ ] Required GitHub Actions checks pass on that exact SHA; the run URL, discovered test count, failures, and skips are recorded.
- [ ] A fresh clone on a supported host completes `npm ci`, `npm run typecheck`, `npm test`, and `npm run build`.
- [ ] Fresh Docker Compose validation completes build/start, the PostgreSQL-backed suite, adversarial E2E, downstream outage, confidence, bounded load, and CI-sized soak gates.
- [ ] Evidence verifies exact approval binding, task/audience/parameter drift denial, atomic one-use enforcement, revocation, idempotent replay, ambiguous timeout handling, HTTP/MCP parity, redaction, tenant isolation, and receipt-chain integrity.
- [ ] Migration up/down, restart, PostgreSQL outage/recovery, and downstream outage/recovery evidence is tied to the candidate SHA and dated environment details.
- [ ] `openapi.yaml`, README, architecture, threat model, deployment runbook, pilot evidence, and known limitations agree with observed behavior.
- [ ] Generated source archives and any published images or SBOMs are tied to the candidate SHA; container builds set `VCS_REF` to that SHA, and checksums/digests and build platform are recorded.

### Publish and verify

- [ ] Release notes summarize security boundaries, user-visible behavior, breaking changes, migration requirements, known limitations, and explicitly deferred production gates.
- [ ] An immutable annotated `v0.1.0` tag is created from the reviewed candidate SHA; the tag is not moved or reused.
- [ ] A GitHub release is published from that tag with checksums/digests for additional artifacts and links to the security policy, runbook, evidence, and API contract.
- [ ] The published source archive is downloaded and its version, checksum, documentation links, and local quick start are verified independently.
- [ ] Announcement text uses “open-source sandbox release” or equivalent language and does not claim production readiness, certification, external security approval, managed failover, or real-provider acceptance.
- [ ] If a material release defect is found, the tag is not rewritten; document impact and ship a new patch version. Follow `SECURITY.md` for vulnerabilities.

### Open-source decision record

- Candidate commit SHA:
- CI run URL and result:
- Evidence report and artifact digests:
- Known residual risks:
- Decision: `GO` / `NO-GO`
- Release approver, date, and release URL:

## B. Separate production/pilot acceptance

Do not copy the open-source `GO` decision into this section. Evaluate these gates for the exact provider configuration, infrastructure, region, tenant, action, traffic envelope, data classification, and accountable pilot owner.

- [ ] The selected principal IdP and workload identity integration are configured, reviewed, and tested for issuer/audience, key rotation, nonce/clock, subject binding, and revocation behavior.
- [ ] The real downstream provider has accepted RFC 8693/RFC 8707 audience restriction, credential containment, sender constraints where available, idempotency, reconciliation, and provider-owned sandbox tests.
- [ ] Managed PostgreSQL uses approved TLS, network isolation, access controls, backups, restore testing, monitoring, capacity limits, and observed primary-failover behavior.
- [ ] Production secrets and signing keys use approved storage, least privilege, rotation, revocation, audit, and break-glass procedures; checked-in local issuers and credentials are excluded.
- [ ] The immutable deployable image is built from the accepted tag, scanned, signed or attested as required, stored in the approved registry, and verified by digest at deployment.
- [ ] Deployment, migration, rollback, recovery, incident response, evidence export/retention, and provider outage procedures have named owners and observed environment-specific drills.
- [ ] A multi-hour soak at the accepted pilot rate and concurrency meets documented error, latency, scheduler-lag, token-refresh, database, and downstream limits.
- [ ] External security review and threat-model review are complete, with no unaccepted critical/high findings and explicit disposition of relevant medium findings.
- [ ] Privacy, legal, compliance, data-residency, retention, and breach-notification obligations for the selected action and evidence have accountable approval.
- [ ] Monitoring, alerting, on-call escalation, audit access, clock synchronization, capacity, and kill/revocation controls are exercised in the target environment.
- [ ] The pilot owner signs the narrow operating envelope and residual risks, including tenant, region, providers, action/resource limits, spend/use budgets, support window, stop conditions, and rollback authority.

### Production/pilot decision record

- Accepted release tag and image digest:
- Target environment and operating envelope:
- Provider and infrastructure evidence:
- Security review and unresolved findings:
- Pilot owner and operational owners:
- Decision: `GO` / `NO-GO` / `NOT REQUESTED`
- Approvers and date:

An open-source `GO` with a production/pilot `NO-GO` or `NOT REQUESTED` is a valid v0.1.0 outcome.
