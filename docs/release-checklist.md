# v0.1.0 release checklist

This checklist has two independent decisions:

1. **Open-source sandbox release** — publishing the Apache-2.0 source, documentation, and local Docker Compose demonstration as `v0.1.0`.
2. **Production or pilot acceptance** — authorizing a particular hosted deployment, real identity/payment providers, operating envelope, and accountable owners.

Completing the open-source checklist does not satisfy, waive, or imply any production/pilot gate. The repository currently describes a controlled sandbox evaluation, not production software.

## A. Open-source sandbox release

### Scope and community safety

- [x] `LICENSE` is present, correct for Apache-2.0, and compatible with all distributed source and assets.
- [x] `SECURITY.md` is published with a private reporting channel, supported-version policy, response expectations, and safe-disclosure guidance; the public repository security-policy route was independently reachable on 2026-08-24.
- [x] Blank issues are disabled, security reports route to `SECURITY.md`, and the structured bug/feature forms and pull-request template are published and were verified through GitHub's public API.
- [x] The README and release notes clearly say that the bundled identity and payment services are test providers and that v0.1.0 is for local/non-production sandbox evaluation.
- [x] Repository history, current files, fixtures, logs, and the implementation candidate have been scanned for credentials, JWTs, grants, personal data, private endpoints, and sensitive downstream payloads; the exact reviewed fixture exceptions are recorded in `.gitleaksignore`.
- [x] Runtime and development dependencies, license notices, and `npm audit --omit=dev` results have been reviewed. Candidate CI and the 2026-08-24 local recheck reported zero vulnerabilities; distributed dependency licenses are Apache-2.0, ISC, or MIT.

### Candidate integrity and evidence

- [x] `package.json` reports `0.1.0`, the implementation candidate is a clean reviewed commit, and its full SHA is recorded below.
- [x] Required GitHub Actions checks pass on that exact implementation SHA; the run URL, discovered test count, failures, and skips are recorded.
- [x] A clean hosted checkout completes `npm ci`, `npm run typecheck`, all 52 PostgreSQL-backed tests with no failures or skips, and `npm run build`.
- [x] Fresh Docker Compose validation completes build/start, the PostgreSQL-backed suite, adversarial E2E, downstream outage, confidence, bounded load, and CI-sized soak gates.
- [x] Evidence verifies exact approval binding, task/audience/parameter drift denial, atomic one-use enforcement, revocation, idempotent replay, ambiguous timeout handling, HTTP/MCP parity, redaction, tenant isolation, and receipt-chain integrity.
- [x] Migration up/down, restart, PostgreSQL outage/recovery, and downstream outage/recovery evidence is tied to the implementation SHA and dated environment details.
- [x] `openapi.yaml`, README, architecture, threat model, deployment runbook, pilot evidence, and known limitations agree with observed behavior.
- [x] The locally rebuilt Node 26 `linux/arm64` gateway image embeds `VCS_REF=c5901de20933238f2f264d26eed231a1c8fb4878` and has digest `sha256:6786252c04899c52f603121057bf90d582835bb9dd105bbfdf81964ae083fa92`. No registry image or SBOM is published for v0.1.0; completed source-tag and archive-linkage evidence is recorded in the publication section below.

### Publish and verify

- [x] Release notes summarize security boundaries, user-visible behavior, breaking changes, migration requirements, known limitations, and explicitly deferred production gates.
- [x] Immutable annotated tag `v0.1.0` was created once at exact green main SHA `f0825f84bdc435b81c4a12a467e330225792f5e0`; the tag has not been moved or reused.
- [x] The [GitHub release](https://github.com/shabbirmur/agent-mandate/releases/tag/v0.1.0) is published from that tag with a `SHA256SUMS` asset and links to the security policy, runbook, evidence, and API contract.
- [x] Both published source archives were downloaded independently on 2026-08-24. They matched file-for-file; version `0.1.0`, documentation links, the Node 26 install/typecheck/unit/build path, and an isolated fresh Docker Compose E2E quick start were verified.
- [x] Release text uses “open-source sandbox release,” states that production/pilot acceptance is not requested, and does not claim production readiness, certification, external security approval, managed failover, or real-provider acceptance.
- [x] Release policy forbids rewriting `v0.1.0`; any material defect will be documented and corrected in a new patch release, with vulnerabilities handled through `SECURITY.md`.

### Open-source decision record

- Validated cumulative protected-main implementation SHA: `66bfe31443e0af2555554df39e5909712e21c366`
- Final tag-target SHA: `f0825f84bdc435b81c4a12a467e330225792f5e0`.
- CI run URL and result: final tag-target [CI 32757385507](https://github.com/shabbirmur/agent-mandate/actions/runs/32757385507) and [CodeQL 32757385479](https://github.com/shabbirmur/agent-mandate/actions/runs/32757385479) passed. CI included 52/52 PostgreSQL-backed tests with no skips plus audit, secret scan, image scan, E2E, outage, confidence, load, and soak gates.
- Evidence report and artifact digests: `docs/pilot-evidence.md`; local Node 26 `linux/arm64` gateway image `sha256:6786252c04899c52f603121057bf90d582835bb9dd105bbfdf81964ae083fa92`; source TAR `sha256:060123fdb6d8b2c68959e19bcb6bcf88fd66e86be61ba160a65599de05643396`; source ZIP `sha256:df8db8f201bb510f37fcb22c367c420cd866347ac1038406026c319b78de88b4`; published [`SHA256SUMS`](https://github.com/shabbirmur/agent-mandate/releases/download/v0.1.0/SHA256SUMS).
- Known residual risks: local test providers, no managed PostgreSQL failover/restore evidence, no multi-hour soak, external security review, production deployment, KMS/WORM evidence, or pilot-owner acceptance.
- Decision: `GO` for the open-source sandbox release only.
- Release approver, date, and release URL: Shabbir Murtaza (`@shabbirmur`), 2026-08-24; <https://github.com/shabbirmur/agent-mandate/releases/tag/v0.1.0>.

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
- Decision: `NOT REQUESTED`
- Approvers and date: N/A — production/pilot acceptance was not requested.

An open-source `GO` with a production/pilot `NO-GO` or `NOT REQUESTED` is a valid v0.1.0 outcome.
