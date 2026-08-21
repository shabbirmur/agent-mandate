# Security Policy

Agent Mandate is a controlled, single-tenant sandbox pilot. It demonstrates
authorization and evidence controls but is not approved for production use,
real payments, real identities, or sensitive data.

## Supported versions

Security fixes target the current `main` branch and, after a release exists,
the latest published `v0.1.x` patch. Older commits, prerelease snapshots, forks,
and modified deployments are not maintained by this project.

## Report a vulnerability

Do not open a public issue or pull request for an undisclosed vulnerability.

Use [GitHub private vulnerability reporting](https://github.com/shabbirmur/agent-mandate/security/advisories/new)
for this repository. It is enabled and is the project's confidential reporting
channel. If GitHub does not make that form available to your account, contact
[GitHub Support](https://support.github.com/) without including exploit details
and ask how to access private vulnerability reporting. Do not send exploit
details through a public GitHub issue, pull request, or discussion.

Include, when possible:

- the affected revision and component;
- reproduction steps or a minimal proof of concept;
- expected and observed authorization or isolation behavior;
- likely impact and prerequisites; and
- any suggested mitigation.

Do not include real secrets, access tokens, personal data, or payment data.
Maintainers will coordinate disclosure and remediation according to severity
and available project capacity; this sandbox pilot does not promise a response
or remediation SLA.

## Scope

Reports are in scope when they affect this repository's authorization,
authentication, tenant isolation, delegation budgets, idempotency, credential
handling, redaction, receipt integrity, dependency boundaries, or hardened
Compose deployment. A way for a documented test-only provider or credential to
escape its intended local sandbox is also in scope.

Documented missing production features are not vulnerabilities by themselves.
These include real-provider integration, managed-database failover, external
immutable evidence storage, production secret management, certification, and
external security review. Reports that expose a new weakness despite those
documented boundaries are welcome.
