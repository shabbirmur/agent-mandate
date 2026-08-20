# Problem definition

## Thesis

The unsolved integration problem is not “give agents identities.” Existing identity systems can identify users, OAuth clients, workloads, and services. The hard problem is preserving a principal's intent across a dynamic chain of agent, sub-agent, tool gateway, and downstream API calls without handing that chain standing authority.

We call the missing object a **mandate**: a signed or server-held authorization artifact representing delegated authority for one task.

## Required semantics

A production mandate must bind:

1. **Principal** — the human or service delegating authority.
2. **Agent/workload** — the runtime allowed to exercise it, backed by an attested identity where possible.
3. **Task** — a stable execution identifier, including parent/child delegation lineage.
4. **Audience** — the gateway or resource server that may accept it.
5. **Actions and resources** — exact operations and object selectors.
6. **Constraints** — amount, recipient, geography, data class, call count, time, and domain-specific invariants.
7. **Approval evidence** — who approved which canonical action envelope and when.
8. **Lifecycle** — expiry, revocation, consumption, and retry/idempotency behavior.
9. **Evidence** — tamper-evident decision and execution receipts.

## What is genuinely new versus standards

- MCP authorization uses OAuth and audience-bound tokens. That protects the MCP server boundary, but does not standardize task identity, action-level constraints, approval envelopes, delegation lineage, or execution receipts.
- OAuth Rich Authorization Requests can encode fine-grained authorization details, but their domain semantics and comparison rules are deliberately application-specific.
- OAuth Token Exchange models delegation and impersonation, but does not define the agent task or safe tool-execution lifecycle.
- SPIFFE/SPIRE provides attested workload identity. It establishes who the workload is, not what a user authorized it to do for this task.
- Cedar, OPA, and OpenFGA can evaluate policy. Agent Mandate supplies a canonical agent/action context, grant lifecycle, enforcement integration, and evidence model; mature deployments should use one of these engines rather than invent a new policy language.

The open-source opportunity is a composable reference profile and enforcement plane joining these layers.

## Initial user

Platform/security engineers deploying agents that can mutate SaaS, cloud, code, money, or customer data. Their immediate pain is replacing raw API keys in model/runtime context with a gateway that is easy for application engineers to adopt and legible to security reviewers.

## Initial wedge

Start with MCP and HTTP tool gateways for consequential actions. A developer wraps a tool, declares its action schema and risk level, and calls Agent Mandate before execution. High-risk calls require a canonical preview and explicit approval. The same approved envelope is what executes.

Success is not GitHub stars alone. The proof metrics are: time to integrate, percentage of tool calls using task-bound grants, denied drift attempts, credential exposure eliminated, approval-to-execution integrity, and incident reconstruction time.
