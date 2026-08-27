# Protect one consequential agent action

Agent Mandate is recruiting five design partners whose agents can modify a real
system. The engagement starts with one action you are not yet comfortable
letting an agent perform unattended—not a platform-wide migration.

Good first actions include creating a repository change, updating a CRM or
support record, modifying cloud infrastructure, invoking a consequential MCP
tool, or preparing a financial or procurement transaction.

## What we will do together

1. Map the exact action, resource, parameters, approver, use limit, credential,
   and failure semantics.
2. Keep the provider credential outside the agent boundary and implement the
   smallest reviewed action profile or adapter.
3. Prove that the approved action succeeds while parameter, resource, task, and
   call-budget drift are denied.
4. Exercise replay, revocation, timeout ambiguity, provider outage, and receipt
   reconstruction for that action.
5. Measure setup time and credential paths removed from the agent's reach.

The core protocol, local gateway, and conformance work remain open source. A
design partnership does not imply a production-readiness claim or require you
to share credentials, customer data, or confidential architecture publicly.

## A strong fit

You are a platform, security, or AI infrastructure team with:

- an agent that can already call a consequential tool;
- a concrete action and non-production environment to evaluate;
- an owner who can review the authorization and credential boundary; and
- time to run the integration and give direct onboarding feedback.

## Start the conversation

[Open a private-detail-free design-partner discussion](https://github.com/shabbirmur/agent-mandate/discussions/new?category=ideas)
and answer:

- What is the first action you are afraid to let your agent perform unattended?
- Which agent client or framework invokes it?
- Which provider and exact resource would the action affect?
- Who should approve it, and should it execute once or within a bounded budget?
- What direct credential or network paths can the agent currently reach?
- What would a successful two-week sandbox evaluation prove for your team?

Do not include secrets, tokens, private keys, customer data, or undisclosed
security details. Vulnerabilities belong in the private process described in
[`SECURITY.md`](../SECURITY.md).
