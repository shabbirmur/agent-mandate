# Agent Mandate launch and design-partner plan

Date: 2026-08-24  
Initial horizon: 30 days  
Primary objective: get five serious teams to evaluate Agent Mandate against one
consequential agent action.

## Positioning

> **Give agents a mandate, not a master key.**
>
> Agent Mandate lets an AI agent execute only the exact action a user approved,
> without exposing standing downstream credentials.

Lead with the user outcome. “Authorization broker,” protocol names, and generic
“AI security” language can explain the implementation after the problem and
proof are clear.

The triggering question is:

> Your agent can call real tools. How do you prevent it from doing more than the
> user actually approved?

## Initial users

Prioritize platform, security, and AI infrastructure engineers building:

- coding agents with repository write access;
- internal agents changing CRM, support, billing, or operational data;
- cloud agents that create or modify infrastructure;
- MCP gateways serving consequential tools; and
- financial or procurement agents preparing transactions.

The first design-partner offer is assistance protecting one concrete action,
not a commitment to adopt a broad platform.

## Product proof

Build a provider-owned GitHub sandbox demonstration with this observable path:

1. A user authorizes an agent to create one specific GitHub issue.
2. The approved issue creation succeeds exactly once.
3. Prompt-injected instructions attempt a destructive repository action.
4. Agent Mandate denies the request because it is outside the approved action
   envelope.
5. The demo displays the approval, denial reason, execution receipt, and
   receipt-chain verification.

The message must remain precise: Agent Mandate does not claim to detect or
eliminate prompt injection. It deterministically enforces the approved boundary
after an agent or its prompt drifts.

Package the same proof as:

- a one-command Docker Compose demo;
- a 60–90 second screen recording;
- a five-minute technical walkthrough;
- one architecture diagram;
- an article titled “Why OAuth identity is not enough to authorize agent
  intent”; and
- a copy-and-paste integration example.

The demo, README, article, launch posts, and outreach must describe the same
action and evidence.

## Public storefront

Completed on 2026-08-24:

- [x] Add the outcome-led GitHub repository description.
- [x] Add the `ai-agents`, `agent-security`, `authorization`, `mcp`, `oauth`,
  `zero-trust`, `policy-as-code`, and `postgresql` topics.
- [x] Set the repository homepage to the README demo.
- [x] Put a short verified-behavior preview near the top of the README.
- [x] Add prominent **Run the demo** and **Become a design partner** actions.
- [x] Enable GitHub Discussions for integration questions and feedback.

Deferred until the product proof is ready:

- [ ] Create a simple landing page centered on the GitHub demonstration.

## Thirty-day execution

### Days 1–7: make the proof undeniable

- [ ] Build and validate the GitHub provider sandbox.
- [ ] Make the first successful protected action achievable in under 15
  minutes from a clean checkout.
- [ ] Record the 60–90 second demonstration.
- [x] Improve the GitHub metadata and README presentation.
- [ ] Document exactly what the provider demo proves and what remains
  sandbox-only.

Gate: an engineer unfamiliar with the project can run the demo, see the allowed
and denied actions, and verify the receipt without assistance.

### Days 8–14: soft launch

- [ ] Recruit 10–15 relevant engineers for private evaluation.
- [ ] Observe installation and first-use friction without coaching the run.
- [ ] Record confusing concepts and failed setup steps.
- [ ] Ask which real action each evaluator would protect first.
- [ ] Fix the highest-frequency onboarding failures before public promotion.

Gate: at least 10 independent demo runs, with time-to-first-protected-action
measured for each run.

### Days 15–21: recruit design partners

- [ ] Build a targeted list of approximately 30 platform, security, and AI
  infrastructure engineers.
- [ ] Send individual outreach tied to the recipient's actual agent/tool risk.
- [ ] Offer hands-on help implementing the first adapter.
- [ ] Hold five design-partner conversations.
- [ ] Start two real integrations.

Suggested outreach:

> I’m building Agent Mandate, an open-source authorization layer for agents that
> call consequential tools. In the demo, an approved GitHub action succeeds
> once while a prompt-injected destructive action is denied, and the agent never
> receives the downstream credential. I’m looking for five design partners with
> an agent that can modify a real system. I’ll help implement the first adapter
> with you. What is the first action you are afraid to let your agent perform
> unattended?

Gate: five qualified conversations, two integrations started, and recurring
integration needs documented without prematurely expanding the core contract.

### Days 22–30: public launch

- [ ] Publish the runnable proof and technical article together.
- [ ] Submit a technically detailed Show HN post.
- [ ] Publish an engineering-focused LinkedIn/X walkthrough.
- [ ] Share the proof in relevant agent, MCP, security, OAuth, and
  developer-tool communities while respecting each community's rules.
- [ ] Follow up directly with soft-launch evaluators and engaged engineers.

Gate: one provider-owned sandbox integration is complete and public claims are
traceable to reproducible evidence.

## MCP distribution

Do not publish a registry entry before there is a genuinely installable public
artifact. After the GitHub proof works:

1. Extract a small public MCP adapter/server.
2. Publish it as a public npm package or OCI image such as GHCR.
3. Add the required MCP package metadata and `server.json`.
4. Submit it to the official MCP Registry.

The v0.1.0 package remains intentionally private and has no published registry
image, so this is a later distribution milestone rather than a current launch
claim.

## Success measures

Primary first-month measures:

- 10 independent successful demo runs;
- 5 design-partner conversations;
- 2 real integrations started;
- 1 provider-owned sandbox integration completed;
- median and p95 time to first protected action;
- downstream credentials removed from agent reach;
- authorization-drift attempts correctly denied; and
- receipt-based incident reconstruction time.

Stars, impressions, and newsletter signups are secondary indicators, not launch
gates.

## Commercial direction

Keep the core protocol, local gateway, and conformance tooling open source. Use
design-partner evidence to determine whether paid demand exists for:

- a managed authorization control plane;
- enterprise identity and workload adapters;
- administrative policy and approval workflows;
- SIEM, immutable evidence, KMS, and compliance integrations;
- high availability and managed PostgreSQL support; and
- enterprise support and security reviews.

## Claims boundary

The v0.1.0 release proves controlled sandbox behavior. It is not evidence of
production readiness, real-provider acceptance, managed-database failover,
external security approval, or pilot-owner acceptance. Those remain explicit
gates and must be verified independently before the corresponding claims are
made.

