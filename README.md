# Agent Mandate

Task-bound authorization infrastructure for AI agents.

Agents should not receive a user's long-lived credential and inherit everything that credential can do. Agent Mandate turns a specific human or service mandate into short-lived authority bound to one agent, one task, one audience, explicit actions and resources, deterministic constraints, revocation, and an audit trail.

> Status: pre-alpha reference implementation. Do not use this in production. The in-memory broker and opaque bearer grants exist to make the authorization semantics executable; durable storage, proof-of-possession, standards adapters, and security review are still required.

## The exact problem

OAuth answers whether a client may access a resource server. Workload identity answers which process is calling. Policy engines answer whether attributes satisfy a rule. Agent systems still need a common control plane that assembles those primitives around a delegated task:

- Which principal authorized this agent instance?
- Is this action part of the approved task, or has the agent drifted?
- Is authority bound to the exact tool, API audience, object, amount, recipient, and time window?
- Can a high-risk mutation require approval without granting broad standing access?
- Can downstream systems verify the decision and can operators reconstruct what happened?

Agent Mandate is the policy enforcement and evidence layer between an agent runtime and tools. It does not infer whether behavior is malicious. It denies actions that fail deterministic, pre-authorized constraints.

## Five-minute demo

```bash
npm install
npm test
npm run dev
```

Issue a one-use mandate:

```bash
curl -s http://127.0.0.1:8787/v1/mandates \
  -H 'content-type: application/json' \
  -d '{"principalId":"user:alice","agentId":"agent:travel","taskId":"task:book-42","audience":"https://travel.example","actions":["booking.create"],"resources":["trip:42"],"expiresInSeconds":300,"constraints":{"maxCalls":1,"equals":{"currency":"USD"},"maximum":{"amount":500}},"approval":{"required":true,"approvedBy":"user:alice"}}'
```

Pass the returned `grant` to `POST /v1/authorize` before executing the side effect. The same grant cannot authorize a different agent, task, audience, action, resource, currency, amount above $500, or a second successful call.

## Architecture

```text
human / service principal
          |
          v
  mandate + approval -----> Agent Mandate control plane
                                  | issue narrow grant
                                  v
agent runtime ---> tool gateway / sidecar ---> downstream API
                       |      ^
                       v      |
                 authorize decision
                       |
                       +----> append-only audit / receipts
```

The model may propose an action. The gateway constructs canonical action attributes. Deterministic policy decides. Only the gateway holds downstream credentials and executes allowed actions.

## Non-goals

- A secrets manager, password manager, identity provider, or card/passport vault
- A replacement for OAuth/OIDC, SPIFFE/SPIRE, cloud IAM, Cedar, OPA, or OpenFGA
- An LLM-based hallucination or prompt-injection detector
- A magical universal agent identity protocol
- Custom cryptography

See [docs/problem.md](docs/problem.md), [docs/architecture.md](docs/architecture.md), [docs/threat-model.md](docs/threat-model.md), and [docs/roadmap.md](docs/roadmap.md).

## License

Apache-2.0
