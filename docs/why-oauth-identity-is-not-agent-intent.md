# Why OAuth identity is not enough to authorize agent intent

OAuth is essential infrastructure. It can identify a client, delegate scopes,
bind a token to a resource server, and keep a user's password away from an
application. But a coding agent holding a repository-write token still has a
problem OAuth was not designed to solve: which exact write did the user intend
this autonomous process to perform right now?

Consider an agent asked to open one issue in a sandbox repository. Its token may
legitimately carry repository write authority. After reading an injected
instruction from a pull request, web page, or tool response, the same agent may
try to change settings, delete content, or write to a different repository. The
token can still be valid. The agent can still be the expected client. The new
action can still fit inside a broad OAuth scope.

Identity and scope answer important questions:

- Who is the user or workload?
- Which client received delegated authority?
- Which resource server and coarse capability may it access?
- When does that delegation expire?

They do not automatically answer:

- Which exact action did the user approve?
- Which immutable resource and parameters did that approval cover?
- How many side effects may occur?
- Did the action drift between preview and execution?
- What happened when a write response was lost?

Agent Mandate adds that missing, task-bound layer. It does not replace OAuth; it
uses OAuth and OIDC to authenticate the agent-facing client and the separately
approving user. It then constructs an immutable action envelope inside a trusted
service.

For the GitHub proof, the envelope binds a versioned profile, selected GitHub App
installation, immutable numeric repository ID, exact title and body, server
correlation value, expiry, approving principal, one-use budget, and prohibition
on delegation. The model may propose the human-readable repository and issue
content. It cannot choose the GitHub API origin, route, HTTP method, installation,
numeric repository ID, permission set, idempotency key, or approval identity.

The flow is deliberately non-blocking:

1. The agent proposes one exact issue.
2. Agent Mandate persists the frozen intent and returns an approval URL plus an
   opaque resume handle.
3. The user signs in through a fresh OIDC code flow and reviews the exact action.
4. The agent resumes with the opaque handle only; it cannot restate or expand
   the approved arguments.
5. Agent Mandate mints a short-lived GitHub App installation token narrowed to
   one repository and Issues write, executes once, and stores a hash-linked
   receipt.

If prompt injection causes the agent to include repository-delete authority,
the strict action profile rejects the request before an approval is created. If
the issue write is dispatched but its response is lost, Agent Mandate does not
blindly repeat it. It performs one bounded read-only reconciliation using a
correlation marker. Without one unique match, the outcome remains ambiguous for
operator inspection.

This is a narrower claim than “prompt-injection protection.” Agent Mandate does
not determine whether a prompt is malicious, whether an approved action is wise,
or whether the user's source data is true. It deterministically prevents its
execution route from exceeding the stored approval after an agent, prompt, or
tool fails.

There is also an operational distinction between mediation and enforcement. A
configured MCP route is mediated: actions sent through it are constrained. The
system is enforced only when direct provider credentials and alternate mutation
paths are removed from the agent boundary and network egress is restricted so
the protected route cannot be bypassed.

The practical question for an agent team is therefore not “Does our agent have
OAuth?” It is:

> Your agent can call real tools. How do you prevent it from doing more than the
> user actually approved?

Run the candidate GitHub proof in
[`product-quickstart.md`](product-quickstart.md), or become a design partner by
bringing one consequential action you are not yet comfortable letting an agent
perform unattended.

## Standards context

- [OAuth 2.0 authorization framework (RFC 6749)](https://www.rfc-editor.org/rfc/rfc6749)
- [OAuth resource indicators (RFC 8707)](https://www.rfc-editor.org/rfc/rfc8707)
- [OAuth token exchange (RFC 8693)](https://www.rfc-editor.org/rfc/rfc8693)
