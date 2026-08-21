import assert from "node:assert/strict";
import test from "node:test";
import { canonicalHash } from "../src/canonical.js";
import { FailClosedPolicyAdapter, LocalPolicyAdapter, OpaPolicyAdapter } from "../src/policy/index.js";
import { ACTION_ENVELOPE_VERSION, type ActionEnvelope, type Mandate, type PolicyInput } from "../src/types.js";

const envelope: ActionEnvelope = {
  version: ACTION_ENVELOPE_VERSION,
  tenantId: "pilot",
  principalId: "user:alice",
  agentId: "agent:pay",
  workloadId: "workload:pay-1",
  taskId: "task:pay-42",
  audience: "https://payments.sandbox",
  action: "payment.create",
  resource: "payment:42",
  parameters: { amount: 480, currency: "USD", recipient: "merchant:42" },
};

function input(): PolicyInput {
  const mandate: Mandate = {
    id: "mandate-1",
    grantHash: "hash",
    tenantId: envelope.tenantId,
    principalId: envelope.principalId,
    agentId: envelope.agentId,
    workloadId: envelope.workloadId,
    taskId: envelope.taskId,
    audience: envelope.audience,
    actions: [envelope.action],
    resources: [envelope.resource],
    expiresInSeconds: 300,
    constraints: { maxCalls: 1, equals: { currency: "USD", recipient: "merchant:42" }, maximum: { amount: 500 } },
    approval: {
      required: true,
      approvedBy: envelope.principalId,
      approvedAt: "2026-08-21T00:00:00.000Z",
      envelopeHash: canonicalHash(envelope),
    },
    issuedAt: "2026-08-21T00:00:00.000Z",
    expiresAt: "2026-08-21T01:00:00.000Z",
    status: "active",
    successfulUses: 0,
  };
  return { envelope: structuredClone(envelope), mandate, now: "2026-08-21T00:01:00.000Z" };
}

test("local policy allows the exact approved bounded envelope", async () => {
  assert.deepEqual(await new LocalPolicyAdapter().evaluate(input()), { outcome: "allow" });
});

test("local policy deterministically denies drift and fails closed on malformed state", async () => {
  const adapter = new LocalPolicyAdapter();
  const taskDrift = input();
  taskDrift.envelope.taskId = "task:prompt-injected";
  assert.equal((await adapter.evaluate(taskDrift)).reason, "task_mismatch");

  const mutation = input();
  mutation.envelope.parameters.amount = 481;
  assert.equal((await adapter.evaluate(mutation)).reason, "approval_mismatch");

  const excessive = input();
  excessive.envelope.parameters.amount = 501;
  assert.equal((await adapter.evaluate(excessive)).reason, "parameter_mismatch");

  const malformed = input();
  malformed.mandate.expiresAt = "not-a-time";
  assert.equal((await adapter.evaluate(malformed)).outcome, "indeterminate");
});

test("OPA adapter uses the data API and malformed/outage responses are indeterminate", async () => {
  let posted: unknown;
  const allow = new OpaPolicyAdapter({
    url: "https://opa.internal/v1/data/agent_mandate/allow",
    fetch: async (_url, init) => {
      posted = JSON.parse(String(init?.body));
      return new Response(JSON.stringify({ result: { allow: true } }), { status: 200 });
    },
  });
  assert.equal((await allow.evaluate(input())).outcome, "allow");
  const expectedInput = input();
  const { grantHash: _, ...expectedMandate } = expectedInput.mandate;
  assert.deepEqual(posted, { input: { ...expectedInput, mandate: expectedMandate } });
  assert.equal(JSON.stringify(posted).includes("hash"), false);

  const malformed = new OpaPolicyAdapter({
    url: "https://opa.internal/v1/data/policy",
    fetch: async () => new Response(JSON.stringify({ result: "maybe" }), { status: 200 }),
  });
  assert.equal((await malformed.evaluate(input())).outcome, "indeterminate");
});

test("combined policy never lets OPA override local constraints and fails closed", async () => {
  let remoteCalls = 0;
  const remote = { evaluate: async () => { remoteCalls += 1; return { outcome: "allow" as const }; } };
  const combined = new FailClosedPolicyAdapter(remote);
  const drift = input();
  drift.envelope.audience = "https://attacker.example";
  assert.equal((await combined.evaluate(drift)).reason, "audience_mismatch");
  assert.equal(remoteCalls, 0);

  const outage = new FailClosedPolicyAdapter({ evaluate: async () => { throw new Error("offline"); } });
  assert.equal((await outage.evaluate(input())).outcome, "indeterminate");
});
