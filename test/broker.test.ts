import assert from "node:assert/strict";
import test from "node:test";
import { MandateBroker } from "../src/broker.js";

function fixture() {
  const broker = new MandateBroker();
  const issued = broker.issue({
    tenantId: "pilot", principalId: "user:alice", agentId: "agent:travel", workloadId: "workload:travel-1", taskId: "task:book-42",
    audience: "https://travel.example", actions: ["booking.create"], resources: ["trip:42"],
    expiresInSeconds: 300, constraints: { maxCalls: 1, equals: { currency: "USD" }, maximum: { amount: 500 } },
    approval: { required: true, approvedBy: "user:alice", approvedAt: new Date().toISOString(), envelopeHash: "test-envelope-hash" },
  });
  return { broker, mandate: issued.mandate, grant: issued.grant };
}

test("allows one exact, bounded action", () => {
  const { broker, grant } = fixture();
  const request = { grant, tenantId: "pilot", agentId: "agent:travel", workloadId: "workload:travel-1", taskId: "task:book-42", audience: "https://travel.example", action: "booking.create", resource: "trip:42", parameters: { amount: 480, currency: "USD" }, idempotencyKey: "idem-1" };
  assert.equal(broker.authorize(request).allowed, true);
  assert.equal(broker.authorize(request).code, "call_limit_exceeded");
});

test("denies task drift and excessive spend", () => {
  const { broker, grant } = fixture();
  const base = { grant, tenantId: "pilot", agentId: "agent:travel", workloadId: "workload:travel-1", taskId: "task:book-42", audience: "https://travel.example", action: "booking.create", resource: "trip:42", parameters: { amount: 480, currency: "USD" }, idempotencyKey: "idem-2" };
  assert.equal(broker.authorize({ ...base, taskId: "task:other" }).code, "task_mismatch");
  assert.equal(broker.authorize({ ...base, parameters: { ...base.parameters, amount: 501 } }).code, "parameter_mismatch");
});

test("revocation is immediate and audited", () => {
  const { broker, mandate, grant } = fixture();
  broker.revoke(mandate.tenantId, mandate.id);
  const decision = broker.authorize({ grant, tenantId: mandate.tenantId, agentId: mandate.agentId, workloadId: mandate.workloadId, taskId: mandate.taskId, audience: mandate.audience, action: mandate.actions[0]!, resource: mandate.resources[0]!, parameters: {}, idempotencyKey: "idem-3" });
  assert.equal(decision.code, "revoked");
  assert.deepEqual(broker.audit("pilot").map((event) => event.type), ["mandate.issued", "mandate.revoked", "action.denied"]);
});
