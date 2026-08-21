import assert from "node:assert/strict";

const gatewayUrl = process.env.GATEWAY_URL ?? "http://127.0.0.1:8787";
const idpUrl = process.env.IDP_URL ?? "http://127.0.0.1:9000";
const audience = "https://payments.sandbox";
const nonce = "docker-e2e-nonce-20260821";

const principalToken = await issueToken({
  token_kind: "principal",
  tenant_id: "pilot",
  subject: "user:alice",
  audience: "agent-mandate-control",
  nonce,
});
const workloadToken = await issueToken({
  token_kind: "workload",
  tenant_id: "pilot",
  subject: "workload:payment-agent-1",
  agent_id: "agent:payment",
  audience: "agent-mandate-gateway",
});
const wrongAudienceWorkloadToken = await issueToken({
  token_kind: "workload",
  tenant_id: "pilot",
  subject: "workload:payment-agent-1",
  agent_id: "agent:payment",
  audience: "wrong-gateway",
});

const issued = await createMandate("payment:42", {
  amount: 480,
  currency: "USD",
  recipient: "merchant:42",
});

const invalidWorkload = await execute(issued.grant, {
  taskId: "task:pay-42",
  resource: "payment:42",
  parameters: { amount: 480, currency: "USD", recipient: "merchant:42" },
  idempotencyKey: "e2e-invalid-workload",
}, wrongAudienceWorkloadToken);
assert.equal(invalidWorkload.status, 401);
assert.equal(invalidWorkload.body.error, "invalid_workload_identity");

const drift = await execute(issued.grant, {
  taskId: "task:prompt-injected",
  resource: "payment:42",
  parameters: { amount: 480, currency: "USD", recipient: "merchant:42" },
  idempotencyKey: "e2e-drift-0001",
});
assert.equal(drift.status, 403);
assert.equal(drift.body.decision?.code ?? drift.body.error, "task_mismatch");

const approvalMutation = await execute(issued.grant, {
  taskId: "task:pay-42",
  resource: "payment:42",
  parameters: { amount: 479, currency: "USD", recipient: "merchant:42" },
  idempotencyKey: "e2e-approval-mutation",
});
assert.equal(approvalMutation.status, 403);
assert.equal(approvalMutation.body.decision?.code ?? approvalMutation.body.error, "approval_mismatch");

const allowedInput = {
  taskId: "task:pay-42",
  resource: "payment:42",
  parameters: { amount: 480, currency: "USD", recipient: "merchant:42" },
  idempotencyKey: "e2e-allow-0001",
};
const allowed = await execute(issued.grant, allowedInput);
assert.equal(allowed.status, 200);
assert.equal(allowed.body.decision.allowed, true);
assert.equal(allowed.body.receipt.outcome, "succeeded");
assert.equal(JSON.stringify(allowed.body).includes("sandbox_"), false);

const replay = await execute(issued.grant, allowedInput);
assert.equal(replay.status, 200);
assert.equal(replay.body.receipt.id, allowed.body.receipt.id);

const mutation = await execute(issued.grant, {
  ...allowedInput,
  parameters: { ...allowedInput.parameters, amount: 481 },
});
assert.equal(mutation.status, 409);
assert.equal(mutation.body.decision?.code ?? mutation.body.error, "idempotency_conflict");

const concurrentMandate = await createMandate("payment:concurrent", {
  amount: 100,
  currency: "USD",
  recipient: "merchant:42",
});
const concurrentBase = {
  taskId: "task:pay-42",
  resource: "payment:concurrent",
  parameters: { amount: 100, currency: "USD", recipient: "merchant:42" },
};
const concurrent = await Promise.all([
  execute(concurrentMandate.grant, { ...concurrentBase, idempotencyKey: "e2e-race-a" }),
  execute(concurrentMandate.grant, { ...concurrentBase, idempotencyKey: "e2e-race-b" }),
]);
assert.equal(concurrent.filter(({ body }) => body.decision?.allowed === true).length, 1);
assert.equal(concurrent.filter(({ body }) => body.decision?.code === "call_limit_exceeded").length, 1);

const timeoutMandate = await createMandate("payment:timeout", {
  amount: 75,
  currency: "USD",
  recipient: "merchant:42",
  simulate: "timeout",
});
const timeoutInput = {
  taskId: "task:pay-42",
  resource: "payment:timeout",
  parameters: { amount: 75, currency: "USD", recipient: "merchant:42", simulate: "timeout" },
  idempotencyKey: "e2e-timeout-0001",
};
const timeout = await execute(timeoutMandate.grant, timeoutInput);
assert.equal(timeout.status, 202);
assert.equal(timeout.body.decision.code, "downstream_ambiguous");
assert.equal(timeout.body.receipt.outcome, "ambiguous");
const timeoutReplay = await execute(timeoutMandate.grant, timeoutInput);
assert.equal(timeoutReplay.status, 202);
assert.equal(timeoutReplay.body.receipt.id, timeout.body.receipt.id);
assert.equal(timeoutReplay.body.receipt.attemptCount, timeout.body.receipt.attemptCount);

const auditResponse = await fetch(`${gatewayUrl}/v1/audit?limit=100`, {
  headers: { authorization: `Bearer ${principalToken}`, "x-oidc-nonce": nonce },
});
assert.equal(auditResponse.status, 200);
const audit = await auditResponse.json();
assert.ok(audit.events.some((event) => event.code === "task_mismatch"));
assert.equal(JSON.stringify(audit).includes(issued.grant), false);

process.stdout.write(`${JSON.stringify({
  ok: true,
  allowedReceiptId: allowed.body.receipt.id,
  driftCode: drift.body.decision?.code ?? drift.body.error,
  mutationCode: approvalMutation.body.decision?.code ?? approvalMutation.body.error,
  timeoutOutcome: timeout.body.receipt.outcome,
  concurrentCodes: concurrent.map(({ body }) => body.decision?.code),
  auditEvents: audit.events.length,
})}\n`);

async function createMandate(resource, parameters) {
  const response = await fetch(`${gatewayUrl}/v1/mandates`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${principalToken}`,
      "x-workload-authorization": `Bearer ${workloadToken}`,
      "x-oidc-nonce": nonce,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      agentId: "agent:payment",
      workloadId: "workload:payment-agent-1",
      taskId: "task:pay-42",
      audience,
      actions: ["payment.create"],
      resources: [resource],
      expiresInSeconds: 300,
      constraints: {
        maxCalls: 1,
        equals: { currency: "USD", recipient: "merchant:42" },
        maximum: { amount: 500 },
      },
      approval: {
        required: true,
        approvedEnvelope: {
          version: "am.action.v1",
          audience,
          action: "payment.create",
          resource,
          parameters,
        },
      },
    }),
  });
  const body = await response.json();
  assert.equal(response.status, 201, JSON.stringify(body));
  assert.ok(body.grant);
  assert.equal("grantHash" in body.mandate, false);
  return body;
}

async function execute(grant, input, executionWorkloadToken = workloadToken) {
  const response = await fetch(`${gatewayUrl}/v1/execute`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${grant}`,
      "x-workload-authorization": `Bearer ${executionWorkloadToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      ...input,
      audience,
      action: "payment.create",
    }),
  });
  return { status: response.status, body: await response.json() };
}

async function issueToken(values) {
  const response = await fetch(`${idpUrl}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "client_credentials", ...values }),
  });
  const body = await response.json();
  assert.equal(response.status, 200, JSON.stringify(body));
  return body.access_token;
}
