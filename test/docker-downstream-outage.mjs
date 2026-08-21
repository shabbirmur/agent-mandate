import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);
const gatewayUrl = process.env.GATEWAY_URL ?? "http://127.0.0.1:8787";
const idpUrl = process.env.IDP_URL ?? "http://127.0.0.1:9000";
const audience = "https://payments.sandbox";
const nonce = "outage-test-nonce-20260821";
const parameters = { amount: 12, currency: "USD", recipient: "merchant:outage" };
const resource = `payment:outage-${Date.now()}`;

const [principalToken, workloadToken] = await Promise.all([
  issueToken({ token_kind: "principal", tenant_id: "pilot", subject: "user:outage", audience: "agent-mandate-control", nonce }),
  issueToken({ token_kind: "workload", tenant_id: "pilot", subject: "workload:payment-agent-1", agent_id: "agent:payment", audience: "agent-mandate-gateway" }),
]);
const issued = await createMandate();

try {
  await exec("docker", ["compose", "stop", "payment-sandbox"]);
  const first = await execute();
  assert.equal(first.status, 502);
  assert.equal(first.body.decision.code, "downstream_failed");
  assert.equal(first.body.receipt.outcome, "failed");

  await exec("docker", ["compose", "start", "payment-sandbox"]);
  await exec("docker", ["compose", "up", "-d", "--wait"]);
  const replay = await execute();
  assert.equal(replay.status, 502);
  assert.equal(replay.body.receipt.id, first.body.receipt.id);
  assert.equal(replay.body.receipt.attemptCount, first.body.receipt.attemptCount);
  process.stdout.write(`${JSON.stringify({ ok: true, outageCode: first.body.decision.code, replayedReceipt: replay.body.receipt.id })}\n`);
} finally {
  await exec("docker", ["compose", "start", "payment-sandbox"]).catch(() => undefined);
  await exec("docker", ["compose", "up", "-d", "--wait"]).catch(() => undefined);
}

async function createMandate() {
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
      taskId: "task:outage",
      audience,
      actions: ["payment.create"],
      resources: [resource],
      expiresInSeconds: 300,
      constraints: { maxCalls: 1, equals: { currency: "USD", recipient: "merchant:outage" }, maximum: { amount: 20 } },
      approval: { required: true, approvedEnvelope: { version: "am.action.v1", audience, action: "payment.create", resource, parameters } },
    }),
  });
  const body = await response.json();
  assert.equal(response.status, 201, JSON.stringify(body));
  return body;
}

async function execute() {
  const response = await fetch(`${gatewayUrl}/v1/execute`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${issued.grant}`,
      "x-workload-authorization": `Bearer ${workloadToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      taskId: "task:outage",
      audience,
      action: "payment.create",
      resource,
      parameters,
      idempotencyKey: `outage-${resource}`,
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
