import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";

const gatewayUrl = process.env.GATEWAY_URL ?? "http://127.0.0.1:8787";
const idpUrl = process.env.IDP_URL ?? "http://127.0.0.1:9000";
const requestCount = boundedInteger(process.env.LOAD_REQUESTS ?? "50", 1, 10_000);
const concurrency = boundedInteger(process.env.LOAD_CONCURRENCY ?? "5", 1, 100);
const audience = "https://payments.sandbox";
const nonce = "load-test-nonce-20260821";

const [principalToken, workloadToken] = await Promise.all([
  issueToken({ token_kind: "principal", tenant_id: "pilot", subject: "user:load", audience: "agent-mandate-control", nonce }),
  issueToken({ token_kind: "workload", tenant_id: "pilot", subject: "workload:payment-agent-1", agent_id: "agent:payment", audience: "agent-mandate-gateway" }),
]);

const latencies = [];
let next = 0;
const startedAt = performance.now();
await Promise.all(Array.from({ length: concurrency }, async () => {
  while (true) {
    const index = next++;
    if (index >= requestCount) return;
    const requestStartedAt = performance.now();
    await oneAction(index);
    latencies.push(performance.now() - requestStartedAt);
  }
}));
const durationMs = performance.now() - startedAt;
latencies.sort((left, right) => left - right);

process.stdout.write(`${JSON.stringify({
  ok: true,
  requests: requestCount,
  concurrency,
  durationMs: rounded(durationMs),
  actionsPerSecond: rounded(requestCount / (durationMs / 1_000)),
  latencyMs: {
    p50: rounded(percentile(latencies, 0.5)),
    p95: rounded(percentile(latencies, 0.95)),
    max: rounded(latencies.at(-1) ?? 0),
  },
})}\n`);

async function oneAction(index) {
  const resource = `payment:load-${Date.now()}-${index}`;
  const parameters = { amount: 1, currency: "USD", recipient: "merchant:load" };
  const creation = await fetch(`${gatewayUrl}/v1/mandates`, {
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
      taskId: "task:load",
      audience,
      actions: ["payment.create"],
      resources: [resource],
      expiresInSeconds: 300,
      constraints: { maxCalls: 1, equals: { currency: "USD", recipient: "merchant:load" }, maximum: { amount: 10 } },
      approval: {
        required: true,
        approvedEnvelope: { version: "am.action.v1", audience, action: "payment.create", resource, parameters },
      },
    }),
  });
  const issued = await creation.json();
  assert.equal(creation.status, 201, JSON.stringify(issued));
  const execution = await fetch(`${gatewayUrl}/v1/execute`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${issued.grant}`,
      "x-workload-authorization": `Bearer ${workloadToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      taskId: "task:load",
      audience,
      action: "payment.create",
      resource,
      parameters,
      idempotencyKey: `load-${Date.now()}-${index}`,
    }),
  });
  const result = await execution.json();
  assert.equal(execution.status, 200, JSON.stringify(result));
  assert.equal(result.decision.allowed, true);
  assert.equal(result.receipt.outcome, "succeeded");
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

function boundedInteger(value, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new Error("invalid load-test bound");
  return parsed;
}

function percentile(sorted, fraction) {
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * fraction) - 1)] ?? 0;
}

function rounded(value) {
  return Math.round(value * 100) / 100;
}
