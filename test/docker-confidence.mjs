import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const exec = promisify(execFile);
const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const gatewayUrl = process.env.GATEWAY_URL ?? "http://127.0.0.1:8787";
const idpUrl = process.env.IDP_URL ?? "http://127.0.0.1:9000";
const audience = "https://payments.sandbox";
const nonce = `confidence-nonce-${Date.now()}`;
const overallTimeoutMs = boundedInteger(process.env.CONFIDENCE_TIMEOUT_SECONDS ?? "180", 30, 300) * 1_000;
const outageObservationMs = boundedInteger(process.env.OUTAGE_OBSERVATION_SECONDS ?? "5", 3, 60) * 1_000;
const deadline = Date.now() + overallTimeoutMs;
requireLocalLifecycleTarget(gatewayUrl, "GATEWAY_URL");
requireLocalLifecycleTarget(idpUrl, "IDP_URL");

let [principalToken, workloadToken] = await Promise.all([
  issueToken({ token_kind: "principal", tenant_id: "pilot", subject: "user:confidence", audience: "agent-mandate-control", nonce }),
  issueToken({ token_kind: "workload", tenant_id: "pilot", subject: "workload:payment-agent-1", agent_id: "agent:payment", audience: "agent-mandate-gateway" }),
]);

const successful = await createMandate("persistent-success", { amount: 21, currency: "USD", recipient: "merchant:confidence" });
const successfulInput = executionInput(successful.resource, successful.parameters, `confidence-success-${Date.now()}`);
const firstExecution = await execute(successful.grant, successfulInput);
assert.equal(firstExecution.status, 200, JSON.stringify(firstExecution.body));
assert.equal(firstExecution.body.receipt.outcome, "succeeded");

const revocable = await createMandate("persistent-revocation", { amount: 22, currency: "USD", recipient: "merchant:confidence" });
const revocation = await requestJson(`${gatewayUrl}/v1/mandates/${encodeURIComponent(revocable.mandateId)}/revoke`, {
  method: "POST",
  headers: { authorization: `Bearer ${principalToken}`, "x-oidc-nonce": nonce },
});
assert.equal(revocation.status, 200, JSON.stringify(revocation.body));
assert.equal(revocation.body.revoked, true);

const revokedInput = executionInput(revocable.resource, revocable.parameters, `confidence-revoked-${Date.now()}`);
await assertRevoked(revocable.grant, revokedInput);
const outageProbe = await createMandate("outage-fail-closed", { amount: 24, currency: "USD", recipient: "merchant:confidence" });
const outageInput = executionInput(outageProbe.resource, outageProbe.parameters, `confidence-outage-${Date.now()}`);

let result;
let operationError;
try {
  await compose("restart", "gateway");
  await waitForStatus("/readyz", 200);
  const replayAfterRestart = await execute(successful.grant, successfulInput);
  assertPersistentReplay(replayAfterRestart, firstExecution);
  await assertRevoked(revocable.grant, revokedInput);

  const gatewayBeforeOutage = await inspectGateway();
  await compose("stop", "postgres");
  await waitForStatus("/readyz", 503);
  const deniedDuringOutage = await execute(outageProbe.grant, outageInput);
  assert.equal(deniedDuringOutage.status, 503, publicFailure(deniedDuringOutage));
  assert.equal(deniedDuringOutage.body.decision?.code ?? deniedDuringOutage.body.error, "policy_indeterminate");
  const outageDeadline = Date.now() + outageObservationMs;
  let outageProbes = 0;
  while (Date.now() < outageDeadline) {
    await requireStatus("/healthz", 200);
    await requireStatus("/readyz", 503);
    outageProbes += 1;
    await delay(250);
  }
  assert.ok(outageProbes >= 2, "database outage observation was too short");
  const gatewayAfterOutage = await inspectGateway();
  assert.deepEqual(gatewayAfterOutage, gatewayBeforeOutage, "gateway restarted during the database outage");

  await compose("start", "postgres");
  await waitForStatus("/readyz", 200);
  [principalToken, workloadToken] = await Promise.all([
    issueToken({ token_kind: "principal", tenant_id: "pilot", subject: "user:confidence", audience: "agent-mandate-control", nonce }),
    issueToken({ token_kind: "workload", tenant_id: "pilot", subject: "workload:payment-agent-1", agent_id: "agent:payment", audience: "agent-mandate-gateway" }),
  ]);
  const replayAfterDatabaseRecovery = await execute(successful.grant, successfulInput);
  assertPersistentReplay(replayAfterDatabaseRecovery, firstExecution);
  const consumedAgain = await execute(successful.grant, {
    ...successfulInput,
    idempotencyKey: `${successfulInput.idempotencyKey}-second-use`,
  });
  assert.equal(consumedAgain.status, 403, publicFailure(consumedAgain));
  assert.equal(consumedAgain.body.decision?.code ?? consumedAgain.body.error, "call_limit_exceeded");
  await assertRevoked(revocable.grant, revokedInput);
  const outageRetry = await execute(outageProbe.grant, outageInput);
  assert.equal(outageRetry.status, 200, publicFailure(outageRetry));
  assert.equal(outageRetry.body.receipt.outcome, "succeeded");

  const fresh = await createMandate("post-recovery-write", { amount: 23, currency: "USD", recipient: "merchant:confidence" });
  const freshInput = executionInput(fresh.resource, fresh.parameters, `confidence-fresh-${Date.now()}`);
  const freshExecution = await execute(fresh.grant, freshInput);
  assert.equal(freshExecution.status, 200, JSON.stringify(freshExecution.body));
  assert.equal(freshExecution.body.receipt.outcome, "succeeded");
  const secondUse = await execute(fresh.grant, { ...freshInput, idempotencyKey: `${freshInput.idempotencyKey}-second` });
  assert.equal(secondUse.status, 403, JSON.stringify(secondUse.body));
  assert.equal(secondUse.body.decision?.code ?? secondUse.body.error, "call_limit_exceeded");

  result = {
    ok: true,
    successfulReceiptId: firstExecution.body.receipt.id,
    replayPersistedAcrossGatewayRestart: true,
    readinessFailedDuringDatabaseOutage: true,
    consequentialActionFailedClosedDuringDatabaseOutage: true,
    gatewayStayedLiveWithoutRestartDuringObservedOutage: true,
    outageObservationSeconds: outageObservationMs / 1_000,
    outageProbes,
    replayPersistedAcrossDatabaseRecovery: true,
    preOutageOneUseConsumptionPersistedAcrossRecovery: true,
    revocationPersistedAcrossRestartAndRecovery: true,
    freshWriteSucceededAfterRecovery: true,
    oneUseEnforcementSucceededAfterRecovery: true,
  };
} catch (error) {
  operationError = error;
} finally {
  try {
    await composeForCleanup("up", "-d", "--wait", "postgres", "gateway");
    await waitForStatus("/readyz", 200, 60_000);
  } catch (cleanupError) {
    operationError = operationError
      ? new AggregateError([operationError, cleanupError], "confidence drill and cleanup failed")
      : cleanupError;
  }
}
if (operationError) throw operationError;
process.stdout.write(`${JSON.stringify(result)}\n`);

async function createMandate(label, parameters) {
  const resource = `payment:${label}-${Date.now()}`;
  const response = await requestJson(`${gatewayUrl}/v1/mandates`, {
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
      taskId: "task:confidence",
      audience,
      actions: ["payment.create"],
      resources: [resource],
      expiresInSeconds: 900,
      constraints: {
        maxCalls: 1,
        equals: { currency: "USD", recipient: "merchant:confidence" },
        maximum: { amount: 50 },
      },
      approval: {
        required: true,
        approvedEnvelope: { version: "am.action.v1", audience, action: "payment.create", resource, parameters },
      },
    }),
  });
  assert.equal(response.status, 201, publicFailure(response));
  return { grant: response.body.grant, mandateId: response.body.mandate.id, resource, parameters };
}

function executionInput(resource, parameters, idempotencyKey) {
  return { taskId: "task:confidence", audience, action: "payment.create", resource, parameters, idempotencyKey };
}

async function execute(grant, input) {
  return requestJson(`${gatewayUrl}/v1/execute`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${grant}`,
      "x-workload-authorization": `Bearer ${workloadToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(input),
  });
}

async function assertRevoked(grant, input) {
  const result = await execute(grant, input);
  assert.equal(result.status, 403, JSON.stringify(result.body));
  assert.equal(result.body.decision?.code ?? result.body.error, "revoked");
}

function assertPersistentReplay(actual, expected) {
  assert.equal(actual.status, 200, publicFailure(actual));
  assert.equal(actual.body.receipt.id, expected.body.receipt.id);
  assert.equal(actual.body.receipt.attemptCount, expected.body.receipt.attemptCount);
}

async function waitForStatus(path, expectedStatus, timeoutOverrideMs) {
  const waitDeadline = timeoutOverrideMs === undefined ? deadline : Date.now() + timeoutOverrideMs;
  let lastStatus = "unreachable";
  while (Date.now() < waitDeadline) {
    try {
      const response = await fetch(`${gatewayUrl}${path}`, {
        signal: AbortSignal.timeout(Math.max(1, Math.min(2_000, waitDeadline - Date.now()))),
      });
      lastStatus = response.status;
      if (response.status === expectedStatus) return;
    } catch {
      lastStatus = "unreachable";
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`timed out waiting for ${path}=${expectedStatus}; last=${lastStatus}`);
}

async function compose(...args) {
  await exec("docker", ["compose", ...args], { cwd: projectRoot, timeout: Math.min(60_000, remainingMs()) });
}

async function composeForCleanup(...args) {
  await exec("docker", ["compose", ...args], { cwd: projectRoot, timeout: 60_000 });
}

async function inspectGateway() {
  const { stdout: containerOutput } = await exec(
    "docker",
    ["compose", "ps", "-q", "gateway"],
    { cwd: projectRoot, timeout: Math.min(10_000, remainingMs()) },
  );
  const containerId = containerOutput.trim();
  assert.ok(containerId, "gateway container was not found");
  const { stdout } = await exec("docker", ["inspect", containerId], { timeout: Math.min(10_000, remainingMs()) });
  const [inspection] = JSON.parse(stdout);
  assert.ok(inspection?.State?.Running, "gateway container is not running");
  return {
    id: inspection.Id,
    startedAt: inspection.State.StartedAt,
    pid: inspection.State.Pid,
    restartCount: inspection.RestartCount,
  };
}

async function requireStatus(path, expectedStatus) {
  const response = await fetch(`${gatewayUrl}${path}`, { signal: AbortSignal.timeout(Math.min(2_000, remainingMs())) });
  assert.equal(response.status, expectedStatus, `${path} returned ${response.status}`);
}

async function issueToken(values) {
  const response = await requestJson(`${idpUrl}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "client_credentials", ...values }),
  });
  assert.equal(response.status, 200, publicFailure(response));
  return response.body.access_token;
}

async function requestJson(url, init) {
  const response = await fetch(url, { ...init, signal: AbortSignal.timeout(Math.min(5_000, remainingMs())) });
  const text = await response.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`expected JSON from ${new URL(url).pathname}; status=${response.status}`);
  }
  return { status: response.status, body };
}

function remainingMs() {
  const remaining = deadline - Date.now();
  if (remaining <= 0) throw new Error("confidence drill exceeded its overall timeout");
  return remaining;
}

function requireLocalLifecycleTarget(value, name) {
  const target = new URL(value);
  if (target.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]"].includes(target.hostname)) {
    throw new Error(`${name} must be a loopback HTTP URL because this test controls local Compose services`);
  }
}

async function delay(milliseconds) {
  if (milliseconds > remainingMs()) throw new Error("confidence drill exceeded its overall timeout");
  await new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function boundedInteger(value, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new Error("invalid confidence-test bound");
  return parsed;
}

function publicFailure(response) {
  return `status=${response.status}; code=${response.body?.decision?.code ?? response.body?.error ?? "unexpected"}`;
}
