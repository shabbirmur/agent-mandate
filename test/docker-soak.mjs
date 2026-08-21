import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";

const gatewayUrl = process.env.GATEWAY_URL ?? "http://127.0.0.1:8787";
const idpUrl = process.env.IDP_URL ?? "http://127.0.0.1:9000";
const durationSeconds = boundedNumber(process.env.SOAK_DURATION_SECONDS ?? "60", 5, 86_400);
const actionsPerSecond = boundedNumber(process.env.SOAK_ACTIONS_PER_SECOND ?? "2", 0.1, 100);
const concurrency = boundedInteger(process.env.SOAK_CONCURRENCY ?? "5", 1, 100);
const maxErrorRate = boundedNumber(process.env.SOAK_MAX_ERROR_RATE ?? "0", 0, 1);
const maxP95Ms = boundedNumber(process.env.SOAK_MAX_P95_MS ?? "2000", 1, 60_000);
const maxSchedulerLagMs = boundedNumber(process.env.SOAK_MAX_SCHEDULER_LAG_MS ?? "1000", 1, 60_000);
const minRateRatio = boundedNumber(process.env.SOAK_MIN_RATE_RATIO ?? "0.95", 0.1, 1);
const requestTimeoutMs = boundedInteger(process.env.SOAK_REQUEST_TIMEOUT_MS ?? "5000", 100, 30_000);
const maxOverrunSeconds = boundedInteger(process.env.SOAK_MAX_OVERRUN_SECONDS ?? "30", 1, 300);
const tokenRefreshSeconds = boundedInteger(process.env.SOAK_TOKEN_REFRESH_SECONDS ?? "240", 1, 240);
const minTokenRefreshes = boundedInteger(process.env.SOAK_MIN_TOKEN_REFRESHES ?? "0", 0, 100_000);
const audience = "https://payments.sandbox";
const nonce = `soak-nonce-${Date.now()}`;
const targetActions = Math.ceil(durationSeconds * actionsPerSecond);
const scheduledActionsPerSecond = targetActions / durationSeconds;

let tokenState;
let tokenRefresh;
let tokenAcquisitionCount = 0;
let next = 0;
let hardDeadlineExceeded = false;
const successfulLatencies = [];
const allLatencies = [];
const schedulerLags = [];
const failures = [];
const startedAt = performance.now();
const targetEndAt = startedAt + durationSeconds * 1_000;
const hardDeadline = targetEndAt + maxOverrunSeconds * 1_000;

await Promise.all(Array.from({ length: concurrency }, async () => {
  while (true) {
    if (hardDeadlineExceeded || performance.now() > hardDeadline) {
      hardDeadlineExceeded = true;
      return;
    }
    const index = next++;
    if (index >= targetActions) return;
    const scheduledAt = startedAt + (index / actionsPerSecond) * 1_000;
    const delayMs = scheduledAt - performance.now();
    if (delayMs > 0) await new Promise((resolve) => setTimeout(resolve, delayMs));
    const actionStartedAt = performance.now();
    schedulerLags.push(Math.max(0, actionStartedAt - scheduledAt));
    try {
      await oneAction(index);
      successfulLatencies.push(performance.now() - actionStartedAt);
    } catch (error) {
      if (performance.now() >= hardDeadline) hardDeadlineExceeded = true;
      failures.push({ index, error: safeError(error) });
    } finally {
      allLatencies.push(performance.now() - actionStartedAt);
    }
  }
}));
const remainingDurationMs = targetEndAt - performance.now();
if (remainingDurationMs > 0) await new Promise((resolve) => setTimeout(resolve, remainingDurationMs));

const durationMs = performance.now() - startedAt;
successfulLatencies.sort((left, right) => left - right);
allLatencies.sort((left, right) => left - right);
schedulerLags.sort((left, right) => left - right);
const attemptedActions = allLatencies.length;
const unattemptedActions = targetActions - attemptedActions;
const completedActions = successfulLatencies.length;
const failedActions = failures.length + unattemptedActions;
const errorRate = failedActions / targetActions;
const p95Ms = percentile(successfulLatencies, 0.95);
const schedulerLagP95Ms = percentile(schedulerLags, 0.95);
const observedActionsPerSecond = completedActions / (durationMs / 1_000);
const minimumActionsPerSecond = actionsPerSecond * minRateRatio;
const tokenRefreshCount = Math.max(0, tokenAcquisitionCount - 1);
const passed = (
  !hardDeadlineExceeded
  && unattemptedActions === 0
  && errorRate <= maxErrorRate
  && p95Ms <= maxP95Ms
  && schedulerLagP95Ms <= maxSchedulerLagMs
  && observedActionsPerSecond >= minimumActionsPerSecond
  && tokenRefreshCount >= minTokenRefreshes
);
const summary = {
  ok: passed,
  targetDurationSeconds: durationSeconds,
  observedDurationSeconds: rounded(durationMs / 1_000),
  targetActions,
  attemptedActions,
  completedActions,
  failedActions,
  unattemptedActions,
  targetActionsPerSecond: actionsPerSecond,
  scheduledActionsPerSecond: rounded(scheduledActionsPerSecond),
  observedActionsPerSecond: rounded(observedActionsPerSecond),
  concurrency,
  tokenAcquisitionCount,
  tokenRefreshCount,
  errorRate,
  hardDeadlineExceeded,
  thresholds: { maxErrorRate, maxP95Ms, maxSchedulerLagMs, minRateRatio, minimumActionsPerSecond: rounded(minimumActionsPerSecond), minTokenRefreshes },
  latencyMs: {
    p50: rounded(percentile(successfulLatencies, 0.5)),
    p95: rounded(p95Ms),
    max: rounded(successfulLatencies.at(-1) ?? 0),
    allAttemptsMax: rounded(allLatencies.at(-1) ?? 0),
  },
  schedulerLagMs: {
    p50: rounded(percentile(schedulerLags, 0.5)),
    p95: rounded(schedulerLagP95Ms),
    max: rounded(schedulerLags.at(-1) ?? 0),
  },
  failures: failures.slice(0, 10),
};
process.stdout.write(`${JSON.stringify(summary)}\n`);
assert.equal(hardDeadlineExceeded, false, "soak exceeded its hard wall-clock deadline");
assert.equal(unattemptedActions, 0, `${unattemptedActions} soak actions were not attempted`);
assert.ok(errorRate <= maxErrorRate, `soak error rate ${errorRate} exceeded ${maxErrorRate}`);
assert.ok(p95Ms <= maxP95Ms, `soak p95 ${p95Ms}ms exceeded ${maxP95Ms}ms`);
assert.ok(schedulerLagP95Ms <= maxSchedulerLagMs, `soak scheduler-lag p95 ${schedulerLagP95Ms}ms exceeded ${maxSchedulerLagMs}ms`);
assert.ok(observedActionsPerSecond >= minimumActionsPerSecond, `soak throughput ${observedActionsPerSecond}/s fell below ${minimumActionsPerSecond}/s`);
assert.ok(tokenRefreshCount >= minTokenRefreshes, `token refresh count ${tokenRefreshCount} fell below ${minTokenRefreshes}`);

async function oneAction(index) {
  const tokens = await currentTokens();
  const unique = `${Date.now()}-${index}`;
  const resource = `payment:soak-${unique}`;
  const parameters = { amount: 1, currency: "USD", recipient: "merchant:soak" };
  const creation = await fetch(`${gatewayUrl}/v1/mandates`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${tokens.principal}`,
      "x-workload-authorization": `Bearer ${tokens.workload}`,
      "x-oidc-nonce": nonce,
      "content-type": "application/json",
    },
    signal: AbortSignal.timeout(operationTimeoutMs()),
    body: JSON.stringify({
      agentId: "agent:payment",
      workloadId: "workload:payment-agent-1",
      taskId: "task:soak",
      audience,
      actions: ["payment.create"],
      resources: [resource],
      expiresInSeconds: 300,
      constraints: { maxCalls: 1, equals: { currency: "USD", recipient: "merchant:soak" }, maximum: { amount: 10 } },
      approval: {
        required: true,
        approvedEnvelope: { version: "am.action.v1", audience, action: "payment.create", resource, parameters },
      },
    }),
  });
  const issued = await creation.json();
  if (creation.status !== 201) throw new Error(`mandate:${creation.status}:${issued.error ?? "unexpected"}`);

  operationTimeoutMs();
  const execution = await fetch(`${gatewayUrl}/v1/execute`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${issued.grant}`,
      "x-workload-authorization": `Bearer ${tokens.workload}`,
      "content-type": "application/json",
    },
    signal: AbortSignal.timeout(operationTimeoutMs()),
    body: JSON.stringify({
      taskId: "task:soak",
      audience,
      action: "payment.create",
      resource,
      parameters,
      idempotencyKey: `soak-${unique}`,
    }),
  });
  const result = await execution.json();
  if (execution.status !== 200 || result.decision?.allowed !== true || result.receipt?.outcome !== "succeeded") {
    throw new Error(`execute:${execution.status}:${result.decision?.code ?? result.error ?? "unexpected"}`);
  }
}

async function currentTokens() {
  if (tokenState && tokenState.refreshAt > Date.now()) return tokenState;
  if (!tokenRefresh) {
    tokenRefresh = Promise.all([
      issueToken({ token_kind: "principal", tenant_id: "pilot", subject: "user:soak", audience: "agent-mandate-control", nonce }),
      issueToken({ token_kind: "workload", tenant_id: "pilot", subject: "workload:payment-agent-1", agent_id: "agent:payment", audience: "agent-mandate-gateway" }),
    ]).then(([principal, workload]) => {
      tokenAcquisitionCount += 1;
      const providerRefreshSeconds = Math.max(1, Math.min(principal.expiresIn, workload.expiresIn) - 60);
      return {
        principal: principal.accessToken,
        workload: workload.accessToken,
        refreshAt: Date.now() + Math.min(tokenRefreshSeconds, providerRefreshSeconds) * 1_000,
      };
    })
      .finally(() => { tokenRefresh = undefined; });
  }
  tokenState = await tokenRefresh;
  return tokenState;
}

async function issueToken(values) {
  const response = await fetch(`${idpUrl}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    signal: AbortSignal.timeout(operationTimeoutMs()),
    body: new URLSearchParams({ grant_type: "client_credentials", ...values }),
  });
  const body = await response.json();
  if (
    response.status !== 200
    || typeof body.access_token !== "string"
    || !Number.isFinite(body.expires_in)
    || body.expires_in <= 0
  ) throw new Error(`token:${response.status}`);
  return { accessToken: body.access_token, expiresIn: body.expires_in };
}

function boundedInteger(value, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new Error("invalid soak integer bound");
  return parsed;
}

function boundedNumber(value, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < minimum || parsed > maximum) throw new Error("invalid soak numeric bound");
  return parsed;
}

function percentile(sorted, fraction) {
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * fraction) - 1)] ?? 0;
}

function rounded(value) {
  return Math.round(value * 10_000) / 10_000;
}

function safeError(error) {
  return error instanceof Error ? error.message.slice(0, 200) : "unknown";
}

function operationTimeoutMs() {
  const remaining = hardDeadline - performance.now();
  if (remaining <= 0) {
    hardDeadlineExceeded = true;
    throw new Error("hard_deadline_exceeded");
  }
  return Math.max(1, Math.min(requestTimeoutMs, Math.floor(remaining)));
}
