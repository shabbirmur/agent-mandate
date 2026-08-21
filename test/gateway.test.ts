import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { canonicalHash } from "../src/canonical.js";
import { DownstreamTimeoutError, HttpDownstreamExecutor, HttpTokenExchangeAdapter, TokenExchangeError } from "../src/downstream/index.js";
import { ExecutionGateway } from "../src/gateway/index.js";
import type { DownstreamExecutor, MandateRepository, PolicyAdapter, TokenExchangeAdapter } from "../src/ports.js";
import { ACTION_ENVELOPE_VERSION, type ActionEnvelope, type ActionRequest, type ExecutionReceipt, type Mandate } from "../src/types.js";

const now = new Date("2026-08-21T00:01:00.000Z");

function mandate(): Mandate {
  return {
    id: "mandate-1",
    grantHash: createHash("sha256").update("inbound-secret").digest("base64url"),
    tenantId: "pilot",
    principalId: "user:alice",
    agentId: "agent:pay",
    workloadId: "workload:pay-1",
    taskId: "task:pay-42",
    audience: "https://payments.sandbox",
    actions: ["payment.create"],
    resources: ["payment:42"],
    expiresInSeconds: 300,
    issuedAt: "2026-08-21T00:00:00.000Z",
    expiresAt: "2026-08-21T01:00:00.000Z",
    status: "active",
    successfulUses: 0,
  };
}

function request(): ActionRequest {
  return {
    grant: "mandate-1.inbound-secret",
    tenantId: "pilot",
    agentId: "agent:pay",
    workloadId: "workload:pay-1",
    taskId: "task:pay-42",
    audience: "https://payments.sandbox",
    action: "payment.create",
    resource: "payment:42",
    parameters: { amount: 480, currency: "USD", recipient: "merchant:42" },
    idempotencyKey: "idem-42",
  };
}

function pendingReceipt(): ExecutionReceipt {
  return {
    id: "receipt-1",
    tenantId: "pilot",
    mandateId: "mandate-1",
    decisionId: "decision-reserved",
    principalId: "user:alice",
    agentId: "agent:pay",
    workloadId: "workload:pay-1",
    taskId: "task:pay-42",
    audience: "https://payments.sandbox",
    action: "payment.create",
    resource: "payment:42",
    envelopeVersion: ACTION_ENVELOPE_VERSION,
    envelopeHash: "envelope-hash",
    idempotencyKey: "idem-42",
    outcome: "pending",
    previousReceiptHash: "previous",
    receiptHash: "pending-hash",
    attemptCount: 1,
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
  };
}

function repository(completions: Array<Parameters<MandateRepository["complete"]>[2]>): MandateRepository {
  const stored = mandate();
  return {
    create: async () => stored,
    find: async (tenantId, id) => tenantId === stored.tenantId && id === stored.id ? structuredClone(stored) : undefined,
    revoke: async () => false,
    reserve: async (_request, _envelope, envelopeHash, decisionId) => ({
      decision: { allowed: true, code: "allowed", decisionId, mandateId: stored.id, envelopeHash },
      mandate: structuredClone(stored),
      receipt: pendingReceipt(),
      replay: false,
    }),
    complete: async (_tenant, _receipt, completion, completedAt) => {
      completions.push(completion);
      return {
        ...pendingReceipt(),
        ...completion,
        receiptHash: `completed-${completion.outcome}`,
        updatedAt: completedAt.toISOString(),
      };
    },
    findReceipt: async () => undefined,
    appendAudit: async () => {},
    listAudit: async () => [],
    readiness: async () => true,
    close: async () => {},
  };
}

const allowPolicy: PolicyAdapter = { evaluate: async () => ({ outcome: "allow" }) };

test("gateway reserves, exchanges, executes and completes without exposing either credential", async () => {
  const completions: Array<Parameters<MandateRepository["complete"]>[2]> = [];
  const credential = "downstream-super-secret";
  let exchangeInput: Parameters<TokenExchangeAdapter["exchange"]>[0] | undefined;
  const gateway = new ExecutionGateway({
    repository: repository(completions),
    policy: allowPolicy,
    tokenExchange: {
      exchange: async (input) => {
        exchangeInput = input;
        return { accessToken: credential, tokenType: "Bearer", audience: input.audience, expiresAt: "2099-01-01T00:00:00.000Z" };
      },
    },
    downstream: {
      execute: async () => ({ status: 201, body: { access_token: credential, note: `Bearer ${credential}`, id: "pay-42" } }),
    },
    now: () => new Date(now),
    id: () => "decision-1",
  });

  const result = await gateway.execute(request());
  assert.equal(result.decision.code, "allowed");
  assert.equal(result.receipt?.outcome, "succeeded");
  assert.equal(JSON.stringify(result).includes(credential), false);
  assert.equal(JSON.stringify(completions).includes(credential), false);
  assert.equal(exchangeInput?.subjectGrant, request().grant);
  assert.equal(completions[0]?.outcome, "succeeded");
});

test("gateway reconciles a timeout once and persists unresolved side effects as ambiguous", async () => {
  const completions: Array<Parameters<MandateRepository["complete"]>[2]> = [];
  let executions = 0;
  let reconciliations = 0;
  const downstream: DownstreamExecutor = {
    execute: async () => { executions += 1; throw new DownstreamTimeoutError(); },
    reconcile: async () => { reconciliations += 1; return undefined; },
  };
  const gateway = new ExecutionGateway({
    repository: repository(completions),
    policy: allowPolicy,
    tokenExchange: { exchange: async (input) => ({ accessToken: "secret", tokenType: "Bearer", audience: input.audience, expiresAt: "2099-01-01T00:00:00.000Z" }) },
    downstream,
    now: () => new Date(now),
    id: () => "decision-2",
  });
  const result = await gateway.execute(request());
  assert.equal(executions, 1);
  assert.equal(reconciliations, 1);
  assert.equal(result.decision.code, "downstream_ambiguous");
  assert.equal(result.receipt?.outcome, "ambiguous");
  assert.deepEqual(completions, [{ outcome: "ambiguous" }]);
});

test("policy outage fails closed and persists a redacted pre-reserve denial", async () => {
  const repo = repository([]);
  const audit: unknown[] = [];
  repo.appendAudit = async (event) => { audit.push(event); };
  let reserveCalls = 0;
  repo.reserve = async () => { reserveCalls += 1; throw new Error("not reached"); };
  const gateway = new ExecutionGateway({
    repository: repo,
    policy: { evaluate: async () => { throw new Error("OPA unavailable with secret-value"); } },
    tokenExchange: { exchange: async () => { throw new Error("not reached"); } },
    downstream: { execute: async () => { throw new Error("not reached"); } },
    now: () => new Date(now),
    id: () => "decision-policy-outage",
  });
  const result = await gateway.execute(request());
  assert.equal(result.decision.code, "policy_indeterminate");
  assert.equal(reserveCalls, 0);
  assert.equal((audit[0] as { code: string }).code, "policy_indeterminate");
  assert.equal(JSON.stringify(audit).includes("secret-value"), false);
  assert.equal(JSON.stringify(audit).includes(request().grant), false);
});

test("idempotent replay maps stored outcomes and bypasses policy/execution after revocation", async () => {
  for (const [outcome, expectedCode, expectedAllowed] of [
    ["succeeded", "allowed", true],
    ["failed", "downstream_failed", false],
    ["ambiguous", "downstream_ambiguous", false],
    ["pending", "downstream_ambiguous", false],
  ] as const) {
    const repo = repository([]);
    const receipt = { ...pendingReceipt(), outcome, envelopeHash: canonicalHash(envelope()) };
    repo.find = async () => ({ ...mandate(), status: "revoked" });
    repo.findReceipt = async () => receipt;
    let policyCalls = 0;
    let exchangeCalls = 0;
    const gateway = new ExecutionGateway({
      repository: repo,
      policy: { evaluate: async () => { policyCalls += 1; return { outcome: "deny" }; } },
      tokenExchange: { exchange: async () => { exchangeCalls += 1; throw new Error("not reached"); } },
      downstream: { execute: async () => { throw new Error("not reached"); } },
      now: () => new Date(now),
      id: () => "decision-replay",
    });
    const result = await gateway.execute(request());
    assert.equal(result.decision.code, expectedCode);
    assert.equal(result.decision.allowed, expectedAllowed);
    assert.equal(result.receipt?.outcome, outcome);
    assert.equal(policyCalls, 0);
    assert.equal(exchangeCalls, 0);
  }
});

test("idempotency hash conflict is denied and audited without rerunning the side effect", async () => {
  const repo = repository([]);
  repo.findReceipt = async () => ({ ...pendingReceipt(), outcome: "succeeded", envelopeHash: "different-envelope" });
  const audit: unknown[] = [];
  repo.appendAudit = async (event) => { audit.push(event); };
  let downstreamCalls = 0;
  const gateway = new ExecutionGateway({
    repository: repo,
    policy: allowPolicy,
    tokenExchange: { exchange: async () => { throw new Error("not reached"); } },
    downstream: { execute: async () => { downstreamCalls += 1; return { status: 200, body: null }; } },
    now: () => new Date(now),
    id: () => "decision-conflict",
  });
  const result = await gateway.execute(request());
  assert.equal(result.decision.code, "idempotency_conflict");
  assert.equal(downstreamCalls, 0);
  assert.equal(JSON.stringify(audit).includes(request().grant), false);
  assert.equal((audit[0] as { code: string }).code, "idempotency_conflict");
});

test("a stolen idempotency key cannot replay a receipt with an invalid grant secret", async () => {
  const repo = repository([]);
  let receiptLookups = 0;
  repo.findReceipt = async () => {
    receiptLookups += 1;
    return { ...pendingReceipt(), outcome: "succeeded", envelopeHash: canonicalHash(envelope()) };
  };
  const audit: Array<{ code: string }> = [];
  repo.appendAudit = async (event) => { audit.push(event); };
  const gateway = new ExecutionGateway({
    repository: repo,
    policy: allowPolicy,
    tokenExchange: { exchange: async () => { throw new Error("not reached"); } },
    downstream: { execute: async () => { throw new Error("not reached"); } },
    now: () => new Date(now),
    id: () => "decision-invalid-grant",
  });
  const result = await gateway.execute({ ...request(), grant: "mandate-1.stolen-secret" });
  assert.equal(result.decision.code, "invalid_grant");
  assert.equal(receiptLookups, 0);
  assert.deepEqual(audit.map((event) => event.code), ["invalid_grant"]);
});

test("RFC 8693 adapter sends an RFC 8707 resource and verifies the returned audience", async () => {
  let form: URLSearchParams | undefined;
  let authorization: string | null = null;
  const adapter = new HttpTokenExchangeAdapter({
    tokenEndpoint: "https://identity.example/token",
    clientId: "gateway",
    clientSecret: "client-secret",
    allowedAudiences: ["https://payments.sandbox"],
    now: () => new Date(now),
    fetch: async (_url, init) => {
      form = new URLSearchParams(String(init?.body));
      authorization = new Headers(init?.headers).get("authorization");
      return new Response(JSON.stringify({
        access_token: "exchanged-secret",
        issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
        token_type: "Bearer",
        expires_in: 60,
        resource: "https://payments.sandbox",
      }), { status: 200 });
    },
  });
  const result = await adapter.exchange({
    tenantId: "pilot", principalId: "user:alice", agentId: "agent:pay", subjectGrant: "mandate.secret",
    audience: "https://payments.sandbox", scope: "payment.create",
  });
  assert.equal(form?.get("grant_type"), "urn:ietf:params:oauth:grant-type:token-exchange");
  assert.equal(form?.get("resource"), "https://payments.sandbox");
  assert.equal(form?.get("subject_token"), "mandate.secret");
  assert.match(authorization ?? "", /^Basic /);
  assert.equal(result.audience, "https://payments.sandbox");

  const mismatch = new HttpTokenExchangeAdapter({
    tokenEndpoint: "https://identity.example/token",
    clientId: "gateway",
    allowedAudiences: ["https://payments.sandbox"],
    fetch: async () => new Response(JSON.stringify({ access_token: "do-not-leak", issued_token_type: "urn:ietf:params:oauth:token-type:access_token", token_type: "Bearer", expires_in: 60, audience: "https://attacker.example" })),
  });
  await assert.rejects(() => mismatch.exchange({
    tenantId: "pilot", principalId: "user:alice", agentId: "agent:pay", subjectGrant: "mandate.secret",
    audience: "https://payments.sandbox", scope: "payment.create",
  }), (error: unknown) => error instanceof TokenExchangeError && !error.message.includes("do-not-leak"));
});

test("HTTP executor requires DPoP proof and gives reconciliation authenticated internal context", async () => {
  const env = envelope();
  const credential = { accessToken: "dpop-secret", tokenType: "DPoP" as const, audience: env.audience, expiresAt: "2099-01-01T00:00:00.000Z" };
  const withoutProof = new HttpDownstreamExecutor({ url: "https://payments.sandbox/actions", audience: env.audience, fetch: async () => new Response("{}") });
  await assert.rejects(() => withoutProof.execute({ envelope: env, credential, idempotencyKey: "idem" }), /DPoP proof is not configured/);

  let headers = new Headers();
  let reconciliationSawCredential = false;
  const executor = new HttpDownstreamExecutor({
    url: "https://payments.sandbox/actions",
    audience: env.audience,
    dpopProof: ({ credential: internal }) => internal.accessToken === credential.accessToken ? "signed-proof" : "",
    fetch: async (_url, init) => {
      headers = new Headers(init?.headers);
      return new Response(JSON.stringify({ ok: true, token: credential.accessToken }), { status: 201 });
    },
    reconcile: async ({ credential: internal }) => {
      reconciliationSawCredential = internal.accessToken === credential.accessToken;
      return { status: 200, body: { access_token: internal.accessToken, state: "committed" } };
    },
  });
  const executed = await executor.execute({ envelope: env, credential, idempotencyKey: "idem" });
  assert.equal(headers.get("authorization"), "DPoP dpop-secret");
  assert.equal(headers.get("dpop"), "signed-proof");
  assert.equal(JSON.stringify(executed).includes(credential.accessToken), false);

  const reconciled = await executor.reconcile({ envelope: env, credential, idempotencyKey: "idem" });
  assert.equal(reconciliationSawCredential, true);
  assert.equal(JSON.stringify(reconciled).includes(credential.accessToken), false);
});

test("HTTP executor classifies an aborted mutation as ambiguous timeout", async () => {
  const env = envelope();
  const executor = new HttpDownstreamExecutor({
    url: "https://payments.sandbox/actions",
    audience: env.audience,
    timeoutMs: 5,
    fetch: async (_url, init) => await new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")), { once: true });
    }),
  });
  await assert.rejects(() => executor.execute({
    envelope: env,
    credential: { accessToken: "secret", tokenType: "Bearer", audience: env.audience, expiresAt: "2099-01-01T00:00:00.000Z" },
    idempotencyKey: "idem-timeout",
  }), DownstreamTimeoutError);
});

function envelope(): ActionEnvelope {
  const requestValue = request();
  return {
    version: ACTION_ENVELOPE_VERSION,
    tenantId: requestValue.tenantId,
    principalId: "user:alice",
    agentId: requestValue.agentId,
    workloadId: requestValue.workloadId,
    taskId: requestValue.taskId,
    audience: requestValue.audience,
    action: requestValue.action,
    resource: requestValue.resource,
    parameters: requestValue.parameters,
  };
}
