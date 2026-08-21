import assert from "node:assert/strict";
import type { IncomingMessage, ServerResponse } from "node:http";
import { Readable } from "node:stream";
import test from "node:test";
import { createRequestHandler, type AppDependencies } from "../src/app.js";
import type { MandateRepository, PrincipalAuthenticator, WorkloadAuthenticator } from "../src/ports.js";
import type {
  ActionRequest,
  AuditEvent,
  ExecutionCompletion,
  ExecutionReceipt,
  ExecutionReservation,
  Mandate,
  MandateCreationInput,
  MandateRequest,
} from "../src/types.js";

class NoopRepository implements MandateRepository {
  async create(_request: MandateRequest, _grantHash: string, _now: Date): Promise<Mandate> { throw new Error("not used"); }
  async find(_tenantId: string, _mandateId: string): Promise<Mandate | undefined> { return undefined; }
  async revoke(_tenantId: string, _mandateId: string, _now: Date): Promise<boolean> { return false; }
  async findReceipt(_tenantId: string, _mandateId: string, _idempotencyKey: string): Promise<ExecutionReceipt | undefined> { return undefined; }
  async reserve(..._args: Parameters<MandateRepository["reserve"]>): Promise<ExecutionReservation> { throw new Error("not used"); }
  async complete(_tenantId: string, _receiptId: string, _completion: ExecutionCompletion, _now: Date): Promise<ExecutionReceipt> { throw new Error("not used"); }
  async appendAudit(_event: AuditEvent): Promise<void> {}
  async listAudit(_tenantId: string, _limit?: number): Promise<AuditEvent[]> { return []; }
  async readiness(): Promise<boolean> { return true; }
  async close(): Promise<void> {}
}

const principalAuthenticator: PrincipalAuthenticator = {
  async authenticate(_token, expectedNonce) {
    if (expectedNonce !== "nonce-1234567890") throw new Error("bad nonce");
    return { tenantId: "pilot", principalId: "user:alice", issuer: "https://id.example", subject: "user:alice", nonce: expectedNonce };
  },
};
const workloadAuthenticator: WorkloadAuthenticator = {
  async authenticate() {
    return { tenantId: "pilot", agentId: "agent:trusted", workloadId: "workload:trusted", issuer: "https://workload.example", subject: "spiffe://trusted" };
  },
};

test("HTTP boundary derives workload fields and keeps grants in headers", async () => {
  let issuedInput: MandateCreationInput | undefined;
  let executed: ActionRequest | undefined;
  const dependencies: AppDependencies = {
    tenantId: "pilot",
    repository: new NoopRepository(),
    principalAuthenticator,
    workloadAuthenticator,
    mandates: {
      async issue(_principal, input) {
        issuedInput = input;
        return { mandate: mandate(), grant: "mandate-1.secret" };
      },
      async revoke() { return true; },
    },
    gateway: {
      async execute(request) {
        executed = request;
        return { decision: { allowed: false, code: "task_mismatch", decisionId: "decision-1" } };
      },
    },
    log: () => undefined,
  };

  const creation = await invoke(dependencies, {
      method: "POST", path: "/v1/mandates", headers: headers("principal-token"),
      body: {
        agentId: "agent:trusted",
        workloadId: "workload:trusted",
        taskId: "task:1",
        audience: "https://payments.sandbox",
        actions: ["payment.read"],
        resources: ["payment:1"],
        expiresInSeconds: 60,
      },
    });
    assert.equal(creation.status, 201);
    assert.equal(issuedInput?.agentId, "agent:trusted");

    const execution = await invoke(dependencies, {
      method: "POST", path: "/v1/execute", headers: headers("mandate-1.secret", false),
      body: {
        tenantId: "attacker",
        agentId: "agent:attacker",
        workloadId: "workload:attacker",
        taskId: "task:prompt-injected",
        audience: "https://payments.sandbox",
        action: "payment.create",
        resource: "payment:1",
        parameters: {},
        idempotencyKey: "idempotency-1",
      },
    });
    assert.equal(execution.status, 403);
    assert.equal(executed?.grant, "mandate-1.secret");
    assert.equal(executed?.tenantId, "pilot");
    assert.equal(executed?.agentId, "agent:trusted");
    assert.equal(executed?.workloadId, "workload:trusted");
});

test("HTTP boundary requires nonce and exact target workload binding", async () => {
  const dependencies: AppDependencies = {
    tenantId: "pilot",
    repository: new NoopRepository(),
    principalAuthenticator,
    workloadAuthenticator,
    mandates: { async issue() { throw new Error("must not issue"); }, async revoke() { return false; } },
    gateway: { async execute() { throw new Error("must not execute"); } },
    log: () => undefined,
  };
    const missingNonce = await invoke(dependencies, {
      method: "POST", path: "/v1/mandates",
      headers: { authorization: "Bearer principal", "x-workload-authorization": "Bearer workload", "content-type": "application/json" },
      body: {},
    });
    assert.equal(missingNonce.status, 401);

    const mismatch = await invoke(dependencies, {
      method: "POST", path: "/v1/mandates", headers: headers("principal"),
      body: { agentId: "agent:attacker", workloadId: "workload:trusted" },
    });
    assert.equal(mismatch.status, 403);
    assert.equal(mismatch.body.error, "workload_mismatch");
});

function headers(authorization: string, includeNonce = true): Record<string, string> {
  return {
    authorization: `Bearer ${authorization}`,
    "x-workload-authorization": "Bearer workload-token",
    ...(includeNonce ? { "x-oidc-nonce": "nonce-1234567890" } : {}),
    "content-type": "application/json",
  };
}

function mandate(): Omit<Mandate, "grantHash"> {
  return {
    id: "mandate-1",
    tenantId: "pilot",
    principalId: "user:alice",
    agentId: "agent:trusted",
    workloadId: "workload:trusted",
    taskId: "task:1",
    audience: "https://payments.sandbox",
    actions: ["payment.read"],
    resources: ["payment:1"],
    expiresInSeconds: 60,
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    status: "active",
    successfulUses: 0,
  };
}

async function invoke(
  dependencies: AppDependencies,
  input: { method: string; path: string; headers: Record<string, string>; body: unknown },
): Promise<{ status: number; body: Record<string, any> }> {
  const request = Readable.from([JSON.stringify(input.body)]) as IncomingMessage;
  request.method = input.method;
  request.url = input.path;
  request.headers = input.headers;
  let responseBody = "";
  const response = {
    statusCode: 200,
    setHeader() { return this; },
    writeHead(status: number) { this.statusCode = status; return this; },
    end(chunk?: string) { responseBody = chunk ?? ""; return this; },
  } as unknown as ServerResponse;
  await createRequestHandler(dependencies)(request, response);
  return { status: response.statusCode, body: JSON.parse(responseBody) as Record<string, any> };
}
