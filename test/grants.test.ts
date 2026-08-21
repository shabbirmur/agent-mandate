import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import type { MandateRepository } from "../src/ports.js";
import {
  MandateService,
  MandateServiceError,
  canonicalJson,
  hashActionEnvelope,
  parseGrant,
} from "../src/grants/index.js";
import type {
  ActionEnvelope,
  ActionRequest,
  AuditEvent,
  ExecutionCompletion,
  ExecutionReceipt,
  ExecutionReservation,
  Mandate,
  MandateCreationInput,
  MandateRequest,
  PrincipalContext,
} from "../src/types.js";

const now = new Date("2026-08-21T10:00:00.000Z");
const principal: PrincipalContext = {
  tenantId: "pilot",
  principalId: "user:alice",
  issuer: "https://id.example",
  subject: "user:alice",
};

function input(overrides: Partial<MandateCreationInput> = {}): MandateCreationInput {
  const approvedEnvelope = {
    version: "am.action.v1" as const,
    audience: "https://payments.sandbox",
    action: "payment.create",
    resource: "payment:42",
    parameters: { recipient: "merchant:7", amount: 480, currency: "USD" },
  };
  return {
    agentId: "agent:payments",
    workloadId: "workload:payments-1",
    taskId: "task:pay-42",
    audience: "https://payments.sandbox",
    actions: ["payment.create"],
    resources: ["payment:42"],
    expiresInSeconds: 300,
    constraints: { maxCalls: 2, equals: { currency: "USD" }, maximum: { amount: 500 } },
    approval: { required: true, approvedEnvelope },
    ...overrides,
  };
}

class RecordingRepository implements MandateRepository {
  readonly mandates = new Map<string, Mandate>();
  readonly auditEvents: AuditEvent[] = [];
  lastGrantHash?: string;
  #nextId = 1;

  async create(request: MandateRequest, grantHash: string, createdAt: Date): Promise<Mandate> {
    this.lastGrantHash = grantHash;
    const mandate: Mandate = {
      ...structuredClone(request),
      id: `mandate-${this.#nextId++}`,
      grantHash,
      issuedAt: createdAt.toISOString(),
      expiresAt: new Date(createdAt.getTime() + request.expiresInSeconds * 1_000).toISOString(),
      status: "active",
      successfulUses: 0,
    };
    this.mandates.set(mandate.id, mandate);
    return structuredClone(mandate);
  }

  async find(tenantId: string, mandateId: string): Promise<Mandate | undefined> {
    const mandate = this.mandates.get(mandateId);
    return mandate?.tenantId === tenantId ? structuredClone(mandate) : undefined;
  }

  async revoke(tenantId: string, mandateId: string): Promise<boolean> {
    const mandate = this.mandates.get(mandateId);
    if (mandate?.tenantId !== tenantId) return false;
    mandate.status = "revoked";
    return true;
  }

  async findReceipt(_tenantId: string, _mandateId: string, _idempotencyKey: string): Promise<ExecutionReceipt | undefined> {
    return undefined;
  }

  async reserve(
    _request: ActionRequest,
    _envelope: ActionEnvelope,
    _envelopeHash: string,
    _decisionId: string,
    _reservedAt: Date,
  ): Promise<ExecutionReservation> {
    throw new Error("not used by mandate service tests");
  }

  async complete(
    _tenantId: string,
    _receiptId: string,
    _completion: ExecutionCompletion,
    _completedAt: Date,
  ): Promise<ExecutionReceipt> {
    throw new Error("not used by mandate service tests");
  }

  async appendAudit(event: AuditEvent): Promise<void> {
    this.auditEvents.push(structuredClone(event));
  }

  async listAudit(_tenantId: string, _limit?: number): Promise<AuditEvent[]> {
    return structuredClone(this.auditEvents);
  }

  async readiness(): Promise<boolean> {
    return true;
  }

  async close(): Promise<void> {}
}

async function rejectsWithCode(promise: Promise<unknown>, code: MandateServiceError["code"]): Promise<void> {
  await assert.rejects(promise, (error: unknown) => error instanceof MandateServiceError && error.code === code);
}

test("issuance derives principal identity, persists only a SHA-256 secret hash, and caps TTL", async () => {
  const repository = new RecordingRepository();
  const service = new MandateService(repository, { now: () => now });
  const bodyWithSpoofedIdentity = {
    ...input(),
    tenantId: "attacker",
    principalId: "user:mallory",
    approval: {
      ...input().approval,
      approvedBy: "user:mallory",
      approvedAt: "1999-01-01T00:00:00.000Z",
    },
  } as unknown as MandateCreationInput;
  const issued = await service.issue(principal, bodyWithSpoofedIdentity);
  const parsed = parseGrant(issued.grant);

  assert.ok(parsed);
  assert.equal(parsed.mandateId, issued.mandate.id);
  assert.equal(parsed.secret.length, 43);
  assert.equal(repository.lastGrantHash, createHash("sha256").update(parsed.secret).digest("base64url"));
  assert.equal(issued.mandate.tenantId, "pilot");
  assert.equal(issued.mandate.principalId, "user:alice");
  assert.equal(issued.mandate.approval?.approvedBy, "user:alice");
  assert.equal(issued.mandate.approval?.approvedAt, now.toISOString());
  assert.equal("grantHash" in issued.mandate, false);
  assert.equal(JSON.stringify([...repository.mandates.values()]).includes(parsed.secret), false);

  await rejectsWithCode(service.issue(principal, input({ expiresInSeconds: 3_601 })), "invalid_request");
  await service.issue(principal, input({ expiresInSeconds: 3_600 }));
});

test("required approval is bound server-side to the exact canonical envelope and authenticated approver", async () => {
  const repository = new RecordingRepository();
  const service = new MandateService(repository, { now: () => now });
  const approvedEnvelope = {
    version: "am.action.v1" as const,
    audience: "https://payments.sandbox",
    action: "payment.create",
    resource: "payment:42",
    parameters: { recipient: "merchant:7", amount: 480, currency: "USD" },
  };
  const issued = await service.issue(principal, input({ approval: { required: true, approvedEnvelope } }));
  const expectedEnvelope: ActionEnvelope = {
    ...approvedEnvelope,
    tenantId: principal.tenantId,
    principalId: principal.principalId,
    agentId: issued.mandate.agentId,
    workloadId: issued.mandate.workloadId,
    taskId: issued.mandate.taskId,
  };

  assert.deepEqual(issued.mandate.approval, {
    required: true,
    approvedBy: "user:alice",
    approvedAt: now.toISOString(),
    envelopeHash: hashActionEnvelope(expectedEnvelope),
  });
  assert.notEqual(
    issued.mandate.approval?.envelopeHash,
    hashActionEnvelope({ ...expectedEnvelope, parameters: { ...expectedEnvelope.parameters, amount: 481 } }),
  );
  await rejectsWithCode(service.issue(principal, input({ approval: { required: true } })), "approval_required");
  await rejectsWithCode(
    service.issue(principal, input({ approval: { required: true, approvedEnvelope: { ...approvedEnvelope, audience: "https://evil.example" } } })),
    "approval_mismatch",
  );
});

test("the pilot high-risk action cannot be issued without a required exact approval", async () => {
  const repository = new RecordingRepository();
  const service = new MandateService(repository, { now: () => now });
  const approvedEnvelope = input().approval?.approvedEnvelope;
  assert.ok(approvedEnvelope);

  await rejectsWithCode(service.issue(principal, input({ approval: undefined })), "approval_required");
  await rejectsWithCode(service.issue(principal, input({ approval: { required: false } })), "approval_required");
  await rejectsWithCode(
    service.issue(principal, input({ approval: { required: false, approvedEnvelope } })),
    "approval_required",
  );
  await rejectsWithCode(
    service.issue(
      principal,
      input({
        actions: ["payment.create", "payment.read"],
        approval: { required: true, approvedEnvelope: { ...approvedEnvelope, action: "payment.read" } },
      }),
    ),
    "approval_mismatch",
  );
});

test("lower-risk actions may omit approval while malformed grant inputs fail closed", async () => {
  const repository = new RecordingRepository();
  const service = new MandateService(repository, { now: () => now });
  const issued = await service.issue(
    principal,
    input({ actions: ["payment.read"], approval: undefined }),
  );
  assert.equal(issued.mandate.approval, undefined);

  const malformed = [
    input({ actions: ["payment.create", "payment.create"] }),
    input({ constraints: null as unknown as MandateCreationInput["constraints"] }),
    input({ approval: null as unknown as MandateCreationInput["approval"] }),
    input({ constraints: { maximum: { amount: Number.NaN } } }),
  ];
  for (const request of malformed) await rejectsWithCode(service.issue(principal, request), "invalid_request");
});

test("canonical JSON is recursive and deterministic while rejecting non-JSON data", () => {
  assert.equal(canonicalJson({ z: [3, { b: true, a: "x" }], a: null }), '{"a":null,"z":[3,{"a":"x","b":true}]}');
  assert.equal(canonicalJson({ b: 2, a: 1 }), canonicalJson({ a: 1, b: 2 }));
  assert.throws(() => canonicalJson({ amount: Number.NaN }));
  assert.throws(() => canonicalJson({ missing: undefined }));
});

test("a child mandate may only attenuate every parent binding, authority set, constraint, and expiry", async () => {
  const repository = new RecordingRepository();
  const service = new MandateService(repository, { now: () => now });
  const parent = await service.issue(
    principal,
    input({
      actions: ["payment.create", "payment.cancel"],
      resources: ["payment:42", "payment:43"],
      expiresInSeconds: 600,
      constraints: { maxCalls: 4, equals: { currency: "USD" }, maximum: { amount: 500 } },
    }),
  );
  const child = await service.issue(
    principal,
    input({
      parentMandateId: parent.mandate.id,
      expiresInSeconds: 300,
      constraints: { maxCalls: 1, equals: { currency: "USD", amount: 400, recipient: "merchant:7" } },
      approval: {
        required: true,
        approvedEnvelope: {
          ...input().approval!.approvedEnvelope!,
          parameters: { recipient: "merchant:7", amount: 400, currency: "USD" },
        },
      },
    }),
  );
  assert.equal(child.mandate.parentMandateId, parent.mandate.id);

  const broaderChildren: MandateCreationInput[] = [
    input({ parentMandateId: parent.mandate.id, agentId: "agent:other" }),
    input({ parentMandateId: parent.mandate.id, workloadId: "workload:other" }),
    input({ parentMandateId: parent.mandate.id, taskId: "task:other" }),
    input({
      parentMandateId: parent.mandate.id,
      audience: "https://other.example",
      approval: {
        required: true,
        approvedEnvelope: { ...input().approval!.approvedEnvelope!, audience: "https://other.example" },
      },
    }),
    input({ parentMandateId: parent.mandate.id, actions: ["refund.create"], approval: undefined }),
    input({
      parentMandateId: parent.mandate.id,
      resources: ["payment:99"],
      approval: {
        required: true,
        approvedEnvelope: { ...input().approval!.approvedEnvelope!, resource: "payment:99" },
      },
    }),
    input({ parentMandateId: parent.mandate.id, expiresInSeconds: 601 }),
    input({ parentMandateId: parent.mandate.id, constraints: { maxCalls: 5, equals: { currency: "USD" }, maximum: { amount: 500 } } }),
    input({ parentMandateId: parent.mandate.id, constraints: { maxCalls: 1, maximum: { amount: 500 } } }),
    input({ parentMandateId: parent.mandate.id, constraints: { maxCalls: 1, equals: { currency: "USD" }, maximum: { amount: 501 } } }),
  ];
  for (const broader of broaderChildren) {
    await rejectsWithCode(service.issue(principal, broader), "delegation_amplification");
  }
});

test("parent status and authenticated principal scope control delegation and revocation", async () => {
  const repository = new RecordingRepository();
  const service = new MandateService(repository, { now: () => now });
  const parent = await service.issue(principal, input());
  const mallory = { ...principal, principalId: "user:mallory", subject: "user:mallory" };

  await rejectsWithCode(service.issue(mallory, input({ parentMandateId: parent.mandate.id })), "delegation_amplification");
  assert.equal(await service.revoke(mallory, parent.mandate.id), false);
  assert.equal(await service.revoke(principal, parent.mandate.id), true);
  await rejectsWithCode(service.issue(principal, input({ parentMandateId: parent.mandate.id })), "revoked");
});
