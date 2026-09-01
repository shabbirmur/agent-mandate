import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { ACTION_ENVELOPE_VERSION, type ActionEnvelope, type ActionRequest, type MandateRequest } from "../src/types.js";
import {
  computeReceiptIntegrityHash,
  hashGrantSecret,
  sha256Base64Url,
  verifyGrantSecret,
} from "../src/storage/integrity.js";
import { revertMigrations } from "../src/storage/migrations.js";
import { postgresTest } from "./support/postgres.js";

const NOW = new Date("2026-08-21T00:00:00.000Z");
const ENVELOPE_HASH = sha256Base64Url("approved-envelope");

function mandateRequest(overrides: Partial<MandateRequest> = {}): MandateRequest {
  return {
    tenantId: "pilot",
    principalId: "user:alice",
    agentId: "agent:payments",
    workloadId: "workload:payments-1",
    taskId: "task:pay-42",
    audience: "https://payments.sandbox",
    actions: ["payment.create"],
    resources: ["payment:42"],
    expiresInSeconds: 300,
    constraints: {
      maxCalls: 2,
      equals: { currency: "USD", recipient: "merchant:one" },
      maximum: { amount: 500 },
    },
    approval: {
      required: true,
      approvedBy: "user:alice",
      approvedAt: NOW.toISOString(),
      envelopeHash: ENVELOPE_HASH,
    },
    ...overrides,
  };
}

function actionEnvelope(): ActionEnvelope {
  return {
    version: ACTION_ENVELOPE_VERSION,
    tenantId: "pilot",
    principalId: "user:alice",
    agentId: "agent:payments",
    workloadId: "workload:payments-1",
    taskId: "task:pay-42",
    audience: "https://payments.sandbox",
    action: "payment.create",
    resource: "payment:42",
    parameters: { amount: 480, currency: "USD", recipient: "merchant:one" },
  };
}

function actionRequest(grant: string, idempotencyKey: string): ActionRequest {
  const envelope = actionEnvelope();
  return {
    grant,
    tenantId: envelope.tenantId,
    agentId: envelope.agentId,
    workloadId: envelope.workloadId,
    taskId: envelope.taskId,
    audience: envelope.audience,
    action: envelope.action,
    resource: envelope.resource,
    parameters: envelope.parameters,
    idempotencyKey,
  };
}

test("grant and receipt integrity hashes are deterministic and domain shaped", () => {
  const secret = "secret-value";
  const hash = hashGrantSecret(secret);
  assert.match(hash, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(verifyGrantSecret(secret, hash), true);
  assert.equal(verifyGrantSecret("wrong", hash), false);

  const base = {
    id: "receipt-1",
    tenantId: "pilot",
    mandateId: "mandate-1",
    decisionId: "decision-1",
    principalId: "user:alice",
    agentId: "agent:payments",
    workloadId: "workload:payments-1",
    taskId: "task:pay-42",
    audience: "https://payments.sandbox",
    action: "payment.create",
    resource: "payment:42",
    envelopeVersion: ACTION_ENVELOPE_VERSION,
    envelopeHash: ENVELOPE_HASH,
    idempotencyKey: "idem-1",
    outcome: "pending" as const,
    attemptCount: 1,
    createdAt: NOW.toISOString(),
    updatedAt: NOW.toISOString(),
  };
  assert.equal(computeReceiptIntegrityHash(base), computeReceiptIntegrityHash({ ...base }));
  assert.notEqual(computeReceiptIntegrityHash(base), computeReceiptIntegrityHash({ ...base, action: "payment.refund" }));
});

postgresTest("migrations are reversible only while evidence tables are empty", async ({ pool }) => {
  await revertMigrations(pool);
  const remaining = await pool.query(
    "SELECT to_regclass('agent_mandates') AS mandates, to_regclass('audit_events') AS audit",
  );
  assert.equal(remaining.rows[0]?.mandates, null);
  assert.equal(remaining.rows[0]?.audit, null);
});

postgresTest("create/find/audit are tenant scoped and structured JSON round-trips safely", async ({ repository, pool }) => {
  const secret = "grant-secret";
  const created = await repository.create(mandateRequest(), hashGrantSecret(secret), NOW);
  assert.deepEqual(await repository.find("pilot", created.id), created);
  assert.equal(await repository.find("other-tenant", created.id), undefined);
  assert.deepEqual(created.constraints, mandateRequest().constraints);
  assert.deepEqual(created.approval, mandateRequest().approval);

  await repository.appendAudit({
    id: "external-denial",
    tenantId: "pilot",
    at: new Date(NOW.getTime() + 1_000).toISOString(),
    type: "action.denied",
    decisionId: "pre-reserve-decision",
    code: "policy_denied",
    details: { reason: "redacted deterministic denial" },
  });

  const events = await repository.listAudit("pilot");
  assert.deepEqual(events.map((event) => event.type), ["action.denied", "mandate.issued"]);
  assert.deepEqual(await repository.listAudit("other-tenant"), []);

  const down = await readFile(new URL("../migrations/001_pilot_storage.down.sql", import.meta.url), "utf8");
  await assert.rejects(pool.query(down), /refusing to delete audit\/receipt evidence/);
  assert.equal(await repository.readiness(), true);
});

postgresTest("reserve verifies grants, persists pending receipts, completes, replays, and rejects conflicts", async ({ repository }) => {
  const secret = "grant-secret";
  const mandate = await repository.create(mandateRequest(), hashGrantSecret(secret), NOW);
  const grant = `${mandate.id}.${secret}`;
  const request = actionRequest(grant, "idem-1");
  const envelope = actionEnvelope();

  const invalid = await repository.reserve({ ...request, grant: `${mandate.id}.wrong` }, envelope, ENVELOPE_HASH, "decision-invalid", NOW);
  assert.equal(invalid.decision.code, "invalid_grant");

  const reservation = await repository.reserve(request, envelope, ENVELOPE_HASH, "decision-1", NOW);
  assert.equal(reservation.decision.allowed, true);
  assert.equal(reservation.replay, false);
  assert.equal(reservation.receipt?.outcome, "pending");
  assert.equal(reservation.receipt?.receiptHash, computeReceiptIntegrityHash(reservation.receipt!));

  const completed = await repository.complete(
    "pilot",
    reservation.receipt!.id,
    { outcome: "succeeded", downstreamStatus: 201, resultHash: sha256Base64Url("redacted-result") },
    new Date(NOW.getTime() + 1_000),
  );
  assert.equal(completed.outcome, "succeeded");
  assert.notEqual(completed.receiptHash, reservation.receipt?.receiptHash);
  assert.equal(completed.receiptHash, computeReceiptIntegrityHash(completed));

  const repeatedCompletion = await repository.complete(
    "pilot",
    completed.id,
    { outcome: "succeeded", downstreamStatus: 201, resultHash: sha256Base64Url("redacted-result") },
    new Date(NOW.getTime() + 2_000),
  );
  assert.deepEqual(repeatedCompletion, completed);

  const replay = await repository.reserve(request, envelope, ENVELOPE_HASH, "ignored-new-decision", new Date(NOW.getTime() + 3_000));
  assert.equal(replay.replay, true);
  assert.equal(replay.decision.decisionId, "decision-1");
  assert.equal(replay.receipt?.outcome, "succeeded");
  assert.deepEqual(await repository.findReceipt("pilot", mandate.id, "idem-1"), completed);
  assert.equal(await repository.findReceipt("other-tenant", mandate.id, "idem-1"), undefined);

  const conflict = await repository.reserve(
    request,
    envelope,
    sha256Base64Url("mutated-envelope"),
    "decision-conflict",
    new Date(NOW.getTime() + 4_000),
  );
  assert.equal(conflict.decision.code, "idempotency_conflict");
  assert.equal((await repository.find("pilot", mandate.id))?.successfulUses, 1);
});

postgresTest("SELECT FOR UPDATE permits only one concurrent reservation of one-use authority", async ({ repository }) => {
  const secret = "grant-secret";
  const mandate = await repository.create(
    mandateRequest({ constraints: { ...mandateRequest().constraints, maxCalls: 1 } }),
    hashGrantSecret(secret),
    NOW,
  );
  const grant = `${mandate.id}.${secret}`;
  const [first, second] = await Promise.all([
    repository.reserve(actionRequest(grant, "concurrent-a"), actionEnvelope(), ENVELOPE_HASH, "decision-a", NOW),
    repository.reserve(actionRequest(grant, "concurrent-b"), actionEnvelope(), ENVELOPE_HASH, "decision-b", NOW),
  ]);
  assert.deepEqual(
    [first.decision.code, second.decision.code].sort(),
    ["allowed", "call_limit_exceeded"].sort(),
  );
  assert.equal((await repository.find("pilot", mandate.id))?.successfulUses, 1);
});

postgresTest("revoke is tenant scoped, immediate, idempotent, and audited once", async ({ repository }) => {
  const secret = "grant-secret";
  const mandate = await repository.create(mandateRequest(), hashGrantSecret(secret), NOW);
  assert.equal(await repository.revoke("other-tenant", mandate.id, NOW), false);
  assert.equal(await repository.revoke("pilot", mandate.id, NOW), true);
  assert.equal(await repository.revoke("pilot", mandate.id, new Date(NOW.getTime() + 1_000)), true);
  const denied = await repository.reserve(
    actionRequest(`${mandate.id}.${secret}`, "after-revoke"),
    actionEnvelope(),
    ENVELOPE_HASH,
    "decision-revoked",
    NOW,
  );
  assert.equal(denied.decision.code, "revoked");
  assert.equal((await repository.listAudit("pilot")).filter((event) => event.type === "mandate.revoked").length, 1);
});

postgresTest("immutable integrity events chain every receipt state and detect tampering", async ({ repository, pool }) => {
  const secret = "grant-secret";
  const mandate = await repository.create(mandateRequest(), hashGrantSecret(secret), NOW);
  const grant = `${mandate.id}.${secret}`;
  const first = await repository.reserve(actionRequest(grant, "chain-a"), actionEnvelope(), ENVELOPE_HASH, "chain-decision-a", NOW);
  const second = await repository.reserve(
    actionRequest(grant, "chain-b"),
    actionEnvelope(),
    ENVELOPE_HASH,
    "chain-decision-b",
    new Date(NOW.getTime() + 1_000),
  );
  assert.equal(second.receipt?.previousReceiptHash, first.receipt?.receiptHash);

  const firstCompleted = await repository.complete(
    "pilot",
    first.receipt!.id,
    { outcome: "ambiguous" },
    new Date(NOW.getTime() + 2_000),
  );
  const reconciled = await repository.complete(
    "pilot",
    first.receipt!.id,
    { outcome: "succeeded", downstreamStatus: 200, resultHash: sha256Base64Url("reconciled") },
    new Date(NOW.getTime() + 3_000),
  );
  assert.equal(firstCompleted.previousReceiptHash, second.receipt?.receiptHash);
  assert.notEqual(firstCompleted.receiptHash, first.receipt?.receiptHash);
  assert.equal(reconciled.previousReceiptHash, firstCompleted.receiptHash);
  assert.notEqual(reconciled.receiptHash, firstCompleted.receiptHash);
  assert.equal(reconciled.attemptCount, 2);
  assert.equal(await repository.verifyReceiptChain("pilot"), true);
  await assert.rejects(
    pool.query("UPDATE receipt_integrity_events SET event_hash = $1 WHERE tenant_id = $2", [sha256Base64Url("tamper"), "pilot"]),
    /append-only/,
  );
  await pool.query("UPDATE execution_receipts SET outcome = 'failed' WHERE tenant_id = $1 AND id = $2", ["pilot", first.receipt!.id]);
  assert.equal(await repository.verifyReceiptChain("pilot"), false);
});

postgresTest("concurrent sibling delegation cannot exceed the locked parent budget", async ({ repository }) => {
  const parent = await repository.create(
    mandateRequest({ constraints: { ...mandateRequest().constraints, maxCalls: 3 } }),
    hashGrantSecret("parent-secret"),
    NOW,
  );
  const child = (suffix: string): MandateRequest => ({
    ...mandateRequest({
      parentMandateId: parent.id,
      expiresInSeconds: 200,
      constraints: {
        maxCalls: 2,
        equals: { currency: "USD", recipient: "merchant:one", amount: 400 },
      },
    }),
    taskId: parent.taskId,
    approval: {
      required: false,
      approvedBy: `audit:${suffix}`,
    },
  });
  const siblings = await Promise.allSettled([
    repository.create(child("a"), hashGrantSecret("child-a"), NOW),
    repository.create(child("b"), hashGrantSecret("child-b"), NOW),
  ]);
  assert.equal(siblings.filter((result) => result.status === "fulfilled").length, 1);
  const rejected = siblings.find((result) => result.status === "rejected");
  assert.match(String(rejected?.status === "rejected" ? rejected.reason : ""), /delegation_amplification/);

  const parentGrant = `${parent.id}.parent-secret`;
  const first = await repository.reserve(actionRequest(parentGrant, "parent-own-a"), actionEnvelope(), ENVELOPE_HASH, "parent-decision-a", NOW);
  const second = await repository.reserve(actionRequest(parentGrant, "parent-own-b"), actionEnvelope(), ENVELOPE_HASH, "parent-decision-b", NOW);
  assert.equal(first.decision.code, "allowed");
  assert.equal(first.decision.remainingCalls, 0);
  assert.equal(second.decision.code, "call_limit_exceeded");
});
