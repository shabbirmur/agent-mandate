import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { canonicalHash } from "../src/canonical.js";
import { PostgresApprovalRepository, buildApprovalIntent, hashOpaqueHandle } from "../src/approvals/index.js";
import { PostgresProviderConnectionRepository } from "../src/connections/index.js";
import { hashGrantSecret } from "../src/grants/index.js";
import { ACTION_ENVELOPE_VERSION, type ApprovalEvidence, type MandateRequest } from "../src/types.js";
import { postgresTest } from "./support/postgres.js";

const NOW = new Date("2026-08-26T08:00:00.000Z");
const PROFILE_HASH = canonicalHash({ profile: "github.issue.create.v1" });
const RESUME_HASH = hashOpaqueHandle(randomBytes(32).toString("base64url"));
const SESSION_HASH = hashOpaqueHandle("oauth-session:alice");

postgresTest("approval request persists immutable intent and append-only decision evidence", async ({ pool, repository }) => {
  const approvals = new PostgresApprovalRepository(pool);
  const connections = new PostgresProviderConnectionRepository(pool);
  await seedConnection(connections);
  const intent = approvalIntent("approval-1");
  const created = await approvals.create({
    intent,
    agentId: "agent:codex",
    workloadId: "workload:codex",
    workflowId: "workflow:one",
    mcpSessionHash: SESSION_HASH,
    resumeHandleHash: RESUME_HASH,
    idempotencyKey: intent.idempotencyKey,
    now: NOW,
  });
  assert.equal(created.request.status, "pending");
  assert.equal((await approvals.find("tenant:one", "approval-1"))?.intentHash, canonicalHash(intent));
  assert.equal(await approvals.find("tenant:two", "approval-1"), undefined);
  assert.equal((await approvals.findByResumeHandle("tenant:one", RESUME_HASH))?.id, "approval-1");

  await assert.rejects(
    approvals.decide({
      tenantId: "tenant:one",
      requestId: "approval-1",
      expectedPrincipalId: "user:alice",
      principalId: "user:mallory",
      authenticatedAt: NOW.toISOString(),
      intentHash: created.request.intentHash,
      decision: "approved",
    }, new Date(NOW.getTime() + 1_000)),
    /approval_mismatch/,
  );
  const approved = await approvals.decide({
    tenantId: "tenant:one",
    requestId: "approval-1",
    expectedPrincipalId: "user:alice",
    principalId: "user:alice",
    authenticatedAt: NOW.toISOString(),
    intentHash: created.request.intentHash,
    decision: "approved",
  }, new Date(NOW.getTime() + 1_000));
  assert.equal(approved.status, "approved");

  const mandate = await repository.create(mandateRequest(approved.id, approved.intentHash, approvalEvidence(approved)), hashGrantSecret("product-secret"), new Date(NOW.getTime() + 2_000));
  const attached = await approvals.attachMandate(
    "tenant:one",
    approved.id,
    approved.intentHash,
    mandate.id,
    new Date(NOW.getTime() + 2_000),
  );
  assert.equal(attached.mandateId, mandate.id);
  assert.equal((await repository.find("tenant:one", mandate.id))?.approvalRequestId, approved.id);

  await approvals.updateExecution("tenant:one", approved.id, approved.intentHash, "dispatching", undefined, new Date(NOW.getTime() + 3_000));
  const reservation = await repository.reserve({
    grant: `${mandate.id}.product-secret`,
    tenantId: "tenant:one",
    agentId: "agent:codex",
    workloadId: "workload:codex",
    taskId: "workflow:one",
    audience: approved.envelope.audience,
    action: approved.envelope.action,
    resource: approved.envelope.resource,
    parameters: approved.envelope.parameters,
    idempotencyKey: approved.idempotencyKey,
  }, approved.envelope, approved.envelopeHash, "decision-product-1", new Date(NOW.getTime() + 3_000));
  assert.equal(reservation.decision.allowed, true);
  const ambiguous = await approvals.updateExecution(
    "tenant:one",
    approved.id,
    approved.intentHash,
    "ambiguous",
    reservation.receipt!.id,
    new Date(NOW.getTime() + 4_000),
  );
  assert.equal(ambiguous.executionStatus, "ambiguous");
  const reconciled = await approvals.updateExecution(
    "tenant:one",
    approved.id,
    approved.intentHash,
    "succeeded",
    reservation.receipt!.id,
    new Date(NOW.getTime() + 5_000),
  );
  assert.equal(reconciled.executionStatus, "succeeded");
  assert.deepEqual((await approvals.listEvents("tenant:one", approved.id)).map((event) => event.type), [
    "requested",
    "approved",
    "execution.updated",
    "execution.updated",
    "execution.updated",
    "execution.updated",
  ]);

  await assert.rejects(
    pool.query("UPDATE approval_events SET type = 'cancelled' WHERE tenant_id = $1", ["tenant:one"]),
    /append-only/,
  );
  const down = await readFile(new URL("../migrations/002_product_control_plane.down.sql", import.meta.url), "utf8");
  await assert.rejects(pool.query(down), /refusing to delete product approval\/provider evidence/);
});

postgresTest("approval decision and expiry races have one terminal winner", async ({ pool }) => {
  const approvals = new PostgresApprovalRepository(pool);
  const connections = new PostgresProviderConnectionRepository(pool);
  await seedConnection(connections);
  const intent = approvalIntent("approval-race", new Date(NOW.getTime() + 30_000));
  const created = await approvals.create({
    intent,
    agentId: "agent:codex",
    workloadId: "workload:codex",
    workflowId: "workflow:one",
    mcpSessionHash: SESSION_HASH,
    resumeHandleHash: hashOpaqueHandle("race-handle"),
    idempotencyKey: intent.idempotencyKey,
    now: NOW,
  });
  const decision = {
    tenantId: "tenant:one",
    requestId: created.request.id,
    expectedPrincipalId: "user:alice",
    principalId: "user:alice",
    authenticatedAt: NOW.toISOString(),
    intentHash: created.request.intentHash,
  };
  const outcomes = await Promise.allSettled([
    approvals.decide({ ...decision, decision: "approved" }, new Date(NOW.getTime() + 1_000)),
    approvals.decide({ ...decision, decision: "denied" }, new Date(NOW.getTime() + 1_000)),
  ]);
  assert.equal(outcomes.filter((outcome) => outcome.status === "fulfilled").length, 1);
  assert.equal(outcomes.filter((outcome) => outcome.status === "rejected").length, 1);
  assert.ok(["approved", "denied"].includes((await approvals.find("tenant:one", created.request.id))!.status));

  const expiringIntent = approvalIntent("approval-expiry", new Date(NOW.getTime() + 5_000));
  await approvals.create({
    intent: expiringIntent,
    agentId: "agent:codex",
    workloadId: "workload:codex",
    workflowId: "workflow:one",
    mcpSessionHash: SESSION_HASH,
    resumeHandleHash: hashOpaqueHandle("expiry-handle"),
    idempotencyKey: expiringIntent.idempotencyKey,
    now: NOW,
  });
  assert.equal(await approvals.expire(new Date(NOW.getTime() + 6_000)), 1);
  assert.equal((await approvals.find("tenant:one", "approval-expiry"))?.status, "expired");
});

postgresTest("provider connections bind active selected resources and contain only secret references", async ({ pool }) => {
  const connections = new PostgresProviderConnectionRepository(pool);
  await seedConnection(connections);
  const connection = await connections.findConnection("tenant:one", "github", "connection:github:123");
  assert.equal(connection?.secretRef, "env://GITHUB_APP_PRIVATE_KEY");
  assert.equal(connection?.metadata.installationId, 123);
  assert.equal((await connections.listResources("tenant:one", "github", connection!.id)).length, 1);
  assert.equal((await connections.findResource("tenant:one", connection!.id, "987654"))?.selector.repository, "octo/demo");
  assert.equal(await connections.findConnection("tenant:other", "github", connection!.id), undefined);

  await assert.rejects(
    connections.putConnection({
      id: "bad",
      tenantId: "tenant:one",
      providerId: "github",
      externalAccountId: "999",
      displayName: "unsafe",
      secretRef: "ghs_plaintext_token",
      metadata: {},
      status: "active",
    }, NOW),
    /invalid_secret_reference/,
  );
  assert.equal(await connections.setResourceStatus("tenant:one", connection!.id, "987654", "removed", new Date(NOW.getTime() + 1_000)), true);
  assert.equal((await connections.findResource("tenant:one", connection!.id, "987654"))?.status, "removed");
  assert.equal(await connections.setConnectionStatus("tenant:one", "github", connection!.id, "suspended", new Date(NOW.getTime() + 2_000)), true);
  assert.equal((await connections.findConnection("tenant:one", "github", connection!.id))?.status, "suspended");
});

async function seedConnection(connections: PostgresProviderConnectionRepository): Promise<void> {
  await connections.putConnection({
    id: "connection:github:123",
    tenantId: "tenant:one",
    providerId: "github",
    externalAccountId: "123",
    displayName: "Octo GitHub App",
    secretRef: "env://GITHUB_APP_PRIVATE_KEY",
    metadata: { installationId: 123 },
    status: "active",
  }, NOW);
  await connections.putResource({
    tenantId: "tenant:one",
    connectionId: "connection:github:123",
    providerResourceId: "987654",
    displayName: "octo/demo",
    selector: { repository: "octo/demo", owner: "octo", name: "demo", repositoryId: 987654 },
    status: "active",
  }, NOW);
}

function approvalIntent(requestId: string, expiresAt = new Date(NOW.getTime() + 300_000)) {
  const correlationId = `correlation_${requestId.replaceAll("-", "_")}`;
  return buildApprovalIntent({
    requestId,
    envelope: {
      version: ACTION_ENVELOPE_VERSION,
      tenantId: "tenant:one",
      principalId: "user:alice",
      agentId: "agent:codex",
      workloadId: "workload:codex",
      taskId: "workflow:one",
      audience: "https://api.github.com",
      action: "github.issue.create.v1",
      resource: "github:repository:987654",
      parameters: { repositoryId: 987654, repository: "octo/demo", title: "Exact title", body: "Exact body", correlationId },
    },
    profileId: "github.issue.create.v1",
    profileHash: PROFILE_HASH,
    providerId: "github",
    providerConnectionId: "connection:github:123",
    providerResourceId: "987654",
    idempotencyKey: correlationId,
    risk: "consequential",
    expiresAt: expiresAt.toISOString(),
    expectedApprover: "user:alice",
  });
}

function approvalEvidence(request: { id: string; intentHash: string; envelopeHash: string; profileId: string; profileHash: string; providerId: string; providerConnectionId: string; providerResourceId: string }): ApprovalEvidence {
  return {
    required: true,
    approvedBy: "user:alice",
    approvedAt: new Date(NOW.getTime() + 1_000).toISOString(),
    authenticatedAt: NOW.toISOString(),
    envelopeHash: request.envelopeHash,
    approvalRequestId: request.id,
    intentHash: request.intentHash,
    profileId: request.profileId,
    profileHash: request.profileHash,
    providerId: request.providerId,
    providerConnectionId: request.providerConnectionId,
    providerResourceId: request.providerResourceId,
  };
}

function mandateRequest(approvalRequestId: string, _intentHash: string, approval: ApprovalEvidence): MandateRequest {
  return {
    tenantId: "tenant:one",
    principalId: "user:alice",
    agentId: "agent:codex",
    workloadId: "workload:codex",
    taskId: "workflow:one",
    audience: "https://api.github.com",
    actions: ["github.issue.create.v1"],
    resources: ["github:repository:987654"],
    expiresInSeconds: 200,
    constraints: { maxCalls: 1 },
    approval,
    approvalRequestId,
  };
}
