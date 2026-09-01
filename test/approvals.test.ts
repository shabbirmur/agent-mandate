import assert from "node:assert/strict";
import test from "node:test";
import {
  ApprovalService,
  ApprovalServiceError,
  InMemoryApprovalRepository,
  InternalGrantDeriver,
  hashApprovalIntent,
} from "../src/approvals/index.js";
import { canonicalHash } from "../src/canonical.js";
import type { ApprovedMandateInput } from "../src/grants/index.js";
import { ACTION_ENVELOPE_VERSION, type ActionRequest, type ExecuteResult, type IssuedMandate } from "../src/types.js";

const NOW = new Date("2026-08-26T12:00:00.000Z");
const PROFILE_HASH = canonicalHash({ id: "github.issue.create.v1", schema: 1 });
const context = {
  tenantId: "tenant:one",
  principalId: "user:alice",
  agentId: "agent:codex",
  workloadId: "workload:codex-local",
  mcpSessionId: "oauth-session:one",
};
const prepared = {
  profileId: "github.issue.create.v1",
  profileHash: PROFILE_HASH,
  providerId: "github",
  providerConnectionId: "github-installation:123",
  providerResourceId: "987654",
  idempotencyKey: "test_key_0000000000",
  audience: "https://api.github.com",
  action: "github.issue.create",
  resource: "github:repository:987654",
  parameters: { title: "Fix authorization boundary", body: "Exact approved body" },
  risk: "consequential" as const,
};

test("approval intent and internal grant derivation are deterministic and domain bound", async () => {
  const fixture = createFixture();
  const proposal = await fixture.service.propose(context, prepared);
  const stored = await fixture.repository.find(context.tenantId, proposal.requestId);
  assert.ok(stored);
  assert.equal(hashApprovalIntent(stored.intent), proposal.intentHash);
  assert.equal(stored.envelopeHash, canonicalHash(stored.envelope));
  assert.equal(stored.envelope.version, ACTION_ENVELOPE_VERSION);
  assert.equal(stored.intent.maxCalls, 1);
  assert.equal(stored.intent.delegationAllowed, false);

  const deriver = new InternalGrantDeriver(Buffer.alloc(32, 7));
  assert.equal(deriver.derive("tenant:one", "request:one"), deriver.derive("tenant:one", "request:one"));
  assert.notEqual(deriver.derive("tenant:one", "request:one"), deriver.derive("tenant:two", "request:one"));
  assert.doesNotMatch(JSON.stringify(proposal), /grant/i);
});

test("proposal requires a separate exact approval and resumes only the stored envelope", async () => {
  const fixture = createFixture();
  const proposal = await fixture.service.propose(context, prepared);
  assert.equal((await fixture.service.resume(context, proposal.resumeHandle)).status, "pending");

  await assert.rejects(
    fixture.service.decide(
      { tenantId: context.tenantId, principalId: "user:mallory", issuer: "https://idp.example", subject: "mallory", authenticatedAt: NOW.toISOString() },
      {
        requestId: proposal.requestId,
        intentHash: proposal.intentHash,
        decision: "approved",
      },
    ),
    (error: unknown) => error instanceof ApprovalServiceError && error.code === "approval_not_found",
  );
  await assert.rejects(
    fixture.service.decide(
      { tenantId: context.tenantId, principalId: context.principalId, issuer: "https://idp.example", subject: "alice", authenticatedAt: NOW.toISOString() },
      {
        requestId: proposal.requestId,
        intentHash: canonicalHash("mutated"),
        decision: "approved",
      },
    ),
    /approval_mismatch/,
  );

  await fixture.service.decide(
    { tenantId: context.tenantId, principalId: context.principalId, issuer: "https://idp.example", subject: "alice", authenticatedAt: NOW.toISOString() },
    {
      requestId: proposal.requestId,
      intentHash: proposal.intentHash,
      decision: "approved",
    },
  );
  const result = await fixture.service.resume(context, proposal.resumeHandle);
  assert.equal(result.status, "succeeded");
  assert.equal(fixture.issued.length, 1);
  assert.equal(fixture.executed.length, 1);
  assert.deepEqual(fixture.executed[0]?.parameters, prepared.parameters);
  assert.equal(fixture.executed[0]?.resource, prepared.resource);
  assert.equal(fixture.executed[0]?.action, prepared.action);
  assert.equal(fixture.issued[0]?.input.approval.intentHash, proposal.intentHash);
  assert.equal(fixture.issued[0]?.input.approval.profileHash, PROFILE_HASH);
  assert.doesNotMatch(JSON.stringify(result), /internal-secret|github-token/);

  const replay = await fixture.service.resume(context, proposal.resumeHandle);
  assert.equal(replay.status, "succeeded");
  assert.equal(fixture.issued.length, 1);
  assert.equal(fixture.executed.length, 1);

  const events = await fixture.repository.listEvents(context.tenantId, proposal.requestId);
  assert.deepEqual(events.map((event) => event.type), [
    "requested",
    "approved",
    "execution.updated",
    "execution.updated",
    "execution.updated",
  ]);
});

test("resume handle is bound to principal, workload, and authenticated MCP session", async () => {
  const fixture = createFixture();
  const proposal = await fixture.service.propose(context, prepared);
  for (const changed of [
    { ...context, principalId: "user:bob" },
    { ...context, workloadId: "workload:other" },
    { ...context, mcpSessionId: "oauth-session:stolen" },
    { ...context, tenantId: "tenant:other" },
  ]) {
    await assert.rejects(
      fixture.service.resume(changed, proposal.resumeHandle),
      (error: unknown) => error instanceof ApprovalServiceError && error.code === "approval_not_found",
    );
  }
});

test("profile or provider connection drift fails closed before execution", async () => {
  let active = true;
  let currentHash: string | undefined = PROFILE_HASH;
  const fixture = createFixture({
    currentProfileHash: () => currentHash,
    connectionIsActive: async () => active,
  });
  const proposal = await fixture.service.propose(context, prepared);
  await fixture.service.decide(
    { tenantId: context.tenantId, principalId: context.principalId, issuer: "https://idp.example", subject: "alice", authenticatedAt: NOW.toISOString() },
    { requestId: proposal.requestId, intentHash: proposal.intentHash, decision: "approved" },
  );

  currentHash = canonicalHash("new-profile");
  await assert.rejects(
    fixture.service.resume(context, proposal.resumeHandle),
    (error: unknown) => error instanceof ApprovalServiceError && error.code === "profile_drift",
  );
  currentHash = PROFILE_HASH;
  active = false;
  await assert.rejects(
    fixture.service.resume(context, proposal.resumeHandle),
    (error: unknown) => error instanceof ApprovalServiceError && error.code === "provider_connection_unavailable",
  );
  assert.equal(fixture.executed.length, 0);
});

test("a recorded terminal execution replays without requiring live provider authority", async () => {
  let active = true;
  let currentHash: string | undefined = PROFILE_HASH;
  const fixture = createFixture({
    currentProfileHash: () => currentHash,
    connectionIsActive: async () => active,
  });
  const proposal = await fixture.service.propose(context, prepared);
  await fixture.service.decide(
    { tenantId: context.tenantId, principalId: context.principalId, issuer: "https://idp.example", subject: "alice", authenticatedAt: NOW.toISOString() },
    { requestId: proposal.requestId, intentHash: proposal.intentHash, decision: "approved" },
  );
  assert.equal((await fixture.service.resume(context, proposal.resumeHandle)).status, "succeeded");
  active = false;
  currentHash = canonicalHash("new-profile");
  assert.equal((await fixture.service.resume(context, proposal.resumeHandle)).status, "succeeded");
  assert.equal(fixture.executed.length, 1);
});

test("receiptless failed or ambiguous execution is terminal and never dispatches again", async () => {
  for (const outcome of ["failed", "ambiguous"] as const) {
    let calls = 0;
    const fixture = createFixture({
      executor: {
        async execute(): Promise<ExecuteResult> {
          calls += 1;
          if (outcome === "ambiguous") throw new Error("response lost after dispatch may have started");
          return {
            decision: {
              allowed: false,
              code: "approval_mismatch",
              decisionId: "decision-denied-before-reservation",
            },
          };
        },
      },
    });
    const proposal = await fixture.service.propose(context, {
      ...prepared,
      idempotencyKey: `correlation_${outcome}_123456`,
    });
    await fixture.service.decide(
      { tenantId: context.tenantId, principalId: context.principalId, issuer: "https://idp.example", subject: "alice", authenticatedAt: NOW.toISOString() },
      { requestId: proposal.requestId, intentHash: proposal.intentHash, decision: "approved" },
    );

    if (outcome === "ambiguous") {
      await assert.rejects(
        fixture.service.resume(context, proposal.resumeHandle),
        (error: unknown) => error instanceof ApprovalServiceError && error.code === "approval_not_ready",
      );
    } else {
      assert.equal((await fixture.service.resume(context, proposal.resumeHandle)).status, "failed");
    }
    const replay = await fixture.service.resume(context, proposal.resumeHandle);
    assert.equal(replay.status, outcome);
    assert.equal("execution" in replay, false);
    assert.equal(calls, 1);
  }
});

test("expired and denied requests are terminal normal results", async () => {
  let clock = new Date(NOW);
  const fixture = createFixture({ now: () => new Date(clock) });
  const denied = await fixture.service.propose(context, prepared);
  await fixture.service.decide(
    { tenantId: context.tenantId, principalId: context.principalId, issuer: "https://idp.example", subject: "alice", authenticatedAt: NOW.toISOString() },
    { requestId: denied.requestId, intentHash: denied.intentHash, decision: "denied", reason: "Not intended" },
  );
  assert.deepEqual(await fixture.service.resume(context, denied.resumeHandle), {
    status: "denied",
    requestId: denied.requestId,
    expiresAt: denied.expiresAt,
    reason: "Not intended",
  });

  const expiring = await fixture.service.propose(context, prepared);
  clock = new Date(NOW.getTime() + 301_000);
  assert.equal((await fixture.service.resume(context, expiring.resumeHandle)).status, "expired");
  assert.equal(fixture.executed.length, 0);
});

function createFixture(overrides: {
  now?: () => Date;
  currentProfileHash?: (id: string) => string | undefined;
  connectionIsActive?: () => Promise<boolean>;
  executor?: { execute(request: ActionRequest): Promise<ExecuteResult> };
} = {}) {
  const repository = new InMemoryApprovalRepository();
  const issued: Array<{ principalId: string; input: ApprovedMandateInput; secret: string }> = [];
  const executed: ActionRequest[] = [];
  const issuedByApproval = new Map<string, IssuedMandate>();
  const executionByIdempotencyKey = new Map<string, ExecuteResult>();
  let mandateSequence = 0;
  const mandates = {
    async issueApproved(principal: { principalId: string }, input: ApprovedMandateInput, secret: string): Promise<IssuedMandate> {
      const existing = issuedByApproval.get(input.approvalRequestId);
      if (existing) return structuredClone(existing);
      issued.push({ principalId: principal.principalId, input: structuredClone(input), secret });
      mandateSequence += 1;
      const issuedAt = NOW.toISOString();
      const result: IssuedMandate = {
        grant: `mandate-${mandateSequence}.${secret}`,
        mandate: {
          id: `mandate-${mandateSequence}`,
          tenantId: context.tenantId,
          principalId: principal.principalId,
          agentId: input.agentId,
          workloadId: input.workloadId,
          taskId: input.taskId,
          audience: input.audience,
          actions: [input.action],
          resources: [input.resource],
          expiresInSeconds: input.expiresInSeconds,
          constraints: { maxCalls: 1 },
          approval: input.approval,
          approvalRequestId: input.approvalRequestId,
          issuedAt,
          expiresAt: new Date(Date.parse(issuedAt) + input.expiresInSeconds * 1_000).toISOString(),
          status: "active",
          successfulUses: 0,
        },
      };
      issuedByApproval.set(input.approvalRequestId, structuredClone(result));
      return result;
    },
  };
  const executor = {
    async execute(request: ActionRequest): Promise<ExecuteResult> {
      const existing = executionByIdempotencyKey.get(request.idempotencyKey);
      if (existing) return structuredClone(existing);
      executed.push(structuredClone(request));
      const at = NOW.toISOString();
      const result: ExecuteResult = {
        decision: {
          allowed: true,
          code: "allowed",
          decisionId: "decision-1",
          mandateId: request.grant.split(".")[0],
          envelopeHash: canonicalHash({
            version: ACTION_ENVELOPE_VERSION,
            tenantId: request.tenantId,
            principalId: context.principalId,
            agentId: request.agentId,
            workloadId: request.workloadId,
            taskId: request.taskId,
            audience: request.audience,
            action: request.action,
            resource: request.resource,
            parameters: request.parameters,
          }),
        },
        receipt: {
          id: "receipt-1",
          tenantId: request.tenantId,
          mandateId: request.grant.split(".")[0]!,
          decisionId: "decision-1",
          principalId: context.principalId,
          agentId: request.agentId,
          workloadId: request.workloadId,
          taskId: request.taskId,
          audience: request.audience,
          action: request.action,
          resource: request.resource,
          envelopeVersion: ACTION_ENVELOPE_VERSION,
          envelopeHash: canonicalHash(request.parameters),
          idempotencyKey: request.idempotencyKey,
          outcome: "succeeded",
          downstreamStatus: 201,
          resultHash: canonicalHash({ number: 1 }),
          receiptHash: canonicalHash({ receipt: 1 }),
          attemptCount: 1,
          createdAt: at,
          updatedAt: at,
        },
        result: { status: 201, body: { number: 1, htmlUrl: "https://github.example/issue/1" } },
      };
      executionByIdempotencyKey.set(request.idempotencyKey, structuredClone(result));
      return result;
    },
  };
  let ids = 0;
  const service = new ApprovalService({
    repository,
    mandates,
    grantDeriver: new InternalGrantDeriver(Buffer.alloc(32, 11)),
    executorFor: () => overrides.executor ?? executor,
    currentProfileHash: overrides.currentProfileHash ?? (() => PROFILE_HASH),
    connectionIsActive: overrides.connectionIsActive ?? (async () => true),
    publicBaseUrl: "http://127.0.0.1:8787",
    now: overrides.now ?? (() => new Date(NOW)),
    id: () => `00000000-0000-4000-8000-${String(++ids).padStart(12, "0")}`,
  });
  return { repository, service, issued, executed };
}
