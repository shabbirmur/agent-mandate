import assert from "node:assert/strict";
import test from "node:test";
import type { ApprovalWorkloadContext, PreparedApprovalAction } from "../src/approvals/index.js";
import type { ProviderConnectionRepository } from "../src/ports.js";
import {
  ProductService,
  ProductServiceError,
  seedConfiguredGitHubConnection,
  type ProductConfig,
} from "../src/product/index.js";
import { ACTION_ENVELOPE_VERSION, type ApprovalRequest, type ExecutionReceipt, type ProviderConnectionResource } from "../src/types.js";

const context: ApprovalWorkloadContext = {
  tenantId: "tenant:one",
  principalId: "user:alice",
  agentId: "agent:codex",
  workloadId: "workload:codex",
  mcpSessionId: "session:one",
};

test("product service derives trusted GitHub profile, connection, repository ID, and correlation", async () => {
  let prepared: PreparedApprovalAction | undefined;
  const resources = [resource()];
  const service = productFixture({
    resources,
    onPropose: (value) => { prepared = value; },
  });
  const proposal = await service.proposeGithubIssue(context, {
    repository: "octo/demo",
    title: "Protect this exact action",
    body: "No broader repository authority",
  });
  assert.equal(proposal.status, "approval_required");
  assert.equal(prepared?.providerConnectionId, "connection:github:123");
  assert.equal(prepared?.providerResourceId, "987654");
  assert.equal(prepared?.resource, "github:repository:987654");
  assert.equal(prepared?.action, "github.issue.create.v1");
  assert.equal(prepared?.risk, "consequential");
  assert.equal(prepared?.parameters.repositoryId, 987654);
  assert.equal(prepared?.parameters.repository, "octo/demo");
  assert.equal(prepared?.parameters.correlationId, "test_key_0000000000");
  assert.equal(prepared?.idempotencyKey, "test_key_0000000000");
});

test("resource selection fails closed for absent, removed, ambiguous, or malformed targets", async () => {
  const cases: ProviderConnectionResource[][] = [
    [],
    [resource({ status: "removed" })],
    [resource(), resource({ providerResourceId: "999999" })],
    [resource({ selector: { repository: "octo/demo", owner: "octo", name: "demo", repositoryId: 111111 } })],
  ];
  for (const resources of cases) {
    await assert.rejects(
      productFixture({ resources }).proposeGithubIssue(context, { repository: "octo/demo", title: "Exact title" }),
      (error: unknown) => error instanceof ProductServiceError || (error instanceof Error && error.message === "invalid_tool_arguments"),
    );
  }
});

test("connection identity is deployment-bound and cannot be injected as a tool field", async () => {
  const service = productFixture({ resources: [resource()] });
  await assert.rejects(
    service.proposeGithubIssue(context, {
      repository: "octo/demo",
      title: "Exact title",
      connectionId: "attacker-connection",
      repositoryId: 1,
      action: "github.repository.delete",
    } as never),
    /invalid_tool_arguments/,
  );
});

test("receipt lookup is bound to the approved principal and workload", async () => {
  const receipt = executionReceipt();
  const request = approvalRequest({ mandateId: receipt.mandateId, receiptId: receipt.id });
  const service = productFixture({ resources: [resource()], request, receipt });
  assert.deepEqual(await service.receipt(context, { requestId: request.id }), {
    status: "available",
    requestId: request.id,
    receipt,
  });

  const mismatched = productFixture({
    resources: [resource()],
    request,
    receipt: { ...receipt, workloadId: "workload:other" },
  });
  await assert.rejects(
    mismatched.receipt(context, { requestId: request.id }),
    (error: unknown) => error instanceof ProductServiceError && error.code === "receipt_mismatch",
  );
});

test("receipt chain verification is returned only when the configured verifier actually runs", async () => {
  const receipt = executionReceipt();
  const request = approvalRequest({ mandateId: receipt.mandateId, receiptId: receipt.id });
  let verifiedTenant: string | undefined;
  const service = productFixture({
    resources: [resource()],
    request,
    receipt,
    verifyReceiptChain: async (tenantId) => {
      verifiedTenant = tenantId;
      return true;
    },
  });
  assert.deepEqual(await service.receipt(context, { requestId: request.id }), {
    status: "available",
    requestId: request.id,
    receipt,
    chainVerified: true,
  });
  assert.equal(verifiedTenant, context.tenantId);
});

test("runtime configuration seeding never reactivates suspended or removed provider authority", async () => {
  let connectionStatus: "active" | "suspended" | "revoked" = "suspended";
  let resourceStatus: "active" | "removed" = "removed";
  const connections: ProviderConnectionRepository = {
    async putConnection(input) {
      connectionStatus = input.status;
      return { ...input, createdAt: "2026-08-26T00:00:00.000Z", updatedAt: "2026-08-26T00:00:00.000Z" };
    },
    async putResource(input) {
      resourceStatus = input.status;
      return { ...input, createdAt: "2026-08-26T00:00:00.000Z", updatedAt: "2026-08-26T00:00:00.000Z" };
    },
    async findConnection() {
      return {
        id: "connection:github:123",
        tenantId: context.tenantId,
        providerId: "github",
        externalAccountId: "123",
        displayName: "GitHub",
        secretRef: "env://GITHUB_APP_PRIVATE_KEY",
        metadata: {},
        status: "suspended",
        createdAt: "2026-08-26T00:00:00.000Z",
        updatedAt: "2026-08-26T00:00:00.000Z",
      };
    },
    async findResource() {
      return resource({ status: "removed" });
    },
    async setConnectionStatus() { return false; },
    async setResourceStatus() { return false; },
    async listResources() { return []; },
    async readiness() { return true; },
    async close() {},
  };
  const config = {
    tenantId: context.tenantId,
    github: {
      appId: 42,
      privateKeyPem: "unused",
      privateKeyReference: "env://GITHUB_APP_PRIVATE_KEY_FILE",
      installationId: 123,
      repositoryId: 987654,
      repository: "octo/demo",
      connectionId: "connection:github:123",
    },
  } as ProductConfig;

  await seedConfiguredGitHubConnection(config, connections);
  assert.equal(connectionStatus, "suspended");
  assert.equal(resourceStatus, "removed");
});

test("runtime configuration seeding removes previously active repository authority", async () => {
  const removed: string[] = [];
  const connections: ProviderConnectionRepository = {
    async putConnection(input) {
      return { ...input, createdAt: "2026-08-26T00:00:00.000Z", updatedAt: "2026-08-26T00:00:00.000Z" };
    },
    async putResource(input) {
      return { ...input, createdAt: "2026-08-26T00:00:00.000Z", updatedAt: "2026-08-26T00:00:00.000Z" };
    },
    async findConnection() { return undefined; },
    async findResource() { return undefined; },
    async setConnectionStatus() { return false; },
    async setResourceStatus(_tenantId, _connectionId, providerResourceId, status) {
      if (status === "removed") removed.push(providerResourceId);
      return true;
    },
    async listResources() {
      return [resource({ providerResourceId: "111111", displayName: "octo/previous", selector: {
        repository: "octo/previous", owner: "octo", name: "previous", repositoryId: 111111,
      } })];
    },
    async readiness() { return true; },
    async close() {},
  };
  const config = {
    tenantId: context.tenantId,
    github: {
      appId: 42,
      privateKeyPem: "unused",
      privateKeyReference: "env://GITHUB_APP_PRIVATE_KEY_FILE",
      installationId: 123,
      repositoryId: 987654,
      repository: "octo/demo",
      connectionId: "connection:github:123",
    },
  } as ProductConfig;

  await seedConfiguredGitHubConnection(config, connections);
  assert.deepEqual(removed, ["111111"]);
});

function productFixture(input: {
  resources: ProviderConnectionResource[];
  onPropose?: (prepared: PreparedApprovalAction) => void;
  request?: ApprovalRequest;
  receipt?: ExecutionReceipt;
  verifyReceiptChain?: (tenantId: string) => Promise<boolean>;
}) {
  const connections: ProviderConnectionRepository = {
    async putConnection() { throw new Error("not used"); },
    async putResource() { throw new Error("not used"); },
    async findConnection(tenantId, providerId, connectionId) {
      return tenantId === context.tenantId && providerId === "github" && connectionId === "connection:github:123"
        ? {
            id: connectionId,
            tenantId,
            providerId,
            externalAccountId: "123",
            displayName: "GitHub",
            secretRef: "env://GITHUB_APP_PRIVATE_KEY",
            metadata: { installationId: 123 },
            status: "active",
            createdAt: "2026-08-26T00:00:00.000Z",
            updatedAt: "2026-08-26T00:00:00.000Z",
          }
        : undefined;
    },
    async findResource() { return undefined; },
    async setConnectionStatus() { return false; },
    async setResourceStatus() { return false; },
    async listResources() { return structuredClone(input.resources); },
    async readiness() { return true; },
    async close() {},
  };
  const request = input.request ?? approvalRequest();
  return new ProductService({
    connections,
    mandates: {
      async findReceipt() { return input.receipt; },
    },
    ...(input.verifyReceiptChain === undefined ? {} : { verifyReceiptChain: input.verifyReceiptChain }),
    approvals: {
      async propose(_context, prepared) {
        input.onPropose?.(prepared);
        return {
          status: "approval_required",
          requestId: request.id,
          resumeHandle: "resume-handle",
          approvalUrl: "https://agent.example/approvals/request-1",
          expiresAt: request.expiresAt,
          intentHash: request.intentHash,
        };
      },
      async get() { return structuredClone(request); },
      async resume() { return { status: "pending", requestId: request.id, expiresAt: request.expiresAt }; },
    },
    githubConnectionId: () => "connection:github:123",
    correlationId: () => "test_key_0000000000",
  });
}

function resource(overrides: Partial<ProviderConnectionResource> = {}): ProviderConnectionResource {
  return {
    tenantId: context.tenantId,
    connectionId: "connection:github:123",
    providerResourceId: "987654",
    displayName: "octo/demo",
    selector: { repository: "octo/demo", owner: "octo", name: "demo", repositoryId: 987654 },
    status: "active",
    createdAt: "2026-08-26T00:00:00.000Z",
    updatedAt: "2026-08-26T00:00:00.000Z",
    ...overrides,
  };
}

function approvalRequest(overrides: Partial<ApprovalRequest> = {}): ApprovalRequest {
  const envelope = {
    version: ACTION_ENVELOPE_VERSION,
    tenantId: context.tenantId,
    principalId: context.principalId,
    agentId: context.agentId,
    workloadId: context.workloadId,
    taskId: "workflow:one",
    audience: "https://api.github.com",
    action: "github.issue.create.v1",
    resource: "github:repository:987654",
    parameters: { repository: "octo/demo", repositoryId: 987654, title: "Exact", body: "Body", correlationId: "test_key_0000000000" },
  } as const;
  return {
    id: "request-1",
    tenantId: context.tenantId,
    expectedPrincipalId: context.principalId,
    agentId: context.agentId,
    workloadId: context.workloadId,
    workflowId: "workflow:one",
    mcpSessionHash: "a".repeat(43),
    profileId: "github.issue.create.v1",
    profileHash: "b".repeat(43),
    providerId: "github",
    providerConnectionId: "connection:github:123",
    providerResourceId: "987654",
    envelope,
    envelopeHash: "c".repeat(43),
    intent: {
      version: "am.approval-intent.v1",
      requestId: "request-1",
      envelope,
      envelopeHash: "c".repeat(43),
      profileId: "github.issue.create.v1",
      profileHash: "b".repeat(43),
      providerId: "github",
      providerConnectionId: "connection:github:123",
      providerResourceId: "987654",
      idempotencyKey: "test_key_0000000000",
      risk: "consequential",
      expiresAt: "2026-08-26T00:05:00.000Z",
      maxCalls: 1,
      delegationAllowed: false,
      expectedApprover: context.principalId,
    },
    intentHash: "d".repeat(43),
    resumeHandleHash: "e".repeat(43),
    idempotencyKey: "test_key_0000000000",
    status: "approved",
    executionStatus: "succeeded",
    createdAt: "2026-08-26T00:00:00.000Z",
    expiresAt: "2026-08-26T00:05:00.000Z",
    ...overrides,
  };
}

function executionReceipt(): ExecutionReceipt {
  return {
    id: "receipt-1",
    tenantId: context.tenantId,
    mandateId: "mandate-1",
    decisionId: "decision-1",
    principalId: context.principalId,
    agentId: context.agentId,
    workloadId: context.workloadId,
    taskId: "workflow:one",
    audience: "https://api.github.com",
    action: "github.issue.create.v1",
    resource: "github:repository:987654",
    envelopeVersion: ACTION_ENVELOPE_VERSION,
    envelopeHash: "c".repeat(43),
    idempotencyKey: "test_key_0000000000",
    outcome: "succeeded",
    downstreamStatus: 201,
    resultHash: "f".repeat(43),
    receiptHash: "g".repeat(43),
    attemptCount: 1,
    createdAt: "2026-08-26T00:01:00.000Z",
    updatedAt: "2026-08-26T00:01:01.000Z",
  };
}
