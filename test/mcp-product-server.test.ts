import assert from "node:assert/strict";
import test from "node:test";
import { InMemoryTransport, type AuthInfo, type JSONRPCMessage } from "@modelcontextprotocol/server";
import {
  RemoteProductMcpBackend,
  RemoteProductMcpBackendError,
  createMcpHttpHandler,
  serveProductStdio,
  type ProductMcpBackend,
  type ProductMcpContext,
  type ProductResumeBackendResult,
} from "../src/mcp/index.js";
import type { ExecutionReceipt } from "../src/types.js";

const HASH = "A".repeat(43);
const RESUME_HANDLE = "B".repeat(43);
const EXPIRES_AT = "2026-08-26T12:00:00.000Z";
const ISSUE = {
  id: 101,
  nodeId: "I_kwDOExample",
  number: 7,
  htmlUrl: "https://github.com/example/project/issues/7",
  state: "open" as const,
  title: "Bounded issue",
};

const RECEIPT: ExecutionReceipt = {
  id: "receipt:1",
  tenantId: "tenant:1",
  mandateId: "mandate:1",
  decisionId: "decision:1",
  principalId: "principal:1",
  agentId: "agent:1",
  workloadId: "workload:1",
  taskId: "workflow:1",
  audience: "https://api.github.com",
  action: "github.issue.create.v1",
  resource: "github:repository:42",
  envelopeVersion: "am.action.v1",
  envelopeHash: HASH,
  idempotencyKey: "approval:request-1",
  outcome: "succeeded",
  downstreamStatus: 201,
  resultHash: HASH,
  receiptHash: HASH,
  attemptCount: 1,
  createdAt: "2026-08-26T11:00:00.000Z",
  updatedAt: "2026-08-26T11:00:01.000Z",
};

test("real legacy initialize/list/call exposes exactly the four narrow product tools", async (t) => {
  const fixture = createFixture();
  t.after(() => fixture.handler.close());

  const initialized = await legacyRpc(fixture.handler, {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "agent-mandate-test", version: "1.0.0" },
    },
  });
  assert.equal(initialized.result?.serverInfo?.name, "agent-mandate");

  const listed = await legacyRpc(fixture.handler, {
    jsonrpc: "2.0",
    id: 2,
    method: "tools/list",
    params: {},
  });
  const tools = listed.result?.tools as Array<Record<string, unknown>>;
  assert.deepEqual(tools.map((tool) => tool.name), [
    "github_create_issue",
    "agent_mandate_status",
    "agent_mandate_resume",
    "agent_mandate_receipt",
  ]);
  for (const tool of tools) {
    const schema = tool.inputSchema as { properties: Record<string, unknown>; additionalProperties: boolean };
    assert.equal(schema.additionalProperties, false);
    for (const forbidden of ["tenantId", "principalId", "agentId", "workloadId", "action", "audience", "resource", "idempotencyKey"]) {
      assert.equal(forbidden in schema.properties, false, `${String(tool.name)} must not expose ${forbidden}`);
    }
  }

  const called = await legacyRpc(fixture.handler, toolCall(3, "github_create_issue", {
    repository: "example/project",
    title: "Bounded issue",
    body: "Exact body",
  }));
  assert.deepEqual(called.result?.structuredContent, {
    status: "approval_required",
    requestId: "request-1",
    resumeHandle: RESUME_HANDLE,
    approvalUrl: "https://mandate.example/approvals/request-1",
    expiresAt: EXPIRES_AT,
    intentHash: HASH,
    terminal: false,
    autoRetryAllowed: false,
    nextAction: "open_approval",
  });
  assert.deepEqual(fixture.calls.proposals[0]?.input, {
    repository: "example/project",
    title: "Bounded issue",
    body: "Exact body",
  });
});

test("strict schemas reject authorization drift and do not call the backend", async (t) => {
  const fixture = createFixture();
  t.after(() => fixture.handler.close());

  const drift = await legacyRpc(fixture.handler, toolCall(1, "github_create_issue", {
    repository: "example/project",
    title: "Bounded issue",
    audience: "https://attacker.example",
    action: "repository.delete",
    tenantId: "attacker",
  }));
  assert.equal(drift.result?.isError, true);
  assert.equal(fixture.calls.proposals.length, 0);

  const statusDrift = await legacyRpc(fixture.handler, toolCall(2, "agent_mandate_status", {
    requestId: "request-1",
    resumeHandle: RESUME_HANDLE,
  }));
  assert.equal(statusDrift.result?.isError, true);
  assert.equal(fixture.calls.status.length, 0);

  const malformed = await legacyRpc(fixture.handler, toolCall(3, "github_create_issue", {
    repository: "example/project",
    title: "line one\nline two",
  }));
  assert.equal(malformed.result?.isError, true);
  assert.equal(fixture.calls.proposals.length, 0);
});

test("HTTP request auth is resolved per request and remains outside tool arguments", async (t) => {
  const seenResolverInputs: Array<{ token?: string; era: string }> = [];
  const fixture = createFixture({
    resolveContext: ({ authInfo, era }) => {
      seenResolverInputs.push({ ...(authInfo?.token === undefined ? {} : { token: authInfo.token }), era });
      return { sessionId: `session:${authInfo?.token ?? "missing"}` };
    },
  });
  t.after(() => fixture.handler.close());

  await legacyRpc(fixture.handler, toolCall(1, "agent_mandate_status", { requestId: "request-1" }), auth("one"));
  await legacyRpc(fixture.handler, toolCall(2, "agent_mandate_status", { requestId: "request-1" }), auth("two"));

  assert.deepEqual(seenResolverInputs, [{ token: "one", era: "legacy" }, { token: "two", era: "legacy" }]);
  assert.deepEqual(fixture.calls.status.map((call) => call.context), [
    { sessionId: "session:one" },
    { sessionId: "session:two" },
  ]);
  assert.deepEqual(fixture.calls.status.map((call) => call.input), [
    { requestId: "request-1" },
    { requestId: "request-1" },
  ]);
});

test("denied and ambiguous outcomes are normal terminal results with automatic retry forbidden", async (t) => {
  const fixture = createFixture({
    proposal: { status: "denied", code: "policy_denied", reason: "Repository is not connected." },
    resume: {
      status: "ambiguous",
      code: "remote_response_ambiguous",
      reason: "The response was lost.",
    },
  });
  t.after(() => fixture.handler.close());

  const denied = await legacyRpc(fixture.handler, toolCall(1, "github_create_issue", {
    repository: "example/project",
    title: "Bounded issue",
  }));
  assert.equal(denied.result?.isError, undefined);
  assert.deepEqual(denied.result?.structuredContent, {
    status: "denied",
    code: "policy_denied",
    reason: "Repository is not connected.",
    terminal: true,
    autoRetryAllowed: false,
    nextAction: "none",
  });

  const ambiguous = await legacyRpc(fixture.handler, toolCall(2, "agent_mandate_resume", {
    resumeHandle: RESUME_HANDLE,
  }));
  assert.equal(ambiguous.result?.isError, undefined);
  assert.deepEqual(ambiguous.result?.structuredContent, {
    status: "ambiguous",
    code: "remote_response_ambiguous",
    reason: "The response was lost.",
    terminal: true,
    autoRetryAllowed: false,
    nextAction: "none",
  });
  assert.match(String((ambiguous.result?.content as Array<{ text: string }>)[0]?.text), /do not retry or repeat/i);
});

test("a persisted receiptless terminal result is returned normally without inviting execution retry", async (t) => {
  const fixture = createFixture({
    resume: {
      status: "failed",
      requestId: "request-1",
      expiresAt: EXPIRES_AT,
      reason: "The prior execution failed before a receipt was available.",
    },
  });
  t.after(() => fixture.handler.close());

  const failed = await legacyRpc(fixture.handler, toolCall(1, "agent_mandate_resume", {
    resumeHandle: RESUME_HANDLE,
  }));
  assert.equal(failed.result?.isError, undefined);
  assert.deepEqual(failed.result?.structuredContent, {
    status: "failed",
    requestId: "request-1",
    expiresAt: EXPIRES_AT,
    reason: "The prior execution failed before a receipt was available.",
    terminal: true,
    autoRetryAllowed: false,
    nextAction: "none",
  });
});

test("receipt output is allowlisted and an invalid secret-bearing backend response is contained", async (t) => {
  const fixture = createFixture();
  t.after(() => fixture.handler.close());

  const receipt = await legacyRpc(fixture.handler, toolCall(1, "agent_mandate_receipt", { requestId: "request-1" }));
  assert.deepEqual(receipt.result?.structuredContent, {
    status: "receipt",
    requestId: "request-1",
    receipt: RECEIPT,
    chainVerified: true,
    chainVerification: "verified",
    issue: ISSUE,
    terminal: true,
    autoRetryAllowed: false,
    nextAction: "none",
  });

  fixture.backend.receipt = async (_context, input) => ({ status: "not_available", requestId: input.requestId });
  const unavailable = await legacyRpc(fixture.handler, toolCall(2, "agent_mandate_receipt", { requestId: "request-2" }));
  assert.deepEqual(unavailable.result?.structuredContent, {
    status: "not_available",
    requestId: "request-2",
    chainVerification: "not_available",
    terminal: false,
    autoRetryAllowed: false,
    nextAction: "wait",
  });

  fixture.backend.proposeGithubIssue = async () => ({
    status: "approval_required",
    requestId: "request-2",
    resumeHandle: RESUME_HANDLE,
    approvalUrl: "https://mandate.example/approvals/request-2",
    expiresAt: EXPIRES_AT,
    intentHash: HASH,
    accessToken: "github-provider-secret",
  } as never);
  const contained = await legacyRpc(fixture.handler, toolCall(3, "github_create_issue", {
    repository: "example/project",
    title: "Bounded issue",
  }));
  assert.equal(contained.result?.isError, true);
  assert.doesNotMatch(JSON.stringify(contained), /github-provider-secret|accessToken/u);
});

test("modern server/discover, tools/list, and tools/call use fresh request-bound servers", async (t) => {
  const fixture = createFixture();
  t.after(() => fixture.handler.close());

  const discovered = await modernRpc(fixture.handler, 1, "server/discover", {});
  assert.deepEqual(discovered.result?.supportedVersions, ["2026-07-28"]);
  const listed = await modernRpc(fixture.handler, 2, "tools/list", {});
  assert.equal((listed.result?.tools as unknown[]).length, 4);
  const called = await modernRpc(fixture.handler, 3, "tools/call", {
    name: "github_create_issue",
    arguments: { repository: "example/project", title: "Bounded issue" },
  }, "github_create_issue");
  assert.equal((called.result?.structuredContent as { status?: string }).status, "approval_required");
  assert.equal(called.result?.resultType, "complete");
  assert.deepEqual(fixture.resolvedEras, ["modern", "modern", "modern"]);
});

test("Host and Origin validation run before context resolution", async (t) => {
  const fixture = createFixture();
  t.after(() => fixture.handler.close());
  const body = JSON.stringify(toolCall(1, "agent_mandate_status", { requestId: "request-1" }));

  const missingHost = await fixture.handler.fetch(new Request("http://localhost/mcp", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  }));
  assert.equal(missingHost.status, 403);

  const badOrigin = await fixture.handler.fetch(new Request("http://localhost/mcp", {
    method: "POST",
    headers: { host: "localhost", origin: "https://attacker.example", "content-type": "application/json" },
    body,
  }));
  assert.equal(badOrigin.status, 403);
  assert.equal(fixture.resolvedEras.length, 0);
});

test("serveProductStdio performs a real initialize and reserves stdout framing for MCP", async () => {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const fixture = createFixture();
  const handle = serveProductStdio({
    backend: fixture.backend,
    resolveContext: () => ({ sessionId: "stdio-session" }),
    transport: serverTransport,
  });
  await clientTransport.start();
  const response = nextMessage(clientTransport);
  await clientTransport.send({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "stdio-test", version: "1.0.0" },
    },
  });
  const initialized = await response;
  assert.equal("result" in initialized && initialized.result.serverInfo?.name, "agent-mandate");
  await clientTransport.close();
  await handle.close();
  await fixture.handler.close();
});

test("thin remote backend sends only Agent Mandate auth/session and treats lost resume responses as ambiguous", async () => {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const backend = new RemoteProductMcpBackend({
    endpoint: "https://mandate.example/mcp",
    accessToken: "agent-mandate-oauth-token",
    sessionId: "session-1",
    fetch: async (input, init) => {
      requests.push({ url: String(input), ...(init === undefined ? {} : { init }) });
      if (String(input).endsWith("/v1/product/approvals/resume")) throw new Error("response lost");
      if (String(input).endsWith("/v1/product/approvals/request-1/receipt")) {
        return Response.json({ status: "available", requestId: "request-1", receipt: RECEIPT });
      }
      if (String(input).endsWith("/v1/product/approvals/request-1")) {
        return Response.json({
          requestId: "request-1",
          status: "approved",
          executionStatus: "not_started",
          profileId: "github.issue.create.v1",
          providerId: "github",
          repository: "example/project",
          action: "github.issue.create.v1",
          parameters: { title: "Bounded issue" },
          expiresAt: EXPIRES_AT,
          decisionReason: "Approved by user.",
        });
      }
      return Response.json({
        status: "approval_required",
        requestId: "request-1",
        resumeHandle: RESUME_HANDLE,
        approvalUrl: "https://mandate.example/approvals/request-1",
        expiresAt: EXPIRES_AT,
        intentHash: HASH,
      });
    },
  });
  const context = { sessionId: "session-1" };

  await backend.proposeGithubIssue(context, { repository: "example/project", title: "Bounded issue" });
  const proposalRequest = requests[0]!;
  assert.equal(proposalRequest.url, "https://mandate.example/v1/product/github/issues/proposals");
  const headers = new Headers(proposalRequest.init?.headers);
  assert.equal(headers.get("authorization"), "Bearer agent-mandate-oauth-token");
  assert.equal(headers.get("x-agent-mandate-session"), "session-1");
  assert.equal(headers.has("x-github-token"), false);
  assert.deepEqual(JSON.parse(String(proposalRequest.init?.body)), {
    repository: "example/project",
    title: "Bounded issue",
  });
  assert.doesNotMatch(String(proposalRequest.init?.body), /tenant|agentId|workload|audience|action|credential|token/iu);

  assert.deepEqual(await backend.status(context, { requestId: "request-1" }), {
    requestId: "request-1",
    status: "approved",
    executionStatus: "not_started",
    expiresAt: EXPIRES_AT,
    reason: "Approved by user.",
  });
  assert.deepEqual(await backend.receipt(context, { requestId: "request-1" }), {
    status: "available",
    requestId: "request-1",
    receipt: RECEIPT,
  });

  assert.deepEqual(await backend.resume(context, { resumeHandle: RESUME_HANDLE }), {
    status: "ambiguous",
    code: "remote_response_ambiguous",
    reason: "The Agent Mandate response was unavailable after execution may have started.",
  });
  await assert.rejects(
    () => backend.status({ sessionId: "stolen-session" }, { requestId: "request-1" }),
    (error: unknown) => error instanceof RemoteProductMcpBackendError && error.code === "remote_context_mismatch",
  );
  assert.equal(JSON.stringify(backend), "{}");
});

test("remote backend rejects credential-bearing or insecure endpoint configuration", () => {
  assert.throws(
    () => new RemoteProductMcpBackend({
      endpoint: "https://user:password@mandate.example/mcp",
      accessToken: "agent-token",
      sessionId: "session-1",
    }),
    (error: unknown) => error instanceof RemoteProductMcpBackendError && error.code === "invalid_remote_configuration",
  );
  assert.throws(
    () => new RemoteProductMcpBackend({
      endpoint: "http://mandate.example/mcp",
      accessToken: "agent-token",
      sessionId: "session-1",
    }),
    (error: unknown) => error instanceof RemoteProductMcpBackendError && error.code === "invalid_remote_configuration",
  );
});

interface RpcResponse {
  jsonrpc?: string;
  id?: string | number | null;
  result?: Record<string, any>;
  error?: Record<string, any>;
}

function createFixture(options: {
  proposal?: Awaited<ReturnType<ProductMcpBackend<ProductMcpContext>["proposeGithubIssue"]>>;
  resume?: ProductResumeBackendResult;
  resolveContext?: Parameters<typeof createMcpHttpHandler<ProductMcpContext>>[0]["resolveContext"];
} = {}) {
  const calls = {
    proposals: [] as Array<{ context: ProductMcpContext; input: unknown }>,
    status: [] as Array<{ context: ProductMcpContext; input: unknown }>,
    resume: [] as Array<{ context: ProductMcpContext; input: unknown }>,
    receipt: [] as Array<{ context: ProductMcpContext; input: unknown }>,
  };
  const backend: ProductMcpBackend<ProductMcpContext> = {
    async proposeGithubIssue(context, input) {
      calls.proposals.push({ context: { ...context }, input: { ...input } });
      return options.proposal ?? {
        status: "approval_required",
        requestId: "request-1",
        resumeHandle: RESUME_HANDLE,
        approvalUrl: "https://mandate.example/approvals/request-1",
        expiresAt: EXPIRES_AT,
        intentHash: HASH,
      };
    },
    async status(context, input) {
      calls.status.push({ context: { ...context }, input: { ...input } });
      return { requestId: input.requestId, status: "pending", expiresAt: EXPIRES_AT };
    },
    async resume(context, input) {
      calls.resume.push({ context: { ...context }, input: { ...input } });
      return options.resume ?? { status: "pending", requestId: "request-1", expiresAt: EXPIRES_AT };
    },
    async receipt(context, input) {
      calls.receipt.push({ context: { ...context }, input: { ...input } });
      return { status: "available", requestId: input.requestId, receipt: RECEIPT, chainVerified: true, issue: ISSUE };
    },
  };
  const resolvedEras: string[] = [];
  const customResolver = options.resolveContext;
  const handler = createMcpHttpHandler({
    backend,
    resolveContext: async (input) => {
      resolvedEras.push(input.era);
      return customResolver ? await customResolver(input) : { sessionId: "http-session" };
    },
  });
  return { backend, calls, handler, resolvedEras };
}

function toolCall(id: number, name: string, args: Record<string, unknown>): Record<string, unknown> {
  return { jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } };
}

async function legacyRpc(
  handler: ReturnType<typeof createMcpHttpHandler>,
  body: Record<string, unknown>,
  authInfo?: AuthInfo,
): Promise<RpcResponse> {
  const request = new Request("http://localhost/mcp", {
    method: "POST",
    headers: {
      host: "localhost",
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
    },
    body: JSON.stringify(body),
  });
  const response = await handler.fetch(request, authInfo === undefined ? undefined : { authInfo });
  assert.equal(response.status, 200);
  return await decodeResponse(response);
}

async function modernRpc(
  handler: ReturnType<typeof createMcpHttpHandler>,
  id: number,
  method: string,
  params: Record<string, unknown>,
  name?: string,
): Promise<RpcResponse> {
  const metadata = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
    "io.modelcontextprotocol/clientInfo": { name: "agent-mandate-test", version: "1.0.0" },
  };
  const request = new Request("http://localhost/mcp", {
    method: "POST",
    headers: {
      host: "localhost",
      "content-type": "application/json",
      accept: "application/json",
      "mcp-protocol-version": "2026-07-28",
      "mcp-method": method,
      ...(name === undefined ? {} : { "mcp-name": name }),
    },
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params: { ...params, _meta: metadata } }),
  });
  const response = await handler.fetch(request);
  assert.equal(response.status, 200);
  return await decodeResponse(response);
}

async function decodeResponse(response: Response): Promise<RpcResponse> {
  const text = await response.text();
  if (!response.headers.get("content-type")?.startsWith("text/event-stream")) return JSON.parse(text) as RpcResponse;
  const data = text.split(/\r?\n/u).find((line) => line.startsWith("data: "));
  assert.ok(data, "SSE response must contain a data frame");
  return JSON.parse(data.slice(6)) as RpcResponse;
}

function auth(token: string): AuthInfo {
  return { token, clientId: "test-client", scopes: ["mcp"], expiresAt: Math.floor(Date.now() / 1000) + 60 };
}

function nextMessage(transport: InMemoryTransport): Promise<JSONRPCMessage> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("timed out waiting for MCP response")), 2_000);
    transport.onmessage = (message) => {
      clearTimeout(timeout);
      resolve(message);
    };
  });
}
