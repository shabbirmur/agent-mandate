import assert from "node:assert/strict";
import type { IncomingMessage, ServerResponse } from "node:http";
import { Readable } from "node:stream";
import test from "node:test";
import { createMcpHttpHandler } from "../src/mcp/index.js";
import {
  createProductRequestHandler,
  productContextFromAuthInfo,
  type ProductAppDependencies,
} from "../src/product/index.js";
import type { AuthenticatedProductContext } from "../src/identity/index.js";

const EXPIRES_AT = "2026-08-27T12:05:00.000Z";
const context: AuthenticatedProductContext = {
  tenantId: "tenant:one",
  principalId: "user:alice",
  agentId: "agent:codex",
  workloadId: "workload:codex",
  mcpSessionId: "session:verified",
  oauthClientId: "codex-cli",
  accessExpiresAt: 2_000_000_000,
  accessScopes: ["agent-mandate:use"],
};

test("product listener exposes OAuth discovery and never mounts legacy raw-authority routes", async () => {
  const fixture = productFixture();
  const metadata = await invoke(fixture.dependencies, {
    method: "GET",
    path: "/.well-known/oauth-protected-resource/mcp",
  });
  assert.equal(metadata.status, 200);
  assert.deepEqual(metadata.body.authorization_servers, ["http://127.0.0.1:9000"]);
  assert.equal(metadata.body.resource, "http://127.0.0.1:8787/mcp");
  assert.deepEqual(metadata.body.scopes_supported, ["agent-mandate:use"]);

  const authorizationMetadata = await invoke(fixture.dependencies, {
    method: "GET",
    path: "/.well-known/oauth-authorization-server",
  });
  assert.equal(authorizationMetadata.status, 200);
  assert.equal(authorizationMetadata.body.authorization_endpoint, "http://127.0.0.1:9000/authorize");
  assert.deepEqual(authorizationMetadata.body.code_challenge_methods_supported, ["S256"]);

  for (const path of ["/v1/mandates", "/v1/execute", "/v1/audit"]) {
    const response = await invoke(fixture.dependencies, { method: "POST", path, body: {} });
    assert.equal(response.status, 404, path);
  }
});

test("product REST boundary derives all identity from a validated bearer and rejects authority drift", async () => {
  const fixture = productFixture();
  const missing = await invoke(fixture.dependencies, {
    method: "POST",
    path: "/v1/product/github/issues/proposals",
    body: { repository: "octo/demo", title: "Exact issue" },
  });
  assert.equal(missing.status, 401);
  assert.match(missing.headers["www-authenticate"] ?? "", /oauth-protected-resource\/mcp/u);
  assert.match(missing.headers["www-authenticate"] ?? "", /scope="agent-mandate:use"/u);

  const drift = await invoke(fixture.dependencies, {
    method: "POST",
    path: "/v1/product/github/issues/proposals",
    token: "agent-access-secret",
    body: {
      repository: "octo/demo",
      title: "Exact issue",
      action: "github.repository.delete",
      tenantId: "attacker",
    },
  });
  assert.equal(drift.status, 400);
  assert.equal(fixture.proposals.length, 0);

  const accepted = await invoke(fixture.dependencies, {
    method: "POST",
    path: "/v1/product/github/issues/proposals",
    token: "agent-access-secret",
    body: { repository: "octo/demo", title: "Exact issue", body: "Exact body" },
  });
  assert.equal(accepted.status, 202);
  assert.deepEqual(fixture.proposals, [{
    context,
    input: { repository: "octo/demo", title: "Exact issue", body: "Exact body" },
  }]);
  assert.doesNotMatch(JSON.stringify(accepted), /agent-access-secret/u);

  const boundedLargeBody = "x".repeat(65_000);
  const large = await invoke(fixture.dependencies, {
    method: "POST",
    path: "/v1/product/github/issues/proposals",
    token: "agent-access-secret",
    body: { repository: "octo/demo", title: "Large exact issue", body: boundedLargeBody },
  });
  assert.equal(large.status, 202);
  assert.equal((fixture.proposals[1]?.input as { body?: string }).body?.length, 65_000);
});

test("product listener contains malformed request-target logging failures", async () => {
  const fixture = productFixture();
  const events: Array<Record<string, unknown>> = [];
  fixture.dependencies.log = (event) => events.push(event);
  const response = await invoke(fixture.dependencies, {
    method: "GET",
    path: "http://[",
  });
  assert.equal(response.status, 500);
  assert.equal(response.body.error, "internal_error");
  assert.equal(events.at(-1)?.path, "<invalid>");
});

test("authenticated MCP requests receive verified context without bearer propagation", async () => {
  const fixture = productFixture();
  const response = await invoke(fixture.dependencies, {
    method: "POST",
    path: "/mcp",
    token: "agent-access-secret",
    headers: {
      accept: "application/json, text/event-stream",
      "content-type": "application/json",
    },
    body: {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "agent_mandate_status", arguments: { requestId: "request-1" } },
    },
  });
  assert.equal(response.status, 200);
  assert.deepEqual(fixture.statusContexts, [context]);
  assert.doesNotMatch(response.rawBody, /agent-access-secret/u);
});

function productFixture() {
  const proposals: Array<{ context: AuthenticatedProductContext; input: unknown }> = [];
  const statusContexts: AuthenticatedProductContext[] = [];
  const service = {
    async proposeGithubIssue(actualContext: AuthenticatedProductContext, input: unknown) {
      proposals.push({ context: structuredClone(actualContext), input: structuredClone(input) });
      return {
        status: "approval_required" as const,
        requestId: "request-1",
        resumeHandle: "R".repeat(43),
        approvalUrl: "http://127.0.0.1:8787/approvals/request-1",
        expiresAt: EXPIRES_AT,
        intentHash: "I".repeat(43),
      };
    },
    async status(actualContext: AuthenticatedProductContext, input: { requestId: string }) {
      statusContexts.push(structuredClone(actualContext));
      return {
        requestId: input.requestId,
        status: "pending" as const,
        executionStatus: "not_started" as const,
        profileId: "github.issue.create.v1",
        providerId: "github",
        repository: "octo/demo",
        action: "github.issue.create.v1",
        parameters: { title: "Exact issue" },
        expiresAt: EXPIRES_AT,
      };
    },
    async resume(_context: AuthenticatedProductContext, _input: { resumeHandle: string }) {
      return { status: "pending" as const, requestId: "request-1", expiresAt: EXPIRES_AT };
    },
    async receipt(_context: AuthenticatedProductContext, input: { requestId: string }) {
      return { status: "not_available" as const, requestId: input.requestId };
    },
  };
  const mcp = createMcpHttpHandler({
    backend: service,
    resolveContext: ({ authInfo }) => productContextFromAuthInfo(authInfo),
    allowedHostnames: ["127.0.0.1"],
    allowedOriginHostnames: ["127.0.0.1"],
  });
  const dependencies: ProductAppDependencies = {
    publicBaseUrl: "http://127.0.0.1:8787",
    readiness: async () => true,
    authenticator: {
      async authenticate(token) {
        if (token !== "agent-access-secret") throw new Error("unexpected token");
        return structuredClone(context);
      },
    },
    service,
    approvalWeb: { async handle() { return false; } },
    mcp,
    oauth: {
      issuer: "http://127.0.0.1:9000",
      authorizationUrl: "http://127.0.0.1:9000/authorize",
      tokenUrl: "http://127.0.0.1:9000/token",
    },
    log: () => undefined,
  };
  return { dependencies, proposals, statusContexts };
}

async function invoke(
  dependencies: ProductAppDependencies,
  input: {
    method: string;
    path: string;
    token?: string;
    headers?: Record<string, string>;
    body?: unknown;
  },
): Promise<{ status: number; body: Record<string, any>; rawBody: string; headers: Record<string, string> }> {
  const rawRequestBody = input.body === undefined ? "" : JSON.stringify(input.body);
  const request = Readable.from(rawRequestBody ? [rawRequestBody] : []) as IncomingMessage;
  request.method = input.method;
  request.url = input.path;
  request.headers = {
    host: "127.0.0.1:8787",
    ...(input.body === undefined ? {} : { "content-type": "application/json" }),
    ...(input.token === undefined ? {} : { authorization: `Bearer ${input.token}` }),
    ...input.headers,
  };
  let rawBody = "";
  const responseHeaders: Record<string, string> = {};
  const response = {
    statusCode: 200,
    destroyed: false,
    setHeader(name: string, value: string) {
      responseHeaders[name.toLowerCase()] = String(value);
      return this;
    },
    writeHead(status: number, headers?: Record<string, string>) {
      this.statusCode = status;
      for (const [name, value] of Object.entries(headers ?? {})) responseHeaders[name.toLowerCase()] = String(value);
      return this;
    },
    write(chunk: string | Uint8Array) {
      rawBody += typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
      return true;
    },
    end(chunk?: string | Uint8Array) {
      if (chunk !== undefined) rawBody += typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
      return this;
    },
    on() { return this; },
  } as unknown as ServerResponse;
  await createProductRequestHandler(dependencies)(request, response);
  const contentType = responseHeaders["content-type"] ?? "";
  const jsonText = contentType.startsWith("text/event-stream")
    ? rawBody.split(/\r?\n/u).find((line) => line.startsWith("data: "))?.slice(6) ?? "{}"
    : rawBody || "{}";
  return {
    status: response.statusCode,
    body: JSON.parse(jsonText) as Record<string, any>,
    rawBody,
    headers: responseHeaders,
  };
}
