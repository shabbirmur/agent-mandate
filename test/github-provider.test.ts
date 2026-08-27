import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { decodeJwt, decodeProtectedHeader } from "jose";
import { canonicalHash } from "../src/canonical.js";
import {
  ACTION_ENVELOPE_VERSION,
  type ActionEnvelope,
  type DownstreamCredential,
} from "../src/types.js";
import {
  ActionProfileValidationError,
  GITHUB_AUDIENCE,
  GITHUB_ISSUE_CREATE_PROFILE_HASH,
  GITHUB_ISSUE_CREATE_PROFILE_ID,
  bodyWithGithubCorrelation,
  githubIssueCreateProfile,
} from "../src/actions/index.js";
import { DownstreamExecutionError, DownstreamTimeoutError } from "../src/downstream/errors.js";
import {
  GITHUB_API_VERSION,
  GitHubAppCredentialMinter,
  GitHubInstallationTokenExchangeAdapter,
  GitHubIssueExecutor,
  ProviderCredentialError,
} from "../src/providers/index.js";

const NOW = new Date("2026-08-26T10:00:00.000Z");
const REPOSITORY_ID = 1_296_269;
const INSTALLATION_ID = 7_654_321;
const CORRELATION_ID = "correlation_1234567890";
const TARGET = { repositoryId: REPOSITORY_ID, owner: "octocat", name: "Hello-World" };
const PRIVATE_KEY = generateKeyPairSync("rsa", { modulusLength: 2_048 }).privateKey
  .export({ type: "pkcs8", format: "pem" }).toString();

test("GitHub issue profile is frozen, deterministic, consequential, and exactly binds title/body to a numeric repository resource", () => {
  assert.equal(GITHUB_ISSUE_CREATE_PROFILE_HASH, "CtAm5nsv3AKG02u_YCQ1D-kpITDBOgxQPO-O75uXBhE");
  assert.equal(GITHUB_ISSUE_CREATE_PROFILE_HASH, canonicalHash(githubIssueCreateProfile.manifest));
  assert.equal(Object.isFrozen(githubIssueCreateProfile.manifest), true);
  assert.equal(Object.isFrozen(githubIssueCreateProfile.manifest.tool.inputSchema), true);

  const first = prepared();
  const second = prepared();
  assert.deepEqual(first, second);
  assert.deepEqual(first, {
    profileId: GITHUB_ISSUE_CREATE_PROFILE_ID,
    profileHash: GITHUB_ISSUE_CREATE_PROFILE_HASH,
    providerId: "github",
    audience: GITHUB_AUDIENCE,
    action: GITHUB_ISSUE_CREATE_PROFILE_ID,
    risk: "consequential",
    resource: `github:repository:${REPOSITORY_ID}`,
    parameters: {
      repositoryId: REPOSITORY_ID,
      repository: "octocat/Hello-World",
      title: "Bound title",
      body: "Exact body",
      correlationId: CORRELATION_ID,
    },
  });

  const otherRepository = githubIssueCreateProfile.prepare(
    { repository: "octocat/Hello-World", title: "Bound title", body: "Exact body" },
    { ...TARGET, repositoryId: REPOSITORY_ID + 1 },
    CORRELATION_ID,
  );
  assert.notEqual(otherRepository.resource, first.resource);
  assert.notEqual(canonicalHash(otherRepository), canonicalHash(first));
});

test("GitHub issue profile rejects extra authority, wrong types, oversized content, reserved markers, and path attacks", () => {
  const invalidInputs: unknown[] = [
    null,
    [],
    { repository: "octocat/Hello-World", title: 42 },
    { repository: "octocat/Hello-World", title: "ok", body: 42 },
    { repository: "octocat/Hello-World", title: "ok", action: "repo.delete" },
    { repository: "octocat/Hello-World", title: "ok", method: "DELETE" },
    { repository: "octocat/Hello-World", title: "ok", url: "https://attacker.example" },
    { repository: "octocat/Hello-World", title: "line\nbreak" },
    { repository: "octocat/Hello-World", title: "x".repeat(257) },
    { repository: "octocat/Hello-World", title: "ok", body: "x".repeat(65_001) },
    { repository: "octocat/Hello-World", title: "ok", body: "<!-- agent-mandate-correlation:forged -->" },
    { repository: "octocat/repo/../../admin", title: "ok" },
    { repository: "octocat/%2Frepo", title: "ok" },
    { repository: "https://attacker.example/repo", title: "ok" },
    { repository: "octocat/repo?admin=true", title: "ok" },
    { repository: "octocat\\repo", title: "ok" },
    { repository: "octocat//repo", title: "ok" },
  ];
  for (const input of invalidInputs) {
    assert.throws(
      () => githubIssueCreateProfile.prepare(input, TARGET, CORRELATION_ID),
      (error: unknown) => error instanceof ActionProfileValidationError,
    );
  }

  for (const target of [
    { ...TARGET, repositoryId: 0 },
    { ...TARGET, repositoryId: 1.5 },
    { ...TARGET, repositoryId: Number.MAX_SAFE_INTEGER + 1 },
    { ...TARGET, owner: "octocat/attacker" },
    { ...TARGET, name: "../admin" },
    { ...TARGET, name: "repo?admin=true" },
  ]) {
    assert.throws(
      () => githubIssueCreateProfile.prepare({ repository: "octocat/Hello-World", title: "ok" }, target, CORRELATION_ID),
      (error: unknown) => error instanceof ActionProfileValidationError,
    );
  }
  assert.throws(
    () => githubIssueCreateProfile.prepare({ repository: "octocat/other", title: "ok" }, TARGET, CORRELATION_ID),
    (error: unknown) => error instanceof ActionProfileValidationError,
  );
});

test("GitHub App minter signs RS256 and requests only one explicit repository with issues write", async () => {
  let observedUrl = "";
  let observedInit: RequestInit | undefined;
  const minter = new GitHubAppCredentialMinter({
    appId: 12345,
    privateKeyPem: PRIVATE_KEY,
    now: () => NOW,
    fetch: async (input, init) => {
      observedUrl = String(input);
      observedInit = init;
      return jsonResponse(201, installationTokenResponse("ghs_installation_secret"));
    },
  });

  const credential = await minter.mint({ installationId: INSTALLATION_ID, repositoryId: REPOSITORY_ID });
  assert.equal(observedUrl, `https://api.github.com/app/installations/${INSTALLATION_ID}/access_tokens`);
  assert.equal(observedInit?.method, "POST");
  assert.equal(observedInit?.redirect, "manual");
  assert.deepEqual(JSON.parse(String(observedInit?.body)), {
    repository_ids: [REPOSITORY_ID],
    permissions: { issues: "write" },
  });

  const headers = new Headers(observedInit?.headers);
  assert.equal(headers.get("x-github-api-version"), GITHUB_API_VERSION);
  const appJwt = headers.get("authorization")?.replace(/^Bearer /, "");
  assert.ok(appJwt);
  assert.equal(decodeProtectedHeader(appJwt).alg, "RS256");
  const payload = decodeJwt(appJwt);
  assert.equal(payload.iss, "12345");
  assert.equal(payload.iat, Math.floor(NOW.getTime() / 1_000) - 60);
  assert.equal(payload.exp, Math.floor(NOW.getTime() / 1_000) + 9 * 60);
  assert.deepEqual(credential, {
    accessToken: "ghs_installation_secret",
    tokenType: "Bearer",
    audience: GITHUB_AUDIENCE,
    expiresAt: new Date(NOW.getTime() + 60 * 60 * 1_000).toISOString(),
  });
});

test("GitHub App minter validates a strong RSA private key before startup succeeds", () => {
  const weakRsa = generateKeyPairSync("rsa", { modulusLength: 1_024 }).privateKey
    .export({ type: "pkcs8", format: "pem" }).toString();
  const ec = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey
    .export({ type: "pkcs8", format: "pem" }).toString();
  for (const privateKeyPem of ["not-a-private-key".repeat(8), weakRsa, ec]) {
    assert.throws(
      () => new GitHubAppCredentialMinter({ appId: 12345, privateKeyPem }),
      /invalid_provider_configuration/,
    );
  }
});

test("GitHub App minter rejects redirects, broader token responses, oversized responses, and never exposes response secrets", async () => {
  const cases: Array<() => Promise<Response>> = [
    async () => new Response(null, { status: 307, headers: { location: "https://attacker.example/token" } }),
    async () => jsonResponse(201, {
      ...installationTokenResponse("ghs_broad_secret"),
      permissions: { issues: "write", administration: "write" },
    }),
    async () => new Response(JSON.stringify({ token: "ghs_oversized_secret", padding: "x".repeat(70_000) }), { status: 201 }),
    async () => jsonResponse(422, { message: "ghs_error_body_secret" }),
  ];

  for (const response of cases) {
    let calls = 0;
    const minter = new GitHubAppCredentialMinter({
      appId: 12345,
      privateKeyPem: PRIVATE_KEY,
      now: () => NOW,
      fetch: async () => { calls += 1; return response(); },
    });
    await assert.rejects(
      minter.mint({ installationId: INSTALLATION_ID, repositoryId: REPOSITORY_ID }),
      (error: unknown) => {
        assert.equal(error instanceof ProviderCredentialError, true);
        assert.equal(/ghs_|attacker|administration/.test(String(error)), false);
        return true;
      },
    );
    assert.equal(calls, 1);
  }
});

test("GitHub executor uses one fixed POST endpoint, deterministic correlated body, and allowlists output", async () => {
  let observedUrl = "";
  let observedInit: RequestInit | undefined;
  const executor = new GitHubIssueExecutor({
    now: () => NOW,
    fetch: async (input, init) => {
      observedUrl = String(input);
      observedInit = init;
      return jsonResponse(201, issueResponse({
        body: bodyWithGithubCorrelation("Exact body", CORRELATION_ID),
        installationToken: "ghs_installation_secret",
        deeplySensitive: { authorization: "Bearer ghs_installation_secret" },
      }));
    },
  });

  const result = await executor.execute(executionInput());
  assert.equal(observedUrl, "https://api.github.com/repos/octocat/Hello-World/issues");
  assert.equal(observedInit?.method, "POST");
  assert.equal(observedInit?.redirect, "manual");
  assert.deepEqual(JSON.parse(String(observedInit?.body)), {
    body: bodyWithGithubCorrelation("Exact body", CORRELATION_ID),
    title: "Bound title",
  });
  assert.deepEqual(result, {
    status: 201,
    body: {
      id: 10,
      nodeId: "ISSUE_node_10",
      number: 42,
      htmlUrl: "https://github.com/octocat/Hello-World/issues/42",
      state: "open",
      title: "Bound title",
    },
  });
  const serialized = JSON.stringify(result);
  assert.equal(serialized.includes("ghs_installation_secret"), false);
  assert.equal(serialized.includes("Exact body"), false);
  assert.equal(serialized.includes("deeplySensitive"), false);
});

test("GitHub executor rejects redirects and altered bindings without following or dispatching arbitrary routes", async () => {
  let calls = 0;
  const executor = new GitHubIssueExecutor({
    now: () => NOW,
    fetch: async () => {
      calls += 1;
      return new Response(null, { status: 307, headers: { location: "https://attacker.example" } });
    },
  });
  await assert.rejects(
    executor.execute(executionInput()),
    (error: unknown) => error instanceof DownstreamTimeoutError && error.ambiguous,
  );
  assert.equal(calls, 1);

  const changedAction = executionInput();
  changedAction.envelope = { ...changedAction.envelope, action: "github.repository.delete.v1" };
  await assert.rejects(
    executor.execute(changedAction),
    (error: unknown) => error instanceof DownstreamExecutionError && error.message === "github_action_binding_invalid",
  );
  assert.equal(calls, 1);
});

test("GitHub transport ambiguity reconciles by correlation with GET only and never blindly repeats POST", async () => {
  const methods: string[] = [];
  const urls: string[] = [];
  const executor = new GitHubIssueExecutor({
    now: () => NOW,
    fetch: async (input, init) => {
      methods.push(String(init?.method));
      urls.push(String(input));
      if (init?.method === "POST") throw new Error("connection reset after dispatch");
      return jsonResponse(200, [
        issueResponse({ title: "unrelated", body: "different" }),
        issueResponse({ body: bodyWithGithubCorrelation("Altered body", CORRELATION_ID) }),
        issueResponse({ body: bodyWithGithubCorrelation("Exact body", CORRELATION_ID) }),
      ]);
    },
  });

  await assert.rejects(
    executor.execute(executionInput()),
    (error: unknown) => error instanceof DownstreamTimeoutError && error.ambiguous,
  );
  const reconciled = await executor.reconcile(executionInput());
  assert.equal(reconciled?.status, 200);
  assert.deepEqual(methods, ["POST", "GET"]);
  assert.equal(methods.filter((method) => method === "POST").length, 1);
  assert.equal(urls[1], "https://api.github.com/repos/octocat/Hello-World/issues?state=all&sort=created&direction=desc&per_page=100");
});

test("GitHub executor treats an unreadable successful response as ambiguous and does not leak credentials", async () => {
  for (const response of [
    new Response(JSON.stringify({ token: "ghs_response_secret", padding: "x".repeat(600_000) }), { status: 201 }),
    jsonResponse(201, issueResponse({ body: "missing-correlation-marker" })),
    jsonResponse(201, issueResponse({ body: bodyWithGithubCorrelation("Altered body", CORRELATION_ID) })),
  ]) {
    const executor = new GitHubIssueExecutor({ now: () => NOW, fetch: async () => response });
    await assert.rejects(
      executor.execute(executionInput()),
      (error: unknown) => {
        assert.equal(error instanceof DownstreamTimeoutError, true);
        assert.equal(String(error).includes("ghs_response_secret"), false);
        return true;
      },
    );
  }
});

test("GitHub gateway credential exchange is fixed to its installation and numeric repository resource", async () => {
  const minted: Array<{ installationId: number; repositoryId: number }> = [];
  const adapter = new GitHubInstallationTokenExchangeAdapter({
    installationId: INSTALLATION_ID,
    minter: {
      async mint(input) {
        minted.push(input);
        return {
          accessToken: "github-installation-token",
          tokenType: "Bearer",
          audience: GITHUB_AUDIENCE,
          expiresAt: new Date(NOW.getTime() + 60_000).toISOString(),
        };
      },
    },
  });
  await adapter.exchange({
    tenantId: "tenant:one",
    principalId: "user:alice",
    agentId: "agent:codex",
    subjectGrant: "internal-mandate-grant",
    audience: GITHUB_AUDIENCE,
    scope: `github:repository:${REPOSITORY_ID}`,
  });
  assert.deepEqual(minted, [{ installationId: INSTALLATION_ID, repositoryId: REPOSITORY_ID }]);
  for (const mutation of [
    { audience: "https://attacker.example", scope: `github:repository:${REPOSITORY_ID}` },
    { audience: GITHUB_AUDIENCE, scope: "github:repository:../../secrets" },
    { audience: GITHUB_AUDIENCE, scope: "github:repository:0" },
  ]) {
    await assert.rejects(adapter.exchange({
      tenantId: "tenant:one",
      principalId: "user:alice",
      agentId: "agent:codex",
      subjectGrant: "internal-mandate-grant",
      ...mutation,
    }), (error: unknown) => error instanceof ProviderCredentialError);
  }
  assert.equal(minted.length, 1);
});

function prepared() {
  return githubIssueCreateProfile.prepare(
    { repository: "OCTOCAT/hello-world", title: "Bound title", body: "Exact body" },
    TARGET,
    CORRELATION_ID,
  );
}

function executionInput(): { envelope: ActionEnvelope; credential: DownstreamCredential; idempotencyKey: string } {
  const intent = prepared();
  return {
    envelope: {
      version: ACTION_ENVELOPE_VERSION,
      tenantId: "tenant:one",
      principalId: "user:alice",
      agentId: "agent:codex",
      workloadId: "workload:codex-1",
      taskId: "task:issue-42",
      audience: intent.audience,
      action: intent.action,
      resource: intent.resource,
      parameters: intent.parameters,
    },
    credential: {
      accessToken: "ghs_installation_secret",
      tokenType: "Bearer",
      audience: GITHUB_AUDIENCE,
      expiresAt: new Date(NOW.getTime() + 60 * 60 * 1_000).toISOString(),
    },
    idempotencyKey: CORRELATION_ID,
  };
}

function installationTokenResponse(token: string): Record<string, unknown> {
  return {
    token,
    expires_at: new Date(NOW.getTime() + 60 * 60 * 1_000).toISOString(),
    permissions: { issues: "write", metadata: "read" },
    repository_selection: "selected",
    repositories: [{ id: REPOSITORY_ID, full_name: "octocat/Hello-World" }],
  };
}

function issueResponse(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 10,
    node_id: "ISSUE_node_10",
    number: 42,
    html_url: "https://github.com/octocat/Hello-World/issues/42",
    repository_url: "https://api.github.com/repos/octocat/Hello-World",
    state: "open",
    title: "Bound title",
    body: bodyWithGithubCorrelation("Exact body", CORRELATION_ID),
    user: { login: "octocat", email: "private@example.com" },
    ...overrides,
  };
}

function jsonResponse(status: number, value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}
