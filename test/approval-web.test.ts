import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer, type Server } from "node:http";
import test, { type TestContext } from "node:test";
import { SignJWT } from "jose";
import { ApprovalWebController } from "../src/approvals/web.js";
import { OidcPrincipalAuthenticator } from "../src/identity/index.js";
import {
  ACTION_ENVELOPE_VERSION,
  APPROVAL_INTENT_VERSION,
  type ApprovalRequest,
  type PrincipalContext,
} from "../src/types.js";

const IDP_KEY = new TextEncoder().encode("approval-web-idp-test-key-at-least-32-bytes");
const COOKIE_KEY = new TextEncoder().encode("approval-web-cookie-test-key-at-least-32-bytes");
const REQUEST_ID = "approval-request-one";
const INTENT_HASH = "A".repeat(43);
const NOW = new Date("2026-08-26T12:00:00.000Z");

test("unauthenticated approval starts fixed OIDC authorization-code PKCE without URL identity or capability", async (t) => {
  const fixture = await createFixture(t);
  assert.throws(() => createControllerForValidation("http://example.test"), /HTTPS/u);

  const response = await fixture.request(`/approvals/${REQUEST_ID}`);
  assert.equal(response.status, 302);
  const authorization = new URL(requiredHeader(response, "location"));
  assert.equal(authorization.origin + authorization.pathname, `${fixture.baseUrl}/oidc/authorize`);
  assert.equal(authorization.searchParams.get("response_type"), "code");
  assert.equal(authorization.searchParams.get("response_mode"), "query");
  assert.equal(authorization.searchParams.get("client_id"), "approval-browser");
  assert.equal(authorization.searchParams.get("redirect_uri"), `${fixture.baseUrl}/oauth/callback`);
  assert.equal(authorization.searchParams.get("scope"), "openid profile");
  assert.equal(authorization.searchParams.get("code_challenge_method"), "S256");
  assert.match(authorization.searchParams.get("state") ?? "", /^[A-Za-z0-9_-]{43}$/u);
  assert.match(authorization.searchParams.get("nonce") ?? "", /^[A-Za-z0-9_-]{43}$/u);
  assert.match(authorization.searchParams.get("code_challenge") ?? "", /^[A-Za-z0-9_-]{43}$/u);
  assert.doesNotMatch(requiredHeader(response, "location"), /approval-request-one|user%3Aalice|intentHash/iu);

  const setCookie = response.headers.getSetCookie()[0]!;
  assert.match(setCookie, /^agent_mandate_login=v1\.[A-Za-z0-9_.-]+;/u);
  assert.match(setCookie, /HttpOnly/u);
  assert.match(setCookie, /SameSite=Lax/u);
  assert.match(setCookie, /Path=\//u);
  assert.doesNotMatch(setCookie, /approval-request-one|user:alice/u);
  assert.equal(fixture.approvals.getCalls.length, 0);
});

test("callback binds state, PKCE verifier, nonce, auth_time, expected principal, and one-time login state", async (t) => {
  const fixture = await createFixture(t);
  const authorization = await fixture.begin();
  const savedLogin = fixture.cookies.get("agent_mandate_login")!;
  const response = await fixture.callback(authorization, "code-one");

  assert.equal(response.status, 303);
  assert.equal(requiredHeader(response, "location"), `/approvals/${REQUEST_ID}`);
  assert.equal(fixture.tokenCalls.length, 1);
  const tokenCall = fixture.tokenCalls[0]!;
  assert.equal(tokenCall.url, `${fixture.baseUrl}/oidc/token`);
  assert.equal(tokenCall.redirect, "manual");
  const tokenBody = new URLSearchParams(tokenCall.body);
  assert.equal(tokenBody.get("grant_type"), "authorization_code");
  assert.equal(tokenBody.get("code"), "code-one");
  assert.equal(tokenBody.get("redirect_uri"), `${fixture.baseUrl}/oauth/callback`);
  assert.equal(tokenBody.get("client_id"), null);
  assert.match(tokenBody.get("code_verifier") ?? "", /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(
    createHash("sha256").update(tokenBody.get("code_verifier")!, "ascii").digest("base64url"),
    authorization.searchParams.get("code_challenge"),
  );
  assert.match(tokenCall.authorization ?? "", /^Basic /u);
  assert.doesNotMatch(tokenCall.body, /test-client-secret/u);
  assert.deepEqual(fixture.approvals.getCalls.at(-1), { tenantId: "tenant:one", principalId: "user:alice", requestId: REQUEST_ID });
  assert.equal(fixture.cookies.has("agent_mandate_login"), false);
  assert.match(fixture.cookies.get("agent_mandate_session") ?? "", /^v1\./u);

  fixture.cookies.set("agent_mandate_login", savedLogin);
  const replay = await fixture.callback(authorization, "code-one");
  assert.equal(replay.status, 401);
  assert.match(await replay.text(), /authentication_failed/u);
  assert.equal(fixture.tokenCalls.length, 1);
});

test("authenticated preview is exact, non-cacheable, framed off, and renders XSS, controls, and bidi visibly", async (t) => {
  const fixture = await createFixture(t);
  await fixture.login();
  const response = await fixture.request(`/approvals/${REQUEST_ID}`);
  const html = await response.text();

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store, max-age=0");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("content-security-policy"), "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  assert.match(html, /github\.issue\.create/u);
  assert.match(html, /github:repository:123/u);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/u);
  assert.doesNotMatch(html, /<script|onerror=|src="https?:/iu);
  assert.match(html, /\\u202E/u);
  assert.doesNotMatch(html, /\u202e/u);
  assert.match(html, /Approve this exact action once/u);
  assert.match(html, new RegExp(`name="intentHash" value="${INTENT_HASH}"`, "u"));
});

test("wrong OIDC user is denied before a session is established", async (t) => {
  const fixture = await createFixture(t, { tokenPrincipalId: "user:bob" });
  const authorization = await fixture.begin();
  const response = await fixture.callback(authorization, "wrong-user-code");
  assert.equal(response.status, 404);
  assert.match(await response.text(), /approval_not_found/u);
  assert.equal(fixture.cookies.has("agent_mandate_session"), false);
});

test("tampered and expired login or session cookies fail closed", async (t) => {
  const fixture = await createFixture(t);
  const authorization = await fixture.begin();
  fixture.cookies.set("agent_mandate_login", tamper(fixture.cookies.get("agent_mandate_login")!));
  const tampered = await fixture.callback(authorization, "tampered-cookie-code");
  assert.equal(tampered.status, 401);
  assert.equal(fixture.tokenCalls.length, 0);

  const expiring = await createFixture(t, { loginTtlSeconds: 30, sessionTtlSeconds: 30 });
  const secondAuthorization = await expiring.begin();
  expiring.advance(31_000);
  const expiredLogin = await expiring.callback(secondAuthorization, "expired-login-code");
  assert.equal(expiredLogin.status, 401);
  assert.match(await expiredLogin.text(), /authentication_expired/u);

  const sessionFixture = await createFixture(t, { sessionTtlSeconds: 30 });
  await sessionFixture.login();
  sessionFixture.advance(31_000);
  const expiredSession = await sessionFixture.request(`/approvals/${REQUEST_ID}`);
  assert.equal(expiredSession.status, 302);
  assert.match(requiredHeader(expiredSession, "location"), /\/oidc\/authorize/u);
});

test("decision POST enforces exact Origin, form type, constant-time CSRF, request binding, intent, and IDOR", async (t) => {
  const fixture = await createFixture(t);
  const preview = await fixture.loginAndPreview();
  const csrf = hidden(preview, "csrf");

  const missingOrigin = await fixture.decide({ csrf }, { origin: undefined });
  assert.equal(missingOrigin.status, 403);
  const wrongOrigin = await fixture.decide({ csrf }, { origin: "https://attacker.example" });
  assert.equal(wrongOrigin.status, 403);
  const wrongType = await fixture.decide({ csrf }, { contentType: "application/json" });
  assert.equal(wrongType.status, 415);
  const wrongCsrf = await fixture.decide({ csrf: "B".repeat(43) });
  assert.equal(wrongCsrf.status, 403);
  const pathMismatch = await fixture.decide({ csrf, requestId: "approval-request-two" });
  assert.equal(pathMismatch.status, 400);
  const wrongIntent = await fixture.decide({ csrf, intentHash: "C".repeat(43) });
  assert.equal(wrongIntent.status, 409);
  const idor = await fixture.decide(
    { csrf, requestId: "approval-request-two" },
    { pathRequestId: "approval-request-two" },
  );
  assert.equal(idor.status, 404);
  assert.equal(fixture.approvals.decideCalls.length, 2);
  assert.equal(fixture.approvals.request.status, "pending");
});

test("approve and deny use only the encrypted session principal and exact frozen form values", async (t) => {
  const approved = await createFixture(t);
  const approveHtml = await approved.loginAndPreview();
  const approve = await approved.decide({ csrf: hidden(approveHtml, "csrf") });
  assert.equal(approve.status, 303);
  assert.equal(approved.approvals.request.status, "approved");
  assert.deepEqual(approved.approvals.decideCalls[0], {
    principalId: "user:alice",
    tenantId: "tenant:one",
    requestId: REQUEST_ID,
    intentHash: INTENT_HASH,
    decision: "approved",
    reason: undefined,
  });
  const decidedPreview = await approved.request(`/approvals/${REQUEST_ID}`);
  assert.doesNotMatch(await decidedPreview.text(), /Approve this exact action once/u);

  const denied = await createFixture(t);
  const denyHtml = await denied.loginAndPreview();
  const deny = await denied.decide({ csrf: hidden(denyHtml, "csrf"), decision: "denied", reason: "Not this operation" });
  assert.equal(deny.status, 303);
  assert.equal(denied.approvals.request.status, "denied");
  assert.equal(denied.approvals.request.decisionReason, "Not this operation");
});

test("token endpoint redirects, oversized bodies, non-JSON, and error responses are bounded and fail closed", async (t) => {
  for (const mode of ["redirect", "oversize", "non_json", "error"] as const) {
    const fixture = await createFixture(t, { tokenMode: mode, maxTokenResponseBytes: 1_024 });
    const authorization = await fixture.begin();
    const response = await fixture.callback(authorization, `code-${mode}`);
    assert.equal(response.status, 502, mode);
    const body = await response.text();
    assert.match(body, /token_exchange_failed/u, mode);
    assert.doesNotMatch(body, new RegExp(`code-${mode}|test-client-secret`, "u"), mode);
    assert.equal(fixture.cookies.has("agent_mandate_session"), false, mode);
  }
});

test("stale or missing verified auth_time is rejected and decision replay is terminal", async (t) => {
  const stale = await createFixture(t, { tokenAuthTime: new Date(NOW.getTime() - 301_000) });
  const staleAuthorization = await stale.begin();
  const staleResponse = await stale.callback(staleAuthorization, "stale-auth-code");
  assert.equal(staleResponse.status, 401);
  assert.match(await staleResponse.text(), /authentication_expired/u);

  const missing = await createFixture(t, { omitAuthTime: true });
  const missingAuthorization = await missing.begin();
  const missingResponse = await missing.callback(missingAuthorization, "missing-auth-time-code");
  assert.equal(missingResponse.status, 401);
  assert.match(await missingResponse.text(), /authentication_failed/u);

  const fixture = await createFixture(t);
  const html = await fixture.loginAndPreview();
  const csrf = hidden(html, "csrf");
  assert.equal((await fixture.decide({ csrf })).status, 303);
  const replay = await fixture.decide({ csrf });
  assert.equal(replay.status, 409);
  assert.equal(fixture.approvals.decideCalls.length, 2);
});

interface FixtureOptions {
  tokenPrincipalId?: string;
  tokenAuthTime?: Date;
  omitAuthTime?: boolean;
  tokenMode?: "ok" | "redirect" | "oversize" | "non_json" | "error";
  loginTtlSeconds?: number;
  sessionTtlSeconds?: number;
  maxTokenResponseBytes?: number;
}

async function createFixture(t: TestContext, options: FixtureOptions = {}) {
  let clock = new Date(NOW);
  let controller: ApprovalWebController | undefined;
  const approvals = new FakeApprovals(() => new Date(clock));
  const cookies = new Map<string, string>();
  let callbackNonce = "";
  const tokenCalls: Array<{ url: string; body: string; redirect: RequestRedirect | undefined; authorization: string | undefined }> = [];
  const server = createServer((request, response) => {
    void controller!.handle(request, response).then((handled) => {
      if (!handled && !response.headersSent) {
        response.statusCode = 404;
        response.end();
      }
    }).catch(() => {
      if (!response.headersSent) response.writeHead(500);
      response.end();
    });
  });
  const baseUrl = await listen(server);
  t.after(() => close(server));
  const principalAuthenticator = new OidcPrincipalAuthenticator({
    issuer: `${baseUrl}/oidc`,
    audience: "approval-browser",
    verificationKey: IDP_KEY,
    algorithms: ["HS256"],
  });
  const tokenFetch: typeof fetch = async (input, init) => {
    tokenCalls.push({
      url: String(input),
      body: String(init?.body ?? ""),
      redirect: init?.redirect,
      authorization: headerFrom(init?.headers, "authorization"),
    });
    switch (options.tokenMode ?? "ok") {
      case "redirect":
        return new Response(null, { status: 302, headers: { location: "https://attacker.example/token" } });
      case "oversize":
        return new Response("x".repeat(2_048), { status: 200, headers: { "content-type": "application/json", "content-length": "2048" } });
      case "non_json":
        return new Response("not-json", { status: 200, headers: { "content-type": "text/plain" } });
      case "error":
        return new Response(JSON.stringify({ error: "raw-secret-error" }), { status: 500, headers: { "content-type": "application/json" } });
      case "ok": {
        const principalId = options.tokenPrincipalId ?? "user:alice";
        const token = await idToken({
          issuer: `${baseUrl}/oidc`,
          nonce: callbackNonce,
          principalId,
          authenticatedAt: options.tokenAuthTime ?? clock,
          omitAuthTime: options.omitAuthTime === true,
        });
        return new Response(JSON.stringify({ id_token: token, access_token: "must-not-leak" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
    }
  };
  controller = new ApprovalWebController({
    approvals,
    principalAuthenticator,
    cookieKey: COOKIE_KEY,
    publicBaseUrl: baseUrl,
    authorizationEndpoint: `${baseUrl}/oidc/authorize`,
    tokenEndpoint: `${baseUrl}/oidc/token`,
    clientId: "approval-browser",
    clientSecret: "test-client-secret",
    scope: "openid profile",
    allowInsecureLoopback: true,
    ...(options.loginTtlSeconds === undefined ? {} : { loginTtlSeconds: options.loginTtlSeconds }),
    ...(options.sessionTtlSeconds === undefined ? {} : { sessionTtlSeconds: options.sessionTtlSeconds }),
    ...(options.maxTokenResponseBytes === undefined ? {} : { maxTokenResponseBytes: options.maxTokenResponseBytes }),
    fetch: tokenFetch,
    now: () => new Date(clock),
  });

  async function request(path: string, init: RequestInit = {}): Promise<Response> {
    const headers = new Headers(init.headers);
    if (cookies.size > 0 && !headers.has("cookie")) {
      headers.set("cookie", [...cookies].map(([name, value]) => `${name}=${value}`).join("; "));
    }
    const response = await fetch(`${baseUrl}${path}`, { ...init, headers, redirect: "manual" });
    applyCookies(cookies, response.headers.getSetCookie());
    return response;
  }

  async function begin(): Promise<URL> {
    const response = await request(`/approvals/${REQUEST_ID}`);
    assert.equal(response.status, 302);
    const authorization = new URL(requiredHeader(response, "location"));
    callbackNonce = authorization.searchParams.get("nonce") ?? "";
    return authorization;
  }

  async function callback(authorization: URL, code: string): Promise<Response> {
    const state = authorization.searchParams.get("state")!;
    return request(`/oauth/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`);
  }

  async function login(): Promise<void> {
    const authorization = await begin();
    const response = await callback(authorization, "valid-code");
    assert.equal(response.status, 303);
  }

  async function loginAndPreview(): Promise<string> {
    await login();
    const response = await request(`/approvals/${REQUEST_ID}`);
    assert.equal(response.status, 200);
    return response.text();
  }

  async function decide(
    fields: { csrf: string; requestId?: string; intentHash?: string; decision?: "approved" | "denied"; reason?: string },
    requestOptions: { pathRequestId?: string; origin?: string; contentType?: string } = {},
  ): Promise<Response> {
    const form = new URLSearchParams({
      requestId: fields.requestId ?? REQUEST_ID,
      intentHash: fields.intentHash ?? INTENT_HASH,
      decision: fields.decision ?? "approved",
      csrf: fields.csrf,
      ...(fields.reason === undefined ? {} : { reason: fields.reason }),
    });
    const headers: Record<string, string> = {
      "content-type": requestOptions.contentType ?? "application/x-www-form-urlencoded",
    };
    if (requestOptions.origin !== undefined) headers.origin = requestOptions.origin;
    else if (!("origin" in requestOptions)) headers.origin = baseUrl;
    return request(`/approvals/${requestOptions.pathRequestId ?? REQUEST_ID}/decision`, {
      method: "POST",
      headers,
      body: form.toString(),
    });
  }

  return {
    approvals,
    baseUrl,
    cookies,
    tokenCalls,
    request,
    begin,
    callback,
    login,
    loginAndPreview,
    decide,
    advance(milliseconds: number) {
      clock = new Date(clock.getTime() + milliseconds);
    },
  };
}

class FakeApprovals {
  request = approvalRequest();
  readonly getCalls: Array<{ tenantId: string; principalId: string; requestId: string }> = [];
  readonly decideCalls: Array<{
    principalId: string;
    tenantId: string;
    requestId: string;
    intentHash: string;
    decision: "approved" | "denied";
    reason: string | undefined;
  }> = [];

  constructor(readonly now: () => Date) {}

  async getForPrincipal(principal: PrincipalContext, requestId: string): Promise<ApprovalRequest> {
    this.getCalls.push({ tenantId: principal.tenantId, principalId: principal.principalId, requestId });
    if (principal.tenantId !== this.request.tenantId || principal.principalId !== this.request.expectedPrincipalId || requestId !== this.request.id) {
      throw serviceError("approval_not_found");
    }
    return structuredClone(this.request);
  }

  async decide(principal: PrincipalContext, input: {
    requestId: string;
    intentHash: string;
    decision: "approved" | "denied";
    reason?: string;
  }): Promise<ApprovalRequest> {
    this.decideCalls.push({
      principalId: principal.principalId,
      tenantId: principal.tenantId,
      requestId: input.requestId,
      intentHash: input.intentHash,
      decision: input.decision,
      reason: input.reason,
    });
    if (principal.tenantId !== this.request.tenantId || principal.principalId !== this.request.expectedPrincipalId || input.requestId !== this.request.id) {
      throw serviceError("approval_not_found");
    }
    if (input.intentHash !== this.request.intentHash || this.request.status !== "pending") throw serviceError("approval_mismatch");
    if (Date.parse(this.request.expiresAt) <= this.now().getTime()) throw serviceError("approval_expired");
    this.request.status = input.decision;
    this.request.decidedBy = principal.principalId;
    this.request.decidedAt = this.now().toISOString();
    this.request.authenticatedAt = principal.authenticatedAt;
    if (input.reason !== undefined) this.request.decisionReason = input.reason;
    return structuredClone(this.request);
  }
}

function approvalRequest(): ApprovalRequest {
  const envelope = {
    version: ACTION_ENVELOPE_VERSION,
    tenantId: "tenant:one",
    principalId: "user:alice",
    agentId: "agent:codex",
    workloadId: "workload:codex",
    taskId: "workflow:one",
    audience: "https://api.github.com",
    action: "github.issue.create",
    resource: "github:repository:123",
    parameters: {
      title: "<script>alert(1)</script>",
      body: "safe\u202Etxt",
      nested: { z: "last", a: "first" },
    },
  };
  return {
    id: REQUEST_ID,
    tenantId: "tenant:one",
    expectedPrincipalId: "user:alice",
    agentId: "agent:codex",
    workloadId: "workload:codex",
    workflowId: "workflow:one",
    mcpSessionHash: "M".repeat(43),
    profileId: "github.issue.create.v1",
    profileHash: "P".repeat(43),
    providerId: "github",
    providerConnectionId: "github-installation:1",
    providerResourceId: "123",
    envelope,
    envelopeHash: "E".repeat(43),
    intent: {
      version: APPROVAL_INTENT_VERSION,
      requestId: REQUEST_ID,
      envelope,
      envelopeHash: "E".repeat(43),
      profileId: "github.issue.create.v1",
      profileHash: "P".repeat(43),
      providerId: "github",
      providerConnectionId: "github-installation:1",
      providerResourceId: "123",
      risk: "consequential",
      expiresAt: new Date(NOW.getTime() + 10 * 60_000).toISOString(),
      maxCalls: 1,
      delegationAllowed: false,
      expectedApprover: "user:alice",
    },
    intentHash: INTENT_HASH,
    resumeHandleHash: "R".repeat(43),
    idempotencyKey: `approval:${REQUEST_ID}`,
    status: "pending",
    executionStatus: "not_started",
    createdAt: NOW.toISOString(),
    expiresAt: new Date(NOW.getTime() + 10 * 60_000).toISOString(),
  };
}

async function idToken(input: {
  issuer: string;
  nonce: string;
  principalId: string;
  authenticatedAt: Date;
  omitAuthTime: boolean;
}): Promise<string> {
  // JWT lifetime validation intentionally uses the verifier's real clock. Keep
  // transport validity independent from the fixture clock used to exercise
  // auth_time and approval expiry behavior.
  const jwtNowSeconds = Math.floor(Date.now() / 1_000);
  const claims: Record<string, unknown> = { tenant_id: "tenant:one", nonce: input.nonce };
  if (!input.omitAuthTime) claims.auth_time = Math.floor(input.authenticatedAt.getTime() / 1_000);
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(input.issuer)
    .setAudience("approval-browser")
    .setSubject(input.principalId)
    .setIssuedAt(jwtNowSeconds)
    .setExpirationTime(jwtNowSeconds + 600)
    .sign(IDP_KEY);
}

function createControllerForValidation(publicBaseUrl: string): ApprovalWebController {
  return new ApprovalWebController({
    approvals: new FakeApprovals(() => new Date(NOW)),
    principalAuthenticator: { async authenticate() { throw new Error("unused"); } },
    cookieKey: COOKIE_KEY,
    publicBaseUrl,
    authorizationEndpoint: "https://idp.example/authorize",
    tokenEndpoint: "https://idp.example/token",
    clientId: "client",
  });
}

function applyCookies(jar: Map<string, string>, setCookies: readonly string[]): void {
  for (const setCookie of setCookies) {
    const first = setCookie.split(";", 1)[0]!;
    const separator = first.indexOf("=");
    const name = first.slice(0, separator);
    const value = first.slice(separator + 1);
    if (/;\s*Max-Age=0(?:;|$)/iu.test(setCookie)) jar.delete(name);
    else jar.set(name, value);
  }
}

function hidden(html: string, name: string): string {
  const match = html.match(new RegExp(`name="${name}" value="([^"]+)"`, "u"));
  assert.ok(match, `missing hidden ${name}`);
  return match[1]!;
}

function tamper(value: string): string {
  const last = value.at(-1)!;
  return `${value.slice(0, -1)}${last === "A" ? "B" : "A"}`;
}

function requiredHeader(response: Response, name: string): string {
  const value = response.headers.get(name);
  assert.ok(value, `missing ${name}`);
  return value;
}

function headerFrom(headers: HeadersInit | undefined, name: string): string | undefined {
  return headers === undefined ? undefined : new Headers(headers).get(name) ?? undefined;
}

function serviceError(code: string): Error & { code: string } {
  return Object.assign(new Error(code), { code });
}

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  assert.ok(address && typeof address === "object");
  return `http://127.0.0.1:${address.port}`;
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
