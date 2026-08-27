import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { PrincipalAuthenticator } from "../ports.js";
import type { ApprovalRequest, JsonValue, PrincipalContext } from "../types.js";
import type { ApprovalService } from "./service.js";

const LOGIN_COOKIE_SECURE = "__Host-agent_mandate_login";
const SESSION_COOKIE_SECURE = "__Host-agent_mandate_session";
const LOGIN_COOKIE_LOOPBACK = "agent_mandate_login";
const SESSION_COOKIE_LOOPBACK = "agent_mandate_session";
const DEFAULT_LOGIN_TTL_SECONDS = 300;
const DEFAULT_SESSION_TTL_SECONDS = 300;
const DEFAULT_MAX_AUTHENTICATION_AGE_SECONDS = 300;
const DEFAULT_TOKEN_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_TOKEN_RESPONSE_BYTES = 64 * 1024;
const MAX_FORM_BYTES = 8 * 1024;
const MAX_COOKIE_HEADER_BYTES = 16 * 1024;
const COOKIE_VERSION = 1;

type ApprovalOperations = Pick<ApprovalService, "getForPrincipal" | "decide">;

export interface ApprovalWebControllerOptions {
  approvals: ApprovalOperations;
  principalAuthenticator: PrincipalAuthenticator;
  /** At least 32 bytes of deployment secret material. Separate AEAD keys are derived per cookie purpose. */
  cookieKey: Uint8Array;
  /** Exact externally visible origin. Request Host and forwarding headers are never trusted. */
  publicBaseUrl: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  clientId: string;
  clientSecret?: string;
  scope?: string;
  loginTtlSeconds?: number;
  sessionTtlSeconds?: number;
  maxAuthenticationAgeSeconds?: number;
  tokenTimeoutMs?: number;
  maxTokenResponseBytes?: number;
  /** Intended only for explicit localhost/loopback development and tests. */
  allowInsecureLoopback?: boolean;
  fetch?: typeof globalThis.fetch;
  now?: () => Date;
  randomBytes?: (size: number) => Uint8Array;
}

interface LoginCookie {
  v: typeof COOKIE_VERSION;
  requestId: string;
  state: string;
  nonce: string;
  verifier: string;
  expiresAt: number;
}

interface SessionCookie {
  v: typeof COOKIE_VERSION;
  principal: PrincipalContext;
  csrf: string;
  expiresAt: number;
}

type CookiePurpose = "login" | "session";

class ApprovalWebError extends Error {
  constructor(readonly status: number, readonly publicCode: string) {
    super(publicCode);
    this.name = "ApprovalWebError";
  }
}

/**
 * Browser approval flow. It owns only interactive OIDC/session state; the
 * ApprovalService remains the authority for principal, intent, and expiry.
 */
export class ApprovalWebController {
  readonly #approvals: ApprovalOperations;
  readonly #principalAuthenticator: PrincipalAuthenticator;
  readonly #codec: CookieCodec;
  readonly #publicOrigin: string;
  readonly #redirectUri: string;
  readonly #authorizationEndpoint: URL;
  readonly #tokenEndpoint: URL;
  readonly #clientId: string;
  readonly #clientSecret: string | undefined;
  readonly #scope: string;
  readonly #loginTtlSeconds: number;
  readonly #sessionTtlSeconds: number;
  readonly #maxAuthenticationAgeSeconds: number;
  readonly #tokenTimeoutMs: number;
  readonly #maxTokenResponseBytes: number;
  readonly #secureCookies: boolean;
  readonly #loginCookieName: string;
  readonly #sessionCookieName: string;
  readonly #fetch: typeof globalThis.fetch;
  readonly #now: () => Date;
  readonly #randomBytes: (size: number) => Uint8Array;
  readonly #consumedLoginStates = new Map<string, number>();

  constructor(options: ApprovalWebControllerOptions) {
    this.#approvals = options.approvals;
    this.#principalAuthenticator = options.principalAuthenticator;
    this.#codec = new CookieCodec(options.cookieKey);
    const publicBase = exactOrigin(options.publicBaseUrl, "publicBaseUrl", true);
    const insecureLoopback = publicBase.protocol === "http:" && isLoopback(publicBase.hostname);
    if (publicBase.protocol !== "https:" && !(options.allowInsecureLoopback === true && insecureLoopback)) {
      throw new TypeError("publicBaseUrl must use HTTPS");
    }
    this.#secureCookies = publicBase.protocol === "https:";
    this.#loginCookieName = this.#secureCookies ? LOGIN_COOKIE_SECURE : LOGIN_COOKIE_LOOPBACK;
    this.#sessionCookieName = this.#secureCookies ? SESSION_COOKIE_SECURE : SESSION_COOKIE_LOOPBACK;
    this.#publicOrigin = publicBase.origin;
    this.#redirectUri = `${publicBase.origin}/oauth/callback`;
    this.#authorizationEndpoint = endpoint(options.authorizationEndpoint, "authorizationEndpoint", options.allowInsecureLoopback === true);
    this.#tokenEndpoint = endpoint(options.tokenEndpoint, "tokenEndpoint", options.allowInsecureLoopback === true);
    this.#clientId = boundedConfig(options.clientId, "clientId", 512);
    this.#clientSecret = options.clientSecret === undefined
      ? undefined
      : boundedConfig(options.clientSecret, "clientSecret", 2_048);
    this.#scope = boundedConfig(options.scope ?? "openid", "scope", 1_024);
    if (!this.#scope.split(/\s+/u).includes("openid")) throw new TypeError("scope must include openid");
    this.#loginTtlSeconds = boundedInteger(options.loginTtlSeconds ?? DEFAULT_LOGIN_TTL_SECONDS, 30, 900, "loginTtlSeconds");
    this.#sessionTtlSeconds = boundedInteger(options.sessionTtlSeconds ?? DEFAULT_SESSION_TTL_SECONDS, 30, 900, "sessionTtlSeconds");
    this.#maxAuthenticationAgeSeconds = boundedInteger(
      options.maxAuthenticationAgeSeconds ?? DEFAULT_MAX_AUTHENTICATION_AGE_SECONDS,
      0,
      3_600,
      "maxAuthenticationAgeSeconds",
    );
    this.#tokenTimeoutMs = boundedInteger(options.tokenTimeoutMs ?? DEFAULT_TOKEN_TIMEOUT_MS, 100, 30_000, "tokenTimeoutMs");
    this.#maxTokenResponseBytes = boundedInteger(
      options.maxTokenResponseBytes ?? DEFAULT_MAX_TOKEN_RESPONSE_BYTES,
      1_024,
      1024 * 1024,
      "maxTokenResponseBytes",
    );
    this.#fetch = options.fetch ?? globalThis.fetch;
    if (typeof this.#fetch !== "function") throw new TypeError("fetch implementation is required");
    this.#now = options.now ?? (() => new Date());
    this.#randomBytes = options.randomBytes ?? randomBytes;
  }

  /** Returns false only when the request is outside this controller's routes. */
  async handle(request: IncomingMessage, response: ServerResponse): Promise<boolean> {
    const url = new URL(request.url ?? "/", this.#publicOrigin);
    if (url.pathname === "/oauth/callback") {
      if (request.method !== "GET") {
        this.#sendError(response, 405, "method_not_allowed", { allow: "GET" });
        return true;
      }
      await this.#callback(request, response, url);
      return true;
    }

    const decisionMatch = url.pathname.match(/^\/approvals\/([^/]+)\/decision$/u);
    if (decisionMatch) {
      if (request.method !== "POST") {
        this.#sendError(response, 405, "method_not_allowed", { allow: "POST" });
        return true;
      }
      await this.#decision(request, response, decodeRequestId(decisionMatch[1]!));
      return true;
    }

    const approvalMatch = url.pathname.match(/^\/approvals\/([^/]+)$/u);
    if (approvalMatch) {
      if (request.method !== "GET") {
        this.#sendError(response, 405, "method_not_allowed", { allow: "GET" });
        return true;
      }
      await this.#approval(request, response, decodeRequestId(approvalMatch[1]!));
      return true;
    }
    return false;
  }

  async #approval(request: IncomingMessage, response: ServerResponse, requestId: string): Promise<void> {
    const session = this.#readSession(request);
    if (!session) {
      this.#startLogin(response, requestId);
      return;
    }
    try {
      const approval = await this.#approvals.getForPrincipal(session.principal, requestId);
      this.#sendHtml(response, 200, renderApproval(approval, session.csrf));
    } catch (error) {
      this.#sendApprovalError(response, error);
    }
  }

  #startLogin(response: ServerResponse, requestId: string): void {
    const now = this.#validNow();
    const verifier = opaque(this.#randomBytes, 32);
    const login: LoginCookie = {
      v: COOKIE_VERSION,
      requestId,
      state: opaque(this.#randomBytes, 32),
      nonce: opaque(this.#randomBytes, 32),
      verifier,
      expiresAt: now.getTime() + this.#loginTtlSeconds * 1_000,
    };
    const authorization = new URL(this.#authorizationEndpoint);
    authorization.searchParams.set("response_type", "code");
    authorization.searchParams.set("response_mode", "query");
    authorization.searchParams.set("client_id", this.#clientId);
    authorization.searchParams.set("redirect_uri", this.#redirectUri);
    authorization.searchParams.set("scope", this.#scope);
    authorization.searchParams.set("state", login.state);
    authorization.searchParams.set("nonce", login.nonce);
    authorization.searchParams.set("code_challenge", createHash("sha256").update(verifier, "ascii").digest("base64url"));
    authorization.searchParams.set("code_challenge_method", "S256");
    authorization.searchParams.set("max_age", String(this.#maxAuthenticationAgeSeconds));
    response.setHeader("set-cookie", this.#setCookie(this.#loginCookieName, this.#codec.seal("login", login), login.expiresAt));
    this.#redirect(response, 302, authorization.toString());
  }

  async #callback(request: IncomingMessage, response: ServerResponse, url: URL): Promise<void> {
    const rawLogin = readCookie(request, this.#loginCookieName);
    response.setHeader("set-cookie", this.#clearCookie(this.#loginCookieName));
    try {
      const login = this.#decodeLogin(rawLogin);
      if (url.searchParams.has("error")) throw new ApprovalWebError(401, "authentication_failed");
      exactQueryKeys(url.searchParams, ["code", "state", "session_state"]);
      const state = oneQueryValue(url.searchParams, "state", 512);
      const code = oneQueryValue(url.searchParams, "code", 8_192);
      if (!constantTimeEqual(state, login.state)) throw new ApprovalWebError(401, "authentication_failed");
      this.#consumeLoginState(login);
      const idToken = await this.#exchangeCode(code, login.verifier);
      const principal = await this.#principalAuthenticator.authenticate(idToken, login.nonce);
      const authenticatedAt = verifiedAuthenticationTime(principal, this.#validNow(), this.#maxAuthenticationAgeSeconds);
      const approval = await this.#approvals.getForPrincipal(principal, login.requestId);
      const now = this.#validNow();
      const authExpiry = authenticatedAt.getTime() + this.#maxAuthenticationAgeSeconds * 1_000;
      const expiresAt = Math.min(
        now.getTime() + this.#sessionTtlSeconds * 1_000,
        authExpiry,
        Date.parse(approval.expiresAt),
      );
      if (!Number.isFinite(expiresAt) || expiresAt <= now.getTime()) throw new ApprovalWebError(401, "authentication_expired");
      const session: SessionCookie = {
        v: COOKIE_VERSION,
        principal,
        csrf: opaque(this.#randomBytes, 32),
        expiresAt,
      };
      response.setHeader("set-cookie", [
        this.#clearCookie(this.#loginCookieName),
        this.#setCookie(this.#sessionCookieName, this.#codec.seal("session", session), expiresAt),
      ]);
      this.#redirect(response, 303, `/approvals/${encodeURIComponent(login.requestId)}`);
    } catch (error) {
      this.#sendCallbackError(response, error);
    }
  }

  async #exchangeCode(code: string, verifier: string): Promise<string> {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: this.#redirectUri,
      client_id: this.#clientId,
      code_verifier: verifier,
    });
    const headers: Record<string, string> = {
      accept: "application/json",
      "content-type": "application/x-www-form-urlencoded",
    };
    if (this.#clientSecret !== undefined) {
      headers.authorization = `Basic ${Buffer.from(`${formEncode(this.#clientId)}:${formEncode(this.#clientSecret)}`, "utf8").toString("base64")}`;
      body.delete("client_id");
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.#tokenTimeoutMs);
    let tokenResponse: Response;
    try {
      tokenResponse = await this.#fetch(this.#tokenEndpoint, {
        method: "POST",
        headers,
        body: body.toString(),
        redirect: "manual",
        signal: controller.signal,
      });
    } catch {
      throw new ApprovalWebError(502, "token_exchange_failed");
    } finally {
      clearTimeout(timer);
    }
    if (tokenResponse.status >= 300 && tokenResponse.status < 400) {
      await tokenResponse.body?.cancel().catch(() => undefined);
      throw new ApprovalWebError(502, "token_exchange_failed");
    }
    if (tokenResponse.status !== 200) {
      await tokenResponse.body?.cancel().catch(() => undefined);
      throw new ApprovalWebError(502, "token_exchange_failed");
    }
    const mediaType = tokenResponse.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
    if (mediaType !== "application/json") {
      await tokenResponse.body?.cancel().catch(() => undefined);
      throw new ApprovalWebError(502, "token_exchange_failed");
    }
    const text = await boundedResponseText(tokenResponse, this.#maxTokenResponseBytes);
    let payload: unknown;
    try {
      payload = JSON.parse(text);
    } catch {
      throw new ApprovalWebError(502, "token_exchange_failed");
    }
    if (!isRecord(payload) || typeof payload.id_token !== "string" || payload.id_token.length === 0 || payload.id_token.length > 128 * 1024) {
      throw new ApprovalWebError(502, "token_exchange_failed");
    }
    return payload.id_token;
  }

  async #decision(request: IncomingMessage, response: ServerResponse, pathRequestId: string): Promise<void> {
    try {
      const origin = singleHeader(request, "origin");
      if (origin !== this.#publicOrigin) throw new ApprovalWebError(403, "cross_site_request_denied");
      const contentType = singleHeader(request, "content-type")?.toLowerCase();
      if (!contentType || !/^application\/x-www-form-urlencoded(?:\s*;\s*charset=utf-8)?$/u.test(contentType)) {
        throw new ApprovalWebError(415, "content_type_required");
      }
      const session = this.#readSession(request);
      if (!session) throw new ApprovalWebError(401, "authentication_required");
      const form = new URLSearchParams(await readBoundedBody(request, MAX_FORM_BYTES));
      exactFormKeys(form, ["requestId", "intentHash", "decision", "csrf", "reason"]);
      const requestId = oneFormValue(form, "requestId", 512);
      const intentHash = oneFormValue(form, "intentHash", 512);
      const csrf = oneFormValue(form, "csrf", 512);
      const decision = oneFormValue(form, "decision", 16);
      const reason = optionalFormValue(form, "reason", 500);
      if (!constantTimeEqual(requestId, pathRequestId)) throw new ApprovalWebError(400, "request_mismatch");
      if (!constantTimeEqual(csrf, session.csrf)) throw new ApprovalWebError(403, "csrf_failed");
      if (decision !== "approved" && decision !== "denied") throw new ApprovalWebError(400, "invalid_decision");
      await this.#approvals.decide(session.principal, {
        requestId: pathRequestId,
        intentHash,
        decision,
        ...(reason === undefined || reason.length === 0 ? {} : { reason }),
      });
      this.#redirect(response, 303, `/approvals/${encodeURIComponent(pathRequestId)}`);
    } catch (error) {
      if (error instanceof ApprovalWebError) {
        this.#sendError(response, error.status, error.publicCode);
      } else {
        this.#sendApprovalError(response, error);
      }
    }
  }

  #decodeLogin(raw: string | undefined): LoginCookie {
    if (!raw) throw new ApprovalWebError(401, "authentication_required");
    const value = this.#codec.open("login", raw);
    if (!isRecord(value) || value.v !== COOKIE_VERSION || !isSafeOpaque(value.state) || !isSafeOpaque(value.nonce) ||
      !isPkceVerifier(value.verifier) || !isRequestId(value.requestId) || !isExpiry(value.expiresAt)) {
      throw new ApprovalWebError(401, "authentication_failed");
    }
    if (value.expiresAt <= this.#validNow().getTime()) throw new ApprovalWebError(401, "authentication_expired");
    return value as unknown as LoginCookie;
  }

  #consumeLoginState(login: LoginCookie): void {
    const now = this.#validNow().getTime();
    for (const [digest, expiresAt] of this.#consumedLoginStates) {
      if (expiresAt <= now) this.#consumedLoginStates.delete(digest);
    }
    const digest = createHash("sha256").update(login.state, "ascii").digest("base64url");
    if (this.#consumedLoginStates.has(digest)) throw new ApprovalWebError(401, "authentication_failed");
    this.#consumedLoginStates.set(digest, login.expiresAt);
    if (this.#consumedLoginStates.size > 10_000) {
      const oldest = this.#consumedLoginStates.keys().next().value as string | undefined;
      if (oldest !== undefined) this.#consumedLoginStates.delete(oldest);
    }
  }

  #readSession(request: IncomingMessage): SessionCookie | undefined {
    const raw = readCookie(request, this.#sessionCookieName);
    if (!raw) return undefined;
    try {
      const value = this.#codec.open("session", raw);
      if (!isRecord(value) || value.v !== COOKIE_VERSION || !isSafeOpaque(value.csrf) || !isExpiry(value.expiresAt) ||
        !isPrincipal(value.principal) || value.expiresAt <= this.#validNow().getTime()) return undefined;
      verifiedAuthenticationTime(value.principal, this.#validNow(), this.#maxAuthenticationAgeSeconds);
      return value as unknown as SessionCookie;
    } catch {
      return undefined;
    }
  }

  #setCookie(name: string, value: string, expiresAt: number): string {
    const seconds = Math.max(0, Math.floor((expiresAt - this.#validNow().getTime()) / 1_000));
    return `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${seconds}; Expires=${new Date(expiresAt).toUTCString()}${this.#secureCookies ? "; Secure" : ""}`;
  }

  #clearCookie(name: string): string {
    return `${name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT${this.#secureCookies ? "; Secure" : ""}`;
  }

  #redirect(response: ServerResponse, status: 302 | 303, location: string): void {
    securityHeaders(response);
    response.writeHead(status, { location, "cache-control": "no-store" });
    response.end();
  }

  #sendError(response: ServerResponse, status: number, code: string, extraHeaders: Record<string, string> = {}): void {
    this.#sendHtml(response, status, errorPage(code, status), extraHeaders);
  }

  #sendHtml(response: ServerResponse, status: number, html: string, extraHeaders: Record<string, string> = {}): void {
    securityHeaders(response);
    response.writeHead(status, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store, max-age=0",
      pragma: "no-cache",
      ...extraHeaders,
    });
    response.end(html);
  }

  #sendCallbackError(response: ServerResponse, error: unknown): void {
    if (error instanceof ApprovalWebError) {
      this.#sendError(response, error.status, error.publicCode);
      return;
    }
    const code = publicApprovalCode(error);
    if (code === "approval_not_found") {
      this.#sendError(response, 404, "approval_not_found");
      return;
    }
    this.#sendError(response, 401, "authentication_failed");
  }

  #sendApprovalError(response: ServerResponse, error: unknown): void {
    const code = publicApprovalCode(error);
    if (code === "approval_not_found") return this.#sendError(response, 404, code);
    if (code === "approval_expired") return this.#sendError(response, 410, code);
    if (code === "approval_mismatch") return this.#sendError(response, 409, code);
    this.#sendError(response, 500, "internal_error");
  }

  #validNow(): Date {
    const value = this.#now();
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw new TypeError("now must return a valid Date");
    return new Date(value.getTime());
  }
}

class CookieCodec {
  readonly #keys: Record<CookiePurpose, Buffer>;

  constructor(masterKey: Uint8Array) {
    if (!(masterKey instanceof Uint8Array) || masterKey.byteLength < 32) throw new TypeError("cookieKey must contain at least 32 bytes");
    const master = Buffer.from(masterKey);
    this.#keys = {
      login: createHmac("sha256", master).update("agent-mandate/approval-web/login/aes-256-gcm/v1").digest(),
      session: createHmac("sha256", master).update("agent-mandate/approval-web/session/aes-256-gcm/v1").digest(),
    };
  }

  seal(purpose: CookiePurpose, payload: LoginCookie | SessionCookie): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.#keys[purpose], iv);
    cipher.setAAD(Buffer.from(`agent-mandate:${purpose}:v1`, "utf8"));
    const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return `v1.${iv.toString("base64url")}.${ciphertext.toString("base64url")}.${cipher.getAuthTag().toString("base64url")}`;
  }

  open(purpose: CookiePurpose, encoded: string): unknown {
    try {
      if (encoded.length > 12 * 1024) throw new Error("cookie too large");
      const parts = encoded.split(".");
      if (parts.length !== 4 || parts[0] !== "v1") throw new Error("invalid cookie");
      const iv = strictBase64Url(parts[1]!, 12);
      const ciphertext = strictBase64Url(parts[2]!, undefined, 10 * 1024);
      const tag = strictBase64Url(parts[3]!, 16);
      const decipher = createDecipheriv("aes-256-gcm", this.#keys[purpose], iv);
      decipher.setAAD(Buffer.from(`agent-mandate:${purpose}:v1`, "utf8"));
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return JSON.parse(plaintext.toString("utf8")) as unknown;
    } catch {
      throw new ApprovalWebError(401, "authentication_failed");
    }
  }
}

function renderApproval(approval: ApprovalRequest, csrf: string): string {
  const pending = approval.status === "pending";
  const requestId = visibleHtml(approval.id);
  const intentHash = visibleHtml(approval.intentHash);
  const parameters = visibleHtml(stablePreview(approval.envelope.parameters));
  const decisionForms = pending
    ? `<section aria-labelledby="decision-heading"><h2 id="decision-heading">Decision</h2>
<form method="post" action="/approvals/${encodeURIComponent(approval.id)}/decision">
<input type="hidden" name="requestId" value="${attribute(approval.id)}">
<input type="hidden" name="intentHash" value="${attribute(approval.intentHash)}">
<input type="hidden" name="csrf" value="${attribute(csrf)}">
<input type="hidden" name="decision" value="approved">
<button type="submit">Approve this exact action once</button>
</form>
<form method="post" action="/approvals/${encodeURIComponent(approval.id)}/decision">
<input type="hidden" name="requestId" value="${attribute(approval.id)}">
<input type="hidden" name="intentHash" value="${attribute(approval.intentHash)}">
<input type="hidden" name="csrf" value="${attribute(csrf)}">
<input type="hidden" name="decision" value="denied">
<label>Reason (optional) <input name="reason" maxlength="500"></label>
<button type="submit">Deny</button>
</form></section>`
    : `<p role="status">This request is ${visibleHtml(approval.status)}.</p>`;

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Review agent action</title></head><body><main>
<h1>Review exact agent action</h1>
<p>The agent will not receive the downstream provider credential.</p>
<dl>
<dt>Request</dt><dd><code>${requestId}</code></dd>
<dt>Action</dt><dd><code>${visibleHtml(approval.envelope.action)}</code></dd>
<dt>Resource</dt><dd><code>${visibleHtml(approval.envelope.resource)}</code></dd>
<dt>Provider</dt><dd>${visibleHtml(approval.providerId)}</dd>
<dt>Provider resource</dt><dd><code>${visibleHtml(approval.providerResourceId)}</code></dd>
<dt>Risk</dt><dd>${visibleHtml(approval.intent.risk)}</dd>
<dt>Maximum executions</dt><dd>${approval.intent.maxCalls}</dd>
<dt>Delegation</dt><dd>${approval.intent.delegationAllowed ? "allowed" : "not allowed"}</dd>
<dt>Expires</dt><dd><time datetime="${attribute(approval.expiresAt)}">${visibleHtml(approval.expiresAt)}</time></dd>
<dt>Intent hash</dt><dd><code>${intentHash}</code></dd>
</dl>
<h2>Exact parameters</h2><pre>${parameters}</pre>
${decisionForms}
</main></body></html>`;
}

function stablePreview(value: Record<string, JsonValue>): string {
  return JSON.stringify(sortedJson(value), null, 2);
}

function sortedJson(value: JsonValue): JsonValue {
  if (Array.isArray(value)) return value.map(sortedJson);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortedJson(value[key]!) ]));
  }
  return value;
}

function visibleHtml(value: string): string {
  return escapeHtml(showControls(value));
}

function attribute(value: string): string {
  return escapeHtml(showControls(value));
}

function showControls(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu, (character) => {
    const point = character.codePointAt(0)!;
    return `\\u${point.toString(16).toUpperCase().padStart(4, "0")}`;
  });
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/gu, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;",
  })[character]!);
}

function errorPage(code: string, status: number): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Approval unavailable</title></head><body><main><h1>Approval unavailable</h1><p>Status ${status}: <code>${visibleHtml(code)}</code></p></main></body></html>`;
}

function securityHeaders(response: ServerResponse): void {
  response.setHeader("content-security-policy", "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  response.setHeader("x-frame-options", "DENY");
  response.setHeader("x-content-type-options", "nosniff");
  response.setHeader("referrer-policy", "no-referrer");
  response.setHeader("permissions-policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
}

function exactOrigin(value: string, label: string, originOnly: boolean): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError(`${label} must be an absolute URL`);
  }
  if (parsed.username || parsed.password || parsed.hash || parsed.search || (originOnly && parsed.pathname !== "/")) {
    throw new TypeError(`${label} must be an origin without credentials, query, or fragment`);
  }
  return parsed;
}

function endpoint(value: string, label: string, allowInsecureLoopback: boolean): URL {
  const parsed = exactOrigin(value, label, false);
  if (parsed.protocol !== "https:" && !(allowInsecureLoopback && parsed.protocol === "http:" && isLoopback(parsed.hostname))) {
    throw new TypeError(`${label} must use HTTPS`);
  }
  return parsed;
}

function isLoopback(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]" || hostname === "::1";
}

function boundedConfig(value: string, label: string, maximum: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function boundedInteger(value: number, minimum: number, maximum: number, label: string): number {
  if (!Number.isInteger(value) || value < minimum || value > maximum) throw new TypeError(`${label} is out of range`);
  return value;
}

function opaque(source: (size: number) => Uint8Array, size: number): string {
  const bytes = source(size);
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== size) throw new TypeError("randomBytes returned an invalid value");
  return Buffer.from(bytes).toString("base64url");
}

function decodeRequestId(value: string): string {
  try {
    const decoded = decodeURIComponent(value);
    if (!isRequestId(decoded)) throw new Error("invalid request ID");
    return decoded;
  } catch {
    throw new ApprovalWebError(400, "invalid_request");
  }
}

function isRequestId(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 512 && !/[\u0000-\u001f\u007f]/u.test(value);
}

function isSafeOpaque(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43,128}$/u.test(value);
}

function isPkceVerifier(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9._~-]{43,128}$/u.test(value);
}

function isExpiry(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function isPrincipal(value: unknown): value is PrincipalContext {
  if (!isRecord(value)) return false;
  return [value.tenantId, value.principalId, value.issuer, value.subject, value.authenticatedAt]
    .every((field) => typeof field === "string" && field.length > 0 && field.length <= 2_048);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function verifiedAuthenticationTime(principal: PrincipalContext, now: Date, maximumAgeSeconds: number): Date {
  if (principal.authenticatedAt === undefined) throw new ApprovalWebError(401, "authentication_failed");
  const milliseconds = Date.parse(principal.authenticatedAt);
  if (!Number.isFinite(milliseconds) || milliseconds > now.getTime() || now.getTime() - milliseconds > maximumAgeSeconds * 1_000) {
    throw new ApprovalWebError(401, "authentication_expired");
  }
  return new Date(milliseconds);
}

function strictBase64Url(value: string, exactBytes?: number, maximumBytes?: number): Buffer {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) throw new Error("invalid base64url");
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value || (exactBytes !== undefined && decoded.byteLength !== exactBytes) ||
    (maximumBytes !== undefined && decoded.byteLength > maximumBytes)) throw new Error("invalid base64url");
  return decoded;
}

function readCookie(request: IncomingMessage, name: string): string | undefined {
  const header = singleHeader(request, "cookie");
  if (!header || Buffer.byteLength(header) > MAX_COOKIE_HEADER_BYTES) return undefined;
  const found: string[] = [];
  for (const component of header.split(";")) {
    const separator = component.indexOf("=");
    if (separator < 1) continue;
    if (component.slice(0, separator).trim() === name) found.push(component.slice(separator + 1).trim());
  }
  return found.length === 1 ? found[0] : undefined;
}

function singleHeader(request: IncomingMessage, name: string): string | undefined {
  const value = request.headers[name];
  return Array.isArray(value) ? (value.length === 1 ? value[0] : undefined) : value;
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftDigest = createHash("sha256").update(left, "utf8").digest();
  const rightDigest = createHash("sha256").update(right, "utf8").digest();
  return timingSafeEqual(leftDigest, rightDigest);
}

function exactQueryKeys(parameters: URLSearchParams, allowed: readonly string[]): void {
  const set = new Set(allowed);
  for (const key of parameters.keys()) if (!set.has(key)) throw new ApprovalWebError(400, "authentication_failed");
}

function oneQueryValue(parameters: URLSearchParams, name: string, maximum: number): string {
  const values = parameters.getAll(name);
  if (values.length !== 1 || values[0]!.length === 0 || values[0]!.length > maximum) {
    throw new ApprovalWebError(400, "authentication_failed");
  }
  return values[0]!;
}

function exactFormKeys(parameters: URLSearchParams, allowed: readonly string[]): void {
  const set = new Set(allowed);
  for (const key of parameters.keys()) if (!set.has(key)) throw new ApprovalWebError(400, "invalid_form");
}

function oneFormValue(parameters: URLSearchParams, name: string, maximum: number): string {
  const values = parameters.getAll(name);
  if (values.length !== 1 || values[0]!.length === 0 || values[0]!.length > maximum) {
    throw new ApprovalWebError(400, "invalid_form");
  }
  return values[0]!;
}

function optionalFormValue(parameters: URLSearchParams, name: string, maximum: number): string | undefined {
  const values = parameters.getAll(name);
  if (values.length === 0) return undefined;
  if (values.length !== 1 || values[0]!.length > maximum) throw new ApprovalWebError(400, "invalid_form");
  return values[0]!;
}

async function readBoundedBody(request: IncomingMessage, maximumBytes: number): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const bytes = Buffer.from(chunk);
    size += bytes.byteLength;
    if (size > maximumBytes) throw new ApprovalWebError(413, "request_too_large");
    chunks.push(bytes);
  }
  if (size === 0) throw new ApprovalWebError(400, "invalid_form");
  return Buffer.concat(chunks).toString("utf8");
}

async function boundedResponseText(response: Response, maximumBytes: number): Promise<string> {
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > maximumBytes)) {
    await response.body?.cancel().catch(() => undefined);
    throw new ApprovalWebError(502, "token_exchange_failed");
  }
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > maximumBytes) throw new ApprovalWebError(502, "token_exchange_failed");
      chunks.push(part.value);
    }
  } finally {
    if (size > maximumBytes) await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString("utf8");
}

function formEncode(value: string): string {
  return encodeURIComponent(value).replace(/%20/gu, "+");
}

function publicApprovalCode(error: unknown): string | undefined {
  if (!isRecord(error) || typeof error.code !== "string") return undefined;
  return ["approval_not_found", "approval_expired", "approval_mismatch"].includes(error.code) ? error.code : undefined;
}
