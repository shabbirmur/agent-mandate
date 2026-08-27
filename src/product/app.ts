import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { toNodeHandler } from "@modelcontextprotocol/node";
import {
  getOAuthProtectedResourceMetadataUrl,
  oauthMetadataResponse,
  type AuthInfo,
  type OAuthMetadata,
} from "@modelcontextprotocol/server";
import { ActionProfileValidationError } from "../actions/index.js";
import { ApprovalServiceError, type ApprovalWebController } from "../approvals/index.js";
import { HttpError, bearer, readJson, requestUrl, sendJson } from "../http.js";
import {
  ProductAccessAuthenticationError,
  type AuthenticatedProductContext,
  type ProductAccessAuthenticator,
} from "../identity/index.js";
import type { ProductMcpHttpHandler } from "../mcp/index.js";
import { redactSensitive } from "../security/index.js";
import { ProductServiceError, type ProductContext, type ProductService } from "./service.js";

const PRODUCT_CONTEXT_KEY = "agentMandateProductContext";
const PRODUCT_SCOPE = "agent-mandate:use";
const PRODUCT_REQUEST_BYTES = 300 * 1_024;

export interface ProductOAuthDiscovery {
  issuer: string;
  authorizationUrl: string;
  tokenUrl: string;
  registrationUrl?: string;
}

export interface ProductAppDependencies {
  publicBaseUrl: string;
  readiness(): Promise<boolean>;
  authenticator: ProductAccessAuthenticator;
  service: Pick<ProductService, "proposeGithubIssue" | "status" | "resume" | "receipt">;
  approvalWeb: Pick<ApprovalWebController, "handle">;
  mcp: ProductMcpHttpHandler;
  oauth: ProductOAuthDiscovery;
  log?: (event: Record<string, unknown>) => void;
}

/**
 * Product-only HTTP surface. It intentionally does not mount the v0.1 raw
 * mandate or generic execution routes, so agents cannot ask this listener for
 * broader authority than the reviewed product tools expose.
 */
export function createProductRequestHandler(dependencies: ProductAppDependencies) {
  const log = dependencies.log ?? defaultLog;
  const publicBaseUrl = exactBaseUrl(dependencies.publicBaseUrl);
  const resourceServerUrl = new URL("/mcp", `${publicBaseUrl}/`);
  const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(resourceServerUrl);
  const metadataOptions = {
    oauthMetadata: oauthMetadata(dependencies.oauth),
    resourceServerUrl,
    serviceDocumentationUrl: new URL("/docs", `${publicBaseUrl}/`),
    scopesSupported: [PRODUCT_SCOPE] as string[],
    resourceName: "Agent Mandate",
    dangerouslyAllowInsecureIssuerUrl: resourceServerUrl.protocol === "http:",
  };
  const metadataNodeHandler = toNodeHandler({
    fetch: async (request) => oauthMetadataResponse(request, metadataOptions)
      ?? Response.json({ error: "not_found" }, { status: 404 }),
  });
  const mcpNodeHandler = toNodeHandler(dependencies.mcp, {
    onerror: () => log({ level: "error", event: "mcp.adapter_error" }),
  });

  return async (request: IncomingMessage, response: ServerResponse): Promise<void> => {
    const requestId = trustedRequestId(request.headers["x-request-id"]);
    const startedAt = Date.now();
    let loggedPath = "<invalid>";
    response.setHeader("x-request-id", requestId);
    try {
      const url = requestUrl(request);
      loggedPath = url.pathname;
      if (request.method === "GET" && url.pathname === "/healthz") return sendJson(response, 200, { ok: true });
      if (request.method === "GET" && url.pathname === "/readyz") {
        const ready = await dependencies.readiness().catch(() => false);
        return sendJson(response, ready ? 200 : 503, { ok: ready });
      }
      if (request.method === "GET" && url.pathname === "/") {
        return sendJson(response, 200, {
          name: "Agent Mandate",
          version: "0.2.0",
          protection: "mediated",
          mcp: resourceServerUrl.toString(),
          docs: `${publicBaseUrl}/docs`,
        });
      }
      if (request.method === "GET" && url.pathname === "/docs") {
        return sendJson(response, 200, {
          product: "Give agents a mandate, not a master key.",
          action: "github.issue.create.v1",
          flow: ["propose", "approve", "resume", "verify_receipt"],
          limitation: "This listener mediates its own route; deployment isolation is required before claiming enforced protection.",
        });
      }
      if (isMetadataPath(url.pathname)) {
        await metadataNodeHandler(request as Parameters<typeof metadataNodeHandler>[0], response);
        return;
      }
      if (await dependencies.approvalWeb.handle(request, response)) return;
      if (url.pathname === "/mcp") {
        const token = bearer(request);
        const context = await dependencies.authenticator.authenticate(token);
        const authenticatedRequest = request as IncomingMessage & { auth?: AuthInfo };
        authenticatedRequest.auth = toAuthInfo(context, resourceServerUrl);
        await mcpNodeHandler(authenticatedRequest as Parameters<typeof mcpNodeHandler>[0], response);
        return;
      }

      if (request.method === "POST" && url.pathname === "/v1/product/github/issues/proposals") {
        const context = await authenticateProductRequest(request, dependencies.authenticator);
        const input = exactObject(await readJson(request, PRODUCT_REQUEST_BYTES), ["repository", "title", "body"]);
        const body = optionalStringField(input, "body");
        const proposal = await dependencies.service.proposeGithubIssue(context, {
          repository: stringField(input, "repository"),
          title: stringField(input, "title"),
          ...(body === undefined ? {} : { body }),
        });
        return sendJson(response, 202, proposal);
      }
      const receipt = request.method === "GET"
        ? url.pathname.match(/^\/v1\/product\/approvals\/([^/]+)\/receipt$/u)
        : undefined;
      if (receipt) {
        const context = await authenticateProductRequest(request, dependencies.authenticator);
        return sendJson(response, 200, await dependencies.service.receipt(context, {
          requestId: decodeIdentifier(receipt[1]!),
        }));
      }
      const status = request.method === "GET"
        ? url.pathname.match(/^\/v1\/product\/approvals\/([^/]+)$/u)
        : undefined;
      if (status) {
        const context = await authenticateProductRequest(request, dependencies.authenticator);
        return sendJson(response, 200, await dependencies.service.status(context, {
          requestId: decodeIdentifier(status[1]!),
        }));
      }
      if (request.method === "POST" && url.pathname === "/v1/product/approvals/resume") {
        const context = await authenticateProductRequest(request, dependencies.authenticator);
        const input = exactObject(await readJson(request, PRODUCT_REQUEST_BYTES), ["resumeHandle"]);
        return sendJson(response, 200, await dependencies.service.resume(context, {
          resumeHandle: stringField(input, "resumeHandle"),
        }));
      }
      throw new HttpError(404, "not_found");
    } catch (error) {
      const failure = publicError(error);
      const headers = failure.status === 401
        ? { "www-authenticate": `Bearer resource_metadata="${resourceMetadataUrl}", scope="${PRODUCT_SCOPE}"` }
        : {};
      sendJsonWithHeaders(response, failure.status, { error: failure.code }, headers);
    } finally {
      log(redactSensitive({
        level: "info",
        event: "product.http_request",
        requestId,
        method: request.method ?? "unknown",
        path: loggedPath,
        status: response.statusCode,
        durationMs: Date.now() - startedAt,
      }) as Record<string, unknown>);
    }
  };
}

/** Resolve only the context placed in AuthInfo after successful JWT validation. */
export function productContextFromAuthInfo(authInfo: AuthInfo | undefined): ProductContext {
  const context = authInfo?.extra?.[PRODUCT_CONTEXT_KEY];
  if (!isAuthenticatedContext(context)) throw new ProductAccessAuthenticationError();
  return Object.freeze({ ...context });
}

function toAuthInfo(context: AuthenticatedProductContext, resource: URL): AuthInfo {
  return {
    // The SDK requires the field, but downstream tool handlers do not need the
    // bearer value. Keeping a sentinel here prevents accidental propagation.
    token: "[validated]",
    clientId: context.oauthClientId,
    scopes: [...context.accessScopes],
    expiresAt: context.accessExpiresAt,
    resource,
    extra: { [PRODUCT_CONTEXT_KEY]: Object.freeze({ ...context }) },
  };
}

async function authenticateProductRequest(
  request: IncomingMessage,
  authenticator: ProductAccessAuthenticator,
): Promise<AuthenticatedProductContext> {
  return authenticator.authenticate(bearer(request));
}

function oauthMetadata(input: ProductOAuthDiscovery): OAuthMetadata {
  const issuer = exactOriginOrUrl(input.issuer, "issuer");
  const authorizationEndpoint = exactOriginOrUrl(input.authorizationUrl, "authorizationUrl");
  const tokenEndpoint = exactOriginOrUrl(input.tokenUrl, "tokenUrl");
  const registrationEndpoint = input.registrationUrl === undefined
    ? undefined
    : exactOriginOrUrl(input.registrationUrl, "registrationUrl");
  return {
    issuer,
    authorization_endpoint: authorizationEndpoint,
    token_endpoint: tokenEndpoint,
    ...(registrationEndpoint === undefined ? {} : { registration_endpoint: registrationEndpoint }),
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: [PRODUCT_SCOPE],
  };
}

function isMetadataPath(pathname: string): boolean {
  return pathname === "/.well-known/oauth-authorization-server"
    || pathname === "/.well-known/oauth-protected-resource/mcp";
}

function publicError(error: unknown): { status: number; code: string } {
  if (error instanceof HttpError) return { status: error.status, code: error.code };
  if (error instanceof ProductAccessAuthenticationError) return { status: 401, code: error.code };
  if (error instanceof ActionProfileValidationError) return { status: 400, code: error.code };
  if (error instanceof ApprovalServiceError) {
    if (error.code === "approval_not_found") return { status: 404, code: error.code };
    if (error.code === "approval_not_ready") return { status: 503, code: error.code };
    if (error.code === "invalid_request") return { status: 400, code: error.code };
    if (error.code === "approval_expired") return { status: 410, code: error.code };
    return { status: 409, code: error.code };
  }
  if (error instanceof ProductServiceError) {
    if (error.code === "resource_not_connected") return { status: 404, code: error.code };
    if (error.code === "receipt_mismatch" || error.code === "resource_ambiguous") return { status: 409, code: error.code };
    return { status: 403, code: error.code };
  }
  return { status: 500, code: "internal_error" };
}

function exactObject(value: unknown, allowedKeys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new HttpError(400, "invalid_request");
  const object = value as Record<string, unknown>;
  const allowed = new Set(allowedKeys);
  if (Object.keys(object).some((key) => !allowed.has(key))) throw new HttpError(400, "invalid_request");
  return object;
}

function stringField(object: Record<string, unknown>, name: string): string {
  const value = object[name];
  if (typeof value !== "string" || value.length === 0) throw new HttpError(400, "invalid_request");
  return value;
}

function optionalStringField(object: Record<string, unknown>, name: string): string | undefined {
  const value = object[name];
  if (value === undefined) return undefined;
  if (typeof value !== "string") throw new HttpError(400, "invalid_request");
  return value;
}

function decodeIdentifier(value: string): string {
  let decoded: string;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    throw new HttpError(400, "invalid_request");
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(decoded)) throw new HttpError(400, "invalid_request");
  return decoded;
}

function sendJsonWithHeaders(
  response: ServerResponse,
  status: number,
  value: unknown,
  headers: Record<string, string>,
): void {
  response.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    ...headers,
  });
  response.end(JSON.stringify(value));
}

function exactBaseUrl(value: string): string {
  const url = new URL(value);
  if (url.pathname !== "/" || url.search || url.hash || url.username || url.password) throw new TypeError("invalid public base URL");
  return url.origin;
}

function exactOriginOrUrl(value: string, label: string): string {
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash) throw new TypeError(`invalid ${label}`);
  return url.toString().replace(/\/$/u, "");
}

function isAuthenticatedContext(value: unknown): value is AuthenticatedProductContext {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const context = value as Partial<AuthenticatedProductContext>;
  return [
    context.tenantId,
    context.principalId,
    context.agentId,
    context.workloadId,
    context.mcpSessionId,
    context.oauthClientId,
  ].every((field) => typeof field === "string" && field.length > 0)
    && Number.isSafeInteger(context.accessExpiresAt)
    && Array.isArray(context.accessScopes)
    && context.accessScopes.every((scope) => typeof scope === "string" && scope.length > 0);
}

function trustedRequestId(value: string | string[] | undefined): string {
  const candidate = Array.isArray(value) ? value[0] : value;
  return candidate && /^[A-Za-z0-9_.:-]{1,128}$/u.test(candidate) ? candidate : randomUUID();
}

function defaultLog(event: Record<string, unknown>): void {
  process.stdout.write(`${JSON.stringify(event)}\n`);
}
