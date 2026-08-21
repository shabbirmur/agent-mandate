import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { ExecutionGateway } from "./gateway/index.js";
import type { MandateService } from "./grants/index.js";
import { MandateServiceError } from "./grants/index.js";
import { HttpError, bearer, readJson, requestUrl, sendJson } from "./http.js";
import { IdentityAuthenticationError } from "./identity/index.js";
import type { MandateRepository, PrincipalAuthenticator, WorkloadAuthenticator } from "./ports.js";
import { redactSensitive } from "./security/index.js";
import type { ActionRequest, JsonValue, MandateCreationInput } from "./types.js";

interface ExecutionBody {
  taskId: string;
  audience: string;
  action: string;
  resource: string;
  parameters: Record<string, JsonValue>;
  idempotencyKey: string;
}

export interface AppDependencies {
  tenantId: string;
  repository: MandateRepository;
  mandates: Pick<MandateService, "issue" | "revoke">;
  gateway: Pick<ExecutionGateway, "execute">;
  principalAuthenticator: PrincipalAuthenticator;
  workloadAuthenticator: WorkloadAuthenticator;
  log?: (event: Record<string, unknown>) => void;
}

export function createRequestHandler(dependencies: AppDependencies) {
  const log = dependencies.log ?? defaultLog;
  return async (request: IncomingMessage, response: ServerResponse): Promise<void> => {
    const requestId = trustedRequestId(request.headers["x-request-id"]);
    const startedAt = Date.now();
    response.setHeader("x-request-id", requestId);
    try {
      const url = requestUrl(request);
      if (request.method === "GET" && url.pathname === "/healthz") return sendJson(response, 200, { ok: true });
      if (request.method === "GET" && url.pathname === "/readyz") {
        const ready = await dependencies.repository.readiness();
        return sendJson(response, ready ? 200 : 503, { ok: ready });
      }
      if (request.method === "POST" && url.pathname === "/v1/mandates") {
        const principal = await dependencies.principalAuthenticator.authenticate(bearer(request), requiredHeader(request, "x-oidc-nonce"));
        const workload = await dependencies.workloadAuthenticator.authenticate(bearer(request, "x-workload-authorization"));
        enforcePilotTenant(dependencies.tenantId, principal.tenantId, workload.tenantId);
        const input = requireObject(await readJson<MandateCreationInput>(request));
        if (input.agentId !== workload.agentId || input.workloadId !== workload.workloadId) throw new HttpError(403, "workload_mismatch");
        const issued = await dependencies.mandates.issue(principal, input);
        return sendJson(response, 201, issued);
      }
      if (request.method === "POST" && url.pathname === "/v1/execute") {
        const grant = bearer(request);
        const workload = await dependencies.workloadAuthenticator.authenticate(bearer(request, "x-workload-authorization"));
        enforcePilotTenant(dependencies.tenantId, workload.tenantId);
        const input = requireObject(await readJson<ExecutionBody>(request));
        const action: ActionRequest = {
          grant,
          tenantId: workload.tenantId,
          agentId: workload.agentId,
          workloadId: workload.workloadId,
          taskId: input.taskId,
          audience: input.audience,
          action: input.action,
          resource: input.resource,
          parameters: input.parameters,
          idempotencyKey: input.idempotencyKey,
        };
        const result = await dependencies.gateway.execute(action);
        return sendJson(response, executionStatus(result.decision.code, result.receipt?.outcome), result);
      }
      const revoke = request.method === "POST" ? url.pathname.match(/^\/v1\/mandates\/([^/]+)\/revoke$/) : undefined;
      if (revoke) {
        const principal = await dependencies.principalAuthenticator.authenticate(bearer(request), requiredHeader(request, "x-oidc-nonce"));
        enforcePilotTenant(dependencies.tenantId, principal.tenantId);
        const revoked = await dependencies.mandates.revoke(principal, decodeURIComponent(revoke[1]!));
        if (!revoked) throw new HttpError(404, "not_found");
        return sendJson(response, 200, { revoked: true });
      }
      if (request.method === "GET" && url.pathname === "/v1/audit") {
        const principal = await dependencies.principalAuthenticator.authenticate(bearer(request), requiredHeader(request, "x-oidc-nonce"));
        enforcePilotTenant(dependencies.tenantId, principal.tenantId);
        const limit = parseLimit(url.searchParams.get("limit"));
        return sendJson(response, 200, { events: await dependencies.repository.listAudit(principal.tenantId, limit) });
      }
      throw new HttpError(404, "not_found");
    } catch (error) {
      const failure = publicError(error);
      sendJson(response, failure.status, { error: failure.code });
    } finally {
      log(redactSensitive({
        level: "info",
        event: "http.request",
        requestId,
        method: request.method ?? "unknown",
        path: requestUrl(request).pathname,
        status: response.statusCode,
        durationMs: Date.now() - startedAt,
      }) as Record<string, unknown>);
    }
  };
}

function executionStatus(code: string, outcome: string | undefined): number {
  if (outcome === "ambiguous" || outcome === "pending" || code === "downstream_ambiguous") return 202;
  if (code === "idempotency_conflict" || code === "replay_detected") return 409;
  if (code === "downstream_failed" || code === "downstream_audience_mismatch") return 502;
  if (code === "policy_indeterminate") return 503;
  if (code === "invalid_request") return 400;
  return code === "allowed" ? 200 : 403;
}

function publicError(error: unknown): { status: number; code: string } {
  if (error instanceof HttpError) return { status: error.status, code: error.code };
  if (error instanceof IdentityAuthenticationError) return { status: 401, code: error.code };
  if (error instanceof MandateServiceError) {
    const status = error.code === "invalid_request" || error.code === "missing_identity_or_context" ? 400 : 403;
    return { status, code: error.code };
  }
  return { status: 500, code: "internal_error" };
}

function enforcePilotTenant(expected: string, ...actual: string[]): void {
  if (actual.some((tenantId) => tenantId !== expected)) throw new HttpError(403, "tenant_mismatch");
}

function header(request: IncomingMessage, name: string): string | undefined {
  const value = request.headers[name];
  return Array.isArray(value) ? value[0] : value;
}

function requiredHeader(request: IncomingMessage, name: string): string {
  const value = header(request, name);
  if (!value) throw new HttpError(401, "invalid_principal");
  return value;
}

function requireObject<Value>(value: Value): NonNullable<Value> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new HttpError(400, "invalid_request");
  return value;
}

function parseLimit(value: string | null): number {
  if (value === null) return 100;
  const limit = Number(value);
  if (!Number.isInteger(limit) || limit < 1 || limit > 1_000) throw new HttpError(400, "invalid_request");
  return limit;
}

function trustedRequestId(value: string | string[] | undefined): string {
  const candidate = Array.isArray(value) ? value[0] : value;
  return candidate && /^[A-Za-z0-9_.:-]{1,128}$/.test(candidate) ? candidate : randomUUID();
}

function defaultLog(event: Record<string, unknown>): void {
  process.stdout.write(`${JSON.stringify(event)}\n`);
}
