import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type { ActionRequest, AuditEvent, Decision, ErrorCode, IssuedMandate, Mandate, MandateRequest } from "./types.js";

const MAX_TTL_SECONDS = 3_600;

/**
 * Small in-memory conformance implementation. The pilot server uses the
 * PostgreSQL repository; this class remains useful for fast contract tests.
 */
export class MandateBroker {
  readonly #mandates = new Map<string, Mandate>();
  readonly #events: AuditEvent[] = [];

  issue(request: MandateRequest): IssuedMandate {
    validateRequest(request);
    if (request.approval?.required && (!request.approval.approvedBy || !request.approval.envelopeHash)) {
      throw new Error("approval_required");
    }

    const issuedAt = new Date();
    const secret = randomBytes(32).toString("base64url");
    const mandate: Mandate = {
      ...structuredClone(request),
      id: randomUUID(),
      grantHash: hash(secret),
      issuedAt: issuedAt.toISOString(),
      expiresAt: new Date(issuedAt.getTime() + request.expiresInSeconds * 1_000).toISOString(),
      status: "active",
      successfulUses: 0,
    };
    this.#mandates.set(mandate.id, mandate);
    this.#record("mandate.issued", "issued", mandate);
    const { grantHash: _, ...publicMandate } = structuredClone(mandate);
    return { mandate: publicMandate, grant: `${mandate.id}.${secret}` };
  }

  authorize(request: ActionRequest): Decision {
    const decisionId = randomUUID();
    const [id, presentedSecret] = request.grant.split(".", 2);
    const mandate = id ? this.#mandates.get(id) : undefined;
    const deny = (code: ErrorCode): Decision => {
      this.#record("action.denied", code, mandate, request, decisionId);
      return { allowed: false, code, decisionId, ...(mandate ? { mandateId: mandate.id } : {}) };
    };

    if (!mandate || !presentedSecret || !safeEqual(mandate.grantHash, hash(presentedSecret))) return deny("invalid_grant");
    if (mandate.tenantId !== request.tenantId) return deny("tenant_mismatch");
    if (mandate.status !== "active") return deny("revoked");
    if (Date.now() >= Date.parse(mandate.expiresAt)) return deny("expired");
    if (mandate.agentId !== request.agentId) return deny("agent_mismatch");
    if (mandate.workloadId !== request.workloadId) return deny("workload_mismatch");
    if (mandate.taskId !== request.taskId) return deny("task_mismatch");
    if (mandate.audience !== request.audience) return deny("audience_mismatch");
    if (!mandate.actions.includes(request.action)) return deny("action_not_granted");
    if (!mandate.resources.includes(request.resource)) return deny("resource_not_granted");

    const constraints = mandate.constraints;
    if (constraints?.maxCalls !== undefined && mandate.successfulUses >= constraints.maxCalls) return deny("call_limit_exceeded");
    for (const [key, expected] of Object.entries(constraints?.equals ?? {})) {
      if (request.parameters[key] !== expected) return deny("parameter_mismatch");
    }
    for (const [key, maximum] of Object.entries(constraints?.maximum ?? {})) {
      const actual = request.parameters[key];
      if (typeof actual !== "number" || actual > maximum) return deny("parameter_mismatch");
    }

    mandate.successfulUses += 1;
    this.#record("action.allowed", "allowed", mandate, request, decisionId);
    return {
      allowed: true,
      code: "allowed",
      decisionId,
      mandateId: mandate.id,
      remainingCalls: Math.max(0, (constraints?.maxCalls ?? Number.MAX_SAFE_INTEGER) - mandate.successfulUses),
    };
  }

  revoke(tenantId: string, id: string): boolean {
    const mandate = this.#mandates.get(id);
    if (!mandate || mandate.tenantId !== tenantId) return false;
    mandate.status = "revoked";
    this.#record("mandate.revoked", "revoked", mandate);
    return true;
  }

  audit(tenantId: string): AuditEvent[] {
    return structuredClone(this.#events.filter((event) => event.tenantId === tenantId));
  }

  #record(
    type: AuditEvent["type"],
    code: AuditEvent["code"],
    mandate?: Mandate,
    request?: ActionRequest,
    decisionId?: string,
  ): void {
    this.#events.push({
      id: randomUUID(),
      tenantId: mandate?.tenantId ?? request?.tenantId ?? "unknown",
      at: new Date().toISOString(),
      type,
      code,
      ...(mandate
        ? {
            mandateId: mandate.id,
            principalId: mandate.principalId,
            agentId: mandate.agentId,
            workloadId: mandate.workloadId,
            taskId: mandate.taskId,
            audience: mandate.audience,
          }
        : {}),
      ...(request
        ? {
            action: request.action,
            resource: request.resource,
            idempotencyKey: request.idempotencyKey,
          }
        : {}),
      ...(decisionId ? { decisionId } : {}),
    });
  }
}

function validateRequest(request: MandateRequest): void {
  if (!request.tenantId || !request.principalId || !request.agentId || !request.workloadId || !request.taskId || !request.audience) {
    throw new Error("missing_identity_or_context");
  }
  if (request.actions.length === 0 || request.resources.length === 0) throw new Error("empty_authority");
  if (!Number.isInteger(request.expiresInSeconds) || request.expiresInSeconds < 1 || request.expiresInSeconds > MAX_TTL_SECONDS) {
    throw new Error("invalid_ttl");
  }
  if (request.constraints?.maxCalls !== undefined && (!Number.isInteger(request.constraints.maxCalls) || request.constraints.maxCalls < 1)) {
    throw new Error("invalid_max_calls");
  }
}

function hash(value: string): string {
  return createHash("sha256").update(value).digest("base64url");
}

function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}
