import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type { ActionRequest, AuditEvent, Decision, Mandate, MandateRequest } from "./types.js";

const MAX_TTL_SECONDS = 3_600;

export class MandateBroker {
  readonly #mandates = new Map<string, Mandate>();
  readonly #events: AuditEvent[] = [];

  issue(request: MandateRequest): Mandate {
    validateRequest(request);
    if (request.approval?.required && !request.approval.approvedBy) {
      throw new Error("approval_required");
    }

    const issuedAt = new Date();
    const mandate: Mandate = {
      ...structuredClone(request),
      id: randomUUID(),
      secret: randomBytes(32).toString("base64url"),
      issuedAt: issuedAt.toISOString(),
      expiresAt: new Date(issuedAt.getTime() + request.expiresInSeconds * 1_000).toISOString(),
      status: "active",
      successfulUses: 0,
    };
    this.#mandates.set(mandate.id, mandate);
    this.#record("mandate.issued", "issued", mandate);
    return structuredClone(mandate);
  }

  authorize(request: ActionRequest): Decision {
    const [id, presentedSecret] = request.grant.split(".", 2);
    const mandate = id ? this.#mandates.get(id) : undefined;
    const deny = (code: string): Decision => {
      this.#record("action.denied", code, mandate, request);
      return { allowed: false, code };
    };

    if (!mandate || !presentedSecret || !safeEqual(mandate.secret, presentedSecret)) return deny("invalid_grant");
    if (mandate.status !== "active") return deny("revoked");
    if (Date.now() >= Date.parse(mandate.expiresAt)) return deny("expired");
    if (mandate.agentId !== request.agentId) return deny("agent_mismatch");
    if (mandate.taskId !== request.taskId) return deny("task_mismatch");
    if (mandate.audience !== request.audience) return deny("audience_mismatch");
    if (!mandate.actions.includes(request.action)) return deny("action_not_granted");
    if (!mandate.resources.includes(request.resource)) return deny("resource_not_granted");

    const constraints = mandate.constraints;
    if (constraints?.maxCalls !== undefined && mandate.successfulUses >= constraints.maxCalls) return deny("call_limit_exceeded");
    for (const [key, expected] of Object.entries(constraints?.equals ?? {})) {
      if (request.parameters?.[key] !== expected) return deny(`constraint_equals:${key}`);
    }
    for (const [key, maximum] of Object.entries(constraints?.maximum ?? {})) {
      const actual = request.parameters?.[key];
      if (typeof actual !== "number" || actual > maximum) return deny(`constraint_maximum:${key}`);
    }

    mandate.successfulUses += 1;
    this.#record("action.allowed", "allowed", mandate, request);
    return { allowed: true, code: "allowed", mandateId: mandate.id };
  }

  revoke(id: string): boolean {
    const mandate = this.#mandates.get(id);
    if (!mandate) return false;
    mandate.status = "revoked";
    this.#record("mandate.revoked", "revoked", mandate);
    return true;
  }

  audit(): AuditEvent[] {
    return structuredClone(this.#events);
  }

  static bearer(mandate: Mandate): string {
    return `${mandate.id}.${mandate.secret}`;
  }

  #record(type: AuditEvent["type"], code: string, mandate?: Mandate, request?: ActionRequest): void {
    this.#events.push({
      id: randomUUID(), at: new Date().toISOString(), type, code,
      ...(mandate ? { mandateId: mandate.id, agentId: mandate.agentId, taskId: mandate.taskId } : {}),
      ...(request ? { action: request.action, resource: request.resource } : {}),
    });
  }
}

function validateRequest(request: MandateRequest): void {
  if (!request.principalId || !request.agentId || !request.taskId || !request.audience) throw new Error("missing_identity_or_context");
  if (request.actions.length === 0 || request.resources.length === 0) throw new Error("empty_authority");
  if (!Number.isInteger(request.expiresInSeconds) || request.expiresInSeconds < 1 || request.expiresInSeconds > MAX_TTL_SECONDS) {
    throw new Error("invalid_ttl");
  }
  if (request.constraints?.maxCalls !== undefined && (!Number.isInteger(request.constraints.maxCalls) || request.constraints.maxCalls < 1)) {
    throw new Error("invalid_max_calls");
  }
}

function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}
