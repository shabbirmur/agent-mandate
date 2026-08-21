import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { canonicalHash, toJsonValue } from "../canonical.js";
import type { DownstreamExecutor, MandateRepository, PolicyAdapter, TokenExchangeAdapter } from "../ports.js";
import {
  ACTION_ENVELOPE_VERSION,
  ERROR_CODES,
  type ActionEnvelope,
  type ActionRequest,
  type AuditEvent,
  type Decision,
  type DownstreamResult,
  type ErrorCode,
  type ExecuteResult,
  type ExecutionReceipt,
  type Mandate,
} from "../types.js";
import { DownstreamAudienceMismatchError, DownstreamTimeoutError, TokenExchangeAudienceMismatchError } from "../downstream/errors.js";
import { redactSensitive } from "../security/redaction.js";

export interface ExecutionGatewayOptions {
  repository: MandateRepository;
  policy: PolicyAdapter;
  tokenExchange: TokenExchangeAdapter;
  downstream: DownstreamExecutor;
  now?: () => Date;
  id?: () => string;
  scope?: (envelope: ActionEnvelope) => string;
}

/** Shared HTTP/MCP execution pipeline. No downstream credential escapes it. */
export class ExecutionGateway {
  readonly #repository: MandateRepository;
  readonly #policy: PolicyAdapter;
  readonly #tokenExchange: TokenExchangeAdapter;
  readonly #downstream: DownstreamExecutor;
  readonly #now: () => Date;
  readonly #id: () => string;
  readonly #scope: (envelope: ActionEnvelope) => string;

  constructor(options: ExecutionGatewayOptions) {
    this.#repository = options.repository;
    this.#policy = options.policy;
    this.#tokenExchange = options.tokenExchange;
    this.#downstream = options.downstream;
    this.#now = options.now ?? (() => new Date());
    this.#id = options.id ?? randomUUID;
    this.#scope = options.scope ?? ((envelope) => envelope.action);
  }

  async execute(request: ActionRequest): Promise<ExecuteResult> {
    const mandateId = grantMandateId(request.grant);
    if (!mandateId || !validRequestStrings(request)) return await this.#preReserveDenial(request, "invalid_request");

    let mandate: Mandate | undefined;
    try {
      mandate = await this.#repository.find(request.tenantId, mandateId);
    } catch {
      return await this.#preReserveDenial(request, "policy_indeterminate");
    }
    if (!mandate || !validGrant(request.grant, mandate.grantHash)) {
      return await this.#preReserveDenial(request, "invalid_grant", mandate);
    }

    let envelope: ActionEnvelope;
    let envelopeHash: string;
    try {
      if (!isParameterObject(request.parameters)) throw new TypeError("parameters must be an object");
      toJsonValue(request.parameters);
      envelope = envelopeFor(request, mandate);
      envelopeHash = canonicalHash(envelope);
    } catch {
      return await this.#preReserveDenial(request, "invalid_request", mandate);
    }

    let existingReceipt: ExecutionReceipt | undefined;
    try {
      existingReceipt = await this.#repository.findReceipt(request.tenantId, mandate.id, request.idempotencyKey);
    } catch {
      return await this.#preReserveDenial(request, "policy_indeterminate", mandate, envelopeHash);
    }
    if (existingReceipt) {
      if (
        existingReceipt.tenantId !== request.tenantId
        || existingReceipt.mandateId !== mandate.id
        || existingReceipt.idempotencyKey !== request.idempotencyKey
      ) return await this.#preReserveDenial(request, "policy_indeterminate", mandate, envelopeHash);
      if (existingReceipt.envelopeHash !== envelopeHash) {
        return await this.#preReserveDenial(request, "idempotency_conflict", mandate, envelopeHash);
      }
      return this.#replay(existingReceipt);
    }

    const now = this.#now();
    const policy = await safePolicy(this.#policy, { envelope, mandate, now: now.toISOString() });
    if (policy.outcome !== "allow") {
      const code = policy.outcome === "indeterminate" ? "policy_indeterminate" : policyCode(policy.reason);
      return await this.#preReserveDenial(request, code, mandate, envelopeHash);
    }

    let reservation;
    try {
      reservation = await this.#repository.reserve(request, envelope, envelopeHash, this.#id(), now);
    } catch {
      return await this.#preReserveDenial(request, "policy_indeterminate", mandate, envelopeHash);
    }
    if (!reservation.decision.allowed) return { decision: reservation.decision, ...(reservation.receipt ? { receipt: reservation.receipt } : {}) };
    if (reservation.replay) {
      if (!reservation.receipt) return { decision: this.#derive(reservation.decision, "policy_indeterminate") };
      if (reservation.receipt.envelopeHash !== envelopeHash) {
        return { decision: this.#derive(reservation.decision, "idempotency_conflict"), receipt: reservation.receipt };
      }
      return this.#replay(reservation.receipt, reservation.decision);
    }
    if (!reservation.receipt) return { decision: this.#derive(reservation.decision, "policy_indeterminate") };

    let credential: Awaited<ReturnType<TokenExchangeAdapter["exchange"]>>;
    try {
      credential = await this.#tokenExchange.exchange({
        tenantId: mandate.tenantId,
        principalId: mandate.principalId,
        agentId: mandate.agentId,
        subjectGrant: request.grant,
        audience: envelope.audience,
        scope: this.#scope(envelope),
      });
    } catch (error) {
      if (error instanceof TokenExchangeAudienceMismatchError) {
        return await this.#finishFailure(reservation.decision, reservation.receipt, "downstream_audience_mismatch");
      }
      return await this.#finishFailure(reservation.decision, reservation.receipt, "downstream_failed");
    }
    const credentialExpiry = Date.parse(credential.expiresAt);
    if (credential.audience !== envelope.audience) {
      return await this.#finishFailure(reservation.decision, reservation.receipt, "downstream_audience_mismatch");
    }
    if (
      !credential.accessToken
      || (credential.tokenType !== "Bearer" && credential.tokenType !== "DPoP")
      || !Number.isFinite(credentialExpiry)
      || credentialExpiry <= this.#now().getTime()
    ) return await this.#finishFailure(reservation.decision, reservation.receipt, "downstream_failed");

    let result: DownstreamResult;
    try {
      result = await this.#downstream.execute({ envelope, credential, idempotencyKey: request.idempotencyKey });
    } catch (error) {
      if (error instanceof DownstreamTimeoutError) {
        const reconciled = await this.#reconcile(envelope, credential, request.idempotencyKey);
        if (!reconciled) {
          return await this.#finishFailure(reservation.decision, reservation.receipt, "downstream_ambiguous", "ambiguous");
        }
        result = reconciled;
      } else if (error instanceof DownstreamAudienceMismatchError) {
        return await this.#finishFailure(reservation.decision, reservation.receipt, "downstream_audience_mismatch");
      } else {
        return await this.#finishFailure(reservation.decision, reservation.receipt, "downstream_failed");
      }
    }
    if (!Number.isInteger(result.status) || result.status < 100 || result.status > 599) {
      return await this.#finishFailure(reservation.decision, reservation.receipt, "downstream_failed");
    }
    return await this.#finishResult(reservation.decision, reservation.receipt, result, credential.accessToken);
  }

  async #reconcile(
    envelope: ActionEnvelope,
    credential: Awaited<ReturnType<TokenExchangeAdapter["exchange"]>>,
    idempotencyKey: string,
  ): Promise<DownstreamResult | undefined> {
    if (!this.#downstream.reconcile) return undefined;
    try {
      return await this.#downstream.reconcile({ envelope, credential, idempotencyKey });
    } catch {
      return undefined;
    }
  }

  async #finishResult(
    decision: Decision,
    receipt: ExecutionReceipt,
    result: DownstreamResult,
    credential: string,
  ): Promise<ExecuteResult> {
    const safeResult: DownstreamResult = {
      status: result.status,
      body: redactSensitive(result.body, { secrets: [credential] }),
    };
    const succeeded = result.status >= 200 && result.status < 300;
    const completed = await this.#complete(receipt, {
      outcome: succeeded ? "succeeded" : "failed",
      downstreamStatus: result.status,
      resultHash: canonicalHash(safeResult),
    });
    return {
      decision: succeeded ? decision : this.#derive(decision, "downstream_failed"),
      receipt: completed,
      result: safeResult,
    };
  }

  async #finishFailure(
    decision: Decision,
    receipt: ExecutionReceipt,
    code: "downstream_audience_mismatch" | "downstream_failed" | "downstream_ambiguous",
    outcome: "failed" | "ambiguous" = "failed",
  ): Promise<ExecuteResult> {
    const completed = await this.#complete(receipt, { outcome });
    return { decision: this.#derive(decision, code), receipt: completed };
  }

  async #complete(
    receipt: ExecutionReceipt,
    completion: Parameters<MandateRepository["complete"]>[2],
  ): Promise<ExecutionReceipt> {
    try {
      return await this.#repository.complete(receipt.tenantId, receipt.id, completion, this.#now());
    } catch {
      throw new Error("execution completion failed");
    }
  }

  #deny(code: ErrorCode, mandateId?: string, envelopeHash?: string): Decision {
    return {
      allowed: false,
      code,
      decisionId: this.#id(),
      ...(mandateId ? { mandateId } : {}),
      ...(envelopeHash ? { envelopeHash } : {}),
    };
  }

  async #preReserveDenial(
    request: ActionRequest,
    code: ErrorCode,
    mandate?: Mandate,
    envelopeHash?: string,
  ): Promise<ExecuteResult> {
    const decision = this.#deny(code, mandate?.id, envelopeHash);
    const event: AuditEvent = {
      id: this.#id(),
      tenantId: request.tenantId || mandate?.tenantId || "unknown",
      at: this.#now().toISOString(),
      type: "action.denied",
      code,
      decisionId: decision.decisionId,
      ...(mandate ? { mandateId: mandate.id, principalId: mandate.principalId } : {}),
      ...(request.agentId ? { agentId: request.agentId } : {}),
      ...(request.workloadId ? { workloadId: request.workloadId } : {}),
      ...(request.taskId ? { taskId: request.taskId } : {}),
      ...(request.audience ? { audience: request.audience } : {}),
      ...(request.action ? { action: request.action } : {}),
      ...(request.resource ? { resource: request.resource } : {}),
      ...(envelopeHash ? { envelopeHash } : {}),
      ...(request.idempotencyKey ? { idempotencyKey: request.idempotencyKey } : {}),
    };
    try {
      await this.#repository.appendAudit(event);
    } catch {
      // Authorization must remain fail-closed when evidence persistence is degraded.
    }
    return { decision };
  }

  #derive(decision: Decision, code: ErrorCode): Decision {
    return { ...decision, allowed: false, code };
  }

  #replay(receipt: ExecutionReceipt, reservedDecision?: Decision): ExecuteResult {
    const base: Decision = reservedDecision ?? {
      allowed: true,
      code: "allowed",
      decisionId: receipt.decisionId,
      mandateId: receipt.mandateId,
      envelopeHash: receipt.envelopeHash,
    };
    if (receipt.outcome === "succeeded") return { decision: { ...base, allowed: true, code: "allowed" }, receipt };
    if (receipt.outcome === "failed") return { decision: this.#derive(base, "downstream_failed"), receipt };
    return { decision: this.#derive(base, "downstream_ambiguous"), receipt };
  }
}

function envelopeFor(request: ActionRequest, mandate: Mandate): ActionEnvelope {
  return {
    version: ACTION_ENVELOPE_VERSION,
    tenantId: request.tenantId,
    principalId: mandate.principalId,
    agentId: request.agentId,
    workloadId: request.workloadId,
    taskId: request.taskId,
    audience: request.audience,
    action: request.action,
    resource: request.resource,
    parameters: structuredClone(request.parameters),
  };
}

function grantMandateId(grant: unknown): string | undefined {
  if (typeof grant !== "string") return undefined;
  const separator = grant.indexOf(".");
  if (separator <= 0 || separator === grant.length - 1) return undefined;
  return grant.slice(0, separator);
}

function validGrant(grant: string, expectedHash: string): boolean {
  const separator = grant.indexOf(".");
  if (separator <= 0 || separator === grant.length - 1 || grant.indexOf(".", separator + 1) !== -1) return false;
  const secret = grant.slice(separator + 1);
  const actualHash = createHash("sha256").update(secret, "utf8").digest("base64url");
  const actual = Buffer.from(actualHash, "utf8");
  const expected = Buffer.from(expectedHash, "utf8");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function isParameterObject(value: unknown): value is Record<string, import("../types.js").JsonValue> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as object | null;
  return prototype === Object.prototype || prototype === null;
}

function validRequestStrings(request: ActionRequest): boolean {
  return [
    request.tenantId,
    request.agentId,
    request.workloadId,
    request.taskId,
    request.audience,
    request.action,
    request.resource,
    request.idempotencyKey,
  ].every((value) => typeof value === "string" && value.length > 0);
}

async function safePolicy(policy: PolicyAdapter, input: Parameters<PolicyAdapter["evaluate"]>[0]) {
  try {
    const result = await policy.evaluate(input);
    if (result.outcome === "allow" || result.outcome === "deny" || result.outcome === "indeterminate") return result;
  } catch {
    // Fail closed below.
  }
  return { outcome: "indeterminate" as const, reason: "policy_indeterminate" };
}

function policyCode(reason: string | undefined): ErrorCode {
  return reason && (ERROR_CODES as readonly string[]).includes(reason) ? reason as ErrorCode : "policy_denied";
}
