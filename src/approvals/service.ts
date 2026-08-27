import { randomBytes, randomUUID } from "node:crypto";
import type { ExecutionGateway } from "../gateway/index.js";
import type { ApprovedMandateInput, MandateService } from "../grants/index.js";
import type { ApprovalRepository } from "../ports.js";
import {
  ACTION_ENVELOPE_VERSION,
  type ActionEnvelope,
  type ActionRisk,
  type ApprovalRequest,
  type ExecuteResult,
  type JsonValue,
  type PrincipalContext,
} from "../types.js";
import { buildApprovalIntent, hashApprovalIntent, hashOpaqueHandle, InternalGrantDeriver } from "./canonical.js";

export interface ApprovalWorkloadContext {
  tenantId: string;
  principalId: string;
  agentId: string;
  workloadId: string;
  /** Authenticated MCP authorization/session identifier, never a model argument. */
  mcpSessionId: string;
}

export interface PreparedApprovalAction {
  profileId: string;
  profileHash: string;
  providerId: string;
  providerConnectionId: string;
  providerResourceId: string;
  idempotencyKey: string;
  audience: string;
  action: string;
  resource: string;
  parameters: Record<string, JsonValue>;
  risk: ActionRisk;
}

export interface ApprovalProposalResult {
  status: "approval_required";
  requestId: string;
  resumeHandle: string;
  approvalUrl: string;
  expiresAt: string;
  intentHash: string;
}

export type ApprovalResumeResult =
  | { status: "pending" | "denied" | "expired" | "cancelled"; requestId: string; expiresAt: string; reason?: string }
  | { status: "failed" | "ambiguous"; requestId: string; expiresAt: string; reason: string }
  | { status: "succeeded" | "failed" | "ambiguous"; requestId: string; execution: ExecuteResult };

interface ApprovalExecutor {
  execute(request: Parameters<ExecutionGateway["execute"]>[0]): Promise<ExecuteResult>;
}

export interface ApprovalServiceOptions {
  repository: ApprovalRepository;
  mandates: Pick<MandateService, "issueApproved">;
  grantDeriver: InternalGrantDeriver;
  executorFor(input: { providerId: string; connectionId: string }): ApprovalExecutor;
  currentProfileHash(profileId: string): string | undefined;
  connectionIsActive(input: { tenantId: string; providerId: string; connectionId: string; providerResourceId: string }): Promise<boolean>;
  publicBaseUrl: string;
  approvalTtlSeconds?: number;
  maxApprovalAuthenticationAgeSeconds?: number;
  now?: () => Date;
  id?: () => string;
}

export class ApprovalServiceError extends Error {
  constructor(readonly code:
    | "invalid_request"
    | "approval_not_found"
    | "approval_mismatch"
    | "approval_expired"
    | "approval_not_ready"
    | "profile_drift"
    | "provider_connection_unavailable") {
    super(code);
    this.name = "ApprovalServiceError";
  }
}

export class ApprovalService {
  readonly #repository: ApprovalRepository;
  readonly #mandates: Pick<MandateService, "issueApproved">;
  readonly #grantDeriver: InternalGrantDeriver;
  readonly #executorFor: ApprovalServiceOptions["executorFor"];
  readonly #currentProfileHash: ApprovalServiceOptions["currentProfileHash"];
  readonly #connectionIsActive: ApprovalServiceOptions["connectionIsActive"];
  readonly #publicBaseUrl: string;
  readonly #ttlSeconds: number;
  readonly #maxAuthenticationAgeSeconds: number;
  readonly #now: () => Date;
  readonly #id: () => string;

  constructor(options: ApprovalServiceOptions) {
    this.#repository = options.repository;
    this.#mandates = options.mandates;
    this.#grantDeriver = options.grantDeriver;
    this.#executorFor = options.executorFor;
    this.#currentProfileHash = options.currentProfileHash;
    this.#connectionIsActive = options.connectionIsActive;
    this.#publicBaseUrl = normalizedBaseUrl(options.publicBaseUrl);
    this.#ttlSeconds = options.approvalTtlSeconds ?? 300;
    if (!Number.isInteger(this.#ttlSeconds) || this.#ttlSeconds < 30 || this.#ttlSeconds > 3_600) {
      throw new TypeError("approvalTtlSeconds must be an integer from 30 to 3600");
    }
    this.#maxAuthenticationAgeSeconds = options.maxApprovalAuthenticationAgeSeconds ?? 300;
    if (!Number.isInteger(this.#maxAuthenticationAgeSeconds) || this.#maxAuthenticationAgeSeconds < 0 || this.#maxAuthenticationAgeSeconds > 3_600) {
      throw new TypeError("maxApprovalAuthenticationAgeSeconds must be an integer from 0 to 3600");
    }
    this.#now = options.now ?? (() => new Date());
    this.#id = options.id ?? randomUUID;
  }

  async propose(context: ApprovalWorkloadContext, prepared: PreparedApprovalAction): Promise<ApprovalProposalResult> {
    validateWorkloadContext(context);
    validatePreparedAction(prepared);
    if (prepared.risk === "read") throw new ApprovalServiceError("invalid_request");
    const now = this.#validNow();
    const requestId = this.#id();
    const workflowId = `workflow:${this.#id()}`;
    const expiresAt = new Date(now.getTime() + this.#ttlSeconds * 1_000).toISOString();
    const envelope: ActionEnvelope = {
      version: ACTION_ENVELOPE_VERSION,
      tenantId: context.tenantId,
      principalId: context.principalId,
      agentId: context.agentId,
      workloadId: context.workloadId,
      taskId: workflowId,
      audience: prepared.audience,
      action: prepared.action,
      resource: prepared.resource,
      parameters: structuredClone(prepared.parameters),
    };
    const intent = buildApprovalIntent({
      requestId,
      envelope,
      profileId: prepared.profileId,
      profileHash: prepared.profileHash,
      providerId: prepared.providerId,
      providerConnectionId: prepared.providerConnectionId,
      providerResourceId: prepared.providerResourceId,
      idempotencyKey: prepared.idempotencyKey,
      risk: prepared.risk,
      expiresAt,
      expectedApprover: context.principalId,
    });
    const intentHash = hashApprovalIntent(intent);
    const resumeHandle = randomBytes(32).toString("base64url");
    await this.#repository.create({
      intent,
      agentId: context.agentId,
      workloadId: context.workloadId,
      workflowId,
      mcpSessionHash: hashOpaqueHandle(context.mcpSessionId),
      resumeHandleHash: hashOpaqueHandle(resumeHandle),
      idempotencyKey: prepared.idempotencyKey,
      now,
    });
    return {
      status: "approval_required",
      requestId,
      resumeHandle,
      approvalUrl: `${this.#publicBaseUrl}/approvals/${encodeURIComponent(requestId)}`,
      expiresAt,
      intentHash,
    };
  }

  async get(context: ApprovalWorkloadContext, requestId: string): Promise<ApprovalRequest> {
    validateWorkloadContext(context);
    const request = await this.#repository.find(context.tenantId, required(requestId));
    if (!request || !matchesContext(request, context)) throw new ApprovalServiceError("approval_not_found");
    return this.#expireProjection(request);
  }

  async decide(
    principal: PrincipalContext,
    input: { requestId: string; intentHash: string; decision: "approved" | "denied"; reason?: string },
  ): Promise<ApprovalRequest> {
    validatePrincipal(principal);
    const now = this.#validNow();
    const authenticatedAt = principal.authenticatedAt;
    if (
      authenticatedAt === undefined ||
      !Number.isFinite(Date.parse(authenticatedAt)) ||
      Date.parse(authenticatedAt) > now.getTime() ||
      now.getTime() - Date.parse(authenticatedAt) > this.#maxAuthenticationAgeSeconds * 1_000
    ) {
      throw new ApprovalServiceError("invalid_request");
    }
    const existing = await this.#repository.find(principal.tenantId, required(input.requestId));
    if (!existing || existing.expectedPrincipalId !== principal.principalId) throw new ApprovalServiceError("approval_not_found");
    this.#verifyFrozenIntent(existing);
    if (existing.expiresAt <= now.toISOString()) throw new ApprovalServiceError("approval_expired");
    return this.#repository.decide({
      tenantId: principal.tenantId,
      requestId: existing.id,
      expectedPrincipalId: existing.expectedPrincipalId,
      principalId: principal.principalId,
      authenticatedAt,
      intentHash: required(input.intentHash),
      decision: input.decision,
      ...(input.reason === undefined ? {} : { reason: boundedReason(input.reason) }),
    }, now);
  }

  async resume(context: ApprovalWorkloadContext, resumeHandle: string): Promise<ApprovalResumeResult> {
    validateWorkloadContext(context);
    const now = this.#validNow();
    let request = await this.#repository.findByResumeHandle(context.tenantId, hashOpaqueHandle(required(resumeHandle)));
    if (!request || !matchesContext(request, context)) throw new ApprovalServiceError("approval_not_found");
    request = await this.#expireProjection(request);
    if (request.status !== "approved") {
      return {
        status: request.status,
        requestId: request.id,
        expiresAt: request.expiresAt,
        ...(request.decisionReason === undefined ? {} : { reason: request.decisionReason }),
      };
    }
    this.#verifyFrozenIntent(request);
    if (
      request.receiptId === undefined
      && (request.executionStatus === "failed" || request.executionStatus === "ambiguous")
    ) {
      return {
        status: request.executionStatus,
        requestId: request.id,
        expiresAt: request.expiresAt,
        reason: request.executionStatus === "ambiguous"
          ? "The prior execution may have started; no automatic retry is allowed."
          : "The prior execution failed before a receipt was available.",
      };
    }
    if (request.executionStatus === "succeeded" && request.receiptId === undefined) {
      throw new ApprovalServiceError("approval_not_ready");
    }
    const recordedTerminal = request.receiptId !== undefined
      && (request.executionStatus === "succeeded" || request.executionStatus === "failed" || request.executionStatus === "ambiguous");
    if (!recordedTerminal) {
      if (this.#currentProfileHash(request.profileId) !== request.profileHash) throw new ApprovalServiceError("profile_drift");
      if (!await this.#connectionIsActive({
        tenantId: request.tenantId,
        providerId: request.providerId,
        connectionId: request.providerConnectionId,
        providerResourceId: request.providerResourceId,
      })) throw new ApprovalServiceError("provider_connection_unavailable");
    }

    const secret = this.#grantDeriver.derive(request.tenantId, request.id);
    const issued = await this.#mandates.issueApproved(
      internalPrincipal(request),
      approvedMandateInput(request, now),
      secret,
    );
    request = await this.#repository.attachMandate(request.tenantId, request.id, request.intentHash, issued.mandate.id, now);
    if (request.executionStatus === "not_started" || request.executionStatus === "reserved") {
      request = await this.#repository.updateExecution(
        request.tenantId,
        request.id,
        request.intentHash,
        "dispatching",
        request.receiptId,
        now,
      );
    }

    let execution: ExecuteResult;
    try {
      execution = await this.#executorFor({ providerId: request.providerId, connectionId: request.providerConnectionId }).execute({
        grant: issued.grant,
        tenantId: request.tenantId,
        agentId: request.agentId,
        workloadId: request.workloadId,
        taskId: request.workflowId,
        audience: request.envelope.audience,
        action: request.envelope.action,
        resource: request.envelope.resource,
        parameters: structuredClone(request.envelope.parameters),
        idempotencyKey: request.idempotencyKey,
      });
    } catch {
      if (request.executionStatus === "reserved" || request.executionStatus === "dispatching") {
        await this.#repository.updateExecution(request.tenantId, request.id, request.intentHash, "ambiguous", request.receiptId, this.#validNow());
      }
      throw new ApprovalServiceError("approval_not_ready");
    }
    const status = execution.receipt?.outcome === "succeeded"
      ? "succeeded"
      : execution.receipt?.outcome === "ambiguous" || execution.receipt?.outcome === "pending"
        ? "ambiguous"
        : "failed";
    await this.#repository.updateExecution(
      request.tenantId,
      request.id,
      request.intentHash,
      status,
      execution.receipt?.id,
      this.#validNow(),
    );
    return { status, requestId: request.id, execution };
  }

  async getForPrincipal(principal: PrincipalContext, requestId: string): Promise<ApprovalRequest> {
    validatePrincipal(principal);
    const request = await this.#repository.find(principal.tenantId, required(requestId));
    if (!request || request.expectedPrincipalId !== principal.principalId) throw new ApprovalServiceError("approval_not_found");
    this.#verifyFrozenIntent(request);
    return this.#expireProjection(request);
  }

  #verifyFrozenIntent(request: ApprovalRequest): void {
    if (
      hashApprovalIntent(request.intent) !== request.intentHash ||
      request.intent.requestId !== request.id ||
      request.intent.envelopeHash !== request.envelopeHash ||
      request.intent.profileId !== request.profileId ||
      request.intent.profileHash !== request.profileHash ||
      request.intent.providerConnectionId !== request.providerConnectionId ||
      request.intent.providerResourceId !== request.providerResourceId
    ) throw new ApprovalServiceError("approval_mismatch");
  }

  async #expireProjection(request: ApprovalRequest): Promise<ApprovalRequest> {
    if (request.status === "pending" && request.expiresAt <= this.#validNow().toISOString()) {
      await this.#repository.expire(this.#validNow(), 100);
      return await this.#repository.find(request.tenantId, request.id) ?? request;
    }
    return request;
  }

  #validNow(): Date {
    const now = this.#now();
    if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw new TypeError("now must return a valid Date");
    return new Date(now.getTime());
  }
}

function approvedMandateInput(request: ApprovalRequest, now: Date): ApprovedMandateInput {
  const remainingSeconds = Math.floor((Date.parse(request.expiresAt) - now.getTime()) / 1_000);
  if (remainingSeconds < 1) throw new ApprovalServiceError("approval_expired");
  if (!request.decidedBy || !request.decidedAt || !request.authenticatedAt) throw new ApprovalServiceError("approval_mismatch");
  return {
    approvalRequestId: request.id,
    agentId: request.agentId,
    workloadId: request.workloadId,
    taskId: request.workflowId,
    audience: request.envelope.audience,
    action: request.envelope.action,
    resource: request.envelope.resource,
    expiresInSeconds: Math.min(3_600, remainingSeconds),
    approval: {
      required: true,
      approvedBy: request.decidedBy,
      approvedAt: request.decidedAt,
      authenticatedAt: request.authenticatedAt,
      envelopeHash: request.envelopeHash,
      approvalRequestId: request.id,
      intentHash: request.intentHash,
      profileId: request.profileId,
      profileHash: request.profileHash,
      providerId: request.providerId,
      providerConnectionId: request.providerConnectionId,
      providerResourceId: request.providerResourceId,
    },
  };
}

function matchesContext(request: ApprovalRequest, context: ApprovalWorkloadContext): boolean {
  return request.tenantId === context.tenantId &&
    request.expectedPrincipalId === context.principalId &&
    request.agentId === context.agentId &&
    request.workloadId === context.workloadId &&
    request.mcpSessionHash === hashOpaqueHandle(context.mcpSessionId);
}

function internalPrincipal(request: ApprovalRequest): PrincipalContext {
  return {
    tenantId: request.tenantId,
    principalId: request.expectedPrincipalId,
    issuer: "urn:agent-mandate:approved-request",
    subject: request.expectedPrincipalId,
  };
}

function validateWorkloadContext(context: ApprovalWorkloadContext): void {
  for (const value of [context.tenantId, context.principalId, context.agentId, context.workloadId, context.mcpSessionId]) required(value);
}

function validatePrincipal(principal: PrincipalContext): void {
  for (const value of [principal.tenantId, principal.principalId, principal.issuer, principal.subject]) required(value);
}

function validatePreparedAction(prepared: PreparedApprovalAction): void {
  for (const value of [
    prepared.profileId,
    prepared.profileHash,
    prepared.providerId,
    prepared.providerConnectionId,
    prepared.providerResourceId,
    prepared.idempotencyKey,
    prepared.audience,
    prepared.action,
    prepared.resource,
  ]) required(value);
  if (!/^[A-Za-z0-9_-]{43}$/.test(prepared.profileHash)) throw new ApprovalServiceError("invalid_request");
  if (prepared.risk !== "read" && prepared.risk !== "write" && prepared.risk !== "consequential" && prepared.risk !== "prohibited") {
    throw new ApprovalServiceError("invalid_request");
  }
  if (prepared.risk === "prohibited") throw new ApprovalServiceError("invalid_request");
}

function normalizedBaseUrl(value: string): string {
  const url = new URL(value);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && (url.hostname === "127.0.0.1" || url.hostname === "localhost" || url.hostname === "::1"))) {
    throw new TypeError("publicBaseUrl must use HTTPS except on loopback");
  }
  return url.toString().replace(/\/$/, "");
}

function required(value: string): string {
  if (typeof value !== "string" || value.length === 0) throw new ApprovalServiceError("invalid_request");
  return value;
}

function boundedReason(value: string): string {
  if (typeof value !== "string" || value.length > 500) throw new ApprovalServiceError("invalid_request");
  return value;
}
