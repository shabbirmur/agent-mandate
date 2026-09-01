import { randomUUID } from "node:crypto";
import type { ApprovalDecisionInput, ApprovalProposalRecord, ApprovalRepository } from "../ports.js";
import type { ApprovalEvent, ApprovalExecutionStatus, ApprovalRequest } from "../types.js";
import { hashApprovalIntent } from "./canonical.js";

/** Development/test repository. Production and restart-safe demos use PostgreSQL. */
export class InMemoryApprovalRepository implements ApprovalRepository {
  readonly #requests = new Map<string, ApprovalRequest>();
  readonly #handles = new Map<string, string>();
  readonly #events = new Map<string, ApprovalEvent[]>();

  async create(input: Parameters<ApprovalRepository["create"]>[0]): Promise<ApprovalProposalRecord> {
    const key = requestKey(input.intent.envelope.tenantId, input.intent.requestId);
    const handleKey = requestKey(input.intent.envelope.tenantId, input.resumeHandleHash);
    if (this.#requests.has(key) || this.#handles.has(handleKey)) throw new Error("approval_request_conflict");
    const createdAt = validDate(input.now).toISOString();
    const request: ApprovalRequest = {
      id: input.intent.requestId,
      tenantId: input.intent.envelope.tenantId,
      expectedPrincipalId: input.intent.expectedApprover,
      agentId: input.agentId,
      workloadId: input.workloadId,
      workflowId: input.workflowId,
      mcpSessionHash: input.mcpSessionHash,
      profileId: input.intent.profileId,
      profileHash: input.intent.profileHash,
      providerId: input.intent.providerId,
      providerConnectionId: input.intent.providerConnectionId,
      providerResourceId: input.intent.providerResourceId,
      envelope: structuredClone(input.intent.envelope),
      envelopeHash: input.intent.envelopeHash,
      intent: structuredClone(input.intent),
      intentHash: hashApprovalIntent(input.intent),
      resumeHandleHash: input.resumeHandleHash,
      idempotencyKey: input.idempotencyKey,
      status: "pending",
      executionStatus: "not_started",
      createdAt,
      expiresAt: input.intent.expiresAt,
    };
    this.#requests.set(key, request);
    this.#handles.set(handleKey, key);
    const event = this.#record(request, "requested", input.now);
    return { request: structuredClone(request), event };
  }

  async find(tenantId: string, requestId: string): Promise<ApprovalRequest | undefined> {
    return clone(this.#requests.get(requestKey(tenantId, requestId)));
  }

  async findByResumeHandle(tenantId: string, resumeHandleHash: string): Promise<ApprovalRequest | undefined> {
    const key = this.#handles.get(requestKey(tenantId, resumeHandleHash));
    return key === undefined ? undefined : clone(this.#requests.get(key));
  }

  async decide(input: ApprovalDecisionInput, now: Date): Promise<ApprovalRequest> {
    const key = requestKey(input.tenantId, input.requestId);
    const current = this.#requests.get(key);
    if (!current) throw new Error("approval_not_found");
    if (
      current.expectedPrincipalId !== input.expectedPrincipalId ||
      current.expectedPrincipalId !== input.principalId ||
      current.intentHash !== input.intentHash
    ) throw new Error("approval_mismatch");
    if (current.status !== "pending") {
      if (current.status === input.decision && current.decidedBy === input.principalId) return structuredClone(current);
      throw new Error(`approval_not_pending:${current.status}`);
    }
    const at = validDate(now).toISOString();
    if (current.expiresAt <= at) {
      current.status = "expired";
      current.decisionReason = "expired";
      this.#record(current, "expired", now);
      return structuredClone(current);
    }
    const authenticatedAt = validDate(new Date(input.authenticatedAt)).toISOString();
    if (authenticatedAt > at) throw new Error("authentication_from_future");
    current.status = input.decision;
    current.decidedAt = at;
    current.decidedBy = input.principalId;
    current.authenticatedAt = authenticatedAt;
    if (input.reason !== undefined) current.decisionReason = input.reason;
    this.#record(current, input.decision, now, input.principalId);
    return structuredClone(current);
  }

  async attachMandate(
    tenantId: string,
    requestId: string,
    intentHash: string,
    mandateId: string,
    now: Date,
  ): Promise<ApprovalRequest> {
    const current = this.#required(tenantId, requestId);
    if (current.status !== "approved" || current.intentHash !== intentHash) throw new Error("approval_mismatch");
    if (current.mandateId !== undefined && current.mandateId !== mandateId) throw new Error("approval_mandate_conflict");
    if (current.mandateId === undefined) {
      current.mandateId = mandateId;
      this.#record(current, "execution.updated", now);
    }
    return structuredClone(current);
  }

  async updateExecution(
    tenantId: string,
    requestId: string,
    intentHash: string,
    status: ApprovalExecutionStatus,
    receiptId: string | undefined,
    now: Date,
  ): Promise<ApprovalRequest> {
    const current = this.#required(tenantId, requestId);
    if (current.status !== "approved" || current.intentHash !== intentHash) throw new Error("approval_mismatch");
    if (!validTransition(current.executionStatus, status)) throw new Error("invalid_execution_transition");
    if (current.receiptId !== undefined && receiptId !== undefined && current.receiptId !== receiptId) {
      throw new Error("approval_receipt_conflict");
    }
    if (current.executionStatus !== status || (current.receiptId === undefined && receiptId !== undefined)) {
      current.executionStatus = status;
      if (receiptId !== undefined) current.receiptId = receiptId;
      this.#record(current, "execution.updated", now);
    }
    return structuredClone(current);
  }

  async listEvents(tenantId: string, requestId: string): Promise<ApprovalEvent[]> {
    return structuredClone(this.#events.get(requestKey(tenantId, requestId)) ?? []);
  }

  async expire(now: Date, limit = 100): Promise<number> {
    const at = validDate(now).toISOString();
    let count = 0;
    for (const request of this.#requests.values()) {
      if (count >= limit) break;
      if (request.status === "pending" && request.expiresAt <= at) {
        request.status = "expired";
        request.decisionReason = "expired";
        this.#record(request, "expired", now);
        count += 1;
      }
    }
    return count;
  }

  async readiness(): Promise<boolean> {
    return true;
  }

  async close(): Promise<void> {}

  #required(tenantId: string, requestId: string): ApprovalRequest {
    const request = this.#requests.get(requestKey(tenantId, requestId));
    if (!request) throw new Error("approval_not_found");
    return request;
  }

  #record(request: ApprovalRequest, type: ApprovalEvent["type"], at: Date, principalId?: string): ApprovalEvent {
    const key = requestKey(request.tenantId, request.id);
    const events = this.#events.get(key) ?? [];
    const event: ApprovalEvent = {
      id: randomUUID(),
      tenantId: request.tenantId,
      requestId: request.id,
      sequence: events.length + 1,
      type,
      at: validDate(at).toISOString(),
      ...(principalId === undefined ? {} : { principalId }),
      intentHash: request.intentHash,
      snapshot: structuredClone(request),
    };
    events.push(event);
    this.#events.set(key, events);
    return structuredClone(event);
  }
}

function requestKey(tenantId: string, value: string): string {
  if (!tenantId || !value) throw new Error("approval key is required");
  return `${tenantId}\u0000${value}`;
}

function validDate(value: Date): Date {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw new Error("invalid date");
  return new Date(value.getTime());
}

function clone<Value>(value: Value | undefined): Value | undefined {
  return value === undefined ? undefined : structuredClone(value);
}

function validTransition(from: ApprovalExecutionStatus, to: ApprovalExecutionStatus): boolean {
  if (from === to) return true;
  if (from === "not_started") return to === "reserved" || to === "dispatching" || to === "failed";
  if (from === "reserved") return to === "dispatching" || to === "failed" || to === "ambiguous";
  if (from === "dispatching") return to === "succeeded" || to === "failed" || to === "ambiguous";
  if (from === "ambiguous") return to === "succeeded" || to === "failed";
  return false;
}
