import type {
  ActionEnvelope,
  ActionRequest,
  ApprovalEvent,
  ApprovalExecutionStatus,
  ApprovalIntent,
  ApprovalRequest,
  ApprovalRequestStatus,
  AuditEvent,
  DownstreamCredential,
  DownstreamResult,
  ExecutionCompletion,
  ExecutionReceipt,
  ExecutionReservation,
  Mandate,
  MandateRequest,
  PolicyInput,
  PolicyResult,
  PrincipalContext,
  ProviderConnection,
  ProviderConnectionResource,
  ProviderConnectionStatus,
  ProviderResourceStatus,
  WorkloadContext,
} from "./types.js";

export interface PrincipalAuthenticator {
  authenticate(token: string, expectedNonce?: string): Promise<PrincipalContext>;
}

export interface WorkloadAuthenticator {
  authenticate(token: string): Promise<WorkloadContext>;
}

export interface PolicyAdapter {
  evaluate(input: PolicyInput): Promise<PolicyResult>;
}

export interface MandateRepository {
  create(request: MandateRequest, grantHash: string, now: Date): Promise<Mandate>;
  find(tenantId: string, mandateId: string): Promise<Mandate | undefined>;
  revoke(tenantId: string, mandateId: string, now: Date): Promise<boolean>;
  findReceipt(tenantId: string, mandateId: string, idempotencyKey: string): Promise<ExecutionReceipt | undefined>;
  /** Atomically rechecks the mandate and reserves one use/idempotency key. */
  reserve(
    request: ActionRequest,
    envelope: ActionEnvelope,
    envelopeHash: string,
    decisionId: string,
    now: Date,
  ): Promise<ExecutionReservation>;
  complete(tenantId: string, receiptId: string, completion: ExecutionCompletion, now: Date): Promise<ExecutionReceipt>;
  /** Persist a redacted decision/audit event that did not enter reserve(). */
  appendAudit(event: AuditEvent): Promise<void>;
  listAudit(tenantId: string, limit?: number): Promise<AuditEvent[]>;
  readiness(): Promise<boolean>;
  close(): Promise<void>;
}

export interface ApprovalProposalRecord {
  request: ApprovalRequest;
  event: ApprovalEvent;
}

export interface ApprovalDecisionInput {
  tenantId: string;
  requestId: string;
  expectedPrincipalId: string;
  principalId: string;
  authenticatedAt: string;
  intentHash: string;
  decision: "approved" | "denied";
  reason?: string;
}

/** Durable product control-plane state. Provider credentials are never accepted here. */
export interface ApprovalRepository {
  create(input: {
    intent: ApprovalIntent;
    agentId: string;
    workloadId: string;
    workflowId: string;
    mcpSessionHash: string;
    resumeHandleHash: string;
    idempotencyKey: string;
    now: Date;
  }): Promise<ApprovalProposalRecord>;
  find(tenantId: string, requestId: string): Promise<ApprovalRequest | undefined>;
  findByResumeHandle(tenantId: string, resumeHandleHash: string): Promise<ApprovalRequest | undefined>;
  decide(input: ApprovalDecisionInput, now: Date): Promise<ApprovalRequest>;
  attachMandate(tenantId: string, requestId: string, intentHash: string, mandateId: string, now: Date): Promise<ApprovalRequest>;
  updateExecution(
    tenantId: string,
    requestId: string,
    intentHash: string,
    status: ApprovalExecutionStatus,
    receiptId: string | undefined,
    now: Date,
  ): Promise<ApprovalRequest>;
  listEvents(tenantId: string, requestId: string): Promise<ApprovalEvent[]>;
  expire(now: Date, limit?: number): Promise<number>;
  readiness(): Promise<boolean>;
  close(): Promise<void>;
}

export interface ProviderConnectionRepository {
  putConnection(input: Omit<ProviderConnection, "createdAt" | "updatedAt">, now: Date): Promise<ProviderConnection>;
  putResource(input: Omit<ProviderConnectionResource, "createdAt" | "updatedAt">, now: Date): Promise<ProviderConnectionResource>;
  findConnection(tenantId: string, providerId: string, connectionId: string): Promise<ProviderConnection | undefined>;
  findResource(
    tenantId: string,
    connectionId: string,
    providerResourceId: string,
  ): Promise<ProviderConnectionResource | undefined>;
  setConnectionStatus(
    tenantId: string,
    providerId: string,
    connectionId: string,
    status: ProviderConnectionStatus,
    now: Date,
  ): Promise<boolean>;
  setResourceStatus(
    tenantId: string,
    connectionId: string,
    providerResourceId: string,
    status: ProviderResourceStatus,
    now: Date,
  ): Promise<boolean>;
  listResources(tenantId: string, providerId: string, connectionId: string): Promise<ProviderConnectionResource[]>;
  readiness(): Promise<boolean>;
  close(): Promise<void>;
}

export interface TokenExchangeAdapter {
  exchange(input: {
    tenantId: string;
    principalId: string;
    agentId: string;
    subjectGrant: string;
    audience: string;
    scope: string;
  }): Promise<DownstreamCredential>;
}

export interface DownstreamExecutor {
  execute(input: {
    envelope: ActionEnvelope;
    credential: DownstreamCredential;
    idempotencyKey: string;
  }): Promise<DownstreamResult>;
  reconcile?(input: {
    envelope: ActionEnvelope;
    credential: DownstreamCredential;
    idempotencyKey: string;
  }): Promise<DownstreamResult | undefined>;
}
