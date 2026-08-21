import type {
  ActionEnvelope,
  ActionRequest,
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
