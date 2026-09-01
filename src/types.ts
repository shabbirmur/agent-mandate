export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

/** The pilot only accepts this exact envelope profile. Changes require a new version. */
export const ACTION_ENVELOPE_VERSION = "am.action.v1" as const;
export type ActionEnvelopeVersion = typeof ACTION_ENVELOPE_VERSION;

export const ERROR_CODES = [
  "allowed",
  "invalid_request",
  "missing_identity_or_context",
  "invalid_principal",
  "invalid_workload_identity",
  "tenant_mismatch",
  "invalid_grant",
  "revoked",
  "expired",
  "agent_mismatch",
  "workload_mismatch",
  "task_mismatch",
  "audience_mismatch",
  "action_not_granted",
  "resource_not_granted",
  "parameter_mismatch",
  "call_limit_exceeded",
  "approval_required",
  "approval_mismatch",
  "delegation_amplification",
  "replay_detected",
  "idempotency_conflict",
  "policy_denied",
  "policy_indeterminate",
  "downstream_audience_mismatch",
  "downstream_failed",
  "downstream_ambiguous",
] as const;
export type ErrorCode = (typeof ERROR_CODES)[number];

export interface PrincipalContext {
  tenantId: string;
  principalId: string;
  issuer: string;
  subject: string;
  /** Present when the relying party required a nonce for this authentication. */
  nonce?: string;
  /** OIDC auth_time, when asserted by the verified identity token. */
  authenticatedAt?: string;
}

export interface WorkloadContext {
  tenantId: string;
  agentId: string;
  workloadId: string;
  issuer: string;
  subject: string;
}

export interface ConstraintSet {
  /** Maximum number of accepted executions across the mandate lifetime. */
  maxCalls?: number;
  /** Exact envelope parameter fields that must equal these values. */
  equals?: Record<string, JsonPrimitive>;
  /** Numeric envelope parameter fields that must not exceed these values. */
  maximum?: Record<string, number>;
}

export interface ActionEnvelope {
  version: ActionEnvelopeVersion;
  tenantId: string;
  principalId: string;
  agentId: string;
  workloadId: string;
  taskId: string;
  audience: string;
  action: string;
  resource: string;
  parameters: Record<string, JsonValue>;
}

export interface ApprovalEvidence {
  required: boolean;
  approvedBy?: string;
  approvedAt?: string;
  envelopeHash?: string;
  /** v0.2 product approval binding. Older v0.1 records omit these fields. */
  approvalRequestId?: string;
  intentHash?: string;
  profileId?: string;
  profileHash?: string;
  providerId?: string;
  providerConnectionId?: string;
  providerResourceId?: string;
  authenticatedAt?: string;
}

export const APPROVAL_INTENT_VERSION = "am.approval-intent.v1" as const;
export type ApprovalIntentVersion = typeof APPROVAL_INTENT_VERSION;
export type ActionRisk = "read" | "write" | "consequential" | "prohibited";
export type ApprovalRequestStatus = "pending" | "approved" | "denied" | "expired" | "cancelled";
export type ApprovalExecutionStatus = "not_started" | "reserved" | "dispatching" | "succeeded" | "failed" | "ambiguous";

/** Immutable terms shown to, and later approved by, a separately authenticated user. */
export interface ApprovalIntent {
  version: ApprovalIntentVersion;
  requestId: string;
  envelope: ActionEnvelope;
  envelopeHash: string;
  profileId: string;
  profileHash: string;
  providerId: string;
  providerConnectionId: string;
  providerResourceId: string;
  /** Server/profile-minted provider correlation key; never model supplied. */
  idempotencyKey: string;
  risk: ActionRisk;
  expiresAt: string;
  maxCalls: number;
  delegationAllowed: false;
  expectedApprover: string;
}

export interface ApprovalRequest {
  id: string;
  tenantId: string;
  expectedPrincipalId: string;
  agentId: string;
  workloadId: string;
  workflowId: string;
  mcpSessionHash: string;
  profileId: string;
  profileHash: string;
  providerId: string;
  providerConnectionId: string;
  providerResourceId: string;
  envelope: ActionEnvelope;
  envelopeHash: string;
  intent: ApprovalIntent;
  intentHash: string;
  resumeHandleHash: string;
  idempotencyKey: string;
  status: ApprovalRequestStatus;
  executionStatus: ApprovalExecutionStatus;
  createdAt: string;
  expiresAt: string;
  decidedAt?: string;
  decidedBy?: string;
  authenticatedAt?: string;
  decisionReason?: string;
  mandateId?: string;
  receiptId?: string;
}

export interface ApprovalEvent {
  id: string;
  tenantId: string;
  requestId: string;
  sequence: number;
  type: "requested" | "approved" | "denied" | "expired" | "cancelled" | "execution.updated";
  at: string;
  principalId?: string;
  intentHash: string;
  snapshot: ApprovalRequest;
}

export type ProviderConnectionStatus = "active" | "suspended" | "revoked";
export type ProviderResourceStatus = "active" | "removed";

export interface ProviderConnection {
  id: string;
  tenantId: string;
  providerId: string;
  externalAccountId: string;
  displayName: string;
  /** Reference into the deployment secret store; never a provider credential. */
  secretRef: string;
  metadata: Record<string, JsonValue>;
  status: ProviderConnectionStatus;
  createdAt: string;
  updatedAt: string;
}

export interface ProviderConnectionResource {
  tenantId: string;
  connectionId: string;
  providerResourceId: string;
  displayName: string;
  selector: Record<string, JsonValue>;
  status: ProviderResourceStatus;
  createdAt: string;
  updatedAt: string;
}

/** Internal request. tenantId and principalId must come from PrincipalContext. */
export interface MandateRequest {
  tenantId: string;
  principalId: string;
  agentId: string;
  workloadId: string;
  taskId: string;
  audience: string;
  actions: string[];
  resources: string[];
  expiresInSeconds: number;
  constraints?: ConstraintSet;
  approval?: ApprovalEvidence;
  /** Server-owned idempotency link for a separately approved product request. */
  approvalRequestId?: string;
  parentMandateId?: string;
}

/** Public request body. The server supplies tenantId/principalId and approval identity. */
export interface MandateCreationInput {
  agentId: string;
  workloadId: string;
  taskId: string;
  audience: string;
  actions: string[];
  resources: string[];
  expiresInSeconds: number;
  constraints?: ConstraintSet;
  approval?: {
    required: boolean;
    approvedEnvelope?: Omit<ActionEnvelope, "tenantId" | "principalId" | "agentId" | "workloadId" | "taskId">;
  };
  parentMandateId?: string;
}

/** Persisted mandate. Grants are stored as hashes and never returned by repositories. */
export interface Mandate extends MandateRequest {
  id: string;
  grantHash: string;
  issuedAt: string;
  expiresAt: string;
  status: "active" | "revoked";
  successfulUses: number;
}

export interface IssuedMandate {
  mandate: Omit<Mandate, "grantHash">;
  grant: string;
}

/** Internal gateway request after identity resolution. */
export interface ActionRequest {
  grant: string;
  tenantId: string;
  agentId: string;
  workloadId: string;
  taskId: string;
  audience: string;
  action: string;
  resource: string;
  parameters: Record<string, JsonValue>;
  idempotencyKey: string;
}

/** Public execution body. tenantId/agentId/workloadId come from WorkloadContext. */
export type ActionExecutionInput = Omit<ActionRequest, "tenantId" | "agentId" | "workloadId">;

export interface PolicyInput {
  envelope: ActionEnvelope;
  mandate: Mandate;
  now: string;
}

export interface PolicyResult {
  outcome: "allow" | "deny" | "indeterminate";
  reason?: string;
}

export interface Decision {
  allowed: boolean;
  code: ErrorCode;
  decisionId: string;
  mandateId?: string;
  envelopeHash?: string;
  remainingCalls?: number;
}

export type ReceiptOutcome = "pending" | "succeeded" | "failed" | "ambiguous";

export interface ExecutionReceipt {
  id: string;
  tenantId: string;
  mandateId: string;
  decisionId: string;
  principalId: string;
  agentId: string;
  workloadId: string;
  taskId: string;
  audience: string;
  action: string;
  resource: string;
  envelopeVersion: ActionEnvelopeVersion;
  envelopeHash: string;
  idempotencyKey: string;
  outcome: ReceiptOutcome;
  downstreamStatus?: number;
  resultHash?: string;
  previousReceiptHash?: string;
  receiptHash: string;
  attemptCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface AuditEvent {
  id: string;
  tenantId: string;
  at: string;
  type:
    | "mandate.issued"
    | "mandate.revoked"
    | "action.allowed"
    | "action.denied"
    | "execution.succeeded"
    | "execution.failed"
    | "execution.ambiguous";
  mandateId?: string;
  decisionId?: string;
  principalId?: string;
  agentId?: string;
  workloadId?: string;
  taskId?: string;
  audience?: string;
  action?: string;
  resource?: string;
  envelopeHash?: string;
  idempotencyKey?: string;
  code: ErrorCode | "issued" | "revoked" | "executed";
  details?: Record<string, JsonValue>;
}

export interface DownstreamCredential {
  accessToken: string;
  tokenType: "Bearer" | "DPoP";
  audience: string;
  expiresAt: string;
}

export interface DownstreamResult {
  status: number;
  body: JsonValue;
}

export interface ExecuteResult {
  decision: Decision;
  receipt?: ExecutionReceipt;
  /** Redacted downstream response. Credentials are never part of this type. */
  result?: DownstreamResult;
}

export interface ExecutionReservation {
  decision: Decision;
  mandate?: Mandate;
  receipt?: ExecutionReceipt;
  replay: boolean;
}

export interface ExecutionCompletion {
  outcome: Exclude<ReceiptOutcome, "pending">;
  downstreamStatus?: number;
  resultHash?: string;
}
