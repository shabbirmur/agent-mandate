export type JsonPrimitive = string | number | boolean | null;

export interface ConstraintSet {
  /** Maximum number of successful uses across the grant lifetime. */
  maxCalls?: number;
  /** Exact request fields that must equal these values. */
  equals?: Record<string, JsonPrimitive>;
  /** Numeric request fields that must not exceed these values. */
  maximum?: Record<string, number>;
}

export interface MandateRequest {
  principalId: string;
  agentId: string;
  taskId: string;
  audience: string;
  actions: string[];
  resources: string[];
  expiresInSeconds: number;
  constraints?: ConstraintSet;
  approval?: {
    required: boolean;
    approvedBy?: string;
  };
}

export interface Mandate extends MandateRequest {
  id: string;
  secret: string;
  issuedAt: string;
  expiresAt: string;
  status: "active" | "revoked";
  successfulUses: number;
}

export interface ActionRequest {
  grant: string;
  agentId: string;
  taskId: string;
  audience: string;
  action: string;
  resource: string;
  parameters?: Record<string, JsonPrimitive>;
}

export interface Decision {
  allowed: boolean;
  code: string;
  mandateId?: string;
}

export interface AuditEvent {
  id: string;
  at: string;
  type: "mandate.issued" | "mandate.revoked" | "action.allowed" | "action.denied";
  mandateId?: string;
  agentId?: string;
  taskId?: string;
  action?: string;
  resource?: string;
  code: string;
}
