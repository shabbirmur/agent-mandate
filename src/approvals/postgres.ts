import { randomUUID } from "node:crypto";
import { Pool, type PoolClient, type PoolConfig, type QueryResultRow } from "pg";
import { canonicalHash, toJsonValue } from "../canonical.js";
import type { ApprovalDecisionInput, ApprovalProposalRecord, ApprovalRepository } from "../ports.js";
import {
  ACTION_ENVELOPE_VERSION,
  APPROVAL_INTENT_VERSION,
  type ActionEnvelope,
  type ApprovalEvent,
  type ApprovalExecutionStatus,
  type ApprovalIntent,
  type ApprovalRequest,
  type ApprovalRequestStatus,
  type JsonValue,
} from "../types.js";
import { withPostgresTransaction } from "../storage/pool.js";
import { hashApprovalIntent } from "./canonical.js";

type DatabaseRow = QueryResultRow & Record<string, unknown>;
const APPROVAL_STATUSES = new Set<ApprovalRequestStatus>(["pending", "approved", "denied", "expired", "cancelled"]);
const EXECUTION_STATUSES = new Set<ApprovalExecutionStatus>([
  "not_started", "reserved", "dispatching", "succeeded", "failed", "ambiguous",
]);
const EVENT_TYPES = new Set<ApprovalEvent["type"]>([
  "requested", "approved", "denied", "expired", "cancelled", "execution.updated",
]);

export type PostgresApprovalRepositoryConfiguration = Pool | PoolConfig | string;

export class PostgresApprovalRepository implements ApprovalRepository {
  readonly #pool: Pool;

  constructor(configuration: PostgresApprovalRepositoryConfiguration) {
    this.#pool = typeof configuration === "string"
      ? new Pool({ connectionString: configuration })
      : configuration instanceof Pool
        ? configuration
        : new Pool(configuration);
  }

  async create(input: Parameters<ApprovalRepository["create"]>[0]): Promise<ApprovalProposalRecord> {
    validateCreateInput(input);
    return this.#transaction(async (client) => {
      const result = await client.query<DatabaseRow>(
        `INSERT INTO approval_requests (
           id, tenant_id, expected_principal_id, agent_id, workload_id,
           workflow_id, mcp_session_hash, profile_id, profile_hash, provider_id,
           provider_connection_id, provider_resource_id, envelope_json,
           envelope_hash, intent_version, intent_json, intent_hash,
           resume_handle_hash, idempotency_key, status, execution_status,
           created_at, expires_at
         ) VALUES (
           $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
           $11, $12, $13::jsonb, $14, $15, $16::jsonb, $17,
           $18, $19, 'pending', 'not_started', $20, $21
         ) RETURNING *`,
        [
          input.intent.requestId,
          input.intent.envelope.tenantId,
          input.intent.expectedApprover,
          input.agentId,
          input.workloadId,
          input.workflowId,
          input.mcpSessionHash,
          input.intent.profileId,
          input.intent.profileHash,
          input.intent.providerId,
          input.intent.providerConnectionId,
          input.intent.providerResourceId,
          JSON.stringify(input.intent.envelope),
          input.intent.envelopeHash,
          input.intent.version,
          JSON.stringify(input.intent),
          hashApprovalIntent(input.intent),
          input.resumeHandleHash,
          input.idempotencyKey,
          input.now,
          new Date(input.intent.expiresAt),
        ],
      );
      const request = mapApprovalRequest(first(result.rows, "created approval request"));
      const event = await insertEvent(client, request, "requested", input.now);
      return { request, event };
    });
  }

  async find(tenantId: string, requestId: string): Promise<ApprovalRequest | undefined> {
    requireString(tenantId, "tenantId");
    requireString(requestId, "requestId");
    const result = await this.#pool.query<DatabaseRow>(
      "SELECT * FROM approval_requests WHERE tenant_id = $1 AND id = $2",
      [tenantId, requestId],
    );
    return result.rows[0] === undefined ? undefined : mapApprovalRequest(result.rows[0]);
  }

  async findByResumeHandle(tenantId: string, resumeHandleHash: string): Promise<ApprovalRequest | undefined> {
    requireString(tenantId, "tenantId");
    requireDigest(resumeHandleHash, "resumeHandleHash");
    const result = await this.#pool.query<DatabaseRow>(
      "SELECT * FROM approval_requests WHERE tenant_id = $1 AND resume_handle_hash = $2",
      [tenantId, resumeHandleHash],
    );
    return result.rows[0] === undefined ? undefined : mapApprovalRequest(result.rows[0]);
  }

  async decide(input: ApprovalDecisionInput, now: Date): Promise<ApprovalRequest> {
    validDate(now, "now");
    return this.#transaction(async (client) => {
      const found = await client.query<DatabaseRow>(
        "SELECT * FROM approval_requests WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
        [input.tenantId, input.requestId],
      );
      let request = mapApprovalRequest(first(found.rows, "approval request"));
      if (
        request.expectedPrincipalId !== input.expectedPrincipalId ||
        request.expectedPrincipalId !== input.principalId ||
        request.intentHash !== input.intentHash
      ) throw new Error("approval_mismatch");
      if (request.status !== "pending") {
        if (request.status === input.decision && request.decidedBy === input.principalId) return request;
        throw new Error(`approval_not_pending:${request.status}`);
      }
      if (Date.parse(request.expiresAt) <= now.getTime()) {
        request = await updateDecision(client, request, "expired", now);
        await insertEvent(client, request, "expired", now);
        return request;
      }
      const authenticatedAt = validDate(new Date(input.authenticatedAt), "authenticatedAt");
      if (authenticatedAt.getTime() > now.getTime()) throw new Error("authentication_from_future");
      const result = await client.query<DatabaseRow>(
        `UPDATE approval_requests
         SET status = $3, decided_at = $4, decided_by = $5,
             authenticated_at = $6, decision_reason = $7
         WHERE tenant_id = $1 AND id = $2
         RETURNING *`,
        [input.tenantId, input.requestId, input.decision, now, input.principalId, authenticatedAt, input.reason ?? null],
      );
      request = mapApprovalRequest(first(result.rows, "decided approval request"));
      await insertEvent(client, request, input.decision, now, input.principalId);
      return request;
    });
  }

  async attachMandate(
    tenantId: string,
    requestId: string,
    intentHash: string,
    mandateId: string,
    now: Date,
  ): Promise<ApprovalRequest> {
    validDate(now, "now");
    return this.#transaction(async (client) => {
      const found = await client.query<DatabaseRow>(
        "SELECT * FROM approval_requests WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
        [tenantId, requestId],
      );
      const request = mapApprovalRequest(first(found.rows, "approval request"));
      if (request.status !== "approved" || request.intentHash !== intentHash) throw new Error("approval_mismatch");
      if (request.mandateId !== undefined) {
        if (request.mandateId !== mandateId) throw new Error("approval_mandate_conflict");
        return request;
      }
      const updated = await client.query<DatabaseRow>(
        `UPDATE approval_requests SET mandate_id = $3
         WHERE tenant_id = $1 AND id = $2 RETURNING *`,
        [tenantId, requestId, mandateId],
      );
      const next = mapApprovalRequest(first(updated.rows, "approval request with mandate"));
      await insertEvent(client, next, "execution.updated", now);
      return next;
    });
  }

  async updateExecution(
    tenantId: string,
    requestId: string,
    intentHash: string,
    status: ApprovalExecutionStatus,
    receiptId: string | undefined,
    now: Date,
  ): Promise<ApprovalRequest> {
    if (!EXECUTION_STATUSES.has(status)) throw new Error("invalid_execution_status");
    validDate(now, "now");
    return this.#transaction(async (client) => {
      const found = await client.query<DatabaseRow>(
        "SELECT * FROM approval_requests WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
        [tenantId, requestId],
      );
      const request = mapApprovalRequest(first(found.rows, "approval request"));
      if (request.status !== "approved" || request.intentHash !== intentHash) throw new Error("approval_mismatch");
      if (!validExecutionTransition(request.executionStatus, status)) throw new Error("invalid_execution_transition");
      if (request.receiptId !== undefined && receiptId !== undefined && request.receiptId !== receiptId) {
        throw new Error("approval_receipt_conflict");
      }
      if (request.executionStatus === status && (receiptId === undefined || request.receiptId === receiptId)) return request;
      const updated = await client.query<DatabaseRow>(
        `UPDATE approval_requests
         SET execution_status = $3, receipt_id = COALESCE(receipt_id, $4)
         WHERE tenant_id = $1 AND id = $2 RETURNING *`,
        [tenantId, requestId, status, receiptId ?? null],
      );
      const next = mapApprovalRequest(first(updated.rows, "updated approval execution"));
      await insertEvent(client, next, "execution.updated", now);
      return next;
    });
  }

  async listEvents(tenantId: string, requestId: string): Promise<ApprovalEvent[]> {
    requireString(tenantId, "tenantId");
    requireString(requestId, "requestId");
    const result = await this.#pool.query<DatabaseRow>(
      `SELECT * FROM approval_events
       WHERE tenant_id = $1 AND request_id = $2 ORDER BY sequence ASC`,
      [tenantId, requestId],
    );
    return result.rows.map(mapApprovalEvent);
  }

  async expire(now: Date, limit = 100): Promise<number> {
    validDate(now, "now");
    if (!Number.isInteger(limit) || limit < 1 || limit > 1_000) throw new Error("invalid_expiry_limit");
    return this.#transaction(async (client) => {
      const candidates = await client.query<DatabaseRow>(
        `SELECT * FROM approval_requests
         WHERE status = 'pending' AND expires_at <= $1
         ORDER BY expires_at ASC
         LIMIT $2 FOR UPDATE SKIP LOCKED`,
        [now, limit],
      );
      for (const row of candidates.rows) {
        const current = mapApprovalRequest(row);
        const expired = await updateDecision(client, current, "expired", now);
        await insertEvent(client, expired, "expired", now);
      }
      return candidates.rows.length;
    });
  }

  async readiness(): Promise<boolean> {
    try {
      await this.#pool.query("SELECT 1 FROM approval_requests LIMIT 0");
      return true;
    } catch {
      return false;
    }
  }

  close(): Promise<void> {
    return this.#pool.end();
  }

  #transaction<T>(work: (client: PoolClient) => Promise<T>): Promise<T> {
    return withPostgresTransaction(this.#pool, work);
  }
}

async function updateDecision(
  client: PoolClient,
  request: ApprovalRequest,
  status: "expired" | "cancelled",
  now: Date,
): Promise<ApprovalRequest> {
  const updated = await client.query<DatabaseRow>(
    `UPDATE approval_requests SET status = $3, decision_reason = $4
     WHERE tenant_id = $1 AND id = $2 RETURNING *`,
    [request.tenantId, request.id, status, status],
  );
  validDate(now, "now");
  return mapApprovalRequest(first(updated.rows, `${status} approval request`));
}

async function insertEvent(
  client: PoolClient,
  request: ApprovalRequest,
  type: ApprovalEvent["type"],
  at: Date,
  principalId?: string,
): Promise<ApprovalEvent> {
  const sequenceResult = await client.query<{ sequence: number }>(
    "SELECT COALESCE(MAX(sequence), 0)::integer + 1 AS sequence FROM approval_events WHERE tenant_id = $1 AND request_id = $2",
    [request.tenantId, request.id],
  );
  const sequence = sequenceResult.rows[0]?.sequence;
  if (!Number.isInteger(sequence) || sequence! < 1) throw new Error("invalid_approval_event_sequence");
  const event: ApprovalEvent = {
    id: randomUUID(),
    tenantId: request.tenantId,
    requestId: request.id,
    sequence: sequence!,
    type,
    at: validDate(at, "event.at").toISOString(),
    ...(principalId === undefined ? {} : { principalId }),
    intentHash: request.intentHash,
    snapshot: structuredClone(request),
  };
  await client.query(
    `INSERT INTO approval_events (
       id, tenant_id, request_id, sequence, type, at, principal_id,
       intent_hash, snapshot_json
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)`,
    [
      event.id,
      event.tenantId,
      event.requestId,
      event.sequence,
      event.type,
      event.at,
      event.principalId ?? null,
      event.intentHash,
      JSON.stringify(event.snapshot),
    ],
  );
  return event;
}

function mapApprovalRequest(row: DatabaseRow): ApprovalRequest {
  const status = requiredEnum(row.status, APPROVAL_STATUSES, "approval_requests.status");
  const executionStatus = requiredEnum(row.execution_status, EXECUTION_STATUSES, "approval_requests.execution_status");
  const envelope = parseEnvelope(row.envelope_json);
  const intent = parseIntent(row.intent_json);
  const request: ApprovalRequest = {
    id: requireString(row.id, "approval_requests.id"),
    tenantId: requireString(row.tenant_id, "approval_requests.tenant_id"),
    expectedPrincipalId: requireString(row.expected_principal_id, "approval_requests.expected_principal_id"),
    agentId: requireString(row.agent_id, "approval_requests.agent_id"),
    workloadId: requireString(row.workload_id, "approval_requests.workload_id"),
    workflowId: requireString(row.workflow_id, "approval_requests.workflow_id"),
    mcpSessionHash: requireDigest(row.mcp_session_hash, "approval_requests.mcp_session_hash"),
    profileId: requireString(row.profile_id, "approval_requests.profile_id"),
    profileHash: requireDigest(row.profile_hash, "approval_requests.profile_hash"),
    providerId: requireString(row.provider_id, "approval_requests.provider_id"),
    providerConnectionId: requireString(row.provider_connection_id, "approval_requests.provider_connection_id"),
    providerResourceId: requireString(row.provider_resource_id, "approval_requests.provider_resource_id"),
    envelope,
    envelopeHash: requireDigest(row.envelope_hash, "approval_requests.envelope_hash"),
    intent,
    intentHash: requireDigest(row.intent_hash, "approval_requests.intent_hash"),
    resumeHandleHash: requireDigest(row.resume_handle_hash, "approval_requests.resume_handle_hash"),
    idempotencyKey: requireString(row.idempotency_key, "approval_requests.idempotency_key"),
    status,
    executionStatus,
    createdAt: dateIso(row.created_at, "approval_requests.created_at"),
    expiresAt: dateIso(row.expires_at, "approval_requests.expires_at"),
    ...optionalStringProperty("decidedAt", row.decided_at, true),
    ...optionalStringProperty("decidedBy", row.decided_by),
    ...optionalStringProperty("authenticatedAt", row.authenticated_at, true),
    ...optionalStringProperty("decisionReason", row.decision_reason),
    ...optionalStringProperty("mandateId", row.mandate_id),
    ...optionalStringProperty("receiptId", row.receipt_id),
  };
  if (
    request.envelopeHash !== canonicalHash(request.envelope) ||
    request.intentHash !== hashApprovalIntent(request.intent) ||
    request.intent.requestId !== request.id ||
    request.intent.envelopeHash !== request.envelopeHash
  ) throw new Error("approval_request_integrity_error");
  return request;
}

function mapApprovalEvent(row: DatabaseRow): ApprovalEvent {
  const type = requiredEnum(row.type, EVENT_TYPES, "approval_events.type");
  const snapshot = mapSnapshot(row.snapshot_json);
  const event: ApprovalEvent = {
    id: requireString(row.id, "approval_events.id"),
    tenantId: requireString(row.tenant_id, "approval_events.tenant_id"),
    requestId: requireString(row.request_id, "approval_events.request_id"),
    sequence: requireInteger(row.sequence, "approval_events.sequence"),
    type,
    at: dateIso(row.at, "approval_events.at"),
    ...optionalStringProperty("principalId", row.principal_id),
    intentHash: requireDigest(row.intent_hash, "approval_events.intent_hash"),
    snapshot,
  };
  if (event.snapshot.id !== event.requestId || event.snapshot.tenantId !== event.tenantId || event.snapshot.intentHash !== event.intentHash) {
    throw new Error("approval_event_integrity_error");
  }
  return event;
}

function mapSnapshot(value: unknown): ApprovalRequest {
  const object = jsonObject(value, "approval event snapshot");
  return mapApprovalRequest({
    id: object.id,
    tenant_id: object.tenantId,
    expected_principal_id: object.expectedPrincipalId,
    agent_id: object.agentId,
    workload_id: object.workloadId,
    workflow_id: object.workflowId,
    mcp_session_hash: object.mcpSessionHash,
    profile_id: object.profileId,
    profile_hash: object.profileHash,
    provider_id: object.providerId,
    provider_connection_id: object.providerConnectionId,
    provider_resource_id: object.providerResourceId,
    envelope_json: object.envelope,
    envelope_hash: object.envelopeHash,
    intent_json: object.intent,
    intent_hash: object.intentHash,
    resume_handle_hash: object.resumeHandleHash,
    idempotency_key: object.idempotencyKey,
    status: object.status,
    execution_status: object.executionStatus,
    created_at: object.createdAt,
    expires_at: object.expiresAt,
    decided_at: object.decidedAt,
    decided_by: object.decidedBy,
    authenticated_at: object.authenticatedAt,
    decision_reason: object.decisionReason,
    mandate_id: object.mandateId,
    receipt_id: object.receiptId,
  });
}

function parseEnvelope(value: unknown): ActionEnvelope {
  const object = jsonObject(value, "approval envelope");
  if (object.version !== ACTION_ENVELOPE_VERSION) throw new Error("unsupported_action_envelope");
  const parameters = jsonObject(object.parameters, "approval envelope parameters");
  return {
    version: ACTION_ENVELOPE_VERSION,
    tenantId: requireString(object.tenantId, "envelope.tenantId"),
    principalId: requireString(object.principalId, "envelope.principalId"),
    agentId: requireString(object.agentId, "envelope.agentId"),
    workloadId: requireString(object.workloadId, "envelope.workloadId"),
    taskId: requireString(object.taskId, "envelope.taskId"),
    audience: requireString(object.audience, "envelope.audience"),
    action: requireString(object.action, "envelope.action"),
    resource: requireString(object.resource, "envelope.resource"),
    parameters,
  };
}

function parseIntent(value: unknown): ApprovalIntent {
  const object = jsonObject(value, "approval intent");
  if (object.version !== APPROVAL_INTENT_VERSION) throw new Error("unsupported_approval_intent");
  const risk = requireString(object.risk, "intent.risk");
  if (risk !== "read" && risk !== "write" && risk !== "consequential" && risk !== "prohibited") throw new Error("invalid_intent_risk");
  if (object.maxCalls !== 1 || object.delegationAllowed !== false) throw new Error("invalid_intent_authority");
  return {
    version: APPROVAL_INTENT_VERSION,
    requestId: requireString(object.requestId, "intent.requestId"),
    envelope: parseEnvelope(object.envelope),
    envelopeHash: requireDigest(object.envelopeHash, "intent.envelopeHash"),
    profileId: requireString(object.profileId, "intent.profileId"),
    profileHash: requireDigest(object.profileHash, "intent.profileHash"),
    providerId: requireString(object.providerId, "intent.providerId"),
    providerConnectionId: requireString(object.providerConnectionId, "intent.providerConnectionId"),
    providerResourceId: requireString(object.providerResourceId, "intent.providerResourceId"),
    idempotencyKey: requireString(object.idempotencyKey, "intent.idempotencyKey"),
    risk,
    expiresAt: dateIso(object.expiresAt, "intent.expiresAt"),
    maxCalls: 1,
    delegationAllowed: false,
    expectedApprover: requireString(object.expectedApprover, "intent.expectedApprover"),
  };
}

function validateCreateInput(input: Parameters<ApprovalRepository["create"]>[0]): void {
  const now = validDate(input.now, "now");
  for (const [value, label] of [
    [input.agentId, "agentId"],
    [input.workloadId, "workloadId"],
    [input.workflowId, "workflowId"],
    [input.idempotencyKey, "idempotencyKey"],
  ] as const) requireString(value, label);
  requireDigest(input.mcpSessionHash, "mcpSessionHash");
  requireDigest(input.resumeHandleHash, "resumeHandleHash");
  if (input.intent.envelope.agentId !== input.agentId || input.intent.envelope.workloadId !== input.workloadId || input.intent.envelope.taskId !== input.workflowId) {
    throw new Error("approval_context_mismatch");
  }
  if (input.intent.idempotencyKey !== input.idempotencyKey) throw new Error("approval_idempotency_mismatch");
  if (Date.parse(input.intent.expiresAt) <= now.getTime()) throw new Error("approval_expiry_invalid");
  hashApprovalIntent(input.intent);
}

function validExecutionTransition(from: ApprovalExecutionStatus, to: ApprovalExecutionStatus): boolean {
  if (from === to) return true;
  if (from === "not_started") return to === "reserved" || to === "dispatching" || to === "failed";
  if (from === "reserved") return to === "dispatching" || to === "failed" || to === "ambiguous";
  if (from === "dispatching") return to === "succeeded" || to === "failed" || to === "ambiguous";
  if (from === "ambiguous") return to === "succeeded" || to === "failed";
  return false;
}

function requiredEnum<Value extends string>(value: unknown, allowed: ReadonlySet<Value>, label: string): Value {
  const parsed = requireString(value, label) as Value;
  if (!allowed.has(parsed)) throw new Error(`${label} is invalid`);
  return parsed;
}

function optionalStringProperty<Key extends string>(key: Key, value: unknown, date = false): { [K in Key]?: string } {
  if (value === null || value === undefined) return {};
  const parsed = date ? dateIso(value, key) : requireString(value, key);
  return { [key]: parsed } as { [K in Key]?: string };
}

function jsonObject(value: unknown, label: string): Record<string, JsonValue> {
  let parsed = value;
  if (typeof value === "string") parsed = JSON.parse(value) as unknown;
  let json: JsonValue;
  try {
    json = toJsonValue(parsed);
  } catch (error) {
    throw new Error(`${label} is invalid JSON`, { cause: error });
  }
  if (json === null || Array.isArray(json) || typeof json !== "object") throw new Error(`${label} must be an object`);
  return json;
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${label} must be a non-empty string`);
  return value;
}

function requireDigest(value: unknown, label: string): string {
  const parsed = requireString(value, label);
  if (!/^[A-Za-z0-9_-]{43}$/.test(parsed)) throw new Error(`${label} must be a SHA-256 base64url digest`);
  return parsed;
}

function requireInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) throw new Error(`${label} must be a positive integer`);
  return value;
}

function dateIso(value: unknown, label: string): string {
  const date = value instanceof Date ? value : new Date(requireString(value, label));
  return validDate(date, label).toISOString();
}

function validDate(value: Date, label: string): Date {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw new Error(`${label} must be a valid date`);
  return new Date(value.getTime());
}

function first<Row>(rows: Row[], label: string): Row {
  if (rows[0] === undefined) throw new Error(`${label} was not returned`);
  return rows[0];
}
