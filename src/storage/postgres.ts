import { randomUUID } from "node:crypto";
import { Pool, type PoolClient, type PoolConfig, type QueryResultRow } from "pg";
import { canonicalHash } from "../canonical.js";
import type { MandateRepository } from "../ports.js";
import {
  ACTION_ENVELOPE_VERSION,
  ERROR_CODES,
  type ActionEnvelope,
  type ActionRequest,
  type ApprovalEvidence,
  type AuditEvent,
  type ConstraintSet,
  type Decision,
  type ErrorCode,
  type ExecutionCompletion,
  type ExecutionReceipt,
  type ExecutionReservation,
  type JsonPrimitive,
  type JsonValue,
  type Mandate,
  type MandateRequest,
  type ReceiptOutcome,
} from "../types.js";
import { computeReceiptIntegrityHash, isSha256Base64Url, verifyGrantSecret } from "./integrity.js";
import { withPostgresTransaction } from "./pool.js";

const AUDIT_TYPES = new Set<AuditEvent["type"]>([
  "mandate.issued",
  "mandate.revoked",
  "action.allowed",
  "action.denied",
  "execution.succeeded",
  "execution.failed",
  "execution.ambiguous",
]);
const AUDIT_CODES = new Set<AuditEvent["code"]>([...ERROR_CODES, "issued", "revoked", "executed"]);
const RECEIPT_OUTCOMES = new Set<ReceiptOutcome>(["pending", "succeeded", "failed", "ambiguous"]);

type DatabaseRow = QueryResultRow & Record<string, unknown>;

export type PostgresRepositoryConfiguration = Pool | PoolConfig | string;

/** PostgreSQL implementation of the frozen `MandateRepository` contract. */
export class PostgresMandateRepository implements MandateRepository {
  readonly #pool: Pool;

  constructor(configuration: PostgresRepositoryConfiguration) {
    this.#pool =
      typeof configuration === "string"
        ? new Pool({ connectionString: configuration })
        : configuration instanceof Pool
          ? configuration
          : new Pool(configuration);
  }

  async create(request: MandateRequest, grantHash: string, now: Date): Promise<Mandate> {
    validateMandateRequest(request);
    if (!isSha256Base64Url(grantHash)) throw new Error("grantHash must be a base64url-encoded SHA-256 digest");
    const issuedAt = validDate(now, "now");
    const expiresAt = new Date(issuedAt.getTime() + request.expiresInSeconds * 1_000);
    if (!Number.isSafeInteger(expiresAt.getTime())) throw new Error("mandate expiry is outside the supported date range");

    return this.#transaction(async (client) => {
      if (request.approvalRequestId !== undefined) {
        await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [
          JSON.stringify([request.tenantId, request.approvalRequestId]),
        ]);
        const existing = await client.query<DatabaseRow>(
          "SELECT * FROM agent_mandates WHERE tenant_id = $1 AND approval_request_id = $2",
          [request.tenantId, request.approvalRequestId],
        );
        if (existing.rows[0] !== undefined) {
          const mandate = mapMandate(existing.rows[0]);
          assertIdempotentMandate(mandate, request, grantHash);
          return mandate;
        }
      }
      const id = randomUUID();
      if (request.parentMandateId !== undefined) {
        const parentResult = await client.query<DatabaseRow>(
          "SELECT * FROM agent_mandates WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
          [request.tenantId, request.parentMandateId],
        );
        const parentRow = parentResult.rows[0];
        if (parentRow === undefined) throw new Error("delegation_amplification");
        const parent = mapMandate(parentRow);
        const delegatedCalls = requiredInteger(parentRow.delegated_calls, "agent_mandates.delegated_calls");
        const reservedCalls = validateChildAttenuation(parent, delegatedCalls, request, expiresAt, issuedAt);
        if (reservedCalls > 0) {
          await client.query(
            `UPDATE agent_mandates
             SET delegated_calls = delegated_calls + $3
             WHERE tenant_id = $1 AND id = $2`,
            [parent.tenantId, parent.id, reservedCalls],
          );
        }
      }
      const result = await client.query<DatabaseRow>(
        `INSERT INTO agent_mandates (
           id, tenant_id, principal_id, agent_id, workload_id, task_id,
           audience, actions, resources, expires_in_seconds, constraints_json,
           approval_json, parent_mandate_id, approval_request_id, grant_hash, issued_at, expires_at
         ) VALUES (
           $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
           $11::jsonb, $12::jsonb, $13, $14, $15, $16, $17
         )
         RETURNING *`,
        [
          id,
          request.tenantId,
          request.principalId,
          request.agentId,
          request.workloadId,
          request.taskId,
          request.audience,
          request.actions,
          request.resources,
          request.expiresInSeconds,
          request.constraints === undefined ? null : JSON.stringify(request.constraints),
          request.approval === undefined ? null : JSON.stringify(request.approval),
          request.parentMandateId ?? null,
          request.approvalRequestId ?? null,
          grantHash,
          issuedAt,
          expiresAt,
        ],
      );
      const mandate = mapMandate(requireFirstRow(result.rows, "created mandate"));
      await insertAudit(client, {
        id: randomUUID(),
        tenantId: mandate.tenantId,
        at: mandate.issuedAt,
        type: "mandate.issued",
        mandateId: mandate.id,
        principalId: mandate.principalId,
        agentId: mandate.agentId,
        workloadId: mandate.workloadId,
        taskId: mandate.taskId,
        audience: mandate.audience,
        code: "issued",
      });
      return mandate;
    });
  }

  async find(tenantId: string, mandateId: string): Promise<Mandate | undefined> {
    requireNonEmpty(tenantId, "tenantId");
    requireNonEmpty(mandateId, "mandateId");
    const result = await this.#pool.query<DatabaseRow>(
      "SELECT * FROM agent_mandates WHERE tenant_id = $1 AND id = $2",
      [tenantId, mandateId],
    );
    return result.rows[0] === undefined ? undefined : mapMandate(result.rows[0]);
  }

  async revoke(tenantId: string, mandateId: string, now: Date): Promise<boolean> {
    requireNonEmpty(tenantId, "tenantId");
    requireNonEmpty(mandateId, "mandateId");
    const revokedAt = validDate(now, "now");

    return this.#transaction(async (client) => {
      const updated = await client.query<DatabaseRow>(
        `UPDATE agent_mandates
         SET status = 'revoked', revoked_at = $3
         WHERE tenant_id = $1 AND id = $2 AND status = 'active'
         RETURNING *`,
        [tenantId, mandateId, revokedAt],
      );
      const row = updated.rows[0];
      if (row !== undefined) {
        const mandate = mapMandate(row);
        await insertAudit(client, {
          id: randomUUID(),
          tenantId,
          at: revokedAt.toISOString(),
          type: "mandate.revoked",
          mandateId,
          principalId: mandate.principalId,
          agentId: mandate.agentId,
          workloadId: mandate.workloadId,
          taskId: mandate.taskId,
          audience: mandate.audience,
          code: "revoked",
        });
        return true;
      }

      const existing = await client.query("SELECT 1 FROM agent_mandates WHERE tenant_id = $1 AND id = $2", [tenantId, mandateId]);
      return existing.rowCount !== 0;
    });
  }

  async findReceipt(tenantId: string, mandateId: string, idempotencyKey: string): Promise<ExecutionReceipt | undefined> {
    requireNonEmpty(tenantId, "tenantId");
    requireNonEmpty(mandateId, "mandateId");
    requireNonEmpty(idempotencyKey, "idempotencyKey");
    const result = await this.#pool.query<DatabaseRow>(
      `SELECT * FROM execution_receipts
       WHERE tenant_id = $1 AND mandate_id = $2 AND idempotency_key = $3`,
      [tenantId, mandateId, idempotencyKey],
    );
    return result.rows[0] === undefined ? undefined : mapReceipt(result.rows[0]);
  }

  async reserve(
    request: ActionRequest,
    envelope: ActionEnvelope,
    envelopeHash: string,
    decisionId: string,
    now: Date,
  ): Promise<ExecutionReservation> {
    validateReservationInput(request, envelopeHash, decisionId);
    const at = validDate(now, "now");
    const parsedGrant = parseGrant(request.grant);

    return this.#transaction(async (client) => {
      const mandateResult =
        parsedGrant === undefined
          ? undefined
          : await client.query<DatabaseRow>(
              "SELECT * FROM agent_mandates WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
              [request.tenantId, parsedGrant.mandateId],
            );
      const row = mandateResult?.rows[0];
      const mandate = row === undefined ? undefined : mapMandate(row);
      const delegatedCalls = row === undefined ? 0 : requiredInteger(row.delegated_calls, "agent_mandates.delegated_calls");
      const deny = async (code: ErrorCode): Promise<ExecutionReservation> => {
        const decision: Decision = {
          allowed: false,
          code,
          decisionId,
          ...(mandate === undefined ? {} : { mandateId: mandate.id }),
          ...(isSha256Base64Url(envelopeHash) ? { envelopeHash } : {}),
        };
        await insertActionAudit(client, request, at, decision, mandate);
        return { decision, replay: false };
      };

      if (mandate === undefined || parsedGrant === undefined || !verifyGrantSecret(parsedGrant.secret, mandate.grantHash)) {
        return deny("invalid_grant");
      }
      if (!envelopeMatchesRequest(envelope, request, mandate.principalId)) return deny("invalid_request");

      const existingResult = await client.query<DatabaseRow>(
        `SELECT * FROM execution_receipts
         WHERE tenant_id = $1 AND mandate_id = $2 AND idempotency_key = $3`,
        [request.tenantId, mandate.id, request.idempotencyKey],
      );
      const existingRow = existingResult.rows[0];
      if (existingRow !== undefined) {
        const existing = mapReceipt(existingRow);
        if (existing.envelopeHash !== envelopeHash) return deny("idempotency_conflict");
        const decision: Decision = {
          allowed: true,
          code: "allowed",
          decisionId: existing.decisionId,
          mandateId: mandate.id,
          envelopeHash,
          ...remainingCalls(mandate, delegatedCalls),
        };
        return { decision, mandate, receipt: existing, replay: true };
      }

      if (mandate.approvalRequestId !== undefined) {
        const approvalResult = await client.query<DatabaseRow>(
          `SELECT approval.*, connection.status AS connection_status,
                  resource.status AS resource_status
           FROM approval_requests AS approval
           JOIN provider_connections AS connection
             ON connection.tenant_id = approval.tenant_id
            AND connection.id = approval.provider_connection_id
           JOIN provider_connection_resources AS resource
             ON resource.tenant_id = approval.tenant_id
            AND resource.connection_id = approval.provider_connection_id
            AND resource.provider_resource_id = approval.provider_resource_id
           WHERE approval.tenant_id = $1 AND approval.id = $2
           FOR SHARE OF approval, connection, resource`,
          [mandate.tenantId, mandate.approvalRequestId],
        );
        const approvalCode = productApprovalCode(approvalResult.rows[0], mandate, request, envelopeHash, at);
        if (approvalCode !== "allowed") return deny(approvalCode);
      }

      if (mandate.status !== "active") return deny("revoked");
      if (at.getTime() >= Date.parse(mandate.expiresAt)) return deny("expired");
      if (mandate.agentId !== request.agentId) return deny("agent_mismatch");
      if (mandate.workloadId !== request.workloadId) return deny("workload_mismatch");
      if (mandate.taskId !== request.taskId) return deny("task_mismatch");
      if (mandate.audience !== request.audience) return deny("audience_mismatch");
      if (!mandate.actions.includes(request.action)) return deny("action_not_granted");
      if (!mandate.resources.includes(request.resource)) return deny("resource_not_granted");
      if (mandate.approval?.required && mandate.approval.envelopeHash !== envelopeHash) return deny("approval_mismatch");
      if (!parametersSatisfy(request.parameters, mandate.constraints)) return deny("parameter_mismatch");
      if (
        mandate.constraints?.maxCalls !== undefined &&
        mandate.successfulUses + delegatedCalls >= mandate.constraints.maxCalls
      ) {
        return deny("call_limit_exceeded");
      }

      const usesResult = await client.query<DatabaseRow>(
        `UPDATE agent_mandates
         SET successful_uses = successful_uses + 1
         WHERE tenant_id = $1 AND id = $2
         RETURNING *`,
        [mandate.tenantId, mandate.id],
      );
      const reservedMandate = mapMandate(requireFirstRow(usesResult.rows, "reserved mandate"));

      await client.query(
        `INSERT INTO receipt_chain_heads (tenant_id)
         VALUES ($1)
         ON CONFLICT (tenant_id) DO NOTHING`,
        [mandate.tenantId],
      );
      const headResult = await client.query<DatabaseRow>(
        "SELECT chain_sequence, receipt_hash FROM receipt_chain_heads WHERE tenant_id = $1 FOR UPDATE",
        [mandate.tenantId],
      );
      const head = requireFirstRow(headResult.rows, "receipt chain head");
      const previousReceiptHash = nullableSha256(head.receipt_hash, "receipt_chain_heads.receipt_hash");
      const chainSequence = requiredBigintAsSafeInteger(head.chain_sequence, "receipt_chain_heads.chain_sequence") + 1;
      const createdAt = at.toISOString();
      const receiptState = {
        id: randomUUID(),
        tenantId: mandate.tenantId,
        mandateId: mandate.id,
        decisionId,
        principalId: mandate.principalId,
        agentId: request.agentId,
        workloadId: request.workloadId,
        taskId: request.taskId,
        audience: request.audience,
        action: request.action,
        resource: request.resource,
        envelopeVersion: ACTION_ENVELOPE_VERSION,
        envelopeHash,
        idempotencyKey: request.idempotencyKey,
        outcome: "pending" as const,
        ...(previousReceiptHash === undefined ? {} : { previousReceiptHash }),
        attemptCount: 1,
        createdAt,
        updatedAt: createdAt,
      };
      const receipt: ExecutionReceipt = {
        ...receiptState,
        receiptHash: computeReceiptIntegrityHash(receiptState),
      };

      await client.query(
        `INSERT INTO execution_receipts (
           id, tenant_id, mandate_id, decision_id, principal_id, agent_id,
           workload_id, task_id, audience, action, resource, envelope_version,
           envelope_hash, idempotency_key, outcome, previous_receipt_hash,
           receipt_hash, integrity_sequence, attempt_count, created_at, updated_at
         ) VALUES (
           $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
           $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
         )`,
        [
          receipt.id,
          receipt.tenantId,
          receipt.mandateId,
          receipt.decisionId,
          receipt.principalId,
          receipt.agentId,
          receipt.workloadId,
          receipt.taskId,
          receipt.audience,
          receipt.action,
          receipt.resource,
          receipt.envelopeVersion,
          receipt.envelopeHash,
          receipt.idempotencyKey,
          receipt.outcome,
          receipt.previousReceiptHash ?? null,
          receipt.receiptHash,
          1,
          receipt.attemptCount,
          at,
          at,
        ],
      );
      await insertIntegrityEvent(client, receipt, chainSequence, 1, at);
      await client.query(
        `UPDATE receipt_chain_heads
         SET chain_sequence = $2, receipt_id = $3, receipt_hash = $4
         WHERE tenant_id = $1`,
        [receipt.tenantId, chainSequence, receipt.id, receipt.receiptHash],
      );

      const decision: Decision = {
        allowed: true,
        code: "allowed",
        decisionId,
        mandateId: mandate.id,
        envelopeHash,
        ...remainingCalls(reservedMandate, delegatedCalls),
      };
      await insertActionAudit(client, request, at, decision, reservedMandate);
      return { decision, mandate: reservedMandate, receipt, replay: false };
    });
  }

  async complete(
    tenantId: string,
    receiptId: string,
    completion: ExecutionCompletion,
    now: Date,
  ): Promise<ExecutionReceipt> {
    requireNonEmpty(tenantId, "tenantId");
    requireNonEmpty(receiptId, "receiptId");
    validateCompletion(completion);
    const updatedAt = validDate(now, "now");

    return this.#transaction(async (client) => {
      const found = await client.query<DatabaseRow>(
        "SELECT * FROM execution_receipts WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
        [tenantId, receiptId],
      );
      const row = found.rows[0];
      if (row === undefined) throw new Error("receipt_not_found");
      const current = mapReceipt(row);
      if (completionMatches(current, completion)) return current;
      if (current.outcome !== "pending" && current.outcome !== "ambiguous") {
        throw new Error("receipt_already_completed");
      }
      if (updatedAt.getTime() < Date.parse(current.createdAt)) throw new Error("completion time precedes receipt creation");

      const attemptCount = current.attemptCount + (current.outcome === "ambiguous" ? 1 : 0);
      await client.query(
        `INSERT INTO receipt_chain_heads (tenant_id)
         VALUES ($1)
         ON CONFLICT (tenant_id) DO NOTHING`,
        [tenantId],
      );
      const headResult = await client.query<DatabaseRow>(
        "SELECT chain_sequence, receipt_hash FROM receipt_chain_heads WHERE tenant_id = $1 FOR UPDATE",
        [tenantId],
      );
      const head = requireFirstRow(headResult.rows, "receipt chain head");
      const previousReceiptHash = nullableSha256(head.receipt_hash, "receipt_chain_heads.receipt_hash");
      const chainSequence = requiredBigintAsSafeInteger(head.chain_sequence, "receipt_chain_heads.chain_sequence") + 1;
      const receiptSequence = requiredInteger(row.integrity_sequence, "execution_receipts.integrity_sequence") + 1;
      const {
        receiptHash: _oldReceiptHash,
        previousReceiptHash: _oldPreviousReceiptHash,
        downstreamStatus: _oldDownstreamStatus,
        resultHash: _oldResultHash,
        ...stableReceipt
      } = current;
      const receiptState = {
        ...stableReceipt,
        outcome: completion.outcome,
        ...(completion.downstreamStatus === undefined ? {} : { downstreamStatus: completion.downstreamStatus }),
        ...(completion.resultHash === undefined ? {} : { resultHash: completion.resultHash }),
        ...(previousReceiptHash === undefined ? {} : { previousReceiptHash }),
        attemptCount,
        updatedAt: updatedAt.toISOString(),
      };
      const nextReceipt: ExecutionReceipt = {
        ...receiptState,
        receiptHash: computeReceiptIntegrityHash(receiptState),
      };
      const changed = await client.query<DatabaseRow>(
        `UPDATE execution_receipts
         SET outcome = $3,
             downstream_status = $4,
             result_hash = $5,
             previous_receipt_hash = $6,
             receipt_hash = $7,
             integrity_sequence = $8,
             attempt_count = $9,
             updated_at = $10
         WHERE tenant_id = $1 AND id = $2
         RETURNING *`,
        [
          tenantId,
          receiptId,
          completion.outcome,
          completion.downstreamStatus ?? null,
          completion.resultHash ?? null,
          nextReceipt.previousReceiptHash ?? null,
          nextReceipt.receiptHash,
          receiptSequence,
          attemptCount,
          updatedAt,
        ],
      );
      const receipt = mapReceipt(requireFirstRow(changed.rows, "completed receipt"));
      await insertIntegrityEvent(client, receipt, chainSequence, receiptSequence, updatedAt);
      await client.query(
        `UPDATE receipt_chain_heads
         SET chain_sequence = $2, receipt_id = $3, receipt_hash = $4
         WHERE tenant_id = $1`,
        [tenantId, chainSequence, receipt.id, receipt.receiptHash],
      );
      await insertAudit(client, completionAudit(receipt));
      return receipt;
    });
  }

  async appendAudit(event: AuditEvent): Promise<void> {
    validateAuditEvent(event);
    await this.#transaction(async (client) => insertAudit(client, event));
  }

  async listAudit(tenantId: string, limit = 100): Promise<AuditEvent[]> {
    requireNonEmpty(tenantId, "tenantId");
    if (!Number.isInteger(limit) || limit < 1 || limit > 1_000) throw new Error("audit limit must be an integer from 1 to 1000");
    const result = await this.#pool.query<DatabaseRow>(
      `SELECT * FROM audit_events
       WHERE tenant_id = $1
       ORDER BY at DESC, id DESC
       LIMIT $2`,
      [tenantId, limit],
    );
    return result.rows.map(mapAudit);
  }

  /** Verify every immutable event and ensure each current receipt projection matches its latest event. */
  async verifyReceiptChain(tenantId: string): Promise<boolean> {
    requireNonEmpty(tenantId, "tenantId");
    try {
      const eventsResult = await this.#pool.query<DatabaseRow>(
        `SELECT * FROM receipt_integrity_events
         WHERE tenant_id = $1
         ORDER BY chain_sequence ASC`,
        [tenantId],
      );
      let previousHash: string | undefined;
      let expectedChainSequence = 1;
      const latest = new Map<string, { receipt: ExecutionReceipt; receiptSequence: number }>();
      for (const eventRow of eventsResult.rows) {
        const chainSequence = requiredBigintAsSafeInteger(eventRow.chain_sequence, "receipt_integrity_events.chain_sequence");
        if (chainSequence !== expectedChainSequence) return false;
        const eventPreviousHash = nullableSha256(eventRow.previous_event_hash, "receipt_integrity_events.previous_event_hash");
        if (eventPreviousHash !== previousHash) return false;
        const eventHash = requiredSha256(eventRow.event_hash, "receipt_integrity_events.event_hash");
        const snapshot = mapReceiptSnapshot(eventRow.snapshot_json);
        if (snapshot.tenantId !== tenantId || snapshot.id !== eventRow.receipt_id) return false;
        if (snapshot.previousReceiptHash !== eventPreviousHash || snapshot.receiptHash !== eventHash) return false;
        if (computeReceiptIntegrityHash(snapshot) !== eventHash) return false;
        const receiptSequence = requiredInteger(eventRow.receipt_sequence, "receipt_integrity_events.receipt_sequence");
        const prior = latest.get(snapshot.id);
        if (receiptSequence !== (prior?.receiptSequence ?? 0) + 1) return false;
        latest.set(snapshot.id, { receipt: snapshot, receiptSequence });
        previousHash = eventHash;
        expectedChainSequence += 1;
      }

      const projections = await this.#pool.query<DatabaseRow>(
        "SELECT * FROM execution_receipts WHERE tenant_id = $1",
        [tenantId],
      );
      if (projections.rows.length !== latest.size) return false;
      for (const projectionRow of projections.rows) {
        const projection = mapReceipt(projectionRow);
        const expected = latest.get(projection.id);
        if (expected === undefined) return false;
        if (requiredInteger(projectionRow.integrity_sequence, "execution_receipts.integrity_sequence") !== expected.receiptSequence) {
          return false;
        }
        if (!jsonEquals(toJsonValue(projection, "receipt projection"), toJsonValue(expected.receipt, "receipt event"))) return false;
      }

      const headResult = await this.#pool.query<DatabaseRow>(
        "SELECT chain_sequence, receipt_hash FROM receipt_chain_heads WHERE tenant_id = $1",
        [tenantId],
      );
      const head = headResult.rows[0];
      if (head === undefined) return eventsResult.rows.length === 0;
      return (
        requiredBigintAsSafeInteger(head.chain_sequence, "receipt_chain_heads.chain_sequence") === eventsResult.rows.length &&
        nullableSha256(head.receipt_hash, "receipt_chain_heads.receipt_hash") === previousHash
      );
    } catch {
      return false;
    }
  }

  async readiness(): Promise<boolean> {
    try {
      await this.#pool.query("SELECT 1 FROM agent_mandates LIMIT 0");
      return true;
    } catch {
      return false;
    }
  }

  async close(): Promise<void> {
    await this.#pool.end();
  }

  async #transaction<T>(work: (client: PoolClient) => Promise<T>): Promise<T> {
    return withPostgresTransaction(this.#pool, work);
  }
}

function productApprovalCode(
  row: DatabaseRow | undefined,
  mandate: Mandate,
  request: ActionRequest,
  envelopeHash: string,
  now: Date,
): "allowed" | ErrorCode {
  const evidence = mandate.approval;
  if (row === undefined || evidence === undefined || evidence.required !== true) return "approval_mismatch";
  if (requiredString(row.status, "approval_requests.status") !== "approved") return "approval_mismatch";
  if (now.getTime() >= Date.parse(dateIso(row.expires_at, "approval_requests.expires_at"))) return "expired";
  if (
    requiredString(row.connection_status, "provider_connections.status") !== "active" ||
    requiredString(row.resource_status, "provider_connection_resources.status") !== "active"
  ) return "revoked";
  const intent = parseJsonObject(row.intent_json, "approval_requests.intent_json");
  const matches =
    requiredString(row.id, "approval_requests.id") === mandate.approvalRequestId &&
    optionalString(row.mandate_id, "approval_requests.mandate_id") === mandate.id &&
    requiredString(row.tenant_id, "approval_requests.tenant_id") === mandate.tenantId &&
    requiredString(row.expected_principal_id, "approval_requests.expected_principal_id") === mandate.principalId &&
    requiredString(row.agent_id, "approval_requests.agent_id") === mandate.agentId &&
    requiredString(row.workload_id, "approval_requests.workload_id") === mandate.workloadId &&
    requiredString(row.workflow_id, "approval_requests.workflow_id") === mandate.taskId &&
    requiredSha256(row.envelope_hash, "approval_requests.envelope_hash") === envelopeHash &&
    requiredSha256(row.intent_hash, "approval_requests.intent_hash") === evidence.intentHash &&
    intent !== undefined && canonicalHash(intent) === evidence.intentHash &&
    requiredString(row.idempotency_key, "approval_requests.idempotency_key") === request.idempotencyKey &&
    requiredString(row.profile_id, "approval_requests.profile_id") === evidence.profileId &&
    requiredSha256(row.profile_hash, "approval_requests.profile_hash") === evidence.profileHash &&
    requiredString(row.provider_id, "approval_requests.provider_id") === evidence.providerId &&
    requiredString(row.provider_connection_id, "approval_requests.provider_connection_id") === evidence.providerConnectionId &&
    requiredString(row.provider_resource_id, "approval_requests.provider_resource_id") === evidence.providerResourceId &&
    evidence.approvalRequestId === mandate.approvalRequestId &&
    evidence.envelopeHash === envelopeHash &&
    evidence.approvedBy === mandate.principalId;
  return matches ? "allowed" : "approval_mismatch";
}

function parseGrant(grant: string): { mandateId: string; secret: string } | undefined {
  const separator = grant.indexOf(".");
  if (separator <= 0 || separator !== grant.lastIndexOf(".") || separator === grant.length - 1) return undefined;
  return { mandateId: grant.slice(0, separator), secret: grant.slice(separator + 1) };
}

function validateMandateRequest(request: MandateRequest): void {
  requireNonEmpty(request.tenantId, "tenantId");
  requireNonEmpty(request.principalId, "principalId");
  requireNonEmpty(request.agentId, "agentId");
  requireNonEmpty(request.workloadId, "workloadId");
  requireNonEmpty(request.taskId, "taskId");
  requireNonEmpty(request.audience, "audience");
  requireStringArray(request.actions, "actions");
  requireStringArray(request.resources, "resources");
  if (!Number.isInteger(request.expiresInSeconds) || request.expiresInSeconds < 1) {
    throw new Error("expiresInSeconds must be a positive integer");
  }
  if (request.constraints !== undefined) validateConstraints(request.constraints, "constraints");
  if (request.approval !== undefined) validateApproval(request.approval, "approval");
  if (request.approvalRequestId !== undefined) requireNonEmpty(request.approvalRequestId, "approvalRequestId");
  if (request.approvalRequestId !== undefined && request.approval?.approvalRequestId !== request.approvalRequestId) {
    throw new Error("approvalRequestId must match approval evidence");
  }
  if (request.parentMandateId !== undefined) requireNonEmpty(request.parentMandateId, "parentMandateId");
}

function assertIdempotentMandate(mandate: Mandate, request: MandateRequest, grantHash: string): void {
  const same =
    mandate.grantHash === grantHash &&
    mandate.tenantId === request.tenantId &&
    mandate.principalId === request.principalId &&
    mandate.agentId === request.agentId &&
    mandate.workloadId === request.workloadId &&
    mandate.taskId === request.taskId &&
    mandate.audience === request.audience &&
    (request.approvalRequestId !== undefined || mandate.expiresInSeconds === request.expiresInSeconds) &&
    mandate.parentMandateId === request.parentMandateId &&
    mandate.approvalRequestId === request.approvalRequestId &&
    jsonEquals(toJsonValue(mandate.actions, "mandate.actions"), toJsonValue(request.actions, "request.actions")) &&
    jsonEquals(toJsonValue(mandate.resources, "mandate.resources"), toJsonValue(request.resources, "request.resources")) &&
    jsonEquals(toJsonValue(mandate.constraints ?? null, "mandate.constraints"), toJsonValue(request.constraints ?? null, "request.constraints")) &&
    jsonEquals(toJsonValue(mandate.approval ?? null, "mandate.approval"), toJsonValue(request.approval ?? null, "request.approval"));
  if (!same) throw new Error("approval_request_mandate_conflict");
}

function validateReservationInput(request: ActionRequest, envelopeHash: string, decisionId: string): void {
  requireNonEmpty(request.grant, "grant");
  requireNonEmpty(request.tenantId, "tenantId");
  requireNonEmpty(request.agentId, "agentId");
  requireNonEmpty(request.workloadId, "workloadId");
  requireNonEmpty(request.taskId, "taskId");
  requireNonEmpty(request.audience, "audience");
  requireNonEmpty(request.action, "action");
  requireNonEmpty(request.resource, "resource");
  requireNonEmpty(request.idempotencyKey, "idempotencyKey");
  requireNonEmpty(decisionId, "decisionId");
  if (!isSha256Base64Url(envelopeHash)) throw new Error("envelopeHash must be a base64url-encoded SHA-256 digest");
  toJsonObject(request.parameters, "parameters");
}

function validateCompletion(completion: ExecutionCompletion): void {
  const outcome: string = completion.outcome;
  if (!RECEIPT_OUTCOMES.has(outcome as ReceiptOutcome) || outcome === "pending") {
    throw new Error("completion outcome must be succeeded, failed, or ambiguous");
  }
  if (
    completion.downstreamStatus !== undefined &&
    (!Number.isInteger(completion.downstreamStatus) || completion.downstreamStatus < 100 || completion.downstreamStatus > 599)
  ) {
    throw new Error("downstreamStatus must be an HTTP status from 100 to 599");
  }
  if (completion.resultHash !== undefined && !isSha256Base64Url(completion.resultHash)) {
    throw new Error("resultHash must be a base64url-encoded SHA-256 digest");
  }
}

function validateAuditEvent(event: AuditEvent): void {
  requireNonEmpty(event.id, "audit.id");
  requireNonEmpty(event.tenantId, "audit.tenantId");
  validDate(new Date(event.at), "audit.at");
  if (!AUDIT_TYPES.has(event.type)) throw new Error(`invalid audit type: ${event.type}`);
  if (!AUDIT_CODES.has(event.code)) throw new Error(`invalid audit code: ${event.code}`);
  for (const [label, value] of Object.entries({
    mandateId: event.mandateId,
    decisionId: event.decisionId,
    principalId: event.principalId,
    agentId: event.agentId,
    workloadId: event.workloadId,
    taskId: event.taskId,
    audience: event.audience,
    action: event.action,
    resource: event.resource,
    idempotencyKey: event.idempotencyKey,
  })) {
    if (value !== undefined) requireNonEmpty(value, `audit.${label}`);
  }
  if (event.envelopeHash !== undefined && !isSha256Base64Url(event.envelopeHash)) {
    throw new Error("audit.envelopeHash must be a base64url-encoded SHA-256 digest");
  }
  if (event.details !== undefined) toJsonObject(event.details, "audit.details");
}

function envelopeMatchesRequest(envelope: ActionEnvelope, request: ActionRequest, principalId: string): boolean {
  try {
    return (
      envelope.version === ACTION_ENVELOPE_VERSION &&
      envelope.tenantId === request.tenantId &&
      envelope.principalId === principalId &&
      envelope.agentId === request.agentId &&
      envelope.workloadId === request.workloadId &&
      envelope.taskId === request.taskId &&
      envelope.audience === request.audience &&
      envelope.action === request.action &&
      envelope.resource === request.resource &&
      jsonEquals(toJsonObject(envelope.parameters, "envelope.parameters"), toJsonObject(request.parameters, "request.parameters"))
    );
  } catch {
    return false;
  }
}

function parametersSatisfy(parameters: Record<string, JsonValue>, constraints: ConstraintSet | undefined): boolean {
  if (constraints === undefined) return true;
  for (const [key, expected] of Object.entries(constraints.equals ?? {})) {
    if (!jsonEquals(parameters[key], expected)) return false;
  }
  for (const [key, maximum] of Object.entries(constraints.maximum ?? {})) {
    const actual = parameters[key];
    if (typeof actual !== "number" || !Number.isFinite(actual) || actual > maximum) return false;
  }
  return true;
}

function remainingCalls(mandate: Mandate, delegatedCalls = 0): Pick<Decision, "remainingCalls"> | Record<string, never> {
  const maximum = mandate.constraints?.maxCalls;
  return maximum === undefined ? {} : { remainingCalls: Math.max(0, maximum - mandate.successfulUses - delegatedCalls) };
}

function validateChildAttenuation(
  parent: Mandate,
  parentDelegatedCalls: number,
  child: MandateRequest,
  childExpiresAt: Date,
  now: Date,
): number {
  const fail = (): never => {
    throw new Error("delegation_amplification");
  };
  if (parent.status !== "active" || now.getTime() >= Date.parse(parent.expiresAt)) fail();
  if (childExpiresAt.getTime() > Date.parse(parent.expiresAt)) fail();
  if (
    child.principalId !== parent.principalId ||
    child.agentId !== parent.agentId ||
    child.workloadId !== parent.workloadId ||
    child.taskId !== parent.taskId ||
    child.audience !== parent.audience
  ) {
    fail();
  }
  if (!child.actions.every((action) => parent.actions.includes(action))) fail();
  if (!child.resources.every((resource) => parent.resources.includes(resource))) fail();

  for (const [key, expected] of Object.entries(parent.constraints?.equals ?? {})) {
    if (!jsonEquals(child.constraints?.equals?.[key], expected)) fail();
  }
  for (const [key, parentMaximum] of Object.entries(parent.constraints?.maximum ?? {})) {
    const childExact = child.constraints?.equals?.[key];
    if (typeof childExact === "number" && Number.isFinite(childExact) && childExact <= parentMaximum) continue;
    const childMaximum = child.constraints?.maximum?.[key];
    if (childMaximum === undefined || childMaximum > parentMaximum) fail();
  }

  const parentMaxCalls = parent.constraints?.maxCalls;
  const childMaxCalls = child.constraints?.maxCalls;
  if (parentMaxCalls === undefined) return 0;
  if (childMaxCalls === undefined) return fail();
  if (parent.successfulUses + parentDelegatedCalls + childMaxCalls > parentMaxCalls) fail();
  return childMaxCalls;
}

function completionMatches(receipt: ExecutionReceipt, completion: ExecutionCompletion): boolean {
  return (
    receipt.outcome === completion.outcome &&
    receipt.downstreamStatus === completion.downstreamStatus &&
    receipt.resultHash === completion.resultHash
  );
}

function completionAudit(receipt: ExecutionReceipt): AuditEvent {
  const outcomeFields =
    receipt.outcome === "succeeded"
      ? ({ type: "execution.succeeded", code: "executed" } as const)
      : receipt.outcome === "failed"
        ? ({ type: "execution.failed", code: "downstream_failed" } as const)
        : ({ type: "execution.ambiguous", code: "downstream_ambiguous" } as const);
  return {
    id: randomUUID(),
    tenantId: receipt.tenantId,
    at: receipt.updatedAt,
    ...outcomeFields,
    mandateId: receipt.mandateId,
    decisionId: receipt.decisionId,
    principalId: receipt.principalId,
    agentId: receipt.agentId,
    workloadId: receipt.workloadId,
    taskId: receipt.taskId,
    audience: receipt.audience,
    action: receipt.action,
    resource: receipt.resource,
    envelopeHash: receipt.envelopeHash,
    idempotencyKey: receipt.idempotencyKey,
    details: {
      attemptCount: receipt.attemptCount,
      ...(receipt.downstreamStatus === undefined ? {} : { downstreamStatus: receipt.downstreamStatus }),
      ...(receipt.resultHash === undefined ? {} : { resultHash: receipt.resultHash }),
    },
  };
}

async function insertActionAudit(
  client: PoolClient,
  request: ActionRequest,
  at: Date,
  decision: Decision,
  mandate: Mandate | undefined,
): Promise<void> {
  await insertAudit(client, {
    id: randomUUID(),
    tenantId: request.tenantId,
    at: at.toISOString(),
    type: decision.allowed ? "action.allowed" : "action.denied",
    ...(decision.mandateId === undefined ? {} : { mandateId: decision.mandateId }),
    decisionId: decision.decisionId,
    ...(mandate === undefined ? {} : { principalId: mandate.principalId }),
    agentId: request.agentId,
    workloadId: request.workloadId,
    taskId: request.taskId,
    audience: request.audience,
    action: request.action,
    resource: request.resource,
    ...(decision.envelopeHash === undefined ? {} : { envelopeHash: decision.envelopeHash }),
    idempotencyKey: request.idempotencyKey,
    code: decision.code,
  });
}

async function insertIntegrityEvent(
  client: PoolClient,
  receipt: ExecutionReceipt,
  chainSequence: number,
  receiptSequence: number,
  createdAt: Date,
): Promise<void> {
  toJsonObject(receipt, "receipt integrity snapshot");
  await client.query(
    `INSERT INTO receipt_integrity_events (
       id, tenant_id, receipt_id, chain_sequence, receipt_sequence,
       previous_event_hash, event_hash, snapshot_json, created_at
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9)`,
    [
      randomUUID(),
      receipt.tenantId,
      receipt.id,
      chainSequence,
      receiptSequence,
      receipt.previousReceiptHash ?? null,
      receipt.receiptHash,
      JSON.stringify(receipt),
      createdAt,
    ],
  );
}

async function insertAudit(client: PoolClient, event: AuditEvent): Promise<void> {
  await client.query(
    `INSERT INTO audit_events (
       id, tenant_id, at, type, mandate_id, decision_id, principal_id,
       agent_id, workload_id, task_id, audience, action, resource,
       envelope_hash, idempotency_key, code, details
     ) VALUES (
       $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
       $11, $12, $13, $14, $15, $16, $17::jsonb
     )`,
    [
      event.id,
      event.tenantId,
      event.at,
      event.type,
      event.mandateId ?? null,
      event.decisionId ?? null,
      event.principalId ?? null,
      event.agentId ?? null,
      event.workloadId ?? null,
      event.taskId ?? null,
      event.audience ?? null,
      event.action ?? null,
      event.resource ?? null,
      event.envelopeHash ?? null,
      event.idempotencyKey ?? null,
      event.code,
      event.details === undefined ? null : JSON.stringify(event.details),
    ],
  );
}

function mapMandate(row: DatabaseRow): Mandate {
  const status = requiredString(row.status, "agent_mandates.status");
  if (status !== "active" && status !== "revoked") throw new Error(`invalid agent_mandates.status: ${status}`);
  const constraints = parseConstraints(row.constraints_json, "agent_mandates.constraints_json");
  const approval = parseApproval(row.approval_json, "agent_mandates.approval_json");
  const parentMandateId = optionalString(row.parent_mandate_id, "agent_mandates.parent_mandate_id");
  const approvalRequestId = optionalString(row.approval_request_id, "agent_mandates.approval_request_id");
  return {
    id: requiredString(row.id, "agent_mandates.id"),
    tenantId: requiredString(row.tenant_id, "agent_mandates.tenant_id"),
    principalId: requiredString(row.principal_id, "agent_mandates.principal_id"),
    agentId: requiredString(row.agent_id, "agent_mandates.agent_id"),
    workloadId: requiredString(row.workload_id, "agent_mandates.workload_id"),
    taskId: requiredString(row.task_id, "agent_mandates.task_id"),
    audience: requiredString(row.audience, "agent_mandates.audience"),
    actions: mapStringArray(row.actions, "agent_mandates.actions"),
    resources: mapStringArray(row.resources, "agent_mandates.resources"),
    expiresInSeconds: requiredInteger(row.expires_in_seconds, "agent_mandates.expires_in_seconds"),
    ...(constraints === undefined ? {} : { constraints }),
    ...(approval === undefined ? {} : { approval }),
    ...(approvalRequestId === undefined ? {} : { approvalRequestId }),
    ...(parentMandateId === undefined ? {} : { parentMandateId }),
    grantHash: requiredSha256(row.grant_hash, "agent_mandates.grant_hash"),
    issuedAt: dateIso(row.issued_at, "agent_mandates.issued_at"),
    expiresAt: dateIso(row.expires_at, "agent_mandates.expires_at"),
    status,
    successfulUses: requiredInteger(row.successful_uses, "agent_mandates.successful_uses"),
  };
}

function mapReceipt(row: DatabaseRow): ExecutionReceipt {
  const envelopeVersion = requiredString(row.envelope_version, "execution_receipts.envelope_version");
  if (envelopeVersion !== ACTION_ENVELOPE_VERSION) throw new Error(`unsupported receipt envelope version: ${envelopeVersion}`);
  const outcome = requiredString(row.outcome, "execution_receipts.outcome");
  if (!RECEIPT_OUTCOMES.has(outcome as ReceiptOutcome)) throw new Error(`invalid execution_receipts.outcome: ${outcome}`);
  const previousReceiptHash = nullableSha256(row.previous_receipt_hash, "execution_receipts.previous_receipt_hash");
  const downstreamStatus = optionalInteger(row.downstream_status, "execution_receipts.downstream_status");
  const resultHash = nullableSha256(row.result_hash, "execution_receipts.result_hash");
  const receipt: ExecutionReceipt = {
    id: requiredString(row.id, "execution_receipts.id"),
    tenantId: requiredString(row.tenant_id, "execution_receipts.tenant_id"),
    mandateId: requiredString(row.mandate_id, "execution_receipts.mandate_id"),
    decisionId: requiredString(row.decision_id, "execution_receipts.decision_id"),
    principalId: requiredString(row.principal_id, "execution_receipts.principal_id"),
    agentId: requiredString(row.agent_id, "execution_receipts.agent_id"),
    workloadId: requiredString(row.workload_id, "execution_receipts.workload_id"),
    taskId: requiredString(row.task_id, "execution_receipts.task_id"),
    audience: requiredString(row.audience, "execution_receipts.audience"),
    action: requiredString(row.action, "execution_receipts.action"),
    resource: requiredString(row.resource, "execution_receipts.resource"),
    envelopeVersion,
    envelopeHash: requiredSha256(row.envelope_hash, "execution_receipts.envelope_hash"),
    idempotencyKey: requiredString(row.idempotency_key, "execution_receipts.idempotency_key"),
    outcome: outcome as ReceiptOutcome,
    ...(downstreamStatus === undefined ? {} : { downstreamStatus }),
    ...(resultHash === undefined ? {} : { resultHash }),
    ...(previousReceiptHash === undefined ? {} : { previousReceiptHash }),
    receiptHash: requiredSha256(row.receipt_hash, "execution_receipts.receipt_hash"),
    attemptCount: requiredInteger(row.attempt_count, "execution_receipts.attempt_count"),
    createdAt: dateIso(row.created_at, "execution_receipts.created_at"),
    updatedAt: dateIso(row.updated_at, "execution_receipts.updated_at"),
  };
  if (computeReceiptIntegrityHash(receipt) !== receipt.receiptHash) throw new Error("receipt_integrity_error");
  return receipt;
}

function mapReceiptSnapshot(value: unknown): ExecutionReceipt {
  const object = parseJsonObject(value, "receipt_integrity_events.snapshot_json");
  if (object === undefined) throw new Error("receipt integrity snapshot is missing");
  const envelopeVersion = requiredString(object.envelopeVersion, "receipt snapshot.envelopeVersion");
  if (envelopeVersion !== ACTION_ENVELOPE_VERSION) throw new Error(`unsupported receipt envelope version: ${envelopeVersion}`);
  const outcome = requiredString(object.outcome, "receipt snapshot.outcome");
  if (!RECEIPT_OUTCOMES.has(outcome as ReceiptOutcome)) throw new Error(`invalid receipt snapshot outcome: ${outcome}`);
  const previousReceiptHash = nullableSha256(object.previousReceiptHash, "receipt snapshot.previousReceiptHash");
  const downstreamStatus = optionalInteger(object.downstreamStatus, "receipt snapshot.downstreamStatus");
  const resultHash = nullableSha256(object.resultHash, "receipt snapshot.resultHash");
  const receipt: ExecutionReceipt = {
    id: requiredString(object.id, "receipt snapshot.id"),
    tenantId: requiredString(object.tenantId, "receipt snapshot.tenantId"),
    mandateId: requiredString(object.mandateId, "receipt snapshot.mandateId"),
    decisionId: requiredString(object.decisionId, "receipt snapshot.decisionId"),
    principalId: requiredString(object.principalId, "receipt snapshot.principalId"),
    agentId: requiredString(object.agentId, "receipt snapshot.agentId"),
    workloadId: requiredString(object.workloadId, "receipt snapshot.workloadId"),
    taskId: requiredString(object.taskId, "receipt snapshot.taskId"),
    audience: requiredString(object.audience, "receipt snapshot.audience"),
    action: requiredString(object.action, "receipt snapshot.action"),
    resource: requiredString(object.resource, "receipt snapshot.resource"),
    envelopeVersion,
    envelopeHash: requiredSha256(object.envelopeHash, "receipt snapshot.envelopeHash"),
    idempotencyKey: requiredString(object.idempotencyKey, "receipt snapshot.idempotencyKey"),
    outcome: outcome as ReceiptOutcome,
    ...(downstreamStatus === undefined ? {} : { downstreamStatus }),
    ...(resultHash === undefined ? {} : { resultHash }),
    ...(previousReceiptHash === undefined ? {} : { previousReceiptHash }),
    receiptHash: requiredSha256(object.receiptHash, "receipt snapshot.receiptHash"),
    attemptCount: requiredInteger(object.attemptCount, "receipt snapshot.attemptCount"),
    createdAt: dateIso(object.createdAt, "receipt snapshot.createdAt"),
    updatedAt: dateIso(object.updatedAt, "receipt snapshot.updatedAt"),
  };
  return receipt;
}

function mapAudit(row: DatabaseRow): AuditEvent {
  const type = requiredString(row.type, "audit_events.type");
  if (!AUDIT_TYPES.has(type as AuditEvent["type"])) throw new Error(`invalid audit_events.type: ${type}`);
  const code = requiredString(row.code, "audit_events.code");
  if (!AUDIT_CODES.has(code as AuditEvent["code"])) throw new Error(`invalid audit_events.code: ${code}`);
  const details = parseJsonObject(row.details, "audit_events.details");
  return {
    id: requiredString(row.id, "audit_events.id"),
    tenantId: requiredString(row.tenant_id, "audit_events.tenant_id"),
    at: dateIso(row.at, "audit_events.at"),
    type: type as AuditEvent["type"],
    ...optionalProperty("mandateId", optionalString(row.mandate_id, "audit_events.mandate_id")),
    ...optionalProperty("decisionId", optionalString(row.decision_id, "audit_events.decision_id")),
    ...optionalProperty("principalId", optionalString(row.principal_id, "audit_events.principal_id")),
    ...optionalProperty("agentId", optionalString(row.agent_id, "audit_events.agent_id")),
    ...optionalProperty("workloadId", optionalString(row.workload_id, "audit_events.workload_id")),
    ...optionalProperty("taskId", optionalString(row.task_id, "audit_events.task_id")),
    ...optionalProperty("audience", optionalString(row.audience, "audit_events.audience")),
    ...optionalProperty("action", optionalString(row.action, "audit_events.action")),
    ...optionalProperty("resource", optionalString(row.resource, "audit_events.resource")),
    ...optionalProperty("envelopeHash", nullableSha256(row.envelope_hash, "audit_events.envelope_hash")),
    ...optionalProperty("idempotencyKey", optionalString(row.idempotency_key, "audit_events.idempotency_key")),
    code: code as AuditEvent["code"],
    ...(details === undefined ? {} : { details }),
  };
}

function parseConstraints(value: unknown, label: string): ConstraintSet | undefined {
  const object = parseJsonObject(value, label);
  if (object === undefined) return undefined;
  assertKnownKeys(object, new Set(["maxCalls", "equals", "maximum"]), label);
  const result: ConstraintSet = {};
  if (object.maxCalls !== undefined) {
    if (!Number.isInteger(object.maxCalls) || (object.maxCalls as number) < 1) throw new Error(`${label}.maxCalls must be positive integer`);
    result.maxCalls = object.maxCalls as number;
  }
  if (object.equals !== undefined) result.equals = primitiveRecord(object.equals, `${label}.equals`);
  if (object.maximum !== undefined) result.maximum = numberRecord(object.maximum, `${label}.maximum`);
  return result;
}

function parseApproval(value: unknown, label: string): ApprovalEvidence | undefined {
  const object = parseJsonObject(value, label);
  if (object === undefined) return undefined;
  assertKnownKeys(object, new Set([
    "required",
    "approvedBy",
    "approvedAt",
    "envelopeHash",
    "approvalRequestId",
    "intentHash",
    "profileId",
    "profileHash",
    "providerId",
    "providerConnectionId",
    "providerResourceId",
    "authenticatedAt",
  ]), label);
  if (typeof object.required !== "boolean") throw new Error(`${label}.required must be boolean`);
  const approvedBy = optionalString(object.approvedBy ?? null, `${label}.approvedBy`);
  const approvedAt = optionalString(object.approvedAt ?? null, `${label}.approvedAt`);
  const envelopeHash = optionalString(object.envelopeHash ?? null, `${label}.envelopeHash`);
  const approvalRequestId = optionalString(object.approvalRequestId ?? null, `${label}.approvalRequestId`);
  const intentHash = optionalString(object.intentHash ?? null, `${label}.intentHash`);
  const profileId = optionalString(object.profileId ?? null, `${label}.profileId`);
  const profileHash = optionalString(object.profileHash ?? null, `${label}.profileHash`);
  const providerId = optionalString(object.providerId ?? null, `${label}.providerId`);
  const providerConnectionId = optionalString(object.providerConnectionId ?? null, `${label}.providerConnectionId`);
  const providerResourceId = optionalString(object.providerResourceId ?? null, `${label}.providerResourceId`);
  const authenticatedAt = optionalString(object.authenticatedAt ?? null, `${label}.authenticatedAt`);
  return {
    required: object.required,
    ...(approvedBy === undefined ? {} : { approvedBy }),
    ...(approvedAt === undefined ? {} : { approvedAt }),
    ...(envelopeHash === undefined ? {} : { envelopeHash }),
    ...(approvalRequestId === undefined ? {} : { approvalRequestId }),
    ...(intentHash === undefined ? {} : { intentHash }),
    ...(profileId === undefined ? {} : { profileId }),
    ...(profileHash === undefined ? {} : { profileHash }),
    ...(providerId === undefined ? {} : { providerId }),
    ...(providerConnectionId === undefined ? {} : { providerConnectionId }),
    ...(providerResourceId === undefined ? {} : { providerResourceId }),
    ...(authenticatedAt === undefined ? {} : { authenticatedAt }),
  };
}

function validateConstraints(value: ConstraintSet, label: string): void {
  parseConstraints(value, label);
}

function validateApproval(value: ApprovalEvidence, label: string): void {
  const parsed = parseApproval(value, label);
  if (parsed?.required && (!parsed.approvedBy || !parsed.approvedAt || !parsed.envelopeHash)) {
    throw new Error(`${label} requires approvedBy, approvedAt, and envelopeHash when required is true`);
  }
  if (parsed?.envelopeHash !== undefined && !isSha256Base64Url(parsed.envelopeHash)) {
    throw new Error(`${label}.envelopeHash must be a base64url-encoded SHA-256 digest`);
  }
  if (parsed?.intentHash !== undefined && !isSha256Base64Url(parsed.intentHash)) {
    throw new Error(`${label}.intentHash must be a base64url-encoded SHA-256 digest`);
  }
  if (parsed?.profileHash !== undefined && !isSha256Base64Url(parsed.profileHash)) {
    throw new Error(`${label}.profileHash must be a base64url-encoded SHA-256 digest`);
  }
  if (parsed?.approvedAt !== undefined) validDate(new Date(parsed.approvedAt), `${label}.approvedAt`);
  if (parsed?.authenticatedAt !== undefined) validDate(new Date(parsed.authenticatedAt), `${label}.authenticatedAt`);
  if (parsed?.approvalRequestId !== undefined) {
    for (const [name, field] of Object.entries({
      intentHash: parsed.intentHash,
      profileId: parsed.profileId,
      profileHash: parsed.profileHash,
      providerId: parsed.providerId,
      providerConnectionId: parsed.providerConnectionId,
      providerResourceId: parsed.providerResourceId,
      authenticatedAt: parsed.authenticatedAt,
    })) {
      if (field === undefined) throw new Error(`${label}.${name} is required for product approval evidence`);
    }
  }
}

function parseJsonObject(value: unknown, label: string): Record<string, JsonValue> | undefined {
  if (value === null || value === undefined) return undefined;
  let parsed: unknown = value;
  if (typeof value === "string") {
    try {
      parsed = JSON.parse(value) as unknown;
    } catch {
      throw new Error(`${label} contains invalid JSON`);
    }
  }
  return toJsonObject(parsed, label);
}

function toJsonObject(value: unknown, label: string): Record<string, JsonValue> {
  const json = toJsonValue(value, label);
  if (json === null || Array.isArray(json) || typeof json !== "object") throw new Error(`${label} must be a JSON object`);
  return json;
}

function toJsonValue(value: unknown, label: string): JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error(`${label} contains a non-finite number`);
    return Object.is(value, -0) ? 0 : value;
  }
  if (Array.isArray(value)) return value.map((entry, index) => toJsonValue(entry, `${label}[${index}]`));
  if (typeof value !== "object") throw new Error(`${label} contains a non-JSON ${typeof value}`);
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) throw new Error(`${label} contains a non-plain object`);
  const result: Record<string, JsonValue> = {};
  for (const [key, entry] of Object.entries(value)) result[key] = toJsonValue(entry, `${label}.${key}`);
  return result;
}

function primitiveRecord(value: JsonValue, label: string): Record<string, JsonPrimitive> {
  const object = toJsonObject(value, label);
  const result: Record<string, JsonPrimitive> = {};
  for (const [key, entry] of Object.entries(object)) {
    if (entry !== null && typeof entry !== "string" && typeof entry !== "number" && typeof entry !== "boolean") {
      throw new Error(`${label}.${key} must be a JSON primitive`);
    }
    result[key] = entry;
  }
  return result;
}

function numberRecord(value: JsonValue, label: string): Record<string, number> {
  const object = toJsonObject(value, label);
  const result: Record<string, number> = {};
  for (const [key, entry] of Object.entries(object)) {
    if (typeof entry !== "number" || !Number.isFinite(entry)) throw new Error(`${label}.${key} must be a finite number`);
    result[key] = entry;
  }
  return result;
}

function jsonEquals(left: JsonValue | undefined, right: JsonValue | undefined): boolean {
  if (left === right) return true;
  if (left === undefined || right === undefined || left === null || right === null) return false;
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left) && Array.isArray(right) && left.length === right.length && left.every((entry, index) => jsonEquals(entry, right[index]));
  }
  if (typeof left === "object" || typeof right === "object") {
    if (typeof left !== "object" || typeof right !== "object") return false;
    const leftKeys = Object.keys(left).sort();
    const rightKeys = Object.keys(right).sort();
    return leftKeys.length === rightKeys.length && leftKeys.every((key, index) => key === rightKeys[index] && jsonEquals(left[key], right[key]));
  }
  return false;
}

function assertKnownKeys(object: Record<string, JsonValue>, allowed: Set<string>, label: string): void {
  for (const key of Object.keys(object)) if (!allowed.has(key)) throw new Error(`${label} contains unknown field ${key}`);
}

function requireFirstRow(rows: DatabaseRow[], label: string): DatabaseRow {
  const row = rows[0];
  if (row === undefined) throw new Error(`database did not return ${label}`);
  return row;
}

function requireNonEmpty(value: string, label: string): void {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${label} must be a non-empty string`);
}

function requireStringArray(value: string[], label: string): void {
  if (!Array.isArray(value) || value.length === 0) throw new Error(`${label} must be a non-empty array`);
  for (const entry of value) requireNonEmpty(entry, `${label} entry`);
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${label} must be a non-empty string`);
  return value;
}

function optionalString(value: unknown, label: string): string | undefined {
  if (value === null || value === undefined) return undefined;
  return requiredString(value, label);
}

function mapStringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.length === 0) throw new Error(`${label} must be a non-empty array`);
  return value.map((entry, index) => requiredString(entry, `${label}[${index}]`));
}

function requiredInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) throw new Error(`${label} must be a safe integer`);
  return value;
}

function requiredBigintAsSafeInteger(value: unknown, label: string): number {
  const parsed = typeof value === "string" && /^\d+$/.test(value) ? Number(value) : value;
  return requiredInteger(parsed, label);
}

function optionalInteger(value: unknown, label: string): number | undefined {
  if (value === null || value === undefined) return undefined;
  return requiredInteger(value, label);
}

function requiredSha256(value: unknown, label: string): string {
  if (!isSha256Base64Url(value)) throw new Error(`${label} must be a base64url-encoded SHA-256 digest`);
  return value;
}

function nullableSha256(value: unknown, label: string): string | undefined {
  if (value === null || value === undefined) return undefined;
  return requiredSha256(value, label);
}

function dateIso(value: unknown, label: string): string {
  const date = value instanceof Date ? value : typeof value === "string" ? new Date(value) : undefined;
  if (date === undefined || !Number.isFinite(date.getTime())) throw new Error(`${label} must be a valid timestamp`);
  return date.toISOString();
}

function validDate(value: Date, label: string): Date {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw new Error(`${label} must be a valid Date`);
  return value;
}

function optionalProperty<Key extends string, Value>(key: Key, value: Value | undefined): { [Property in Key]?: Value } {
  return value === undefined ? {} : ({ [key]: value } as { [Property in Key]: Value });
}
