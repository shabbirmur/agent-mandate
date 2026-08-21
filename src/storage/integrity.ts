import { createHash, timingSafeEqual } from "node:crypto";
import type { ActionEnvelopeVersion, ReceiptOutcome } from "../types.js";

const SHA256_BASE64URL = /^[A-Za-z0-9_-]{43}$/;

export interface ReceiptIntegrityFields {
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
  attemptCount: number;
  createdAt: string;
  updatedAt: string;
}

export function sha256Base64Url(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("base64url");
}

/** Hash the opaque part of a `mandate-id.secret` grant before persistence. */
export function hashGrantSecret(secret: string): string {
  if (secret.length === 0) throw new Error("grant secret must not be empty");
  return sha256Base64Url(secret);
}

export function isSha256Base64Url(value: unknown): value is string {
  return typeof value === "string" && SHA256_BASE64URL.test(value);
}

/** Constant-time comparison after both encoded digests have passed validation. */
export function verifyGrantSecret(secret: string, expectedHash: string): boolean {
  if (!isSha256Base64Url(expectedHash)) return false;
  const actualHash = hashGrantSecret(secret);
  const actual = Buffer.from(actualHash, "base64url");
  const expected = Buffer.from(expectedHash, "base64url");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

/**
 * Hash a complete receipt state. Each state transition is appended as a new
 * immutable integrity event, so mutable reconciliation state is covered without
 * rewriting history.
 */
export function computeReceiptIntegrityHash(receipt: ReceiptIntegrityFields): string {
  return sha256Base64Url(
    canonicalJson({
      action: receipt.action,
      agentId: receipt.agentId,
      audience: receipt.audience,
      createdAt: receipt.createdAt,
      decisionId: receipt.decisionId,
      envelopeHash: receipt.envelopeHash,
      envelopeVersion: receipt.envelopeVersion,
      id: receipt.id,
      idempotencyKey: receipt.idempotencyKey,
      mandateId: receipt.mandateId,
      outcome: receipt.outcome,
      previousReceiptHash: receipt.previousReceiptHash ?? null,
      principalId: receipt.principalId,
      resource: receipt.resource,
      resultHash: receipt.resultHash ?? null,
      downstreamStatus: receipt.downstreamStatus ?? null,
      attemptCount: receipt.attemptCount,
      taskId: receipt.taskId,
      tenantId: receipt.tenantId,
      updatedAt: receipt.updatedAt,
      workloadId: receipt.workloadId,
    }),
  );
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("canonical JSON cannot contain a non-finite number");
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value !== "object") throw new Error(`canonical JSON cannot contain ${typeof value}`);

  const object = value as Record<string, unknown>;
  const prototype = Object.getPrototypeOf(object) as unknown;
  if (prototype !== Object.prototype && prototype !== null) throw new Error("canonical JSON only accepts plain objects");
  return `{${Object.keys(object)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`)
    .join(",")}}`;
}
