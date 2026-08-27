import { createHash, createHmac } from "node:crypto";
import { canonicalHash } from "../canonical.js";
import { APPROVAL_INTENT_VERSION, type ActionEnvelope, type ActionRisk, type ApprovalIntent } from "../types.js";

export interface ApprovalIntentInput {
  requestId: string;
  envelope: ActionEnvelope;
  profileId: string;
  profileHash: string;
  providerId: string;
  providerConnectionId: string;
  providerResourceId: string;
  idempotencyKey: string;
  risk: ActionRisk;
  expiresAt: string;
  expectedApprover: string;
}

export function buildApprovalIntent(input: ApprovalIntentInput): ApprovalIntent {
  const envelopeHash = canonicalHash(input.envelope);
  const intent: ApprovalIntent = {
    version: APPROVAL_INTENT_VERSION,
    requestId: required(input.requestId, "requestId"),
    envelope: structuredClone(input.envelope),
    envelopeHash,
    profileId: required(input.profileId, "profileId"),
    profileHash: digest(input.profileHash, "profileHash"),
    providerId: required(input.providerId, "providerId"),
    providerConnectionId: required(input.providerConnectionId, "providerConnectionId"),
    providerResourceId: required(input.providerResourceId, "providerResourceId"),
    idempotencyKey: required(input.idempotencyKey, "idempotencyKey"),
    risk: input.risk,
    expiresAt: validIso(input.expiresAt, "expiresAt"),
    maxCalls: 1,
    delegationAllowed: false,
    expectedApprover: required(input.expectedApprover, "expectedApprover"),
  };
  if (intent.risk === "prohibited") throw new Error("prohibited_action");
  return intent;
}

export function hashApprovalIntent(intent: ApprovalIntent): string {
  if (intent.version !== APPROVAL_INTENT_VERSION) throw new Error("unsupported_approval_intent");
  if (canonicalHash(intent.envelope) !== intent.envelopeHash) throw new Error("approval_intent_envelope_mismatch");
  return canonicalHash(intent);
}

export function hashOpaqueHandle(handle: string): string {
  required(handle, "handle");
  return createHash("sha256").update(handle, "utf8").digest("base64url");
}

/** Derives a recoverable, request-specific grant without persisting the raw capability. */
export class InternalGrantDeriver {
  readonly #key: Buffer;

  constructor(key: Uint8Array) {
    if (key.byteLength < 32) throw new Error("internal grant key must contain at least 32 bytes");
    this.#key = Buffer.from(key);
  }

  derive(tenantId: string, requestId: string): string {
    return createHmac("sha256", this.#key)
      .update("agent-mandate:approved-grant:v1\0", "utf8")
      .update(required(tenantId, "tenantId"), "utf8")
      .update("\0", "utf8")
      .update(required(requestId, "requestId"), "utf8")
      .digest("base64url");
  }
}

function required(value: string, label: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${label} is required`);
  return value;
}

function digest(value: string, label: string): string {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) throw new Error(`${label} must be a SHA-256 base64url digest`);
  return value;
}

function validIso(value: string, label: string): string {
  if (!Number.isFinite(Date.parse(value))) throw new Error(`${label} must be an ISO timestamp`);
  return value;
}
