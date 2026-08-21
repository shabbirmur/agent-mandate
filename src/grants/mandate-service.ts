import { randomBytes } from "node:crypto";
import type { MandateRepository } from "../ports.js";
import {
  ACTION_ENVELOPE_VERSION,
  type ActionEnvelope,
  type ApprovalEvidence,
  type ConstraintSet,
  type ErrorCode,
  type IssuedMandate,
  type JsonPrimitive,
  type Mandate,
  type MandateCreationInput,
  type MandateRequest,
  type PrincipalContext,
} from "../types.js";
import { hashActionEnvelope, sha256Base64Url } from "./canonical.js";

export const MAX_MANDATE_TTL_SECONDS = 3_600;

export interface MandateServiceOptions {
  now?: () => Date;
  /** Actions that always require an exact, freshly bound approval envelope. */
  highRiskActions?: readonly string[];
}

export class MandateServiceError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, options?: ErrorOptions) {
    super(code, options);
    this.name = "MandateServiceError";
    this.code = code;
  }
}

/** Issues and revokes mandates using authenticated principal context as the identity authority. */
export class MandateService {
  readonly #repository: MandateRepository;
  readonly #now: () => Date;
  readonly #highRiskActions: ReadonlySet<string>;

  constructor(repository: MandateRepository, options: MandateServiceOptions = {}) {
    this.#repository = repository;
    this.#now = options.now ?? (() => new Date());
    const highRiskActions = options.highRiskActions ?? ["payment.create"];
    if (highRiskActions.some((action) => !isNonEmptyString(action))) {
      throw new TypeError("highRiskActions must contain non-empty action names");
    }
    this.#highRiskActions = new Set(highRiskActions);
  }

  async issue(principal: PrincipalContext, input: MandateCreationInput): Promise<IssuedMandate> {
    validatePrincipal(principal);
    validateCreationInput(input);
    const now = this.#validNow();
    const approval = buildApproval(principal, input, now, this.#highRiskActions);
    const request: MandateRequest = {
      tenantId: principal.tenantId,
      principalId: principal.principalId,
      agentId: input.agentId,
      workloadId: input.workloadId,
      taskId: input.taskId,
      audience: input.audience,
      actions: [...input.actions],
      resources: [...input.resources],
      expiresInSeconds: input.expiresInSeconds,
      ...(input.constraints !== undefined ? { constraints: structuredClone(input.constraints) } : {}),
      ...(approval !== undefined ? { approval } : {}),
      ...(input.parentMandateId !== undefined ? { parentMandateId: input.parentMandateId } : {}),
    };

    if (input.parentMandateId !== undefined) {
      const parent = await this.#repository.find(principal.tenantId, input.parentMandateId);
      assertAttenuatedChild(parent, request, now);
    }

    const secret = randomBytes(32).toString("base64url");
    const grantHash = hashGrantSecret(secret);
    const mandate = await this.#repository.create(request, grantHash, now);
    assertCreatedMandate(mandate, request, grantHash);
    const { grantHash: _storedHash, ...publicMandate } = structuredClone(mandate);
    return { mandate: publicMandate, grant: `${mandate.id}.${secret}` };
  }

  async revoke(principal: PrincipalContext, mandateId: string): Promise<boolean> {
    validatePrincipal(principal);
    requireNonEmptyString(mandateId);
    const existing = await this.#repository.find(principal.tenantId, mandateId);
    if (existing === undefined || existing.principalId !== principal.principalId) return false;
    return this.#repository.revoke(principal.tenantId, mandateId, this.#validNow());
  }

  #validNow(): Date {
    const now = this.#now();
    if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw new TypeError("now must return a valid Date");
    return new Date(now.getTime());
  }
}

export interface ParsedGrant {
  mandateId: string;
  secret: string;
}

export function parseGrant(grant: string): ParsedGrant | undefined {
  if (typeof grant !== "string") return undefined;
  const separator = grant.indexOf(".");
  if (separator <= 0 || separator !== grant.lastIndexOf(".") || separator === grant.length - 1) return undefined;
  return { mandateId: grant.slice(0, separator), secret: grant.slice(separator + 1) };
}

export function hashGrantSecret(secret: string): string {
  return sha256Base64Url(secret);
}

function buildApproval(
  principal: PrincipalContext,
  input: MandateCreationInput,
  now: Date,
  highRiskActions: ReadonlySet<string>,
): ApprovalEvidence | undefined {
  const containsHighRiskAction = input.actions.some((action) => highRiskActions.has(action));
  if (containsHighRiskAction && (input.approval?.required !== true || input.approval.approvedEnvelope === undefined)) {
    throw new MandateServiceError("approval_required");
  }
  if (input.approval === undefined) return undefined;
  if (input.approval.required && input.approval.approvedEnvelope === undefined) {
    throw new MandateServiceError("approval_required");
  }
  if (input.approval.approvedEnvelope === undefined) return { required: input.approval.required };
  if (!input.approval.required) throw new MandateServiceError(containsHighRiskAction ? "approval_required" : "invalid_request");

  const approved = input.approval.approvedEnvelope;
  if (
    approved.version !== ACTION_ENVELOPE_VERSION ||
    approved.audience !== input.audience ||
    !input.actions.includes(approved.action) ||
    !input.resources.includes(approved.resource) ||
    (containsHighRiskAction && !highRiskActions.has(approved.action))
  ) {
    throw new MandateServiceError("approval_mismatch");
  }
  validateApprovedParameters(approved.parameters, input.constraints);

  const envelope: ActionEnvelope = {
    version: approved.version,
    tenantId: principal.tenantId,
    principalId: principal.principalId,
    agentId: input.agentId,
    workloadId: input.workloadId,
    taskId: input.taskId,
    audience: approved.audience,
    action: approved.action,
    resource: approved.resource,
    parameters: structuredClone(approved.parameters),
  };
  return {
    required: input.approval.required,
    approvedBy: principal.principalId,
    approvedAt: now.toISOString(),
    envelopeHash: hashActionEnvelope(envelope),
  };
}

function validateApprovedParameters(parameters: ActionEnvelope["parameters"], constraints: ConstraintSet | undefined): void {
  try {
    hashActionEnvelope({
      version: ACTION_ENVELOPE_VERSION,
      tenantId: "validation",
      principalId: "validation",
      agentId: "validation",
      workloadId: "validation",
      taskId: "validation",
      audience: "validation",
      action: "validation",
      resource: "validation",
      parameters,
    });
  } catch (error) {
    throw new MandateServiceError("invalid_request", { cause: error });
  }
  for (const [name, expected] of Object.entries(constraints?.equals ?? {})) {
    if (parameters[name] !== expected) throw new MandateServiceError("approval_mismatch");
  }
  for (const [name, maximum] of Object.entries(constraints?.maximum ?? {})) {
    const actual = parameters[name];
    if (typeof actual !== "number" || actual > maximum) throw new MandateServiceError("approval_mismatch");
  }
}

function assertAttenuatedChild(parent: Mandate | undefined, child: MandateRequest, now: Date): void {
  if (parent === undefined) throw new MandateServiceError("invalid_grant");
  if (parent.status !== "active") throw new MandateServiceError("revoked");
  const parentExpiry = Date.parse(parent.expiresAt);
  if (!Number.isFinite(parentExpiry)) throw new MandateServiceError("invalid_grant");
  if (now.getTime() >= parentExpiry) throw new MandateServiceError("expired");

  if (
    parent.tenantId !== child.tenantId ||
    parent.principalId !== child.principalId ||
    parent.agentId !== child.agentId ||
    parent.workloadId !== child.workloadId ||
    parent.taskId !== child.taskId ||
    parent.audience !== child.audience ||
    child.actions.some((action) => !parent.actions.includes(action)) ||
    child.resources.some((resource) => !parent.resources.includes(resource)) ||
    now.getTime() + child.expiresInSeconds * 1_000 > parentExpiry ||
    !constraintsAreAttenuated(parent.constraints, child.constraints)
  ) {
    throw new MandateServiceError("delegation_amplification");
  }
}

function constraintsAreAttenuated(parent: ConstraintSet | undefined, child: ConstraintSet | undefined): boolean {
  if (parent === undefined) return true;
  if (parent.maxCalls !== undefined && (child?.maxCalls === undefined || child.maxCalls > parent.maxCalls)) return false;

  for (const [name, expected] of Object.entries(parent.equals ?? {})) {
    if (child?.equals?.[name] !== expected) return false;
  }
  for (const [name, maximum] of Object.entries(parent.maximum ?? {})) {
    const exact = child?.equals?.[name];
    if (typeof exact === "number" && exact <= maximum) continue;
    const childMaximum = child?.maximum?.[name];
    if (childMaximum === undefined || childMaximum > maximum) return false;
  }
  return true;
}

function validatePrincipal(principal: PrincipalContext): void {
  if (
    !isNonEmptyString(principal.tenantId) ||
    !isNonEmptyString(principal.principalId) ||
    !isNonEmptyString(principal.issuer) ||
    !isNonEmptyString(principal.subject)
  ) {
    throw new MandateServiceError("invalid_principal");
  }
}

function validateCreationInput(input: MandateCreationInput): void {
  if (!isPlainRecord(input)) throw new MandateServiceError("invalid_request");
  if (
    !isNonEmptyString(input.agentId) ||
    !isNonEmptyString(input.workloadId) ||
    !isNonEmptyString(input.taskId) ||
    !isNonEmptyString(input.audience)
  ) {
    throw new MandateServiceError("missing_identity_or_context");
  }
  validateAuthorityList(input.actions);
  validateAuthorityList(input.resources);
  if (!Number.isInteger(input.expiresInSeconds) || input.expiresInSeconds < 1 || input.expiresInSeconds > MAX_MANDATE_TTL_SECONDS) {
    throw new MandateServiceError("invalid_request");
  }
  if (input.parentMandateId !== undefined) requireNonEmptyString(input.parentMandateId);
  validateConstraints(input.constraints);
  if (input.approval !== undefined) {
    if (!isPlainRecord(input.approval) || typeof input.approval.required !== "boolean") {
      throw new MandateServiceError("invalid_request");
    }
    if (input.approval.approvedEnvelope !== undefined && !isPlainRecord(input.approval.approvedEnvelope)) {
      throw new MandateServiceError("invalid_request");
    }
  }
}

function validateAuthorityList(values: string[]): void {
  if (!Array.isArray(values) || values.length === 0 || values.some((value) => !isNonEmptyString(value))) {
    throw new MandateServiceError("invalid_request");
  }
  if (new Set(values).size !== values.length) throw new MandateServiceError("invalid_request");
}

function validateConstraints(constraints: ConstraintSet | undefined): void {
  if (constraints === undefined) return;
  if (!isPlainRecord(constraints)) throw new MandateServiceError("invalid_request");
  const maxCalls: unknown = constraints.maxCalls;
  if (maxCalls !== undefined && (typeof maxCalls !== "number" || !Number.isInteger(maxCalls) || maxCalls < 1)) {
    throw new MandateServiceError("invalid_request");
  }
  if (constraints.equals !== undefined && !isPlainRecord(constraints.equals)) throw new MandateServiceError("invalid_request");
  if (constraints.maximum !== undefined && !isPlainRecord(constraints.maximum)) throw new MandateServiceError("invalid_request");
  const equals = constraints.equals as Record<string, unknown> | undefined;
  const maximum = constraints.maximum as Record<string, unknown> | undefined;
  for (const [name, value] of Object.entries(equals ?? {})) {
    if (!isNonEmptyString(name) || !isJsonPrimitive(value)) throw new MandateServiceError("invalid_request");
  }
  for (const [name, value] of Object.entries(maximum ?? {})) {
    if (!isNonEmptyString(name) || typeof value !== "number" || !Number.isFinite(value)) {
      throw new MandateServiceError("invalid_request");
    }
    const exact = equals?.[name];
    if (exact !== undefined && (typeof exact !== "number" || exact > value)) throw new MandateServiceError("invalid_request");
  }
}

function assertCreatedMandate(mandate: Mandate, request: MandateRequest, grantHash: string): void {
  if (!isNonEmptyString(mandate.id) || mandate.id.includes(".") || mandate.grantHash !== grantHash) {
    throw new Error("mandate repository returned an invalid created record");
  }
  const fields: (keyof Pick<MandateRequest, "tenantId" | "principalId" | "agentId" | "workloadId" | "taskId" | "audience">)[] = [
    "tenantId",
    "principalId",
    "agentId",
    "workloadId",
    "taskId",
    "audience",
  ];
  if (fields.some((field) => mandate[field] !== request[field])) {
    throw new Error("mandate repository changed an identity binding");
  }
}

function requireNonEmptyString(value: string): void {
  if (!isNonEmptyString(value)) throw new MandateServiceError("invalid_request");
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isJsonPrimitive(value: unknown): value is JsonPrimitive {
  return value === null || typeof value === "string" || typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value));
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
