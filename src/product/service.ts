import { randomBytes } from "node:crypto";
import type { ApprovalService, ApprovalWorkloadContext } from "../approvals/index.js";
import { githubIssueCreateProfile, type GitHubIssueCreateArguments } from "../actions/index.js";
import type { MandateRepository, ProviderConnectionRepository } from "../ports.js";
import type { ApprovalRequest, ExecutionReceipt, JsonValue } from "../types.js";

export interface ProductContext extends ApprovalWorkloadContext {}

export interface ProductStatusResult {
  requestId: string;
  status: ApprovalRequest["status"];
  executionStatus: ApprovalRequest["executionStatus"];
  profileId: string;
  providerId: string;
  repository: string;
  action: string;
  parameters: Record<string, JsonValue>;
  expiresAt: string;
  decisionReason?: string;
  receiptId?: string;
}

export interface ProductReceiptResult {
  status: "not_available" | "available";
  requestId: string;
  receipt?: ExecutionReceipt;
  chainVerified?: boolean;
}

export interface ProductServiceOptions {
  approvals: Pick<ApprovalService, "propose" | "get" | "resume">;
  connections: ProviderConnectionRepository;
  mandates: Pick<MandateRepository, "findReceipt">;
  verifyReceiptChain?: (tenantId: string) => Promise<boolean>;
  /** Trusted deployment/user mapping; connection identity never comes from tool arguments. */
  githubConnectionId(context: ProductContext): string;
  correlationId?: () => string;
}

export class ProductService {
  readonly #approvals: Pick<ApprovalService, "propose" | "get" | "resume">;
  readonly #connections: ProviderConnectionRepository;
  readonly #mandates: Pick<MandateRepository, "findReceipt">;
  readonly #verifyReceiptChain: ProductServiceOptions["verifyReceiptChain"];
  readonly #githubConnectionId: ProductServiceOptions["githubConnectionId"];
  readonly #correlationId: () => string;

  constructor(options: ProductServiceOptions) {
    this.#approvals = options.approvals;
    this.#connections = options.connections;
    this.#mandates = options.mandates;
    this.#verifyReceiptChain = options.verifyReceiptChain;
    this.#githubConnectionId = options.githubConnectionId;
    this.#correlationId = options.correlationId ?? (() => randomBytes(18).toString("base64url"));
  }

  async proposeGithubIssue(context: ProductContext, input: GitHubIssueCreateArguments) {
    const connectionId = required(this.#githubConnectionId(context), "github connection");
    const connection = await this.#connections.findConnection(context.tenantId, "github", connectionId);
    if (!connection || connection.status !== "active") throw new ProductServiceError("provider_connection_unavailable");
    const resources = await this.#connections.listResources(context.tenantId, "github", connectionId);
    const selected = resources.filter((resource) => resource.status === "active" && resource.displayName.toLowerCase() === input.repository.toLowerCase());
    if (selected.length !== 1) throw new ProductServiceError(selected.length === 0 ? "resource_not_connected" : "resource_ambiguous");
    const target = parseGitHubTarget(selected[0]!.selector, selected[0]!.providerResourceId);
    const trusted = githubIssueCreateProfile.prepare(input, target, this.#correlationId());
    return this.#approvals.propose(context, {
      profileId: trusted.profileId,
      profileHash: trusted.profileHash,
      providerId: trusted.providerId,
      providerConnectionId: connectionId,
      providerResourceId: String(target.repositoryId),
      idempotencyKey: requiredStringParameter(trusted.parameters.correlationId, "correlationId"),
      audience: trusted.audience,
      action: trusted.action,
      resource: trusted.resource,
      parameters: trusted.parameters,
      risk: trusted.risk,
    });
  }

  async status(context: ProductContext, input: { requestId: string }): Promise<ProductStatusResult> {
    return publicStatus(await this.#approvals.get(context, input.requestId));
  }

  resume(context: ProductContext, input: { resumeHandle: string }) {
    return this.#approvals.resume(context, input.resumeHandle);
  }

  async receipt(context: ProductContext, input: { requestId: string }): Promise<ProductReceiptResult> {
    const request = await this.#approvals.get(context, input.requestId);
    if (!request.mandateId) return { status: "not_available", requestId: request.id };
    const receipt = await this.#mandates.findReceipt(request.tenantId, request.mandateId, request.idempotencyKey);
    if (!receipt) return { status: "not_available", requestId: request.id };
    if (
      receipt.principalId !== context.principalId ||
      receipt.agentId !== context.agentId ||
      receipt.workloadId !== context.workloadId ||
      request.receiptId !== undefined && request.receiptId !== receipt.id
    ) throw new ProductServiceError("receipt_mismatch");
    const chainVerified = this.#verifyReceiptChain === undefined
      ? undefined
      : await this.#verifyReceiptChain(request.tenantId);
    return {
      status: "available",
      requestId: request.id,
      receipt,
      ...(chainVerified === undefined ? {} : { chainVerified }),
    };
  }
}

export class ProductServiceError extends Error {
  constructor(readonly code: "provider_connection_unavailable" | "resource_not_connected" | "resource_ambiguous" | "receipt_mismatch") {
    super(code);
    this.name = "ProductServiceError";
  }
}

function publicStatus(request: ApprovalRequest): ProductStatusResult {
  const repository = request.envelope.parameters.repository;
  if (typeof repository !== "string") throw new ProductServiceError("resource_not_connected");
  return {
    requestId: request.id,
    status: request.status,
    executionStatus: request.executionStatus,
    profileId: request.profileId,
    providerId: request.providerId,
    repository,
    action: request.envelope.action,
    parameters: structuredClone(request.envelope.parameters),
    expiresAt: request.expiresAt,
    ...(request.decisionReason === undefined ? {} : { decisionReason: request.decisionReason }),
    ...(request.receiptId === undefined ? {} : { receiptId: request.receiptId }),
  };
}

function parseGitHubTarget(selector: Record<string, JsonValue>, resourceId: string) {
  const repositoryId = selector.repositoryId;
  const owner = selector.owner;
  const name = selector.name;
  if (
    typeof repositoryId !== "number" || !Number.isSafeInteger(repositoryId) || repositoryId <= 0 ||
    String(repositoryId) !== resourceId || typeof owner !== "string" || typeof name !== "string"
  ) throw new ProductServiceError("resource_not_connected");
  return { repositoryId, owner, name };
}

function required(value: string, label: string): string {
  if (!value) throw new TypeError(`${label} is required`);
  return value;
}

function requiredStringParameter(value: JsonValue | undefined, label: string): string {
  if (typeof value !== "string" || value.length === 0) throw new TypeError(`${label} is required`);
  return value;
}
