import type { AuthInfo, CallToolResult, McpHttpHandler, McpRequestContext } from "@modelcontextprotocol/server";
import {
  McpServer,
  createMcpHandler as createSdkMcpHandler,
  hostHeaderValidationResponse,
  localhostAllowedHostnames,
  localhostAllowedOrigins,
  originValidationResponse,
} from "@modelcontextprotocol/server";
import { z } from "zod";
import type { ExecuteResult, ExecutionReceipt, JsonValue } from "../types.js";

export const PRODUCT_MCP_SERVER_NAME = "agent-mandate" as const;
export const PRODUCT_MCP_SERVER_VERSION = "0.2.0" as const;

/**
 * An authenticated binding supplied by the host, never by MCP tool arguments.
 * Remote stdio bridges normally populate only `sessionId`; the remote backend
 * validates its bearer token and lets the Agent Mandate service derive identity.
 */
export interface ProductMcpContext {
  sessionId: string;
  tenantId?: string;
  principalId?: string;
  agentId?: string;
  workloadId?: string;
}

export interface GithubCreateIssueToolInput {
  repository: string;
  title: string;
  body?: string;
}

export interface ApprovalRequestToolInput {
  requestId: string;
}

export interface ApprovalResumeToolInput {
  resumeHandle: string;
}

export interface ProductDeniedBackendResult {
  status: "denied";
  code: string;
  reason?: string;
  requestId?: string;
}

export interface ProductApprovalRequiredBackendResult {
  status: "approval_required";
  requestId: string;
  resumeHandle: string;
  approvalUrl: string;
  expiresAt: string;
  intentHash: string;
}

export type ProductProposalBackendResult = ProductApprovalRequiredBackendResult | ProductDeniedBackendResult;

export interface ProductStatusBackendResult {
  requestId: string;
  status: "pending" | "approved" | "denied" | "expired" | "cancelled";
  expiresAt: string;
  executionStatus?: "not_started" | "reserved" | "dispatching" | "succeeded" | "failed" | "ambiguous";
  reason?: string;
  receiptId?: string;
}

export type ProductResumeBackendResult =
  | {
    status: "pending" | "denied" | "expired" | "cancelled";
    requestId: string;
    expiresAt: string;
    reason?: string;
  }
  | {
    status: "failed" | "ambiguous";
    requestId: string;
    expiresAt: string;
    reason: string;
  }
  | {
    status: "succeeded" | "failed" | "ambiguous";
    requestId: string;
    execution: ExecuteResult;
  }
  | {
    status: "ambiguous";
    code: "remote_response_ambiguous";
    reason: string;
  };

export interface ProductReceiptBackendResult {
  status: "not_available" | "available";
  requestId: string;
  receipt?: ExecutionReceipt;
  /** Omitted when this backend can return a receipt but cannot verify its chain. */
  chainVerified?: boolean;
  issue?: {
    id: number;
    nodeId: string;
    number: number;
    htmlUrl: string;
    state: "open" | "closed";
    title: string;
  };
}

/** Every method receives host-resolved context before any untrusted arguments. */
export interface ProductMcpBackend<Context extends object = ProductMcpContext> {
  proposeGithubIssue(
    context: Readonly<Context>,
    input: Readonly<GithubCreateIssueToolInput>,
  ): Promise<ProductProposalBackendResult>;
  status(context: Readonly<Context>, input: Readonly<ApprovalRequestToolInput>): Promise<ProductStatusBackendResult>;
  resume(context: Readonly<Context>, input: Readonly<ApprovalResumeToolInput>): Promise<ProductResumeBackendResult>;
  receipt(context: Readonly<Context>, input: Readonly<ApprovalRequestToolInput>): Promise<ProductReceiptBackendResult>;
}

export interface CreateProductMcpServerOptions<Context extends object> {
  backend: ProductMcpBackend<Context>;
  context: Readonly<Context>;
}

export interface ProductMcpHttpResolverInput {
  era: "legacy" | "modern";
  request?: Request;
  authInfo?: AuthInfo;
}

export interface CreateProductMcpHttpHandlerOptions<Context extends object> {
  backend: ProductMcpBackend<Context>;
  resolveContext(input: ProductMcpHttpResolverInput): Context | Promise<Context>;
  /** Hostnames only, with no scheme or port. Defaults to loopback hosts. */
  allowedHostnames?: readonly string[];
  /** Origin hostnames only. A missing Origin is allowed for non-browser clients. */
  allowedOriginHostnames?: readonly string[];
  legacy?: "stateless" | "reject";
  onerror?: (error: Error) => void;
}

export interface ProductMcpHttpHandler extends McpHttpHandler {
  fetch(request: Request, options?: { authInfo?: AuthInfo; parsedBody?: unknown }): Promise<Response>;
}

const boundedIdentifier = z.string().min(1).max(128).regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/u);
const boundedIdentity = z.string().min(1).max(512).refine((value) => !/[\u0000-\u001f\u007f]/u.test(value));
const boundedCode = z.string().min(1).max(128).regex(/^[a-z][a-z0-9._-]*$/u);
const boundedReason = z.string().min(1).max(500);
const isoTimestamp = z.string().datetime({ offset: true });
const digest = z.string().regex(/^[A-Za-z0-9_-]{43}$/u);
const resumeHandle = z.string().regex(/^[A-Za-z0-9_-]{43}$/u);

export const githubCreateIssueInputSchema = z.object({
  repository: z.string().min(3).max(140).regex(/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/u),
  title: z.string().min(1).max(256)
    .refine((value) => value.trim().length > 0 && !/[\u0000\r\n]/u.test(value) && Buffer.byteLength(value, "utf8") <= 1_024),
  body: z.string().max(65_000)
    .refine((value) => !value.includes("\u0000") && Buffer.byteLength(value, "utf8") <= 256 * 1_024)
    .optional(),
}).strict();

export const approvalRequestInputSchema = z.object({ requestId: boundedIdentifier }).strict();
export const approvalResumeInputSchema = z.object({ resumeHandle }).strict();

const deniedBackendSchema = z.object({
  status: z.literal("denied"),
  code: boundedCode,
  reason: boundedReason.optional(),
  requestId: boundedIdentifier.optional(),
}).strict();

const approvalRequiredBackendSchema = z.object({
  status: z.literal("approval_required"),
  requestId: boundedIdentifier,
  resumeHandle,
  approvalUrl: z.url().max(2_048),
  expiresAt: isoTimestamp,
  intentHash: digest,
}).strict();

const statusBackendSchema = z.object({
  requestId: boundedIdentifier,
  status: z.enum(["pending", "approved", "denied", "expired", "cancelled"]),
  expiresAt: isoTimestamp,
  executionStatus: z.enum(["not_started", "reserved", "dispatching", "succeeded", "failed", "ambiguous"]).optional(),
  reason: boundedReason.optional(),
  decisionReason: boundedReason.optional(),
  receiptId: boundedIdentifier.optional(),
}).strip();

const decisionSchema = z.object({
  allowed: z.boolean(),
  code: boundedCode,
  decisionId: boundedIdentifier,
  mandateId: boundedIdentifier.optional(),
  envelopeHash: digest.optional(),
  remainingCalls: z.number().int().min(0).optional(),
}).strict();

const receiptSchema = z.object({
  id: boundedIdentifier,
  tenantId: boundedIdentity,
  mandateId: boundedIdentifier,
  decisionId: boundedIdentifier,
  principalId: boundedIdentity,
  agentId: boundedIdentity,
  workloadId: boundedIdentity,
  taskId: boundedIdentifier,
  audience: z.string().min(1).max(2_048),
  action: boundedIdentifier,
  resource: z.string().min(1).max(2_048),
  envelopeVersion: z.literal("am.action.v1"),
  envelopeHash: digest,
  idempotencyKey: z.string().min(1).max(256),
  outcome: z.enum(["pending", "succeeded", "failed", "ambiguous"]),
  downstreamStatus: z.number().int().min(100).max(599).optional(),
  resultHash: digest.optional(),
  previousReceiptHash: digest.optional(),
  receiptHash: digest,
  attemptCount: z.number().int().min(0),
  createdAt: isoTimestamp,
  updatedAt: isoTimestamp,
}).strict();

const issueSchema = z.object({
  id: z.number().int().positive(),
  nodeId: z.string().min(1).max(256),
  number: z.number().int().positive(),
  htmlUrl: z.url().max(2_048),
  state: z.enum(["open", "closed"]),
  title: z.string().min(1).max(256),
}).strict();

const executionSchema = z.object({
  decision: decisionSchema,
  receipt: receiptSchema.optional(),
  result: z.object({
    status: z.number().int().min(100).max(599),
    body: z.union([issueSchema, z.object({ error: boundedCode }).strict()]),
  }).strict().optional(),
}).strict();

const resumeBackendSchema = z.union([
  z.object({
    status: z.enum(["pending", "denied", "expired", "cancelled"]),
    requestId: boundedIdentifier,
    expiresAt: isoTimestamp,
    reason: boundedReason.optional(),
  }).strict(),
  z.object({
    status: z.enum(["succeeded", "failed"]),
    requestId: boundedIdentifier,
    execution: executionSchema,
  }).strict(),
  z.object({
    status: z.literal("ambiguous"),
    requestId: boundedIdentifier,
    execution: executionSchema,
  }).strict(),
  z.object({
    status: z.enum(["failed", "ambiguous"]),
    requestId: boundedIdentifier,
    expiresAt: isoTimestamp,
    reason: boundedReason,
  }).strict(),
  z.object({
    status: z.literal("ambiguous"),
    code: z.literal("remote_response_ambiguous"),
    reason: boundedReason,
  }).strict(),
]);

const receiptBackendSchema = z.union([
  z.object({ status: z.literal("not_available"), requestId: boundedIdentifier }).strip(),
  z.object({
    status: z.literal("available"),
    requestId: boundedIdentifier,
    receipt: receiptSchema,
    chainVerified: z.boolean().optional(),
    issue: issueSchema.optional(),
  }).strip(),
]);

const proposalOutputSchema = z.object({
  status: z.enum(["approval_required", "denied"]),
  requestId: boundedIdentifier.optional(),
  resumeHandle: resumeHandle.optional(),
  approvalUrl: z.url().max(2_048).optional(),
  expiresAt: isoTimestamp.optional(),
  intentHash: digest.optional(),
  code: boundedCode.optional(),
  reason: boundedReason.optional(),
  terminal: z.boolean(),
  autoRetryAllowed: z.literal(false),
  nextAction: z.enum(["open_approval", "none"]),
}).strict();

const statusOutputSchema = z.object({
  status: z.enum(["pending", "approved", "denied", "expired", "cancelled", "succeeded", "failed", "ambiguous"]),
  requestId: boundedIdentifier,
  expiresAt: isoTimestamp,
  executionStatus: z.enum(["not_started", "reserved", "dispatching", "succeeded", "failed", "ambiguous"]).optional(),
  reason: boundedReason.optional(),
  receiptId: boundedIdentifier.optional(),
  terminal: z.boolean(),
  autoRetryAllowed: z.literal(false),
  nextAction: z.enum(["wait", "resume", "none"]),
}).strict();

const resumeOutputSchema = z.object({
  status: z.enum(["pending", "denied", "expired", "cancelled", "succeeded", "failed", "ambiguous"]),
  requestId: boundedIdentifier.optional(),
  code: z.literal("remote_response_ambiguous").optional(),
  expiresAt: isoTimestamp.optional(),
  reason: boundedReason.optional(),
  decision: decisionSchema.optional(),
  receipt: receiptSchema.optional(),
  issue: issueSchema.optional(),
  terminal: z.boolean(),
  autoRetryAllowed: z.literal(false),
  nextAction: z.enum(["wait", "none"]),
}).strict();

const receiptOutputSchema = z.object({
  status: z.enum(["receipt", "not_available"]),
  requestId: boundedIdentifier,
  receipt: receiptSchema.optional(),
  chainVerified: z.boolean().optional(),
  chainVerification: z.enum(["verified", "failed", "not_checked", "not_available"]),
  issue: issueSchema.optional(),
  terminal: z.boolean(),
  autoRetryAllowed: z.literal(false),
  nextAction: z.enum(["wait", "none"]),
}).strict();

export function createProductMcpServer<Context extends object>(
  options: CreateProductMcpServerOptions<Context>,
): McpServer {
  const backend = options.backend;
  const context = Object.freeze(options.context);
  const server = new McpServer({
    name: PRODUCT_MCP_SERVER_NAME,
    version: PRODUCT_MCP_SERVER_VERSION,
    title: "Agent Mandate",
  });

  server.registerTool("github_create_issue", {
    title: "Create one approved GitHub issue",
    description: "Propose one exact GitHub issue for separate user approval. This tool never receives a GitHub credential.",
    inputSchema: githubCreateIssueInputSchema,
    outputSchema: proposalOutputSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  }, async (input) => safeToolCall(async () => {
    const proposalInput: GithubCreateIssueToolInput = {
      repository: input.repository,
      title: input.title,
      ...(input.body === undefined ? {} : { body: input.body }),
    };
    const parsed = approvalRequiredBackendSchema.or(deniedBackendSchema).parse(
      await backend.proposeGithubIssue(context, Object.freeze(proposalInput)),
    );
    if (parsed.status === "denied") {
      const output = {
        status: parsed.status,
        code: parsed.code,
        ...(parsed.reason === undefined ? {} : { reason: parsed.reason }),
        ...(parsed.requestId === undefined ? {} : { requestId: parsed.requestId }),
        terminal: true,
        autoRetryAllowed: false as const,
        nextAction: "none" as const,
      };
      return toolResult(output, `Denied (${parsed.code}). This result is terminal; do not retry automatically.`);
    }
    const output = {
      ...parsed,
      terminal: false,
      autoRetryAllowed: false as const,
      nextAction: "open_approval" as const,
    };
    return toolResult(
      output,
      `Approval required for ${parsed.requestId}. Open ${parsed.approvalUrl}, then call agent_mandate_resume with resumeHandle ${parsed.resumeHandle}. Do not repeat github_create_issue.`,
    );
  }));

  server.registerTool("agent_mandate_status", {
    title: "Check approval status",
    description: "Check an approval request under the current authenticated agent session.",
    inputSchema: approvalRequestInputSchema,
    outputSchema: statusOutputSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async (input) => safeToolCall(async () => {
    const parsed = toStatusBackendResult(statusBackendSchema.parse(
      await backend.status(context, Object.freeze({ ...input })),
    ));
    const effective = effectiveStatus(parsed);
    const terminal = isTerminalStatus(effective);
    const nextAction = terminal
      ? "none"
      : parsed.status === "approved" && (parsed.executionStatus === undefined || parsed.executionStatus === "not_started")
        ? "resume"
        : "wait";
    const output = {
      status: effective,
      requestId: parsed.requestId,
      expiresAt: parsed.expiresAt,
      ...(parsed.executionStatus === undefined ? {} : { executionStatus: parsed.executionStatus }),
      ...(parsed.reason === undefined ? {} : { reason: parsed.reason }),
      ...(parsed.receiptId === undefined ? {} : { receiptId: parsed.receiptId }),
      terminal,
      autoRetryAllowed: false as const,
      nextAction,
    };
    const text = effective === "ambiguous"
      ? "Execution outcome is ambiguous and terminal for automatic execution. Do not retry or repeat the action."
      : `Agent Mandate request ${parsed.requestId} is ${effective}.`;
    return toolResult(output, text);
  }));

  server.registerTool("agent_mandate_resume", {
    title: "Resume an approved action",
    description: "Resume the stored immutable proposal by opaque handle. No action fields can be restated or changed.",
    inputSchema: approvalResumeInputSchema,
    outputSchema: resumeOutputSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  }, async (input) => safeToolCall(async () => {
    const parsed = resumeBackendSchema.parse(await backend.resume(context, Object.freeze({ ...input })));
    if (!("execution" in parsed)) {
      if (parsed.status === "ambiguous" && "code" in parsed) {
        const output = {
          status: parsed.status,
          code: parsed.code,
          reason: parsed.reason,
          terminal: true,
          autoRetryAllowed: false as const,
          nextAction: "none" as const,
        };
        return toolResult(
          output,
          "The remote response was lost after execution may have started. This outcome is ambiguous and terminal for automatic execution; do not retry or repeat the action.",
        );
      }
      const terminal = parsed.status !== "pending";
      const output = {
        status: parsed.status,
        requestId: parsed.requestId,
        expiresAt: parsed.expiresAt,
        ...(parsed.reason === undefined ? {} : { reason: parsed.reason }),
        terminal,
        autoRetryAllowed: false as const,
        nextAction: (terminal ? "none" : "wait") as "none" | "wait",
      };
      const text = parsed.status === "pending"
        ? "Approval is still pending. Wait for the user decision; do not create a second proposal."
        : `The action is ${parsed.status}. This result is terminal; do not retry automatically.`;
      return toolResult(output, text);
    }

    const execution = executionSchema.parse(parsed.execution);
    const status = parsed.status === "failed" && !execution.decision.allowed ? "denied" : parsed.status;
    const issue = execution.result?.body && "id" in execution.result.body ? execution.result.body : undefined;
    const failureReason = execution.result?.body && "error" in execution.result.body
      ? execution.result.body.error
      : undefined;
    const output = {
      status,
      requestId: parsed.requestId,
      decision: execution.decision,
      ...(execution.receipt === undefined ? {} : { receipt: execution.receipt }),
      ...(issue === undefined ? {} : { issue }),
      ...(failureReason === undefined ? {} : { reason: failureReason }),
      terminal: true,
      autoRetryAllowed: false as const,
      nextAction: "none" as const,
    };
    const text = status === "ambiguous"
      ? "Execution outcome is ambiguous and terminal for automatic execution. Do not retry, repeat, or create a replacement proposal."
      : status === "denied"
        ? `Execution was denied (${execution.decision.code}). This result is terminal; do not retry automatically.`
        : `Execution ${status}.`;
    return toolResult(output, text);
  }));

  server.registerTool("agent_mandate_receipt", {
    title: "Get execution receipt",
    description: "Read the receipt linked to an approval request under the current authenticated agent session.",
    inputSchema: approvalRequestInputSchema,
    outputSchema: receiptOutputSchema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async (input) => safeToolCall(async () => {
    const parsed = receiptBackendSchema.parse(await backend.receipt(context, Object.freeze({ ...input })));
    if (parsed.status === "not_available") {
      const output = {
        status: parsed.status,
        requestId: parsed.requestId,
        chainVerification: "not_available" as const,
        terminal: false,
        autoRetryAllowed: false as const,
        nextAction: "wait" as const,
      };
      return toolResult(output, `No receipt is available yet for ${parsed.requestId}. Check request status before trying again.`);
    }
    const chainVerification = parsed.chainVerified === true
      ? "verified"
      : parsed.chainVerified === false
        ? "failed"
        : "not_checked";
    const output = {
      status: "receipt" as const,
      requestId: parsed.requestId,
      receipt: parsed.receipt,
      ...(parsed.chainVerified === undefined ? {} : { chainVerified: parsed.chainVerified }),
      chainVerification,
      ...(parsed.issue === undefined ? {} : { issue: parsed.issue }),
      terminal: true as const,
      autoRetryAllowed: false as const,
      nextAction: "none" as const,
    };
    const verificationText = chainVerification === "not_checked"
      ? "not checked by this backend"
      : chainVerification;
    return toolResult(output, `Receipt ${parsed.receipt.id}; chain verification: ${verificationText}.`);
  }));

  return server;
}

export function createMcpHttpHandler<Context extends object>(
  options: CreateProductMcpHttpHandlerOptions<Context>,
): ProductMcpHttpHandler {
  const allowedHostnames = validatedHostnameList(options.allowedHostnames ?? localhostAllowedHostnames(), "allowedHostnames");
  const allowedOrigins = validatedHostnameList(options.allowedOriginHostnames ?? localhostAllowedOrigins(), "allowedOriginHostnames");
  const sdkHandler = createSdkMcpHandler(async (sdkContext: McpRequestContext) => {
    const context = await options.resolveContext({
      era: sdkContext.era,
      ...(sdkContext.requestInfo === undefined ? {} : { request: sdkContext.requestInfo }),
      ...(sdkContext.authInfo === undefined ? {} : { authInfo: sdkContext.authInfo }),
    });
    return createProductMcpServer({ backend: options.backend, context });
  }, {
    legacy: options.legacy ?? "stateless",
    ...(options.onerror === undefined ? {} : { onerror: options.onerror }),
  });

  return {
    ...sdkHandler,
    fetch: async (request, requestOptions) => {
      const rejected = hostHeaderValidationResponse(request, allowedHostnames)
        ?? originValidationResponse(request, allowedOrigins);
      return rejected ?? sdkHandler.fetch(request, requestOptions);
    },
  };
}

export function parseProductProposalBackendResult(value: unknown): ProductProposalBackendResult {
  const parsed = approvalRequiredBackendSchema.or(deniedBackendSchema).parse(value);
  if (parsed.status === "approval_required") return parsed;
  return {
    status: parsed.status,
    code: parsed.code,
    ...(parsed.reason === undefined ? {} : { reason: parsed.reason }),
    ...(parsed.requestId === undefined ? {} : { requestId: parsed.requestId }),
  };
}

export function parseProductStatusBackendResult(value: unknown): ProductStatusBackendResult {
  return toStatusBackendResult(statusBackendSchema.parse(value));
}

export function parseProductResumeBackendResult(value: unknown): ProductResumeBackendResult {
  return resumeBackendSchema.parse(value) as ProductResumeBackendResult;
}

export function parseProductReceiptBackendResult(value: unknown): ProductReceiptBackendResult {
  const parsed = receiptBackendSchema.parse(value);
  if (parsed.status === "not_available") return parsed;
  return {
    status: parsed.status,
    requestId: parsed.requestId,
    receipt: toExecutionReceipt(parsed.receipt),
    ...(parsed.chainVerified === undefined ? {} : { chainVerified: parsed.chainVerified }),
    ...(parsed.issue === undefined ? {} : { issue: parsed.issue }),
  };
}

async function safeToolCall(operation: () => Promise<CallToolResult>): Promise<CallToolResult> {
  try {
    return await operation();
  } catch {
    return {
      isError: true,
      content: [{ type: "text", text: "Agent Mandate could not safely process this request." }],
    };
  }
}

function toolResult<Output extends Record<string, unknown>>(output: Output, text: string): CallToolResult {
  return {
    content: [{ type: "text", text }],
    structuredContent: output as Record<string, JsonValue>,
  };
}

function effectiveStatus(result: ProductStatusBackendResult): ProductStatusBackendResult["status"] | "succeeded" | "failed" | "ambiguous" {
  if (result.executionStatus === "succeeded" || result.executionStatus === "failed" || result.executionStatus === "ambiguous") {
    return result.executionStatus;
  }
  return result.status;
}

function toStatusBackendResult(parsed: z.output<typeof statusBackendSchema>): ProductStatusBackendResult {
  return {
    requestId: parsed.requestId,
    status: parsed.status,
    expiresAt: parsed.expiresAt,
    ...(parsed.executionStatus === undefined ? {} : { executionStatus: parsed.executionStatus }),
    ...(parsed.reason === undefined && parsed.decisionReason === undefined
      ? {}
      : { reason: parsed.reason ?? parsed.decisionReason! }),
    ...(parsed.receiptId === undefined ? {} : { receiptId: parsed.receiptId }),
  };
}

function toExecutionReceipt(parsed: z.output<typeof receiptSchema>): ExecutionReceipt {
  return {
    id: parsed.id,
    tenantId: parsed.tenantId,
    mandateId: parsed.mandateId,
    decisionId: parsed.decisionId,
    principalId: parsed.principalId,
    agentId: parsed.agentId,
    workloadId: parsed.workloadId,
    taskId: parsed.taskId,
    audience: parsed.audience,
    action: parsed.action,
    resource: parsed.resource,
    envelopeVersion: parsed.envelopeVersion,
    envelopeHash: parsed.envelopeHash,
    idempotencyKey: parsed.idempotencyKey,
    outcome: parsed.outcome,
    ...(parsed.downstreamStatus === undefined ? {} : { downstreamStatus: parsed.downstreamStatus }),
    ...(parsed.resultHash === undefined ? {} : { resultHash: parsed.resultHash }),
    ...(parsed.previousReceiptHash === undefined ? {} : { previousReceiptHash: parsed.previousReceiptHash }),
    receiptHash: parsed.receiptHash,
    attemptCount: parsed.attemptCount,
    createdAt: parsed.createdAt,
    updatedAt: parsed.updatedAt,
  };
}

function isTerminalStatus(status: ReturnType<typeof effectiveStatus>): boolean {
  return status === "denied" || status === "expired" || status === "cancelled"
    || status === "succeeded" || status === "failed" || status === "ambiguous";
}

function validatedHostnameList(values: readonly string[], label: string): string[] {
  if (values.length === 0) throw new TypeError(`${label} must not be empty`);
  return values.map((value) => {
    if (!value || value.length > 253 || value.includes("://") || /[/?#\s]/u.test(value)) {
      throw new TypeError(`${label} contains an invalid hostname`);
    }
    return value;
  });
}
