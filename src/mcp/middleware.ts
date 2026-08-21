import type { ActionRequest, ExecuteResult, JsonValue, WorkloadContext } from "../types.js";
import { toJsonValue } from "../canonical.js";

export interface ActionGatewayLike {
  execute(request: ActionRequest): Promise<ExecuteResult>;
}

export interface McpCallContext extends WorkloadContext {
  grant: string;
  taskId: string;
  idempotencyKey: string;
}

export interface McpToolBinding<Arguments extends Record<string, JsonValue> = Record<string, JsonValue>> {
  /** MCP-visible tool name. It is not treated as the authorized action. */
  name: string;
  /** Trusted, server-configured authorization metadata. */
  action: string;
  audience: string;
  resource: string | ((args: Readonly<Arguments>) => string);
  parameters?: (args: Readonly<Arguments>) => Record<string, JsonValue>;
}

export interface McpToolCall {
  name: string;
  arguments?: Record<string, JsonValue>;
}

/** Preserve a binding's generic argument type while defining trusted tools. */
export function defineMcpTool<Arguments extends Record<string, JsonValue>>(
  binding: McpToolBinding<Arguments>,
): McpToolBinding<Arguments> {
  return Object.freeze({ ...binding });
}

/**
 * MCP policy-enforcement middleware. It translates trusted tool metadata into
 * the exact same ActionRequest consumed by the HTTP gateway path.
 */
export class McpExecutionMiddleware {
  readonly #gateway: ActionGatewayLike;
  readonly #tools: ReadonlyMap<string, McpToolBinding>;

  constructor(gateway: ActionGatewayLike, tools: readonly McpToolBinding[]) {
    this.#gateway = gateway;
    const registry = new Map<string, McpToolBinding>();
    for (const tool of tools) {
      if (!tool.name || !tool.action || !tool.audience) throw new TypeError("MCP tool metadata is incomplete");
      if (registry.has(tool.name)) throw new TypeError(`duplicate MCP tool: ${tool.name}`);
      registry.set(tool.name, Object.freeze({ ...tool }));
    }
    this.#tools = registry;
  }

  async execute(call: McpToolCall, context: McpCallContext): Promise<ExecuteResult> {
    const tool = this.#tools.get(call.name);
    if (!tool) throw new McpToolError("unknown_tool");
    validateContext(context);

    const args = (call.arguments ?? {}) as Record<string, JsonValue>;
    let resource: string;
    let parameters: Record<string, JsonValue>;
    try {
      toJsonValue(args);
      resource = typeof tool.resource === "function" ? tool.resource(Object.freeze(structuredClone(args))) : tool.resource;
      parameters = tool.parameters ? tool.parameters(Object.freeze(structuredClone(args))) : structuredClone(args);
      if (!resource || typeof resource !== "string") throw new TypeError("resource selector returned an invalid resource");
      toJsonValue(parameters);
    } catch (error) {
      if (error instanceof McpToolError) throw error;
      throw new McpToolError("invalid_tool_arguments");
    }
    return await this.#gateway.execute({
      grant: context.grant,
      tenantId: context.tenantId,
      agentId: context.agentId,
      workloadId: context.workloadId,
      taskId: context.taskId,
      audience: tool.audience,
      action: tool.action,
      resource,
      parameters,
      idempotencyKey: context.idempotencyKey,
    });
  }

  /** Alias useful for MCP SDK handler composition. */
  call(call: McpToolCall, context: McpCallContext): Promise<ExecuteResult> {
    return this.execute(call, context);
  }
}

export class McpToolError extends Error {
  readonly code: "unknown_tool" | "invalid_tool_arguments" | "missing_identity_or_context";

  constructor(code: McpToolError["code"]) {
    super(code);
    this.name = "McpToolError";
    this.code = code;
  }
}

function validateContext(context: McpCallContext): void {
  if ([
    context.grant,
    context.tenantId,
    context.agentId,
    context.workloadId,
    context.taskId,
    context.idempotencyKey,
  ].some((value) => typeof value !== "string" || value.length === 0)) {
    throw new McpToolError("missing_identity_or_context");
  }
}
