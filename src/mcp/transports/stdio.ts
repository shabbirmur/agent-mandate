import type { McpRequestContext, Transport } from "@modelcontextprotocol/server";
import {
  serveStdio,
  type ServeStdioOptions,
  type StdioServerHandle,
} from "@modelcontextprotocol/server/stdio";
import { RemoteProductMcpBackend, type RemoteProductMcpBackendOptions } from "../remote-client.js";
import {
  createProductMcpServer,
  type ProductMcpBackend,
  type ProductMcpContext,
} from "../product-server.js";

export interface ServeProductStdioOptions<Context extends object> {
  backend: ProductMcpBackend<Context>;
  resolveContext(input: Pick<McpRequestContext, "era">): Context | Promise<Context>;
  legacy?: "serve" | "reject";
  transport?: Transport;
  onerror?: (error: Error) => void;
}

export interface ServeRemoteProductStdioOptions extends RemoteProductMcpBackendOptions {
  legacy?: "serve" | "reject";
  transport?: Transport;
  onerror?: (error: Error) => void;
}

/**
 * Serve one MCP connection over stdio. The SDK creates a fresh server for the
 * connection (and any negotiation probe). This wrapper never writes to stdout;
 * stdout remains exclusively reserved for MCP frames.
 */
export function serveProductStdio<Context extends object>(
  options: ServeProductStdioOptions<Context>,
): StdioServerHandle {
  const stdioOptions: ServeStdioOptions = {
    legacy: options.legacy ?? "serve",
    onerror: options.onerror ?? safeStderrReporter,
    ...(options.transport === undefined ? {} : { transport: options.transport }),
  };
  return serveStdio(async (sdkContext) => {
    const context = await options.resolveContext({ era: sdkContext.era });
    return createProductMcpServer({ backend: options.backend, context });
  }, stdioOptions);
}

/** Convenience entry for clients that can launch only a local stdio process. */
export function serveRemoteProductStdio(options: ServeRemoteProductStdioOptions): StdioServerHandle {
  const backendOptions: RemoteProductMcpBackendOptions = {
    endpoint: options.endpoint,
    accessToken: options.accessToken,
    sessionId: options.sessionId,
    ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
    ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
    ...(options.maximumResponseBytes === undefined ? {} : { maximumResponseBytes: options.maximumResponseBytes }),
  };
  const backend = new RemoteProductMcpBackend(backendOptions);
  const context: ProductMcpContext = Object.freeze({ sessionId: options.sessionId });
  return serveProductStdio({
    backend,
    resolveContext: () => context,
    ...(options.legacy === undefined ? {} : { legacy: options.legacy }),
    ...(options.transport === undefined ? {} : { transport: options.transport }),
    ...(options.onerror === undefined ? {} : { onerror: options.onerror }),
  });
}

function safeStderrReporter(_error: Error): void {
  process.stderr.write("Agent Mandate MCP stdio error.\n");
}
