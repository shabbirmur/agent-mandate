import { toNodeHandler, type NodeMcpRequestHandler, type ToNodeHandlerOptions } from "@modelcontextprotocol/node";
import type { ProductMcpHttpHandler } from "../product-server.js";

/** Adapt the validated fetch handler to node:http, Express, or compatible hosts. */
export function toProductMcpNodeHandler(
  handler: ProductMcpHttpHandler,
  options?: ToNodeHandlerOptions,
): NodeMcpRequestHandler {
  return toNodeHandler(handler, options);
}
