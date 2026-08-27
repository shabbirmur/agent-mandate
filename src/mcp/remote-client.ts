import { isIP } from "node:net";
import type {
  ApprovalRequestToolInput,
  ApprovalResumeToolInput,
  GithubCreateIssueToolInput,
  ProductMcpBackend,
  ProductMcpContext,
  ProductProposalBackendResult,
  ProductReceiptBackendResult,
  ProductResumeBackendResult,
  ProductStatusBackendResult,
} from "./product-server.js";
import {
  parseProductProposalBackendResult,
  parseProductReceiptBackendResult,
  parseProductResumeBackendResult,
  parseProductStatusBackendResult,
} from "./product-server.js";

type Fetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export interface RemoteProductMcpBackendOptions {
  /** Agent Mandate deployment URL. API requests are made against its origin. */
  endpoint: string;
  /** Agent Mandate OAuth access token, never a GitHub credential. */
  accessToken: string;
  /** Opaque Agent Mandate session binding shared with the authenticated service. */
  sessionId: string;
  fetch?: Fetch;
  timeoutMs?: number;
  maximumResponseBytes?: number;
}

export class RemoteProductMcpBackendError extends Error {
  constructor(readonly code:
    | "invalid_remote_configuration"
    | "remote_context_mismatch"
    | "remote_authentication_failed"
    | "remote_request_rejected"
    | "remote_unavailable"
    | "remote_response_invalid") {
    super(code);
    this.name = "RemoteProductMcpBackendError";
  }
}

/**
 * Secret-contained stdio bridge backend. It forwards only Agent Mandate
 * authentication/session material; provider credentials never cross this API.
 */
export class RemoteProductMcpBackend implements ProductMcpBackend<ProductMcpContext> {
  readonly #origin: URL;
  readonly #accessToken: string;
  readonly #sessionId: string;
  readonly #fetch: Fetch;
  readonly #timeoutMs: number;
  readonly #maximumResponseBytes: number;

  constructor(options: RemoteProductMcpBackendOptions) {
    this.#origin = validatedOrigin(options.endpoint);
    this.#accessToken = validatedToken(options.accessToken);
    this.#sessionId = validatedSession(options.sessionId);
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#timeoutMs = boundedInteger(options.timeoutMs ?? 15_000, 100, 60_000);
    this.#maximumResponseBytes = boundedInteger(options.maximumResponseBytes ?? 256 * 1_024, 1_024, 1024 * 1_024);
  }

  async proposeGithubIssue(
    context: Readonly<ProductMcpContext>,
    input: Readonly<GithubCreateIssueToolInput>,
  ): Promise<ProductProposalBackendResult> {
    this.#assertContext(context);
    const payload = await this.#request("POST", "/v1/product/github/issues/proposals", input);
    return parseProductProposalBackendResult(payload);
  }

  async status(
    context: Readonly<ProductMcpContext>,
    input: Readonly<ApprovalRequestToolInput>,
  ): Promise<ProductStatusBackendResult> {
    this.#assertContext(context);
    const payload = await this.#request("GET", `/v1/product/approvals/${encodeURIComponent(input.requestId)}`);
    return parseProductStatusBackendResult(payload);
  }

  async resume(
    context: Readonly<ProductMcpContext>,
    input: Readonly<ApprovalResumeToolInput>,
  ): Promise<ProductResumeBackendResult> {
    this.#assertContext(context);
    try {
      const payload = await this.#request("POST", "/v1/product/approvals/resume", input);
      return parseProductResumeBackendResult(payload);
    } catch (error) {
      if (error instanceof RemoteProductMcpBackendError) {
        if (error.code !== "remote_unavailable" && error.code !== "remote_response_invalid") throw error;
      }
      return {
        status: "ambiguous",
        code: "remote_response_ambiguous",
        reason: "The Agent Mandate response was unavailable after execution may have started.",
      };
    }
  }

  async receipt(
    context: Readonly<ProductMcpContext>,
    input: Readonly<ApprovalRequestToolInput>,
  ): Promise<ProductReceiptBackendResult> {
    this.#assertContext(context);
    const payload = await this.#request(
      "GET",
      `/v1/product/approvals/${encodeURIComponent(input.requestId)}/receipt`,
    );
    return parseProductReceiptBackendResult(payload);
  }

  #assertContext(context: Readonly<ProductMcpContext>): void {
    if (!context || context.sessionId !== this.#sessionId) {
      throw new RemoteProductMcpBackendError("remote_context_mismatch");
    }
  }

  async #request(method: "GET" | "POST", path: string, body?: object): Promise<unknown> {
    const url = new URL(path, this.#origin);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.#timeoutMs);
    try {
      let response: Response;
      try {
        response = await this.#fetch(url, {
          method,
          redirect: "error",
          headers: {
            accept: "application/json",
            authorization: `Bearer ${this.#accessToken}`,
            "x-agent-mandate-session": this.#sessionId,
            ...(body === undefined ? {} : { "content-type": "application/json" }),
          },
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
          signal: controller.signal,
        });
      } catch {
        throw new RemoteProductMcpBackendError("remote_unavailable");
      }

      if (response.status === 401 || response.status === 403) {
        await discardBody(response);
        throw new RemoteProductMcpBackendError("remote_authentication_failed");
      }
      if (response.status < 200 || response.status >= 300) {
        await discardBody(response);
        throw new RemoteProductMcpBackendError(response.status >= 500 ? "remote_unavailable" : "remote_request_rejected");
      }
      if (!isJsonContentType(response.headers.get("content-type"))) {
        await discardBody(response);
        throw new RemoteProductMcpBackendError("remote_response_invalid");
      }
      try {
        return await readBoundedJson(response, this.#maximumResponseBytes);
      } catch {
        throw new RemoteProductMcpBackendError("remote_response_invalid");
      }
    } finally {
      clearTimeout(timeout);
    }
  }
}

function validatedOrigin(value: string): URL {
  if (typeof value !== "string" || value.length === 0 || value.length > 2_048) invalidConfiguration();
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return invalidConfiguration();
  }
  if (
    !url.hostname
    || url.username
    || url.password
    || url.search
    || url.hash
    || (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopback(url.hostname)))
  ) invalidConfiguration();
  return new URL(`${url.protocol}//${url.host}/`);
}

function validatedToken(value: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 8_192 || /\s/u.test(value)) invalidConfiguration();
  return value;
}

function validatedSession(value: string): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9._:-]{1,256}$/u.test(value)) invalidConfiguration();
  return value;
}

function boundedInteger(value: number, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) invalidConfiguration();
  return value;
}

function invalidConfiguration(): never {
  throw new RemoteProductMcpBackendError("invalid_remote_configuration");
}

function isLoopback(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  if (normalized === "localhost" || normalized === "::1" || normalized === "[::1]") return true;
  return isIP(normalized) === 4 && normalized.split(".")[0] === "127";
}

function isJsonContentType(value: string | null): boolean {
  return value !== null && value.split(";", 1)[0]!.trim().toLowerCase() === "application/json";
}

async function readBoundedJson(response: Response, maximumBytes: number): Promise<unknown> {
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    const length = Number(declared);
    if (!Number.isSafeInteger(length) || length < 0 || length > maximumBytes) throw new Error("invalid_response");
  }
  if (response.body === null) throw new Error("invalid_response");

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel();
        throw new Error("invalid_response");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  if (total === 0) throw new Error("invalid_response");
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
}

async function discardBody(response: Response): Promise<void> {
  await response.body?.cancel().catch(() => undefined);
}
