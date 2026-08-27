import type { DownstreamExecutor } from "../ports.js";
import type { ActionEnvelope, DownstreamCredential, DownstreamResult, JsonValue } from "../types.js";
import { canonicalJson, toJsonValue } from "../canonical.js";
import { redactSensitive } from "../security/redaction.js";
import { DownstreamAudienceMismatchError, DownstreamExecutionError, DownstreamTimeoutError } from "./errors.js";

type ExecuteInput = Parameters<DownstreamExecutor["execute"]>[0];
type ReconcileInput = Parameters<NonNullable<DownstreamExecutor["reconcile"]>>[0];

const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;

export interface ReconciliationContext {
  envelope: ActionEnvelope;
  /** Adapter-internal only. Reconciliation implementations must not log it. */
  credential: DownstreamCredential;
  idempotencyKey: string;
  signal: AbortSignal;
}

export interface DpopProofContext {
  url: string;
  method: string;
  envelope: ActionEnvelope;
  credential: DownstreamCredential;
  idempotencyKey: string;
}

export interface HttpDownstreamExecutorOptions {
  url: string;
  audience: string;
  method?: "POST" | "PUT" | "PATCH" | "DELETE";
  timeoutMs?: number;
  /** Maximum decompressed response bytes retained from execute or reconcile. */
  maxResponseBytes?: number;
  fetch?: typeof fetch;
  headers?: Readonly<Record<string, string>>;
  /** Optional side-effect status query. It must not issue the mutation again. */
  reconcile?: (context: ReconciliationContext) => Promise<DownstreamResult | undefined>;
  buildBody?: (envelope: ActionEnvelope) => JsonValue;
  /** Required when the token exchange returns a DPoP-bound credential. */
  dpopProof?: (context: DpopProofContext) => string | Promise<string>;
}

export class HttpDownstreamExecutor implements DownstreamExecutor {
  readonly #url: string;
  readonly #audience: string;
  readonly #method: "POST" | "PUT" | "PATCH" | "DELETE";
  readonly #timeoutMs: number;
  readonly #maxResponseBytes: number;
  readonly #fetch: typeof fetch;
  readonly #headers: Readonly<Record<string, string>>;
  readonly #reconcile?: HttpDownstreamExecutorOptions["reconcile"];
  readonly #buildBody: (envelope: ActionEnvelope) => JsonValue;
  readonly #dpopProof: HttpDownstreamExecutorOptions["dpopProof"];

  constructor(options: HttpDownstreamExecutorOptions) {
    const url = new URL(options.url);
    if (url.username || url.password) throw new TypeError("downstream URL must not contain credentials");
    for (const key of Object.keys(options.headers ?? {})) {
      if (/^(?:authorization|cookie|dpop|proxy-authorization)$/i.test(key)) throw new TypeError(`reserved downstream header: ${key}`);
    }
    this.#url = url.toString();
    this.#audience = options.audience;
    this.#method = options.method ?? "POST";
    this.#timeoutMs = options.timeoutMs ?? 5_000;
    this.#maxResponseBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#headers = { ...(options.headers ?? {}) };
    this.#reconcile = options.reconcile;
    this.#buildBody = options.buildBody ?? defaultBody;
    this.#dpopProof = options.dpopProof;
    if (!this.#audience) throw new TypeError("audience is required");
    if (!Number.isFinite(this.#timeoutMs) || this.#timeoutMs <= 0) throw new TypeError("timeoutMs must be positive");
    if (
      !Number.isSafeInteger(this.#maxResponseBytes)
      || this.#maxResponseBytes <= 0
      || this.#maxResponseBytes > MAX_RESPONSE_BYTES
    ) {
      throw new TypeError(`maxResponseBytes must be an integer from 1 to ${MAX_RESPONSE_BYTES}`);
    }
  }

  async execute(input: ExecuteInput): Promise<DownstreamResult> {
    this.#validateAudience(input.envelope, input.credential);
    const expiresAt = Date.parse(input.credential.expiresAt);
    if (!Number.isFinite(expiresAt) || Date.now() >= expiresAt) throw new DownstreamExecutionError("downstream credential expired");

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.#timeoutMs);
    let dispatched = false;
    try {
      const dpop = await beforeAbort(this.#proof(input), controller.signal);
      let body: string;
      try {
        body = canonicalJson(this.#buildBody(input.envelope));
      } catch {
        throw new DownstreamExecutionError("downstream request construction failed");
      }

      // From this point on, the mutation may have reached the provider. Fetch
      // does not expose enough write-progress information to prove otherwise,
      // so every transport/read failure is conservatively ambiguous.
      dispatched = true;
      const response = await beforeAbort(this.#fetch(this.#url, {
        method: this.#method,
        headers: {
          ...this.#headers,
          "content-type": "application/json",
          authorization: `${input.credential.tokenType} ${input.credential.accessToken}`,
          "idempotency-key": input.idempotencyKey,
          ...(dpop ? { dpop } : {}),
        },
        body,
        redirect: "manual",
        signal: controller.signal,
      }), controller.signal);
      if (response.redirected || isRedirectStatus(response.status)) throw new DownstreamTimeoutError();
      return {
        status: response.status,
        body: await safeResponseBody(
          response,
          input.credential.accessToken,
          this.#maxResponseBytes,
          controller.signal,
        ),
      };
    } catch (error) {
      if (!dispatched) {
        if (error instanceof DownstreamExecutionError) throw error;
        throw new DownstreamExecutionError("downstream request preparation failed");
      }
      if (error instanceof DownstreamTimeoutError) throw error;
      throw new DownstreamTimeoutError();
    } finally {
      clearTimeout(timeout);
    }
  }

  async reconcile(input: ReconcileInput): Promise<DownstreamResult | undefined> {
    this.#validateAudience(input.envelope, input.credential);
    if (!this.#reconcile) return undefined;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.#timeoutMs);
    try {
      const result = await beforeAbort(this.#reconcile({
        envelope: structuredClone(input.envelope),
        credential: Object.freeze({ ...input.credential }),
        idempotencyKey: input.idempotencyKey,
        signal: controller.signal,
      }), controller.signal);
      if (!result) return undefined;
      if (!Number.isInteger(result.status) || result.status < 100 || result.status > 599) return undefined;
      const body = redactSensitive(result.body, { secrets: [input.credential.accessToken] });
      if (Buffer.byteLength(canonicalJson(body), "utf8") > this.#maxResponseBytes) return undefined;
      return { status: result.status, body };
    } catch {
      return undefined;
    } finally {
      clearTimeout(timeout);
    }
  }

  #validateAudience(envelope: ActionEnvelope, credential: DownstreamCredential): void {
    if (envelope.audience !== this.#audience || credential.audience !== this.#audience) {
      throw new DownstreamAudienceMismatchError();
    }
  }

  async #proof(input: ExecuteInput): Promise<string | undefined> {
    if (input.credential.tokenType !== "DPoP") return undefined;
    if (!this.#dpopProof) throw new DownstreamExecutionError("DPoP proof is not configured");
    let proof: string;
    try {
      proof = await this.#dpopProof({
        url: this.#url,
        method: this.#method,
        envelope: structuredClone(input.envelope),
        credential: Object.freeze({ ...input.credential }),
        idempotencyKey: input.idempotencyKey,
      });
    } catch {
      throw new DownstreamExecutionError("DPoP proof generation failed");
    }
    if (!proof) throw new DownstreamExecutionError("DPoP proof generation failed");
    return proof;
  }
}

function defaultBody(envelope: ActionEnvelope): JsonValue {
  return {
    action: envelope.action,
    resource: envelope.resource,
    parameters: structuredClone(envelope.parameters),
  };
}

async function safeResponseBody(
  response: Response,
  credential: string,
  maximumBytes: number,
  signal: AbortSignal,
): Promise<JsonValue> {
  const text = await readBoundedResponseText(response, maximumBytes, signal);
  if (text === "") return null;
  let value: unknown = text;
  try {
    value = JSON.parse(text) as unknown;
    toJsonValue(value);
  } catch {
    if (declaresJson(response)) throw new TypeError("downstream JSON response is unreadable");
    value = text;
  }
  return redactSensitive(value, { secrets: [credential] });
}

function declaresJson(response: Response): boolean {
  const mediaType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  return mediaType === "application/json" || mediaType?.endsWith("+json") === true;
}

async function readBoundedResponseText(response: Response, maximumBytes: number, signal: AbortSignal): Promise<string> {
  const advertisedLength = contentLength(response);
  if (advertisedLength !== undefined && advertisedLength > maximumBytes) throw new TypeError("downstream response is too large");
  if (!response.body) {
    if (advertisedLength !== undefined && advertisedLength !== 0) throw new TypeError("downstream response was truncated");
    return "";
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  const cancel = () => { void reader.cancel().catch(() => undefined); };
  signal.addEventListener("abort", cancel, { once: true });
  try {
    while (true) {
      const { done, value } = await beforeAbort(reader.read(), signal);
      if (done) break;
      size += value.byteLength;
      if (size > maximumBytes) {
        cancel();
        throw new TypeError("downstream response is too large");
      }
      chunks.push(value);
    }
  } finally {
    signal.removeEventListener("abort", cancel);
    reader.releaseLock();
  }

  if (
    advertisedLength !== undefined
    && response.headers.get("content-encoding") === null
    && advertisedLength !== size
  ) {
    throw new TypeError("downstream response was truncated");
  }
  const bytes = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)), size);
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

function contentLength(response: Response): number | undefined {
  const value = response.headers.get("content-length");
  if (value === null || !/^\d+$/.test(value)) return undefined;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : Number.POSITIVE_INFINITY;
}

function isRedirectStatus(status: number): boolean {
  return status >= 300 && status < 400;
}

function beforeAbort<Value>(operation: Promise<Value>, signal: AbortSignal): Promise<Value> {
  if (signal.aborted) return Promise.reject(abortError());
  return new Promise<Value>((resolve, reject) => {
    const onAbort = () => {
      cleanup();
      reject(abortError());
    };
    const cleanup = () => signal.removeEventListener("abort", onAbort);
    signal.addEventListener("abort", onAbort, { once: true });
    operation.then(
      (value) => {
        cleanup();
        resolve(value);
      },
      (error: unknown) => {
        cleanup();
        reject(error);
      },
    );
  });
}

function abortError(): Error {
  const error = new Error("operation aborted");
  error.name = "AbortError";
  return error;
}
