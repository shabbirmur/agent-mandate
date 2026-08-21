import type { DownstreamExecutor } from "../ports.js";
import type { ActionEnvelope, DownstreamCredential, DownstreamResult, JsonValue } from "../types.js";
import { canonicalJson, toJsonValue } from "../canonical.js";
import { redactSensitive } from "../security/redaction.js";
import { DownstreamAudienceMismatchError, DownstreamExecutionError, DownstreamTimeoutError } from "./errors.js";

type ExecuteInput = Parameters<DownstreamExecutor["execute"]>[0];
type ReconcileInput = Parameters<NonNullable<DownstreamExecutor["reconcile"]>>[0];

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
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#headers = { ...(options.headers ?? {}) };
    this.#reconcile = options.reconcile;
    this.#buildBody = options.buildBody ?? defaultBody;
    this.#dpopProof = options.dpopProof;
    if (!this.#audience) throw new TypeError("audience is required");
    if (!Number.isFinite(this.#timeoutMs) || this.#timeoutMs <= 0) throw new TypeError("timeoutMs must be positive");
  }

  async execute(input: ExecuteInput): Promise<DownstreamResult> {
    this.#validateAudience(input.envelope, input.credential);
    const expiresAt = Date.parse(input.credential.expiresAt);
    if (!Number.isFinite(expiresAt) || Date.now() >= expiresAt) throw new DownstreamExecutionError("downstream credential expired");

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.#timeoutMs);
    try {
      const dpop = await this.#proof(input);
      const response = await this.#fetch(this.#url, {
        method: this.#method,
        headers: {
          ...this.#headers,
          "content-type": "application/json",
          authorization: `${input.credential.tokenType} ${input.credential.accessToken}`,
          "idempotency-key": input.idempotencyKey,
          ...(dpop ? { dpop } : {}),
        },
        body: canonicalJson(this.#buildBody(input.envelope)),
        signal: controller.signal,
      });
      return { status: response.status, body: await safeResponseBody(response, input.credential.accessToken) };
    } catch (error) {
      if (error instanceof DownstreamExecutionError) throw error;
      if (controller.signal.aborted || isAbort(error)) throw new DownstreamTimeoutError();
      throw new DownstreamExecutionError("downstream network failure", true);
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
      const result = await this.#reconcile({
        envelope: structuredClone(input.envelope),
        credential: Object.freeze({ ...input.credential }),
        idempotencyKey: input.idempotencyKey,
        signal: controller.signal,
      });
      if (!result) return undefined;
      return { status: result.status, body: redactSensitive(result.body, { secrets: [input.credential.accessToken] }) };
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
    const proof = await this.#dpopProof({
      url: this.#url,
      method: this.#method,
      envelope: structuredClone(input.envelope),
      credential: Object.freeze({ ...input.credential }),
      idempotencyKey: input.idempotencyKey,
    });
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

async function safeResponseBody(response: Response, credential: string): Promise<JsonValue> {
  const text = await response.text();
  if (text === "") return null;
  let value: unknown = text;
  try {
    value = JSON.parse(text) as unknown;
    toJsonValue(value);
  } catch {
    value = text;
  }
  return redactSensitive(value, { secrets: [credential] });
}

function isAbort(error: unknown): boolean {
  return error instanceof Error && (error.name === "AbortError" || error.name === "TimeoutError");
}
