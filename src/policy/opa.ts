import type { PolicyAdapter } from "../ports.js";
import type { PolicyInput, PolicyResult } from "../types.js";

export interface OpaPolicyAdapterOptions {
  url: string;
  bearerToken?: string;
  timeoutMs?: number;
  fetch?: typeof fetch;
}

/** Minimal OPA data API adapter. Every transport/schema error is indeterminate. */
export class OpaPolicyAdapter implements PolicyAdapter {
  readonly #url: string;
  readonly #bearerToken: string | undefined;
  readonly #timeoutMs: number;
  readonly #fetch: typeof fetch;

  constructor(options: OpaPolicyAdapterOptions) {
    const url = new URL(options.url);
    if (url.username || url.password) throw new TypeError("OPA URL must not contain credentials");
    this.#url = url.toString();
    this.#bearerToken = options.bearerToken;
    this.#timeoutMs = options.timeoutMs ?? 2_000;
    this.#fetch = options.fetch ?? globalThis.fetch;
    if (!Number.isFinite(this.#timeoutMs) || this.#timeoutMs <= 0) throw new TypeError("timeoutMs must be positive");
  }

  async evaluate(input: PolicyInput): Promise<PolicyResult> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.#timeoutMs);
    try {
      const response = await this.#fetch(this.#url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(this.#bearerToken ? { authorization: `Bearer ${this.#bearerToken}` } : {}),
        },
        body: JSON.stringify({ input: withoutGrantVerifier(input) }),
        signal: controller.signal,
      });
      if (!response.ok) return indeterminate();
      return parseOpaResult(await response.json());
    } catch {
      return indeterminate();
    } finally {
      clearTimeout(timeout);
    }
  }
}

function withoutGrantVerifier(input: PolicyInput): Omit<PolicyInput, "mandate"> & { mandate: Omit<PolicyInput["mandate"], "grantHash"> } {
  const { grantHash: _, ...mandate } = input.mandate;
  return { ...input, mandate };
}

function parseOpaResult(value: unknown): PolicyResult {
  if (!isRecord(value) || !("result" in value)) return indeterminate();
  const result = value.result;
  if (typeof result === "boolean") return result ? { outcome: "allow" } : { outcome: "deny", reason: "policy_denied" };
  if (!isRecord(result)) return indeterminate();
  if (typeof result.allow === "boolean") {
    return result.allow
      ? { outcome: "allow" }
      : { outcome: "deny", reason: "policy_denied" };
  }
  if (result.outcome === "allow") return { outcome: "allow" };
  if (result.outcome === "deny") {
    return { outcome: "deny", reason: "policy_denied" };
  }
  return indeterminate();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function indeterminate(): PolicyResult {
  return { outcome: "indeterminate", reason: "policy_indeterminate" };
}
