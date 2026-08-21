import type { PolicyAdapter } from "../ports.js";
import type { PolicyInput, PolicyResult } from "../types.js";
import { LocalPolicyAdapter } from "./local.js";

/**
 * Enforces local pilot invariants first and lets an optional remote policy add
 * restrictions. The remote adapter cannot turn a local denial into an allow.
 */
export class FailClosedPolicyAdapter implements PolicyAdapter {
  readonly #local: PolicyAdapter;
  readonly #additional: PolicyAdapter | undefined;

  constructor(additional?: PolicyAdapter, local: PolicyAdapter = new LocalPolicyAdapter()) {
    this.#local = local;
    this.#additional = additional;
  }

  async evaluate(input: PolicyInput): Promise<PolicyResult> {
    const local = await safeEvaluate(this.#local, input);
    if (local.outcome !== "allow") return local;
    if (!this.#additional) return local;
    return safeEvaluate(this.#additional, input);
  }
}

async function safeEvaluate(adapter: PolicyAdapter, input: PolicyInput): Promise<PolicyResult> {
  try {
    const result = await adapter.evaluate(input);
    if (result.outcome === "allow" || result.outcome === "deny" || result.outcome === "indeterminate") return result;
  } catch {
    // Fail closed below.
  }
  return { outcome: "indeterminate", reason: "policy_indeterminate" };
}
