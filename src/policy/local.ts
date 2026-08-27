import { ACTION_ENVELOPE_VERSION, type ErrorCode, type PolicyInput, type PolicyResult } from "../types.js";
import type { PolicyAdapter } from "../ports.js";
import { canonicalHash } from "../canonical.js";

/** Deterministic checks that are always enforced, even when OPA is configured. */
export class LocalPolicyAdapter implements PolicyAdapter {
  async evaluate(input: PolicyInput): Promise<PolicyResult> {
    try {
      return evaluateLocalPolicy(input);
    } catch {
      return { outcome: "indeterminate", reason: "policy_indeterminate" };
    }
  }
}

export function evaluateLocalPolicy(input: PolicyInput): PolicyResult {
  const { envelope, mandate } = input;
  const now = parseTimestamp(input.now);
  const expiresAt = parseTimestamp(mandate.expiresAt);

  if (envelope.version !== ACTION_ENVELOPE_VERSION) return deny("invalid_request");
  if (mandate.tenantId !== envelope.tenantId) return deny("tenant_mismatch");
  if (mandate.principalId !== envelope.principalId) return deny("invalid_principal");
  if (mandate.agentId !== envelope.agentId) return deny("agent_mismatch");
  if (mandate.workloadId !== envelope.workloadId) return deny("workload_mismatch");
  if (mandate.taskId !== envelope.taskId) return deny("task_mismatch");
  if (mandate.audience !== envelope.audience) return deny("audience_mismatch");
  if (mandate.status !== "active") return deny("revoked");
  if (now >= expiresAt) return deny("expired");
  if (!mandate.actions.includes(envelope.action)) return deny("action_not_granted");
  if (!mandate.resources.includes(envelope.resource)) return deny("resource_not_granted");

  const constraints = mandate.constraints;
  if (constraints?.maxCalls !== undefined) {
    if (!Number.isInteger(constraints.maxCalls) || constraints.maxCalls < 1) return indeterminate();
    if (mandate.successfulUses >= constraints.maxCalls) return deny("call_limit_exceeded");
  }

  for (const [key, expected] of Object.entries(constraints?.equals ?? {})) {
    if (!Object.hasOwn(envelope.parameters, key) || envelope.parameters[key] !== expected) {
      return deny("parameter_mismatch");
    }
  }
  for (const [key, maximum] of Object.entries(constraints?.maximum ?? {})) {
    const actual = envelope.parameters[key];
    if (!Number.isFinite(maximum) || typeof actual !== "number" || !Number.isFinite(actual) || actual > maximum) {
      return deny("parameter_mismatch");
    }
  }

  if (mandate.approval?.required) {
    if (!mandate.approval.approvedBy || !mandate.approval.approvedAt || !mandate.approval.envelopeHash) {
      return deny("approval_required");
    }
    if (mandate.approval.approvedBy !== mandate.principalId) return deny("approval_mismatch");
    parseTimestamp(mandate.approval.approvedAt);
    if (mandate.approval.envelopeHash !== canonicalHash(envelope)) return deny("approval_mismatch");
    if (mandate.approvalRequestId !== undefined) {
      const product = mandate.approval;
      if (
        product.approvalRequestId !== mandate.approvalRequestId ||
        !product.approvedAt ||
        !product.intentHash || !digest(product.intentHash) ||
        !product.profileId || !product.profileHash || !digest(product.profileHash) ||
        !product.providerId || !product.providerConnectionId || !product.providerResourceId ||
        !product.authenticatedAt
      ) return deny("approval_mismatch");
      const authenticatedAt = parseTimestamp(product.authenticatedAt);
      const approvedAt = parseTimestamp(product.approvedAt);
      if (authenticatedAt > approvedAt) return deny("approval_mismatch");
    }
  }

  return { outcome: "allow" };
}

function digest(value: string): boolean {
  return /^[A-Za-z0-9_-]{43}$/.test(value);
}

function parseTimestamp(value: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new TypeError("invalid timestamp");
  return parsed;
}

function deny(reason: ErrorCode): PolicyResult {
  return { outcome: "deny", reason };
}

function indeterminate(): PolicyResult {
  return { outcome: "indeterminate", reason: "policy_indeterminate" };
}
