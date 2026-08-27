import type { JsonValue } from "../types.js";

export type ActionRisk = "read" | "write" | "consequential" | "prohibited";

export interface ActionToolManifest {
  name: string;
  description: string;
  inputSchema: JsonValue;
}

/**
 * Hashable, data-only declaration of trusted action semantics. Executable
 * canonicalizers are covered by versioned fixtures and must bump `id` whenever
 * their behavior changes.
 */
export interface ActionProfileManifest {
  id: string;
  providerId: string;
  audience: string;
  risk: ActionRisk;
  requiredPermissions: Readonly<Record<string, string>>;
  tool: ActionToolManifest;
  canonicalization: JsonValue;
}

export interface TrustedActionIntent {
  profileId: string;
  profileHash: string;
  providerId: string;
  audience: string;
  action: string;
  risk: ActionRisk;
  resource: string;
  parameters: Record<string, JsonValue>;
}

export interface TrustedActionProfile<Input, Target> {
  readonly manifest: Readonly<ActionProfileManifest>;
  readonly profileHash: string;
  prepare(input: unknown, target: Target, correlationId: string): TrustedActionIntent;
}

export class ActionProfileValidationError extends Error {
  readonly code = "invalid_tool_arguments" as const;

  constructor() {
    super("invalid_tool_arguments");
    this.name = "ActionProfileValidationError";
  }
}
