import type { ActionEnvelope, DownstreamCredential, DownstreamResult } from "../types.js";

export interface ProviderExecutionInput {
  envelope: ActionEnvelope;
  credential: DownstreamCredential;
  idempotencyKey: string;
}

export interface ProviderExecutor {
  execute(input: ProviderExecutionInput): Promise<DownstreamResult>;
  reconcile(input: ProviderExecutionInput): Promise<DownstreamResult | undefined>;
}

export class ProviderConfigurationError extends Error {
  constructor() {
    super("invalid_provider_configuration");
    this.name = "ProviderConfigurationError";
  }
}

export class ProviderCredentialError extends Error {
  readonly code = "provider_credential_unavailable" as const;

  constructor() {
    super("provider_credential_unavailable");
    this.name = "ProviderCredentialError";
  }
}
