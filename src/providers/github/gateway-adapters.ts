import type { TokenExchangeAdapter } from "../../ports.js";
import type { DownstreamCredential } from "../../types.js";
import { GITHUB_API_ORIGIN } from "./constants.js";
import type { GitHubAppCredentialMinter } from "./app-credential.js";
import { ProviderCredentialError } from "../types.js";

/** Adapts a connection-bound GitHub App installation to the shared gateway port. */
export class GitHubInstallationTokenExchangeAdapter implements TokenExchangeAdapter {
  readonly #installationId: number;
  readonly #minter: Pick<GitHubAppCredentialMinter, "mint">;
  readonly #authorizeResource: ((repositoryId: number) => Promise<boolean>) | undefined;

  constructor(input: {
    installationId: number;
    minter: Pick<GitHubAppCredentialMinter, "mint">;
    authorizeResource?: (repositoryId: number) => Promise<boolean>;
  }) {
    if (!Number.isSafeInteger(input.installationId) || input.installationId <= 0) throw new TypeError("invalid GitHub installation ID");
    this.#installationId = input.installationId;
    this.#minter = input.minter;
    this.#authorizeResource = input.authorizeResource;
  }

  async exchange(input: Parameters<TokenExchangeAdapter["exchange"]>[0]): Promise<DownstreamCredential> {
    if (
      !input.tenantId || !input.principalId || !input.agentId || !input.subjectGrant ||
      input.audience !== GITHUB_API_ORIGIN
    ) throw new ProviderCredentialError();
    const match = input.scope.match(/^github:repository:([1-9][0-9]*)$/);
    if (!match) throw new ProviderCredentialError();
    const repositoryId = Number(match[1]);
    if (!Number.isSafeInteger(repositoryId) || repositoryId <= 0) throw new ProviderCredentialError();
    if (this.#authorizeResource !== undefined && !await this.#authorizeResource(repositoryId)) throw new ProviderCredentialError();
    return this.#minter.mint({ installationId: this.#installationId, repositoryId });
  }
}
