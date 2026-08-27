import type { Pool } from "pg";
import { githubIssueCreateProfile, GITHUB_ISSUE_CREATE_PROFILE_ID } from "../actions/index.js";
import { ApprovalService, InternalGrantDeriver, PostgresApprovalRepository } from "../approvals/index.js";
import { PostgresProviderConnectionRepository } from "../connections/index.js";
import { ExecutionGateway } from "../gateway/index.js";
import { MandateService } from "../grants/index.js";
import {
  createRemoteJwtKeyResolver,
  JwtProductAccessAuthenticator,
  OidcPrincipalAuthenticator,
  ProductAccessAuthenticationError,
  type ProductAccessAuthenticator,
} from "../identity/index.js";
import { LocalPolicyAdapter } from "../policy/index.js";
import {
  GitHubAppCredentialMinter,
  GitHubInstallationTokenExchangeAdapter,
  GitHubIssueExecutor,
} from "../providers/index.js";
import { PostgresMandateRepository } from "../storage/index.js";
import { ProductService } from "./service.js";
import type { ProductConfig } from "./config.js";
import type { ProviderConnectionRepository } from "../ports.js";

export async function createProductRuntime(config: ProductConfig, pool: Pool) {
  const mandatesRepository = new PostgresMandateRepository(pool);
  const approvalsRepository = new PostgresApprovalRepository(pool);
  const connections = new PostgresProviderConnectionRepository(pool);
  await seedConfiguredGitHubConnection(config, connections);

  const minter = new GitHubAppCredentialMinter({
    appId: config.github.appId,
    privateKeyPem: config.github.privateKeyPem,
    timeoutMs: config.requestTimeoutMs,
  });
  const tokenExchange = new GitHubInstallationTokenExchangeAdapter({
    installationId: config.github.installationId,
    minter,
    authorizeResource: async (repositoryId) => {
      const [connection, resource] = await Promise.all([
        connections.findConnection(config.tenantId, "github", config.github.connectionId),
        connections.findResource(config.tenantId, config.github.connectionId, String(repositoryId)),
      ]);
      return connection?.status === "active" && resource?.status === "active";
    },
  });
  const gateway = new ExecutionGateway({
    repository: mandatesRepository,
    policy: new LocalPolicyAdapter(),
    tokenExchange,
    downstream: new GitHubIssueExecutor({ timeoutMs: config.requestTimeoutMs }),
    scope: (envelope) => envelope.resource,
  });
  const mandates = new MandateService(mandatesRepository, { highRiskActions: [GITHUB_ISSUE_CREATE_PROFILE_ID] });
  const approvals = new ApprovalService({
    repository: approvalsRepository,
    mandates,
    grantDeriver: new InternalGrantDeriver(config.internalGrantKey),
    executorFor: ({ providerId, connectionId }) => {
      if (providerId !== "github" || connectionId !== config.github.connectionId) throw new Error("provider_connection_unavailable");
      return gateway;
    },
    currentProfileHash: (profileId) => profileId === githubIssueCreateProfile.manifest.id ? githubIssueCreateProfile.profileHash : undefined,
    connectionIsActive: async ({ tenantId, providerId, connectionId, providerResourceId }) => {
      if (tenantId !== config.tenantId || providerId !== "github" || connectionId !== config.github.connectionId) return false;
      const [connection, resource] = await Promise.all([
        connections.findConnection(tenantId, providerId, connectionId),
        connections.findResource(tenantId, connectionId, providerResourceId),
      ]);
      return connection?.status === "active" && resource?.status === "active";
    },
    publicBaseUrl: config.publicBaseUrl,
  });
  const product = new ProductService({
    approvals,
    connections,
    mandates: mandatesRepository,
    verifyReceiptChain: (tenantId) => mandatesRepository.verifyReceiptChain(tenantId),
    githubConnectionId: (context) => {
      if (context.tenantId !== config.tenantId) throw new ProductAccessAuthenticationError();
      return config.github.connectionId;
    },
  });
  const rawProductAuthenticator = new JwtProductAccessAuthenticator({
    issuer: config.productAccess.issuer,
    audience: config.productAccess.audience,
    verificationKey: createRemoteJwtKeyResolver(config.productAccess.jwksUrl),
    algorithms: ["RS256"],
    clockToleranceSeconds: config.productAccess.clockToleranceSeconds,
    requiredScope: "agent-mandate:use",
  });
  const productAuthenticator: ProductAccessAuthenticator = {
    async authenticate(token) {
      const context = await rawProductAuthenticator.authenticate(token);
      if (context.tenantId !== config.tenantId) throw new ProductAccessAuthenticationError();
      return context;
    },
  };
  const principalAuthenticator = new OidcPrincipalAuthenticator({
    issuer: config.approvalOidc.issuer,
    audience: config.approvalOidc.audience,
    verificationKey: createRemoteJwtKeyResolver(config.approvalOidc.jwksUrl),
    algorithms: ["RS256"],
    clockToleranceSeconds: config.approvalOidc.clockToleranceSeconds,
  });
  return {
    approvals,
    approvalsRepository,
    connections,
    gateway,
    mandates,
    mandatesRepository,
    principalAuthenticator,
    product,
    productAuthenticator,
  };
}

export async function seedConfiguredGitHubConnection(
  config: ProductConfig,
  connections: ProviderConnectionRepository,
): Promise<void> {
  const now = new Date();
  const existingConnection = await connections.findConnection(
    config.tenantId,
    "github",
    config.github.connectionId,
  );
  await connections.putConnection({
    id: config.github.connectionId,
    tenantId: config.tenantId,
    providerId: "github",
    externalAccountId: String(config.github.installationId),
    displayName: `GitHub App installation ${config.github.installationId}`,
    secretRef: config.github.privateKeyReference,
    metadata: { appId: config.github.appId, installationId: config.github.installationId },
    // Startup must never silently undo an operator suspension or revocation.
    status: existingConnection?.status ?? "active",
  }, now);
  const [owner, name] = config.github.repository.split("/");
  if (!owner || !name) throw new Error("invalid GitHub repository configuration");
  const existingResource = await connections.findResource(
    config.tenantId,
    config.github.connectionId,
    String(config.github.repositoryId),
  );
  await connections.putResource({
    tenantId: config.tenantId,
    connectionId: config.github.connectionId,
    providerResourceId: String(config.github.repositoryId),
    displayName: config.github.repository,
    selector: { repository: config.github.repository, repositoryId: config.github.repositoryId, owner, name },
    // Likewise, a removed repository stays removed across restarts.
    status: existingResource?.status ?? "active",
  }, now);
  // This v0.2 profile has exactly one configured repository. A configuration
  // change must attenuate the previous resource instead of accumulating
  // additional active authority across restarts.
  const configuredResources = await connections.listResources(
    config.tenantId,
    "github",
    config.github.connectionId,
  );
  for (const resource of configuredResources) {
    if (resource.providerResourceId !== String(config.github.repositoryId) && resource.status === "active") {
      await connections.setResourceStatus(
        config.tenantId,
        config.github.connectionId,
        resource.providerResourceId,
        "removed",
        now,
      );
    }
  }
}
