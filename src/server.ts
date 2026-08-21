import { createServer } from "node:http";
import { createRequestHandler } from "./app.js";
import { loadConfig } from "./config.js";
import { HttpDownstreamExecutor, HttpTokenExchangeAdapter } from "./downstream/index.js";
import { ExecutionGateway } from "./gateway/index.js";
import { MandateService } from "./grants/index.js";
import { createRemoteJwtKeyResolver, JwtWorkloadAuthenticator, OidcPrincipalAuthenticator } from "./identity/index.js";
import { FailClosedPolicyAdapter, OpaPolicyAdapter } from "./policy/index.js";
import { createPostgresPool, PostgresMandateRepository } from "./storage/index.js";
import type { DownstreamResult, JsonValue } from "./types.js";

const config = loadConfig();
const pool = createPostgresPool(config.databaseUrl, config.databaseTimeoutMs, () => {
  process.stderr.write(`${JSON.stringify({ level: "error", event: "postgres.idle_client_error" })}\n`);
});
const repository = new PostgresMandateRepository(pool);
const principalAuthenticator = new OidcPrincipalAuthenticator({
  issuer: config.oidc.issuer,
  audience: config.oidc.audience,
  verificationKey: createRemoteJwtKeyResolver(config.oidc.jwksUrl),
  algorithms: ["RS256"],
  clockToleranceSeconds: config.oidc.clockToleranceSeconds,
});
const workloadAuthenticator = new JwtWorkloadAuthenticator({
  issuer: config.workload.issuer,
  audience: config.workload.audience,
  verificationKey: createRemoteJwtKeyResolver(config.workload.jwksUrl),
  algorithms: ["RS256"],
  clockToleranceSeconds: config.workload.clockToleranceSeconds,
});
const remotePolicy = config.opaUrl
  ? new OpaPolicyAdapter({ url: config.opaUrl, timeoutMs: config.requestTimeoutMs })
  : undefined;
const policy = new FailClosedPolicyAdapter(remotePolicy);
const tokenExchange = new HttpTokenExchangeAdapter({
  tokenEndpoint: config.tokenExchangeUrl,
  clientId: config.tokenExchangeClientId,
  clientSecret: config.tokenExchangeClientSecret,
  allowedAudiences: [config.downstreamAudience],
  timeoutMs: config.requestTimeoutMs,
});
const downstream = new HttpDownstreamExecutor({
  url: `${config.downstreamUrl}/payments`,
  audience: config.downstreamAudience,
  timeoutMs: config.requestTimeoutMs,
  buildBody: (envelope) => ({
    action: envelope.action,
    resource: envelope.resource,
    ...envelope.parameters,
  }),
  reconcile: async ({ credential, idempotencyKey, signal }) => {
    const response = await fetch(`${config.downstreamUrl}/payments/by-idempotency/${encodeURIComponent(idempotencyKey)}`, {
      headers: { authorization: `${credential.tokenType} ${credential.accessToken}` },
      signal,
    });
    if (response.status === 404) return undefined;
    return { status: response.status, body: await safeJson(response) };
  },
});
const gateway = new ExecutionGateway({ repository, policy, tokenExchange, downstream });
const mandates = new MandateService(repository, { highRiskActions: ["payment.create"] });
const server = createServer(createRequestHandler({
  tenantId: config.tenantId,
  repository,
  mandates,
  gateway,
  principalAuthenticator,
  workloadAuthenticator,
}));
server.requestTimeout = Math.max(10_000, config.requestTimeoutMs + 2_000);
server.headersTimeout = 5_000;
server.keepAliveTimeout = 5_000;
server.maxHeadersCount = 64;

server.listen(config.port, "0.0.0.0", () => {
  process.stdout.write(`${JSON.stringify({ level: "info", event: "gateway.ready", port: config.port })}\n`);
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => {
    server.close(async () => {
      await repository.close();
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10_000).unref();
  });
}

async function safeJson(response: Response): Promise<JsonValue> {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as JsonValue;
  } catch {
    return text;
  }
}
