import { createServer } from "node:http";
import { ApprovalWebController } from "./approvals/index.js";
import { createMcpHttpHandler } from "./mcp/index.js";
import {
  createProductRequestHandler,
  createProductRuntime,
  loadProductConfig,
  productContextFromAuthInfo,
} from "./product/index.js";
import { createPostgresPool } from "./storage/index.js";

async function main(): Promise<void> {
  const config = loadProductConfig();
  const pool = createPostgresPool(config.databaseUrl, config.databaseTimeoutMs, () => {
    process.stderr.write(`${JSON.stringify({ level: "error", event: "postgres.idle_client_error" })}\n`);
  });
  let mcp: ReturnType<typeof createMcpHttpHandler> | undefined;
  try {
    const runtime = await createProductRuntime(config, pool);
    const approvalWeb = new ApprovalWebController({
      approvals: runtime.approvals,
      principalAuthenticator: runtime.principalAuthenticator,
      cookieKey: config.approvalCookieKey,
      publicBaseUrl: config.publicBaseUrl,
      authorizationEndpoint: config.approvalOidc.authorizationUrl,
      tokenEndpoint: config.approvalOidc.tokenUrl,
      clientId: config.approvalOidc.clientId,
      ...(config.approvalOidc.clientSecret === undefined ? {} : { clientSecret: config.approvalOidc.clientSecret }),
      allowInsecureLoopback: new URL(config.publicBaseUrl).protocol === "http:",
    });
    const hostname = new URL(config.publicBaseUrl).hostname;
    mcp = createMcpHttpHandler({
      backend: runtime.product,
      resolveContext: ({ authInfo }) => productContextFromAuthInfo(authInfo),
      allowedHostnames: [hostname],
      allowedOriginHostnames: [hostname],
      legacy: "stateless",
      onerror: () => process.stderr.write(`${JSON.stringify({ level: "error", event: "mcp.handler_error" })}\n`),
    });
    const handler = createProductRequestHandler({
      publicBaseUrl: config.publicBaseUrl,
      readiness: async () => {
        const states = await Promise.all([
          runtime.mandatesRepository.readiness(),
          runtime.approvalsRepository.readiness(),
          runtime.connections.readiness(),
        ]);
        return states.every(Boolean);
      },
      authenticator: runtime.productAuthenticator,
      service: runtime.product,
      approvalWeb,
      mcp,
      oauth: {
        issuer: config.productAccess.issuer,
        authorizationUrl: config.productAccess.authorizationUrl,
        tokenUrl: config.productAccess.tokenUrl,
        ...(config.productAccess.registrationUrl === undefined ? {} : { registrationUrl: config.productAccess.registrationUrl }),
      },
    });
    const server = createServer(handler);
    server.requestTimeout = Math.max(10_000, config.requestTimeoutMs + 5_000);
    server.headersTimeout = 5_000;
    server.keepAliveTimeout = 5_000;
    server.maxHeadersCount = 64;
    await new Promise<void>((resolve, reject) => {
      const startupError = (error: Error) => reject(error);
      server.once("error", startupError);
      server.listen(config.port, config.host, () => {
        server.off("error", startupError);
        resolve();
      });
    });
    process.stdout.write(`${JSON.stringify({
      level: "info",
      event: "product.ready",
      host: config.host,
      port: config.port,
      protection: "mediated",
    })}\n`);

    let closing = false;
    const close = (signal: "SIGINT" | "SIGTERM", exitCode = 0) => {
      if (closing) return;
      closing = true;
      server.close(async () => {
        await mcp?.close().catch(() => undefined);
        await pool.end().catch(() => undefined);
        process.exit(exitCode);
      });
      setTimeout(() => {
        process.stderr.write(`${JSON.stringify({ level: "error", event: "product.shutdown_timeout", signal })}\n`);
        process.exit(1);
      }, 10_000).unref();
    };
    server.on("error", () => {
      process.stderr.write(`${JSON.stringify({ level: "error", event: "product.listener_error" })}\n`);
      close("SIGTERM", 1);
    });
    process.once("SIGINT", () => close("SIGINT"));
    process.once("SIGTERM", () => close("SIGTERM"));
  } catch (error) {
    await mcp?.close().catch(() => undefined);
    await pool.end().catch(() => undefined);
    throw error;
  }
}

await main().catch(() => {
  process.stderr.write(`${JSON.stringify({ level: "error", event: "product.startup_failed" })}\n`);
  process.exitCode = 1;
});
