import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

const port = Number(process.env.PORT ?? 9000);
const issuer = process.env.ISSUER ?? `http://127.0.0.1:${port}`;
const keyId = process.env.KEY_ID ?? "pilot-signing-key-1";
const { publicKey, privateKey } = await generateKeyPair("RS256", { modulusLength: 2048, extractable: true });
const publicJwk = { ...(await exportJWK(publicKey)), kid: keyId, use: "sig", alg: "RS256" };

createServer(async (request, response) => {
  try {
    if (request.method === "GET" && request.url === "/healthz") return json(response, 200, { ok: true });
    if (request.method === "GET" && request.url === "/.well-known/openid-configuration") {
      return json(response, 200, {
        issuer,
        jwks_uri: `${issuer}/jwks.json`,
        token_endpoint: `${issuer}/token`,
        id_token_signing_alg_values_supported: ["RS256"],
      });
    }
    if (request.method === "GET" && request.url === "/jwks.json") return json(response, 200, { keys: [publicJwk] });
    if (request.method === "POST" && request.url === "/token") {
      const params = new URLSearchParams(await readBody(request));
      if (params.get("grant_type") !== "client_credentials") return oauthError(response, "unsupported_grant_type");
      const kind = params.get("token_kind");
      const tenantId = params.get("tenant_id") ?? "pilot";
      const subject = params.get("subject") ?? (kind === "workload" ? "workload:payment-agent-1" : "user:alice");
      const audience = params.get("audience") ?? (kind === "workload" ? "agent-mandate-gateway" : "agent-mandate-control");
      const now = Math.floor(Date.now() / 1_000);
      const claims = kind === "workload"
        ? { tenant_id: tenantId, agent_id: params.get("agent_id") ?? "agent:payment", workload_id: subject }
        : { tenant_id: tenantId, principal_id: subject, ...(params.get("nonce") ? { nonce: params.get("nonce")! } : {}) };
      const accessToken = await new SignJWT(claims)
        .setProtectedHeader({ alg: "RS256", kid: keyId, typ: "JWT" })
        .setIssuer(issuer)
        .setSubject(subject)
        .setAudience(audience)
        .setIssuedAt(now)
        .setExpirationTime(now + 300)
        .sign(privateKey);
      return json(response, 200, { access_token: accessToken, token_type: "Bearer", expires_in: 300 });
    }
    return json(response, 404, { error: "not_found" });
  } catch {
    return json(response, 400, { error: "invalid_request" });
  }
}).listen(port, "0.0.0.0", () => process.stdout.write(`${JSON.stringify({ level: "info", event: "sandbox_idp.ready", port })}\n`));

function oauthError(response: ServerResponse, error: string): void {
  json(response, 400, { error });
}

async function readBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

function json(response: ServerResponse, status: number, value: unknown): void {
  response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  response.end(JSON.stringify(value));
}
