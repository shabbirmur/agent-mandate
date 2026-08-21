import { randomBytes, randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

const port = Number(process.env.PORT ?? 9100);
const audience = process.env.DOWNSTREAM_AUDIENCE ?? "https://payments.sandbox";
const clientId = process.env.TOKEN_EXCHANGE_CLIENT_ID ?? "agent-mandate";
const clientSecret = process.env.TOKEN_EXCHANGE_CLIENT_SECRET ?? "local-only-secret";
const tokens = new Map<string, { audience: string; expiresAt: number }>();
const payments = new Map<string, unknown>();

createServer(async (request, response) => {
  try {
    if (request.method === "GET" && request.url === "/healthz") return json(response, 200, { ok: true });
    if (request.method === "POST" && request.url === "/oauth/token") {
      if (!validClient(request.headers.authorization)) return oauthError(response, 401, "invalid_client");
      const form = new URLSearchParams(await readBody(request));
      if (form.get("grant_type") !== "urn:ietf:params:oauth:grant-type:token-exchange") {
        return oauthError(response, 400, "unsupported_grant_type");
      }
      if (!form.get("subject_token")) return oauthError(response, 400, "invalid_request");
      if (form.get("resource") !== audience) return oauthError(response, 400, "invalid_target");
      const token = `sandbox_${randomBytes(32).toString("base64url")}`;
      tokens.set(token, { audience, expiresAt: Date.now() + 60_000 });
      return json(response, 200, {
        access_token: token,
        issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
        token_type: "Bearer",
        expires_in: 60,
        resource: audience,
      });
    }
    if (request.method === "POST" && request.url === "/payments") {
      if (!validDownstreamToken(request.headers.authorization)) return oauthError(response, 401, "invalid_token");
      const idempotencyKey = header(request, "idempotency-key");
      if (!idempotencyKey) return json(response, 400, { error: "missing_idempotency_key" });
      const existing = payments.get(idempotencyKey);
      if (existing) return json(response, 200, existing);
      const payload = JSON.parse(await readBody(request)) as Record<string, unknown>;
      if (payload.simulate === "timeout") return;
      if (payload.simulate === "failure") return json(response, 503, { error: "sandbox_unavailable" });
      const result = { paymentId: randomUUID(), status: "accepted", amount: payload.amount, currency: payload.currency };
      payments.set(idempotencyKey, result);
      return json(response, 201, result);
    }
    if (request.method === "GET" && request.url?.startsWith("/payments/by-idempotency/")) {
      if (!validDownstreamToken(request.headers.authorization)) return oauthError(response, 401, "invalid_token");
      const key = decodeURIComponent(request.url.slice("/payments/by-idempotency/".length));
      const existing = payments.get(key);
      return existing ? json(response, 200, existing) : json(response, 404, { error: "not_found" });
    }
    return json(response, 404, { error: "not_found" });
  } catch {
    return json(response, 400, { error: "invalid_request" });
  }
}).listen(port, "0.0.0.0", () => process.stdout.write(`${JSON.stringify({ level: "info", event: "payment_sandbox.ready", port })}\n`));

function validClient(authorization: string | undefined): boolean {
  if (!authorization?.startsWith("Basic ")) return false;
  const expected = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
  return authorization.slice("Basic ".length) === expected;
}

function validDownstreamToken(authorization: string | undefined): boolean {
  if (!authorization?.startsWith("Bearer ")) return false;
  const record = tokens.get(authorization.slice("Bearer ".length));
  return record?.audience === audience && record.expiresAt > Date.now();
}

function header(request: IncomingMessage, name: string): string | undefined {
  const value = request.headers[name];
  return Array.isArray(value) ? value[0] : value;
}

function oauthError(response: ServerResponse, status: number, error: string): void {
  response.setHeader("www-authenticate", `Bearer error=\"${error}\"`);
  json(response, status, { error });
}

async function readBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

function json(response: ServerResponse, status: number, value: unknown): void {
  if (response.writableEnded) return;
  response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  response.end(JSON.stringify(value));
}
